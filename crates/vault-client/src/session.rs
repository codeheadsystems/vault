//! The unlocked session and the procedure driver that the Firefox and Android bindings share
//! (docs/android.md, Shared session). Both take Rust types in and out, read no clock, and draw
//! randomness only from the caller's [`Rng`]; the bindings convert to their own types around
//! them.

use crate::autofill::{
    self, AppPage, Offer, Outcome, Page, Prepared, SaveOffer, SuffixList, UrlHost,
};
use crate::commit::{Applied, ApplyError, Commit, CommitHost, apply, apply_first, apply_save};
use crate::edit::{EditError, local_edit};
use crate::error::ClientError;
use crate::items;
use crate::machine::{AnyMachine, Finished, Input, Prompt, Request, Save, SavedKey, Step};
use crate::passwd::{PasswdOptions, PasswdReport, passwd};
use crate::recover::{RecoverReport, recover};
use crate::restore::{
    RestoreScope, RestoreSummary, Revision, fetch_revision, restore, restore_preview,
};
use crate::run::Keys;
use crate::setup::{repair_token, setup};
use crate::state::{ClientState, SecretKeyStore};
use crate::sync::{Mode, SyncReport, sync};
use crate::unlock::{UnlockReport, unlock};
use std::collections::BTreeSet;
use vault_core::body::{Body, Item, ItemFields, Login, LoginUri, TYPE_LOGIN, TYPE_NOTE};
use vault_core::edit::{add_item, delete_item, update_item};
use vault_core::file::open_file;
use vault_core::json::Map;
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, SecretString, VaultKey};
use vault_core::{Error, InputKind};
use zeroize::Zeroizing;

/// An unlocked vault: the local state, its vault key, and the opened body. [`Session::lock`]
/// zeroes the key and the body.
pub struct Session {
    state: ClientState,
    vault_key: Option<VaultKey>,
    body: Option<Body>,
}

/// An item as a list shows it, without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The item ID.
    pub id: String,
    /// The `type`, which may be one this client does not know.
    pub item_type: String,
    /// The name, empty for an item of unknown `type`.
    pub name: String,
    /// The folder path, `""` for none.
    pub folder: String,
    /// A login's username, `""` otherwise.
    pub username: String,
    /// A login's URIs as stored.
    pub uris: Vec<String>,
    /// Whether the item is a favourite.
    pub favourite: bool,
    /// Whether a merge flagged the item for review.
    pub review: bool,
    /// Whether this client knows the item's `type`, and so shows and edits it.
    pub supported: bool,
    /// The time of the last change, in ms.
    pub modified: u64,
}

/// A new login or note, for [`Session::add`].
#[derive(Clone, Default)]
pub struct NewItem {
    /// `"login"` or `"note"`.
    pub item_type: String,
    /// The name.
    pub name: String,
    /// The folder path, `""` for none.
    pub folder: String,
    /// Whether the item is a favourite.
    pub favourite: bool,
    /// The notes.
    pub notes: String,
    /// A login's username.
    pub username: String,
    /// A login's password.
    pub password: String,
    /// A login's URIs.
    pub uris: Vec<LoginUri>,
}

/// A fill candidate, in candidate order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The item ID.
    pub id: String,
    /// The name.
    pub name: String,
    /// The username.
    pub username: String,
    /// `Fill`, or `Confirm` for an `https` item on an `http` page of a local host.
    pub outcome: Outcome,
}

/// A login's username and password, for one fill or copy.
pub struct Credential {
    /// The username.
    pub username: String,
    /// The password.
    pub password: SecretString,
}

/// Serves bytes drawn ahead from the caller's generator, for an edit that needs randomness inside
/// [`local_edit`], which holds the generator itself for sealing.
struct Drawn {
    bytes: Zeroizing<Vec<u8>>,
    at: usize,
}

impl Rng for Drawn {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        let end = self.at + dest.len();
        let src = self.bytes.get(self.at..end).ok_or(Error::Rng)?;
        dest.copy_from_slice(src);
        self.at = end;
        Ok(())
    }
}

fn edit_error(e: EditError<Error>) -> ClientError {
    match e {
        EditError::Client(e) => e,
        EditError::Edit(e) => e.into(),
    }
}

impl Session {
    fn opened(state: ClientState, vault_key: VaultKey, body: Body) -> Session {
        Session {
            state,
            vault_key: Some(vault_key),
            body: Some(body),
        }
    }

    /// Unlocks the local file with the secret key and the master password. Pulling first is
    /// [`Procedure::unlock`]; this opens only the local file. A wrong password or secret key is
    /// [`Error::WrongCredentials`].
    pub fn unlock(
        state: ClientState,
        secret_key: &SecretKey,
        password: &str,
    ) -> Result<Session, ClientError> {
        let u = vault_core::file::unlock(&state.file, password, secret_key)?;
        Ok(Session::opened(state, u.vault_key, u.body))
    }

    /// Reopens the local file with a cached vault key.
    pub fn reopen(state: ClientState, vault_key: VaultKey) -> Result<Session, ClientError> {
        let (_, body) = open_file(&state.file, &vault_key)?;
        Ok(Session::opened(state, vault_key, body))
    }

    /// The local state the session holds.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// The vault key, for a quick-unlock cache. [`ClientError::Locked`] after [`Session::lock`].
    pub fn vault_key(&self) -> Result<&VaultKey, ClientError> {
        self.vault_key.as_ref().ok_or(ClientError::Locked)
    }

    /// The opened body.
    pub fn body(&self) -> Result<&Body, ClientError> {
        self.body.as_ref().ok_or(ClientError::Locked)
    }

    /// Takes a state committed elsewhere, opening its file with the session's vault key. A file
    /// the key does not open fails, and the caller locks.
    pub fn reload(&mut self, state: ClientState) -> Result<(), ClientError> {
        let (_, body) = open_file(&state.file, self.vault_key()?)?;
        self.state = state;
        self.body = Some(body);
        Ok(())
    }

    /// Zeroes the vault key and the body, and clears the dropped item names. Every later call
    /// that needs them fails with [`ClientError::Locked`].
    pub fn lock(&mut self) {
        self.vault_key = None;
        self.body = None;
        self.state.dropped.clear();
    }

    /// Whether the body has a `v` greater than this client writes: it opens read-only, and every
    /// edit fails with [`Error::ReadOnlyBody`].
    pub fn read_only(&self) -> Result<bool, ClientError> {
        Ok(!self.body()?.writable())
    }

    /// List entries in listing order, only those in `folder` (and below) when given, and only
    /// those matching `text` when given.
    pub fn list(
        &self,
        folder: Option<&str>,
        text: Option<&str>,
    ) -> Result<Vec<Entry>, ClientError> {
        let found = items::sorted(
            self.body()?
                .items
                .iter()
                .filter(|i| folder.is_none_or(|f| items::in_folder(i, f)))
                .filter(|i| text.is_none_or(|t| items::matches_text(i, t)))
                .collect(),
        );
        Ok(found
            .into_iter()
            .map(|i| {
                let f = i.fields();
                let login = i.login();
                Entry {
                    id: i.id.clone(),
                    item_type: i.item_type.clone(),
                    name: f.map_or_else(String::new, |f| f.name.clone()),
                    folder: f.map_or_else(String::new, |f| f.folder.clone()),
                    username: login.map_or_else(String::new, |l| l.username.clone()),
                    uris: login
                        .map_or_else(Vec::new, |l| l.uris.iter().map(|u| u.uri.clone()).collect()),
                    favourite: f.is_some_and(|f| f.favourite),
                    review: i.review.is_some(),
                    supported: f.is_some(),
                    modified: i.modified,
                }
            })
            .collect())
    }

    /// Every folder path in use, with the folders above it, sorted.
    pub fn folders(&self) -> Result<Vec<String>, ClientError> {
        let mut out = BTreeSet::new();
        for f in self.body()?.items.iter().filter_map(Item::fields) {
            let mut path = f.folder.as_str();
            while !path.is_empty() {
                out.insert(path.to_owned());
                path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// One item in full, secrets included.
    pub fn item(&self, id: &str) -> Result<&Item, ClientError> {
        self.body()?
            .item(id)
            .ok_or(Error::InvalidInput(InputKind::NotFound).into())
    }

    /// A login's username and password.
    pub fn credential(&self, id: &str) -> Result<Credential, ClientError> {
        let login = self
            .item(id)?
            .login()
            .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?;
        Ok(Credential {
            username: login.username.clone(),
            password: Zeroizing::new(login.password.clone()),
        })
    }

    /// Runs a local edit on `state` (read under the caller's lock) and takes the result into the
    /// session. Returns the edit's value and the state to write, `None` when nothing changed.
    fn edit<R>(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        f: impl FnOnce(&mut Body, u64, &[u8; 16]) -> Result<R, Error>,
    ) -> Result<(R, Option<ClientState>), ClientError> {
        let vk = self.vault_key()?.clone_secret();
        let (r, next) = local_edit(state, &vk, device_id, now, rng, f).map_err(edit_error)?;
        self.reload(next.clone().unwrap_or_else(|| state.clone()))?;
        Ok((r, next))
    }

    /// Adds a login or a note stamped with `now` and `device_id`. Returns its ID and the state
    /// to write.
    pub fn add(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        item: NewItem,
    ) -> Result<(String, Option<ClientState>), ClientError> {
        let login = match item.item_type.as_str() {
            TYPE_LOGIN => Some(Login {
                username: item.username,
                password: item.password,
                uris: item.uris,
                apps: Vec::new(),
                totp: None,
                passkeys: Vec::new(),
                extra: Map::new(),
            }),
            TYPE_NOTE => None,
            _ => return Err(Error::InvalidInput(InputKind::UnsupportedItem).into()),
        };
        let fields = ItemFields {
            name: item.name,
            folder: item.folder,
            favourite: item.favourite,
            notes: item.notes,
            fields: Vec::new(),
            password_history: Vec::new(),
            created: 0,
            login,
            origin: None,
            extra: Map::new(),
        };
        // The item ID's 16 random bytes are drawn before the edit takes the generator.
        let mut id_bytes = Drawn {
            bytes: Zeroizing::new(vec![0; 16]),
            at: 0,
        };
        rng.fill(&mut id_bytes.bytes)?;
        let item_type = item.item_type;
        self.edit(state, device_id, now, rng, |body, now, dev| {
            add_item(body, &mut id_bytes, &item_type, fields, now, dev)
        })
    }

    /// Applies the keys the user changed from `base` to `edited` onto the current item
    /// ([`items::apply_changes`]), so a change that landed meanwhile is kept. Returns the state
    /// to write.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        id: &str,
        base: &ItemFields,
        edited: &ItemFields,
    ) -> Result<Option<ClientState>, ClientError> {
        let ((), next) = self.edit(state, device_id, now, rng, |body, now, dev| {
            let current = body
                .item(id)
                .ok_or(Error::InvalidInput(InputKind::NotFound))?
                .fields()
                .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?;
            let merged = items::apply_changes(base, edited, current);
            if merged != *current {
                update_item(body, id, merged, now, dev)?;
            }
            Ok(())
        })?;
        Ok(next)
    }

    /// Deletes an item. Returns the state to write.
    pub fn remove(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        id: &str,
    ) -> Result<Option<ClientState>, ClientError> {
        let ((), next) = self.edit(state, device_id, now, rng, |body, now, dev| {
            delete_item(body, id, now, dev)
        })?;
        Ok(next)
    }

    /// The hosts whose known suffix [`Session::candidates`] and [`Session::save_offer`] look up
    /// for `page_url`: the page host and the domain of every login URI. A host whose lookup is
    /// asynchronous resolves them first.
    pub fn suffix_hosts(&self, page_url: &str) -> Result<Vec<String>, ClientError> {
        let mut out = BTreeSet::new();
        let mut add = |p: Option<Prepared>| {
            if let Some(Prepared {
                host: UrlHost::Domain(d),
                ..
            }) = p
            {
                out.insert(d);
            }
        };
        add(autofill::page_url(page_url));
        for l in self.body()?.items.iter().filter_map(Item::login) {
            for u in &l.uris {
                add(autofill::prepare_uri(&u.uri));
            }
        }
        Ok(out.into_iter().collect())
    }

    /// The hosts whose known suffix [`Session::page_candidates`] and
    /// [`Session::page_save_offer`] may look up for `page`: the domain of every login URI, and for
    /// a web page its host too. An app page has no host, and app matching itself looks up no
    /// suffix; its list only lets a host resolve every answer ahead.
    pub fn page_suffix_hosts(&self, page: &Page) -> Result<Vec<String>, ClientError> {
        let mut out = BTreeSet::new();
        if let Page::Web(p) | Page::AndroidWeb(p) = page
            && let UrlHost::Domain(d) = &p.host
        {
            out.insert(d.clone());
        }
        for l in self.body()?.items.iter().filter_map(Item::login) {
            for u in &l.uris {
                if let Some(Prepared {
                    host: UrlHost::Domain(d),
                    ..
                }) = autofill::prepare_uri(&u.uri)
                {
                    out.insert(d);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    /// The fill candidates for `page`, in candidate order. For an app page these are the items
    /// with an association with the app.
    pub fn page_candidates(
        &self,
        page: &Page,
        suffixes: &dyn SuffixList,
    ) -> Result<Vec<Candidate>, ClientError> {
        Ok(candidate_list(autofill::page_candidates(
            page,
            &self.body()?.items,
            suffixes,
        )))
    }

    /// The save offer for a form submitted on `page`.
    pub fn page_save_offer(
        &self,
        page: &Page,
        username: &str,
        password: &str,
        suffixes: &dyn SuffixList,
    ) -> Result<Offer, ClientError> {
        Ok(autofill::page_save_offer(
            page,
            username,
            password,
            &self.body()?.items,
            suffixes,
        ))
    }

    /// Records what a confirmed fill of item `id` on the app page `app` binds
    /// ([`autofill::apps_after_fill`]) as a local edit of the item's `login.apps`. The new
    /// associations are worked out from the item in `state`, read under the caller's lock, so a
    /// change that landed meanwhile is kept. Returns the state to write, or `None` when the fill
    /// binds nothing.
    ///
    /// Whether to bind is the caller's decision, not the session's: docs/android.md (App matching)
    /// binds only after a successful pull in the same unlock, because the merge keeps the newer
    /// item whole and a binding made on a device that has not synced could revert a newer password
    /// set elsewhere. Offline, the caller fills without calling this.
    #[allow(clippy::too_many_arguments)]
    pub fn record_app_fill(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        id: &str,
        app: &AppPage,
    ) -> Result<Option<ClientState>, ClientError> {
        let ((), next) = self.edit(state, device_id, now, rng, |body, now, dev| {
            let item = body
                .item(id)
                .ok_or(Error::InvalidInput(InputKind::NotFound))?;
            let Some(apps) = autofill::apps_after_fill(item, app) else {
                return Ok(());
            };
            let mut fields = item
                .fields()
                .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?
                .clone();
            if let Some(login) = fields.login.as_mut() {
                login.apps = apps;
            }
            update_item(body, id, fields, now, dev)
        })?;
        Ok(next)
    }

    /// The fill candidates for `page_url`, in candidate order.
    pub fn candidates(
        &self,
        page_url: &str,
        suffixes: &dyn SuffixList,
    ) -> Result<Vec<Candidate>, ClientError> {
        Ok(candidate_list(autofill::candidates(
            page_url,
            &self.body()?.items,
            suffixes,
        )))
    }

    /// The save offer for a form submitted on `page_url`.
    pub fn save_offer(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        suffixes: &dyn SuffixList,
    ) -> Result<SaveOffer, ClientError> {
        Ok(autofill::save_offer(
            page_url,
            username,
            password,
            &self.body()?.items,
            suffixes,
        ))
    }

    /// What restoring `item` (or the whole vault) from `revision` would change.
    pub fn restore_preview(
        &self,
        revision: &Revision,
        item: Option<&str>,
    ) -> Result<RestoreSummary, ClientError> {
        let scope = item.map_or(RestoreScope::All, RestoreScope::Item);
        restore_preview(self.body()?, revision, scope)
    }

    /// Restores `item` (or the whole vault) from `revision` as a local edit, and takes the result
    /// into the session. Returns the state to write and what changed.
    pub fn restore(
        &mut self,
        state: &ClientState,
        device_id: &[u8; 16],
        now: u64,
        rng: &mut dyn Rng,
        revision: &Revision,
        item: Option<&str>,
    ) -> Result<(ClientState, RestoreSummary), ClientError> {
        let scope = item.map_or(RestoreScope::All, RestoreScope::Item);
        let vk = self.vault_key()?.clone_secret();
        let (next, summary) = restore(state, &vk, revision, scope, device_id, now, rng)?;
        self.reload(next.clone())?;
        Ok((next, summary))
    }
}

fn candidate_list(found: Vec<(&Item, Outcome)>) -> Vec<Candidate> {
    found
        .into_iter()
        .map(|(i, outcome)| Candidate {
            id: i.id.clone(),
            name: i.fields().map_or_else(String::new, |f| f.name.clone()),
            username: i.login().map_or_else(String::new, |l| l.username.clone()),
            outcome,
        })
        .collect()
}

/// What a finished procedure reports.
pub enum Report {
    /// [`Procedure::sync`].
    Sync(SyncReport),
    /// [`Procedure::unlock`].
    Unlock(UnlockReport),
    /// [`Procedure::recover`].
    Recover(RecoverReport),
    /// [`Procedure::passwd`].
    Passwd(PasswdReport),
    /// [`Procedure::setup`].
    Setup,
    /// [`Procedure::repair_token`].
    RepairToken,
    /// [`Procedure::fetch_revision`]: the opened revision, for [`Session::restore_preview`] and
    /// [`Session::restore`].
    Revision(Revision),
}

/// What a procedure needs next, or its end, as [`Procedure::start`] and [`Procedure::step`]
/// return it. A save and the end stay inside the procedure for [`Procedure::apply_save`] and
/// [`Procedure::apply`]; the event borrows them.
pub enum Event<'a> {
    /// Send this request.
    Request(Request),
    /// Ask the user.
    Prompt(Prompt),
    /// Show the kit, then call [`Procedure::apply_save`] and feed [`Input::Saved`].
    Save(&'a Save),
    /// The procedure ended; call [`Procedure::apply`].
    Done(&'a Finished<Report>),
}

/// A running `vault-client` procedure of any kind, with the state its commit needs: the last
/// save, the end, and the pending secret key.
pub struct Procedure {
    machine: AnyMachine<Report>,
    /// The pending secret key, from the keys or a save, so a commit that promotes it needs no
    /// read of the host's pending slot.
    pending: Option<SecretKey>,
    save: Option<Save>,
    finished: Option<Finished<Report>>,
}

impl Procedure {
    fn new(machine: AnyMachine<Report>, pending: Option<SecretKey>) -> Procedure {
        Procedure {
            machine,
            pending,
            save: None,
            finished: None,
        }
    }

    /// Sync.
    pub fn sync(
        state: ClientState,
        keys: Keys,
        mode: Mode,
        rng: impl Rng + Send + 'static,
    ) -> Procedure {
        let pending = pending_of(&keys);
        Procedure::new(
            AnyMachine::new(sync(state, keys, mode, rng), Report::Sync),
            pending,
        )
    }

    /// An unlock with a typed master password, which pulls first.
    pub fn unlock(state: ClientState, keys: Keys, rng: impl Rng + Send + 'static) -> Procedure {
        let pending = pending_of(&keys);
        Procedure::new(
            AnyMachine::new(unlock(state, keys, rng), Report::Unlock),
            pending,
        )
    }

    /// Recovery after an integrity error.
    pub fn recover(state: ClientState, keys: Keys, rng: impl Rng + Send + 'static) -> Procedure {
        let pending = pending_of(&keys);
        Procedure::new(
            AnyMachine::new(recover(state, keys, rng), Report::Recover),
            pending,
        )
    }

    /// A credential change.
    pub fn passwd(
        state: ClientState,
        keys: Keys,
        options: PasswdOptions,
        rng: impl Rng + Send + 'static,
    ) -> Procedure {
        let pending = pending_of(&keys);
        Procedure::new(
            AnyMachine::new(passwd(state, keys, options, rng), Report::Passwd),
            pending,
        )
    }

    /// Adds this client to an existing vault, recording `store` as its secret key store.
    pub fn setup(store: SecretKeyStore, rng: impl Rng + Send + 'static) -> Procedure {
        Procedure::new(AnyMachine::new(setup(store, rng), |()| Report::Setup), None)
    }

    /// Checks a new server token against the stored `vault_id`.
    pub fn repair_token(state: ClientState, rng: impl Rng + Send + 'static) -> Procedure {
        Procedure::new(
            AnyMachine::new(repair_token(state, rng), |()| Report::RepairToken),
            None,
        )
    }

    /// Fetches and opens a revision for a restore.
    pub fn fetch_revision(
        state: ClientState,
        keys: Keys,
        id: u64,
        rng: impl Rng + Send + 'static,
    ) -> Procedure {
        let pending = pending_of(&keys);
        Procedure::new(
            AnyMachine::new(fetch_revision(state, keys, id, rng), Report::Revision),
            pending,
        )
    }

    /// Runs the procedure up to its first step.
    pub fn start(&mut self, now: u64) -> Event<'_> {
        let step = self.machine.start(now);
        self.present(step)
    }

    /// Feeds the input for the previous step and runs up to the next.
    pub fn step(&mut self, input: Input, now: u64) -> Event<'_> {
        let step = self.machine.step(input, now);
        self.present(step)
    }

    fn present(&mut self, step: Step<Report>) -> Event<'_> {
        match step {
            Step::Request(r) => Event::Request(r),
            Step::Prompt(p) => Event::Prompt(p),
            Step::Save(s) => {
                if let SavedKey::Pending(k) = &s.secret_key {
                    self.pending = Some(k.clone_secret());
                }
                Event::Save(self.save.insert(s))
            }
            Step::Done(f) => Event::Done(self.finished.insert(f)),
        }
    }

    /// The procedure's end, once it finished.
    pub fn finished(&self) -> Option<&Finished<Report>> {
        self.finished.as_ref()
    }

    /// The revision a finished [`Procedure::fetch_revision`] opened.
    pub fn revision(&self) -> Option<&Revision> {
        match self.finished.as_ref()?.result.as_ref().ok()? {
            Report::Revision(r) => Some(r),
            _ => None,
        }
    }

    /// The vault key for the committed state, once the procedure finished.
    pub fn vault_key(&self) -> Option<&VaultKey> {
        self.finished.as_ref()?.vault_key.as_ref()
    }

    /// Carries out the last save through `host` ([`apply_save`]): the commit rule, which writes
    /// nothing, then the key in its slot, then the state. When the call returns an error after a
    /// write was issued, the host discards its queued writes (see [`apply_save`]).
    pub fn apply_save<H: CommitHost>(
        &self,
        started: &ClientState,
        on_disk: &ClientState,
        now: u64,
        rng: &mut dyn Rng,
        host: &mut H,
    ) -> Result<Commit, ApplyError<H::Error>> {
        let save = self
            .save
            .as_ref()
            .ok_or(ApplyError::Client(ClientError::UnexpectedInput))?;
        apply_save(save, started, on_disk, now, rng, host)
    }

    /// Commits the end through `host` ([`apply`]), promoting a pending secret key from the key
    /// the procedure holds. As with [`Procedure::apply_save`], a host that queues its writes
    /// discards them when the call returns an error. With no earlier state (`started` and `on_disk` both `None`), as
    /// after [`Procedure::setup`], it writes the first state instead ([`apply_first`]);
    /// `Ok(None)` then means nothing to write, and otherwise it means another sync committed
    /// first.
    pub fn apply<H: CommitHost>(
        &self,
        started: Option<&ClientState>,
        on_disk: Option<&ClientState>,
        background: bool,
        now: u64,
        rng: &mut dyn Rng,
        host: &mut H,
    ) -> Result<Option<Applied<H::Error>>, ApplyError<H::Error>> {
        let finished = self
            .finished
            .as_ref()
            .ok_or(ApplyError::Client(ClientError::UnexpectedInput))?;
        let mut host = WithPending {
            host,
            pending: self.pending.as_ref(),
        };
        match (started, on_disk) {
            (Some(s), Some(d)) => apply(finished, s, d, background, now, rng, &mut host),
            (None, None) => apply_first(finished, &mut host),
            _ => Err(ApplyError::Client(ClientError::UnexpectedInput)),
        }
    }
}

fn pending_of(keys: &Keys) -> Option<SecretKey> {
    keys.pending_secret_key
        .as_ref()
        .map(SecretKey::clone_secret)
}

/// A host whose pending slot is promoted from the key the procedure holds, so a host that cannot
/// read a slot during a commit (an IndexedDB transaction) still promotes it.
struct WithPending<'a, H> {
    host: &'a mut H,
    pending: Option<&'a SecretKey>,
}

impl<H: CommitHost> CommitHost for WithPending<'_, H> {
    type Error = H::Error;

    fn store_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), H::Error> {
        self.host.store_current(store, vault_id, key)
    }

    fn store_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), H::Error> {
        self.host.store_pending(store, vault_id, key)
    }

    fn copy_pending_to_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), H::Error> {
        match self.pending {
            Some(k) => self.host.store_current(store, vault_id, k),
            None => self.host.copy_pending_to_current(store, vault_id),
        }
    }

    fn delete_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), H::Error> {
        self.host.delete_pending(store, vault_id)
    }

    fn write_state(&mut self, state: &ClientState) -> Result<(), H::Error> {
        self.host.write_state(state)
    }
}
