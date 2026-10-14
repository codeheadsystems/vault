//! The one vault of the process: the state lock, the unlocked session, and the idle lock
//! (docs/android.md, Rust bindings and Idle lock). Every call takes the lock, checks the idle
//! time, and only then does its work; an edit reads the state, applies the change, and writes
//! the result under that lock.

use crate::autofill::{self, AppPage, Candidate, ItemUri, Page, SaveOffer};
use crate::error::{Result, VaultError};
use crate::host::{self, Host, KeySlot, OsRng, read_key, require_state};
use crate::procedure::{PasswdChange, Procedure, SyncMode};
use crate::psl;
use std::sync::{Arc, Mutex, MutexGuard};
use vault_client::edit::{EditError, local_edit};
use vault_client::session::{self, NewItem as CoreNewItem, Session};
use vault_client::state::StopReason;
use vault_client::{ClientError, ClientState};
use vault_core::body::{ItemFields, LoginUri};
use vault_core::edit::update_item;
use vault_core::json::Map;
use vault_core::rng::Rng;
use vault_core::secret::VaultKey;
use vault_core::{Error, InputKind};

/// The idle time before a [`Vault::lock_if_idle`] check locks, unless set otherwise.
pub const DEFAULT_IDLE_MS: u64 = 5 * 60 * 1000;

/// The session and the idle lock, behind the state lock.
pub(crate) struct Inner {
    pub(crate) session: Option<Session>,
    /// The last activity on the host's `elapsed_realtime_ms` clock.
    last_activity: u64,
    idle_ms: u64,
    /// Whether a pull succeeded since the session was opened; an app binding needs one.
    pub(crate) pulled: bool,
}

impl Inner {
    /// Zeroes the session.
    pub(crate) fn lock(&mut self) {
        if let Some(mut s) = self.session.take() {
            s.lock();
        }
        self.pulled = false;
    }

    /// Takes `s` as the session, opened at `now` on the idle clock.
    pub(crate) fn open(&mut self, s: Session, now: u64) {
        self.lock();
        self.session = Some(s);
        self.last_activity = now;
    }

    /// Takes `s` as the session in place of the open one, keeping the activity time.
    pub(crate) fn replace(&mut self, s: Session) {
        let pulled = self.pulled;
        let last = self.last_activity;
        self.open(s, last);
        self.pulled = pulled;
    }

    fn session(&self) -> Result<&Session> {
        self.session
            .as_ref()
            .ok_or_else(|| ClientError::Locked.into())
    }

    fn idle(&self, now: u64) -> bool {
        self.session.is_some() && now.saturating_sub(self.last_activity) >= self.idle_ms
    }
}

/// What the main screen shows without unlocking.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StateSummary {
    /// The vault ID, 32 lowercase hex characters.
    pub vault_id: String,
    /// The accepted generation, or `None` before the first push.
    pub generation: Option<u64>,
    /// Whether local changes wait to be pushed.
    pub unpushed: bool,
    /// Why sync stopped, or `None` while it runs.
    pub stopped: Option<Stopped>,
    /// Whether a new secret key waits for the outcome of its push.
    pub pending_secret_key: bool,
    /// The time of the last successful sync, in ms.
    pub last_sync: Option<u64>,
    /// Names of local items a background sync dropped, to show once.
    pub dropped: Vec<String>,
    /// The current `wrap_nonce`, 24 bytes, which a biometric wrap is stored with.
    pub wrap_nonce: Vec<u8>,
}

/// Why sync stopped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Stopped {
    /// `integrity`, `token`, or `credentials`.
    pub reason: String,
    /// The error code, such as `integrity.aead` or `server.token`.
    pub code: String,
    /// When sync stopped, in ms.
    pub at: u64,
}

/// The vault key and the `wrap_nonce` it belongs to, for the biometric wrap.
#[derive(uniffi::Record)]
pub struct VaultKeyExport {
    /// The 32-byte vault key. Kotlin zeroes its `ByteArray` once the cipher has wrapped it.
    pub vault_key: Vec<u8>,
    /// The 24-byte `wrap_nonce` to store with the wrap.
    pub wrap_nonce: Vec<u8>,
}

/// A list entry, without secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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

/// A new login or note.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewItem {
    /// `login` or `note`.
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
    pub uris: Vec<ItemUri>,
}

/// A login's username and password, for one fill or copy.
#[derive(uniffi::Record)]
pub struct Credential {
    /// The username.
    pub username: String,
    /// The password.
    pub password: String,
}

/// What a restore changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct RestoreSummary {
    /// Items restored that were absent or deleted locally.
    pub added: u64,
    /// Items restored over a local item.
    pub changed: u64,
    /// Local items the revision does not hold, deleted by a restore of the whole vault.
    pub removed: u64,
}

impl From<vault_client::restore::RestoreSummary> for RestoreSummary {
    fn from(s: vault_client::restore::RestoreSummary) -> Self {
        RestoreSummary {
            added: s.added as u64,
            changed: s.changed as u64,
            removed: s.removed as u64,
        }
    }
}

/// What a confirmed app fill recorded (spec, App pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Binding {
    /// The item's `login.apps` changed, as a local edit.
    Recorded,
    /// The kind records nothing.
    Unchanged,
    /// The fill would bind or rebind, but no pull has succeeded since the unlock, so nothing
    /// was bound; the fill goes ahead.
    NotPulled,
}

/// The vault: the local state through the [`Host`], the unlocked session, and the idle lock. The
/// app holds one for the process.
#[derive(uniffi::Object)]
pub struct Vault {
    pub(crate) host: Arc<dyn Host>,
    inner: Mutex<Inner>,
}

impl Vault {
    /// Takes the state lock, then locks when the idle time has passed. A lock poisoned by a
    /// panic is taken over with the session locked.
    pub(crate) fn guard(&self) -> MutexGuard<'_, Inner> {
        self.checked().0
    }

    /// [`Vault::guard`], and whether the idle check locked.
    fn checked(&self) -> (MutexGuard<'_, Inner>, bool) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => {
                self.inner.clear_poison();
                let mut g = p.into_inner();
                g.lock();
                g
            }
        };
        let idle = g.idle(self.host.elapsed_realtime_ms());
        if idle {
            g.lock();
        }
        (g, idle)
    }

    pub(crate) fn host(&self) -> &dyn Host {
        self.host.as_ref()
    }

    /// Runs a session edit under the state lock: reads the state and the device ID, runs `f`,
    /// and writes the state it returns. A failed write returns the session to the state on disk.
    pub(crate) fn edit<R>(
        &self,
        f: impl FnOnce(
            &mut Session,
            &ClientState,
            &[u8; 16],
            u64,
            &mut dyn Rng,
        ) -> Result<(R, Option<ClientState>)>,
    ) -> Result<R> {
        self.edit_in(&mut self.guard(), f)
    }

    /// [`Vault::edit`] under a lock the caller holds.
    fn edit_in<R>(
        &self,
        g: &mut Inner,
        f: impl FnOnce(
            &mut Session,
            &ClientState,
            &[u8; 16],
            u64,
            &mut dyn Rng,
        ) -> Result<(R, Option<ClientState>)>,
    ) -> Result<R> {
        let host = self.host();
        let s = g.session.as_mut().ok_or(ClientError::Locked)?;
        let state = require_state(host)?;
        let dev = host::device_id(host)?;
        let (r, next) = f(s, &state, &dev, host.now_ms(), &mut OsRng)?;
        if let Some(next) = next
            && let Err(e) = host::write_state(host, Some(&state.wrap_nonce), &next)
        {
            if s.reload(state).is_err() {
                g.lock();
            }
            return Err(e);
        }
        Ok(r)
    }

    /// The candidates and save offers on Android use the compiled-in list.
    fn suffixes() -> &'static psl::Rules {
        psl::list()
    }
}

fn edit_error(e: EditError<Error>) -> VaultError {
    match e {
        EditError::Client(e) => e.into(),
        EditError::Edit(e) => e.into(),
    }
}

/// Sets the `login.apps` of the new item `id` as a local edit on `state`, and takes the result
/// into the session. `None` when nothing changed.
fn set_apps(
    s: &mut Session,
    state: &ClientState,
    dev: &[u8; 16],
    now: u64,
    rng: &mut dyn Rng,
    id: &str,
    apps: Vec<vault_core::body::AndroidApp>,
) -> Result<Option<ClientState>> {
    let vk = s.vault_key()?.clone_secret();
    let (_, next) = local_edit(state, &vk, dev, now, rng, |body, now, dev| {
        let item = body
            .item(id)
            .ok_or(Error::InvalidInput(InputKind::NotFound))?;
        let mut f = item
            .fields()
            .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?
            .clone();
        f.login
            .as_mut()
            .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?
            .apps = apps;
        update_item(body, id, f, now, dev)
    })
    .map_err(edit_error)?;
    s.reload(next.clone().unwrap_or_else(|| state.clone()))?;
    Ok(next)
}

fn login_uris(uris: Vec<ItemUri>) -> Vec<LoginUri> {
    uris.into_iter()
        .map(|u| LoginUri {
            uri: u.uri,
            match_value: u.match_value,
            extra: Map::new(),
        })
        .collect()
}

fn fields(item: &vault_core::body::Item) -> Result<&ItemFields> {
    item.fields()
        .ok_or_else(|| Error::InvalidInput(InputKind::UnsupportedItem).into())
}

fn vault_key(b: Vec<u8>) -> Result<VaultKey> {
    let b = zeroize::Zeroizing::new(b);
    let a: [u8; 32] = b
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::usage("a vault key is not 32 bytes"))?;
    Ok(VaultKey::from_bytes(a))
}

#[uniffi::export]
impl Vault {
    /// The vault over the app's storage. Nothing is read until the first call.
    #[uniffi::constructor]
    pub fn new(host: Arc<dyn Host>) -> Arc<Vault> {
        Arc::new(Vault {
            host,
            inner: Mutex::new(Inner {
                session: None,
                last_activity: 0,
                idle_ms: DEFAULT_IDLE_MS,
                pulled: false,
            }),
        })
    }

    /// The summary of the local state, or `None` before setup.
    pub fn state_summary(&self) -> Result<Option<StateSummary>> {
        let _g = self.guard();
        let Some(s) = host::read_state(self.host())? else {
            return Ok(None);
        };
        Ok(Some(StateSummary {
            vault_id: hex::encode(s.vault_id),
            generation: s.accepted.as_ref().map(|a| a.generation),
            unpushed: s.unpushed(),
            stopped: s.stopped.as_ref().map(|st| Stopped {
                reason: match st.reason {
                    StopReason::Integrity => "integrity",
                    StopReason::Token => "token",
                    StopReason::Credentials => "credentials",
                }
                .to_owned(),
                code: st.code.clone(),
                at: st.at,
            }),
            pending_secret_key: s.pending_secret_key,
            last_sync: s.last_sync,
            dropped: s.dropped.clone(),
            wrap_nonce: s.wrap_nonce.to_vec(),
        }))
    }

    /// Clears the list of dropped item names, after they were shown.
    pub fn clear_dropped(&self) -> Result<()> {
        let _g = self.guard();
        let mut s = require_state(self.host())?;
        if s.dropped.is_empty() {
            return Ok(());
        }
        s.dropped.clear();
        host::write_state(self.host(), Some(&s.wrap_nonce), &s)
    }

    /// Whether a session is unlocked, after the idle check.
    pub fn is_unlocked(&self) -> bool {
        self.guard().session.is_some()
    }

    /// Locks: zeroes the session and the vault key.
    pub fn lock(&self) {
        self.guard().lock();
    }

    /// The entry-point check of the idle lock. Returns whether it locked.
    pub fn lock_if_idle(&self) -> bool {
        self.checked().1
    }

    /// Records an action in the app's own activities, after the idle check. Requests from other
    /// apps never call it.
    pub fn record_activity(&self) {
        let mut g = self.guard();
        g.last_activity = self.host.elapsed_realtime_ms();
    }

    /// Sets the idle time in ms.
    pub fn set_idle_time(&self, ms: u64) {
        self.guard().idle_ms = ms;
    }

    /// Unlocks the local file with the stored secret key and the master password, without
    /// pulling; `Procedure.unlock` pulls first. A wrong password fails with
    /// `wrong_credentials`. The key derivation runs outside the state lock.
    pub fn unlock(&self, password: String) -> Result<()> {
        let password = zeroize::Zeroizing::new(password);
        let (state, sk) = {
            let _g = self.guard();
            let state = require_state(self.host())?;
            let sk = read_key(self.host(), KeySlot::Current)?
                .ok_or_else(|| VaultError::new("secret_key.missing", "no secret key is stored"))?;
            (state, sk)
        };
        let mut s = Session::unlock(state.clone(), &sk, &password)?;
        let mut g = self.guard();
        let on_disk = require_state(self.host())?;
        if on_disk != state {
            s.reload(on_disk)?;
        }
        g.open(s, self.host.elapsed_realtime_ms());
        Ok(())
    }

    /// Opens the local file with a vault key the biometric cipher unwrapped, stored with
    /// `wrap_nonce`. A wrap stored for another `wrap_nonce` fails with `biometric.stale`. Kotlin
    /// zeroes its `ByteArray` after the call.
    pub fn reopen(&self, vault_key: Vec<u8>, wrap_nonce: Vec<u8>) -> Result<()> {
        let vk = self::vault_key(vault_key)?;
        let mut g = self.guard();
        let state = require_state(self.host())?;
        if wrap_nonce != state.wrap_nonce {
            return Err(VaultError::new(
                "biometric.stale",
                "the biometric wrap belongs to an earlier wrap_nonce",
            ));
        }
        let s = Session::reopen(state, vk)?;
        g.open(s, self.host.elapsed_realtime_ms());
        Ok(())
    }

    /// The vault key and its `wrap_nonce`, for the biometric wrap only. Kotlin zeroes the
    /// `ByteArray` once the cipher has wrapped it.
    pub fn vault_key(&self) -> Result<VaultKeyExport> {
        let g = self.guard();
        let s = g.session()?;
        Ok(VaultKeyExport {
            vault_key: s.vault_key()?.expose().to_vec(),
            wrap_nonce: s.state().wrap_nonce.to_vec(),
        })
    }

    /// The stored secret key's text form, after checking the master password against the local
    /// file (AND-8). The key derivation runs outside the state lock.
    pub fn secret_key_text(&self, password: String) -> Result<String> {
        let password = zeroize::Zeroizing::new(password);
        let (state, sk) = {
            let _g = self.guard();
            let state = require_state(self.host())?;
            let sk = read_key(self.host(), KeySlot::Current)?
                .ok_or_else(|| VaultError::new("secret_key.missing", "no secret key is stored"))?;
            (state, sk)
        };
        vault_core::file::unlock(&state.file, &password, &sk)?;
        Ok(vault_core::secret_key_text::encode(&sk).as_str().to_owned())
    }

    /// Whether the body has a `v` greater than this client writes: it opens read-only, and every
    /// edit fails with `read_only_body`.
    pub fn read_only(&self) -> Result<bool> {
        Ok(self.guard().session()?.read_only()?)
    }

    /// List entries in listing order, only those in `folder` (and below) and matching `text`
    /// when given.
    pub fn list(&self, folder: Option<String>, text: Option<String>) -> Result<Vec<Entry>> {
        let g = self.guard();
        let entries = g.session()?.list(folder.as_deref(), text.as_deref())?;
        Ok(entries
            .into_iter()
            .map(|e: session::Entry| Entry {
                id: e.id,
                item_type: e.item_type,
                name: e.name,
                folder: e.folder,
                username: e.username,
                uris: e.uris,
                favourite: e.favourite,
                review: e.review,
                supported: e.supported,
                modified: e.modified,
            })
            .collect())
    }

    /// Every folder path in use, with the folders above it, sorted.
    pub fn folders(&self) -> Result<Vec<String>> {
        Ok(self.guard().session()?.folders()?)
    }

    /// One item as the body schema defines it, as JSON, secrets included.
    pub fn item(&self, id: String) -> Result<String> {
        let g = self.guard();
        let v = g.session()?.item(&id)?.to_value();
        let text = vault_core::json::to_vec(&v);
        Ok(String::from_utf8(text.to_vec()).expect("JSON is UTF-8"))
    }

    /// A login's username and password, for one fill or copy.
    pub fn credential(&self, id: String) -> Result<Credential> {
        let g = self.guard();
        let c = g.session()?.credential(&id)?;
        Ok(Credential {
            username: c.username,
            password: c.password.as_str().to_owned(),
        })
    }

    /// Adds a login or a note as a local edit, and returns its ID.
    pub fn add(&self, item: NewItem) -> Result<String> {
        let new = CoreNewItem {
            item_type: item.item_type,
            name: item.name,
            folder: item.folder,
            favourite: item.favourite,
            notes: item.notes,
            username: item.username,
            password: item.password,
            uris: login_uris(item.uris),
        };
        self.edit(|s, state, dev, now, rng| Ok(s.add(state, dev, now, rng, new)?))
    }

    /// Applies the keys the user changed from `base` to `edited` (both the item as `item`
    /// returned it, as JSON) onto the current item, so a change that landed meanwhile is kept.
    pub fn update(&self, id: String, base: String, edited: String) -> Result<()> {
        let (base, edited) = (autofill::parse_item(&base)?, autofill::parse_item(&edited)?);
        let (base, edited) = (fields(&base)?, fields(&edited)?);
        self.edit(|s, state, dev, now, rng| {
            Ok(((), s.update(state, dev, now, rng, &id, base, edited)?))
        })
    }

    /// Deletes an item as a local edit.
    pub fn remove(&self, id: String) -> Result<()> {
        self.edit(|s, state, dev, now, rng| Ok(((), s.remove(state, dev, now, rng, &id)?)))
    }

    /// The fill candidates for `page`, in candidate order. For an app page these are the items
    /// with an association with the app.
    pub fn candidates(&self, page: Page) -> Result<Vec<Candidate>> {
        let g = self.guard();
        let items = &g.session()?.body()?.items;
        autofill::candidates(&page, items, Vault::suffixes())
    }

    /// The save offer for a form submitted on `page`.
    pub fn save_offer(&self, page: Page, username: String, password: String) -> Result<SaveOffer> {
        let g = self.guard();
        let items = &g.session()?.body()?.items;
        autofill::save_offer(&page, &username, &password, items, Vault::suffixes())
    }

    /// Carries out a save offer the user confirmed, as a local edit: a new login item, or the
    /// password of an existing one. Returns the item's ID, or `None` for [`SaveOffer::None`].
    pub fn apply_save_offer(
        &self,
        offer: SaveOffer,
        username: String,
        password: String,
    ) -> Result<Option<String>> {
        match offer {
            SaveOffer::None => Ok(None),
            SaveOffer::Update { id } => self.edit(|s, state, dev, now, rng| {
                let base = fields(s.item(&id)?)?.clone();
                let mut edited = base.clone();
                edited
                    .login
                    .as_mut()
                    .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?
                    .password = password;
                let next = s.update(state, dev, now, rng, &id, &base, &edited)?;
                Ok((Some(id), next))
            }),
            SaveOffer::New { name, uris, apps } => self.edit(|s, state, dev, now, rng| {
                let new = CoreNewItem {
                    item_type: "login".to_owned(),
                    name,
                    username,
                    password,
                    uris: login_uris(uris),
                    ..CoreNewItem::default()
                };
                let (id, next) = s.add(state, dev, now, rng, new)?;
                let next = next.ok_or(ClientError::UnexpectedInput)?;
                if apps.is_empty() {
                    return Ok((Some(id), Some(next)));
                }
                let apps = apps
                    .into_iter()
                    .map(|a| vault_core::body::AndroidApp {
                        package: a.package_name,
                        cert_sha256: a.cert_sha256,
                        extra: Map::new(),
                    })
                    .collect();
                let bound = set_apps(s, &next, dev, now, rng, &id, apps)?;
                Ok((Some(id), bound.or(Some(next))))
            }),
        }
    }

    /// Begins a sync, with the session's vault key when unlocked.
    pub fn begin_sync(self: Arc<Self>, mode: SyncMode) -> Result<Arc<Procedure>> {
        Procedure::sync(self, mode)
    }

    /// Begins an unlock with a typed master password, which pulls first. Once applied, the
    /// session is unlocked.
    pub fn begin_unlock(self: Arc<Self>) -> Result<Arc<Procedure>> {
        Procedure::unlock(self)
    }

    /// Begins a recovery after an integrity error.
    pub fn begin_recover(self: Arc<Self>) -> Result<Arc<Procedure>> {
        Procedure::recover(self)
    }

    /// Begins a credential change, with the KDF memory in MiB (64 when `None`).
    pub fn begin_passwd(
        self: Arc<Self>,
        change: PasswdChange,
        kdf_memory_mib: Option<u32>,
    ) -> Result<Arc<Procedure>> {
        Procedure::passwd(self, change, kdf_memory_mib)
    }

    /// Begins adding this phone to an existing vault; refused with `usage` when a vault is set
    /// up. Once applied, the session is unlocked.
    pub fn begin_setup(self: Arc<Self>) -> Result<Arc<Procedure>> {
        Procedure::setup(self)
    }

    /// Begins checking a new server token against the stored `vault_id`.
    pub fn begin_repair_token(self: Arc<Self>) -> Result<Arc<Procedure>> {
        Procedure::repair_token(self)
    }

    /// Begins fetching and opening revision `id` for a restore.
    pub fn begin_fetch_revision(self: Arc<Self>, id: u64) -> Result<Arc<Procedure>> {
        Procedure::fetch_revision(self, id)
    }

    /// Records a confirmed fill of item `id` on `app` as a local edit of its `login.apps`
    /// (spec, App pages): a bind or a rebind. A fill whose kind records nothing is `Unchanged`
    /// whether or not a pull has succeeded; a bind or a rebind waits for a pull since the unlock
    /// (docs/android.md, App matching).
    pub fn record_app_fill(&self, id: String, app: AppPage) -> Result<Binding> {
        let page = app.core()?;
        let mut g = self.guard();
        let binds = vault_client::autofill::apps_after_fill(g.session()?.item(&id)?, &page);
        if binds.is_none() {
            return Ok(Binding::Unchanged);
        }
        if !g.pulled {
            return Ok(Binding::NotPulled);
        }
        self.edit_in(&mut g, |s, state, dev, now, rng| {
            let next = s.record_app_fill(state, dev, now, rng, &id, &page)?;
            let b = if next.is_some() {
                Binding::Recorded
            } else {
                Binding::Unchanged
            };
            Ok((b, next))
        })
    }
}
