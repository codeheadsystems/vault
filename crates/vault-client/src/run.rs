//! The working state of one procedure run, and the flows several procedures share: unlocking the
//! local file, opening a remote under a new wrap, opening the local body for a merge, and finding
//! the revision at which a wrap was retired.

use crate::error::ClientError;
use crate::machine::{
    Answer, Confirmation, Cx, Finished, Prompt, Purpose, Request, SecretKeyChange,
};
use crate::revisions::parse_revisions;
use crate::state::{ClientState, StopReason, Stopped};
use vault_core::Error;
use vault_core::body::{Body, Item};
use vault_core::credentials::PendingKeyOutcome;
use vault_core::file::{Unlocked, open_file, read_header, unlock};
use vault_core::header::Header;
use vault_core::keys::derive_kek;
use vault_core::secret::{SecretKey, SecretString, VaultKey};

/// How many times a procedure asks for a password before it gives up.
pub(crate) const ATTEMPTS: u32 = 3;

/// The keys a caller holds when it starts a procedure. Each is optional: a procedure asks for
/// what it lacks, or fails with [`ClientError::Locked`] when it may not ask.
#[derive(Default)]
pub struct Keys {
    /// The cached vault key for the local file's wrap, from the agent or another quick unlock.
    pub vault_key: Option<VaultKey>,
    /// The stored secret key.
    pub secret_key: Option<SecretKey>,
    /// The pending secret key, while `pending_secret_key` is set in the state.
    pub pending_secret_key: Option<SecretKey>,
}

/// What a procedure does when the remote carries a `wrap_nonce` that is neither current nor
/// retired.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnChanged {
    /// Record `stopped` and fail (background sync).
    Stop,
    /// Run the credential change on another device flow. `ask_again` also asks for a
    /// `wrap_nonce` that failed to open before.
    Prompt { ask_again: bool },
    /// Fail without recording anything (the sync inside `vault passwd`).
    Abort,
}

/// The rules one run follows.
#[derive(Clone, Copy)]
pub(crate) struct Policy {
    pub prompts: bool,
    pub on_changed: OnChanged,
}

/// A new wrap this run opened.
pub(crate) struct Changed {
    pub nonce: [u8; 24],
    pub vault_key: VaultKey,
    /// A new secret key the user typed to open it.
    pub new_secret_key: Option<SecretKey>,
    /// The `ETag` of the first file seen under the new wrap, to find its revision ID.
    pub etag: String,
    /// The revision ID of that file, when already known.
    pub revision: Option<u64>,
}

/// The local body, opened at most once per run.
pub(crate) enum LocalBody {
    Unknown,
    Opened(Body),
    /// Nothing to merge: no unpushed changes, or the user discarded them.
    Skip,
}

/// The state a takeover of a new wrap leaves when the push that follows fails: the remote it
/// opened as the accepted file, and the merged body sealed under the remote's header as the
/// local file, unpushed.
pub(crate) struct Takeover {
    pub generation: u64,
    pub remote_hash: [u8; 32],
    pub local_file: Vec<u8>,
}

/// Secret key changes for one outcome, combined into one [`SecretKeyChange`] at the end.
#[derive(Default)]
pub(crate) struct KeyChanges {
    /// A new secret key typed to open a new wrap.
    pub replace: Option<SecretKey>,
    /// How a pending secret key was settled.
    pub pending: Option<PendingKeyOutcome>,
}

impl KeyChanges {
    fn into_change(self) -> Option<SecretKeyChange> {
        match (self.replace, self.pending) {
            (Some(k), Some(_)) => Some(SecretKeyChange::ReplaceAndDiscardPending(k)),
            (Some(k), None) => Some(SecretKeyChange::Replace(k)),
            (None, Some(PendingKeyOutcome::Landed)) => Some(SecretKeyChange::PromotePending),
            (None, Some(PendingKeyOutcome::NotLanded)) => Some(SecretKeyChange::DiscardPending),
            (None, None) => None,
        }
    }
}

/// A file opened under a new wrap, with the new secret key that opened it, if any.
pub(crate) struct Opened {
    pub index: usize,
    pub unlocked: Unlocked,
    pub new_secret_key: Option<SecretKey>,
}

pub(crate) struct Run {
    /// The state the run started from, or the last state handed out in a save.
    pub started: ClientState,
    /// The state to commit on success.
    pub next: ClientState,
    /// The state to commit on failure.
    pub fail: ClientState,
    /// The vault key for `started`'s wrap.
    pub vault_key: Option<VaultKey>,
    pub secret_key: Option<SecretKey>,
    pub pending_secret_key: Option<SecretKey>,
    pub changed: Option<Changed>,
    pub takeover: Option<Takeover>,
    pub local: LocalBody,
    /// Master passwords typed in this run, tried on the local file before asking for the old one.
    pub typed: Vec<SecretString>,
    pub pending_outcome: Option<PendingKeyOutcome>,
    pub expired: Vec<String>,
    pub keys_ok: KeyChanges,
    pub keys_fail: KeyChanges,
}

impl Run {
    pub(crate) fn new(state: ClientState, keys: Keys) -> Run {
        Run {
            next: state.clone(),
            fail: state.clone(),
            started: state,
            vault_key: keys.vault_key,
            secret_key: keys.secret_key,
            pending_secret_key: keys.pending_secret_key,
            changed: None,
            takeover: None,
            local: LocalBody::Unknown,
            typed: Vec::new(),
            pending_outcome: None,
            expired: Vec::new(),
            keys_ok: KeyChanges::default(),
            keys_fail: KeyChanges::default(),
        }
    }

    /// Ends the run: commits `next` when `success`, and `fail` otherwise. The vault key handed
    /// out is the one for the committed state's wrap.
    pub(crate) fn finish<T>(self, result: Result<T, ClientError>, success: bool) -> Finished<T> {
        let (state, keys) = if success {
            (self.next, self.keys_ok)
        } else {
            (self.fail, self.keys_fail)
        };
        let vault_key = match &self.changed {
            Some(c) if c.nonce == state.wrap_nonce => Some(c.vault_key.clone_secret()),
            _ => self.vault_key.as_ref().map(VaultKey::clone_secret),
        };
        let secret_key = keys.into_change();
        Finished {
            result,
            state: (state != self.started).then_some(state),
            vault_key,
            started_vault_key: self.vault_key,
            secret_key,
        }
    }

    /// Records `stopped` in both outcomes.
    pub(crate) fn stop(&mut self, reason: StopReason, code: &str, now: u64) {
        let s = Some(Stopped {
            reason,
            code: code.to_owned(),
            at: now,
        });
        self.fail.stopped = s.clone();
        self.next.stopped = s;
    }

    /// An error from a remote file: an integrity error stops sync.
    pub(crate) fn remote_error(&mut self, e: Error, now: u64) -> ClientError {
        if let Error::Integrity(k) = e {
            self.stop(StopReason::Integrity, k.code(), now);
        }
        ClientError::Core(e)
    }

    /// A `401`: sync stops until setup runs again.
    pub(crate) fn token(&mut self, now: u64) -> ClientError {
        self.stop(StopReason::Token, ClientError::Token.code(), now);
        ClientError::Token
    }

    /// Records a `wrap_nonce` whose wrap did not open, in both outcomes.
    pub(crate) fn refuse(&mut self, nonce: [u8; 24]) {
        self.next.refuse(nonce);
        self.fail.refuse(nonce);
    }

    /// The vault key for the local file's wrap: the cached one, or one from the master password,
    /// asked for up to three times when prompts are allowed.
    pub(crate) async fn current_key(
        &mut self,
        cx: &mut Cx,
        policy: Policy,
    ) -> Result<VaultKey, ClientError> {
        if self.vault_key.is_none() {
            if !policy.prompts {
                return Err(ClientError::Locked);
            }
            self.unlock_local(cx).await?;
        }
        Ok(self
            .vault_key
            .as_ref()
            .expect("set by unlock_local")
            .clone_secret())
    }

    /// Asks for the master password and opens the local file with it and the stored secret key.
    pub(crate) async fn unlock_local(&mut self, cx: &mut Cx) -> Result<(), ClientError> {
        let sk = self
            .secret_key
            .as_ref()
            .ok_or(ClientError::Locked)?
            .clone_secret();
        for failed in 0..ATTEMPTS {
            let pw = cx
                .password(Prompt::MasterPassword {
                    purpose: Purpose::Unlock,
                    failed,
                })
                .await?;
            match unlock(&self.started.file, &pw, &sk) {
                Ok(u) => {
                    self.vault_key = Some(u.vault_key);
                    self.local = LocalBody::Opened(u.body);
                    self.typed.push(pw);
                    return Ok(());
                }
                Err(Error::WrongCredentials) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::WrongCredentials.into())
    }

    /// The credential change on another device flow, steps 1 and 2, over one or more files in
    /// order of preference: asks for the master password and tries it with the stored secret key
    /// (and the pending one, when there is one), then asks for the master password and the new
    /// secret key. Returns the first file that opens, or `None` when none does.
    pub(crate) async fn open_new_wrap(
        &mut self,
        cx: &mut Cx,
        files: &[&[u8]],
        purpose: Purpose,
    ) -> Result<Option<Opened>, ClientError> {
        let pw = cx
            .password(Prompt::MasterPassword { purpose, failed: 0 })
            .await?;
        let mut stored = Vec::new();
        if let Some(sk) = &self.pending_secret_key {
            stored.push((sk.clone_secret(), true));
        }
        if let Some(sk) = &self.secret_key {
            stored.push((sk.clone_secret(), false));
        }
        for (sk, pending) in &stored {
            if let Some((index, unlocked)) = try_open(files, &pw, sk)? {
                if *pending {
                    self.pending_outcome = Some(PendingKeyOutcome::Landed);
                }
                self.typed.push(pw);
                return Ok(Some(Opened {
                    index,
                    unlocked,
                    new_secret_key: None,
                }));
            }
        }
        self.typed.push(pw);
        let (pw, sk) = match cx
            .prompt(Prompt::MasterPasswordAndSecretKey { purpose })
            .await?
        {
            Answer::PasswordAndSecretKey(pw, sk) => (pw, sk),
            Answer::Declined => return Ok(None),
            _ => return Err(ClientError::UnexpectedInput),
        };
        let opened = try_open(files, &pw, &sk)?;
        self.typed.push(pw);
        Ok(opened.map(|(index, unlocked)| Opened {
            index,
            unlocked,
            new_secret_key: Some(sk),
        }))
    }

    /// The local body to merge into a remote, step 3 of the credential change on another device
    /// flow: opened with the cached vault key, with a password typed in this run, or with the
    /// old master password. `None` means nothing to merge: the file has no unpushed changes, or
    /// the user confirmed discarding them.
    pub(crate) async fn local_body(&mut self, cx: &mut Cx) -> Result<Option<Body>, ClientError> {
        match &self.local {
            LocalBody::Opened(b) => return Ok(Some(b.clone())),
            LocalBody::Skip => return Ok(None),
            LocalBody::Unknown => {}
        }
        if let Some(vk) = &self.vault_key {
            let (_, body) = open_file(&self.started.file, vk)?;
            self.local = LocalBody::Opened(body.clone());
            return Ok(Some(body));
        }
        let sk = self.secret_key.as_ref().map(SecretKey::clone_secret);
        // A password typed in this run may open the old wrap too. Opening the local file then
        // also gives the commit the old vault key, should a command change the file meanwhile.
        if let Some(sk) = &sk {
            for pw in &self.typed {
                if let Ok(u) = unlock(&self.started.file, pw, sk) {
                    return Ok(Some(self.opened_local(u)));
                }
            }
        }
        if !self.started.unpushed() {
            self.local = LocalBody::Skip;
            return Ok(None);
        }
        if let Some(sk) = sk {
            for failed in 0..ATTEMPTS {
                let pw = match cx.prompt(Prompt::OldMasterPassword { failed }).await? {
                    Answer::Password(pw) => pw,
                    Answer::Declined => break,
                    _ => return Err(ClientError::UnexpectedInput),
                };
                match unlock(&self.started.file, &pw, &sk) {
                    Ok(u) => return Ok(Some(self.opened_local(u))),
                    Err(Error::WrongCredentials) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if cx.confirm(Confirmation::DiscardLocalChanges).await? {
            self.local = LocalBody::Skip;
            Ok(None)
        } else {
            Err(ClientError::Cancelled)
        }
    }

    fn opened_local(&mut self, u: Unlocked) -> Body {
        self.vault_key = Some(u.vault_key);
        self.local = LocalBody::Opened(u.body.clone());
        u.body
    }

    /// Completes a credential change in `next`: retires the current `wrap_nonce` at the
    /// revision that carried the new wrap, stores the new one, and records the secret key change.
    /// A change whose wrap the final local file does not carry (the remote went back to the
    /// current wrap after a `412`, or a `404` re-pushed the local file) is dropped.
    pub(crate) async fn complete_change(&mut self, cx: &mut Cx) -> Result<(), ClientError> {
        let Some(c) = &self.changed else {
            return Ok(());
        };
        if self.next.header()?.wrap_nonce != c.nonce {
            self.changed = None;
            return Ok(());
        }
        let revision = self.change_revision(cx).await;
        let c = self.changed.as_ref().expect("checked above");
        self.next.rotate_wrap_nonce(c.nonce, revision)?;
        self.keys_ok.replace = c.new_secret_key.as_ref().map(SecretKey::clone_secret);
        Ok(())
    }

    async fn change_revision(&self, cx: &mut Cx) -> Option<u64> {
        let c = self.changed.as_ref()?;
        match c.revision {
            Some(r) => Some(r),
            None => retirement_revision(cx, &c.etag, &c.nonce).await,
        }
    }

    /// After a failure that followed the takeover of a new wrap: the failure outcome keeps the
    /// takeover, with the merged body as an unpushed local file under the new wrap, so the
    /// credentials typed for it are not asked for again and its vault key stays usable.
    pub(crate) async fn keep_takeover(&mut self, cx: &mut Cx) {
        let Some(t) = self.takeover.take() else {
            return;
        };
        let revision = self.change_revision(cx).await;
        let Some(c) = &self.changed else {
            return;
        };
        let mut fail = self.fail.clone();
        fail.file = t.local_file;
        fail.accepted = Some(vault_core::sync::Accepted {
            generation: t.generation,
            file_hash: t.remote_hash,
        });
        if fail.rotate_wrap_nonce(c.nonce, revision).is_err() {
            return;
        }
        if fail
            .stopped
            .as_ref()
            .is_some_and(|s| s.reason == StopReason::Credentials)
        {
            fail.stopped = None;
        }
        self.keys_fail.replace = c.new_secret_key.as_ref().map(SecretKey::clone_secret);
        if self.started.pending_secret_key {
            fail.pending_secret_key = false;
            self.keys_fail.pending =
                Some(self.pending_outcome.unwrap_or(PendingKeyOutcome::NotLanded));
        }
        self.fail = fail;
    }

    /// Settles a pending secret key in `next` once the run knows which key opens the remote.
    pub(crate) fn settle_pending(&mut self) {
        if !self.started.pending_secret_key {
            return;
        }
        self.next.pending_secret_key = false;
        self.keys_ok.pending = Some(
            *self
                .pending_outcome
                .get_or_insert(PendingKeyOutcome::NotLanded),
        );
    }
}

/// Tries a master password and a secret key on files in order, deriving the KEK once per distinct
/// wrap. Returns the first file whose wrap and body open. A file whose wrap opens and whose body
/// does not counts as garbage.
fn try_open(
    files: &[&[u8]],
    pw: &str,
    sk: &SecretKey,
) -> Result<Option<(usize, Unlocked)>, ClientError> {
    let mut wraps: Vec<(Header, Option<VaultKey>)> = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let Ok(header) = read_header(file) else {
            continue;
        };
        let wrap = header.with_generation(1);
        let vk = match wraps.iter().find(|(h, _)| *h == wrap) {
            Some((_, vk)) => vk.as_ref().map(VaultKey::clone_secret),
            None => {
                let kek = derive_kek(
                    pw,
                    sk,
                    &header.vault_id,
                    &header.kdf,
                    header.test_kdf,
                    &header.kdf_salt,
                )?;
                let vk = header.unwrap(&kek).ok();
                wraps.push((wrap, vk.as_ref().map(VaultKey::clone_secret)));
                vk
            }
        };
        if let Some(vk) = vk
            && let Ok((header, body)) = open_file(file, &vk)
        {
            return Ok(Some((
                index,
                Unlocked {
                    header,
                    vault_key: vk,
                    body,
                },
            )));
        }
    }
    Ok(None)
}

/// The record kept with a retired `wrap_nonce` (spec, Credential change on another device): the
/// lowest revision ID under the new wrap `nonce`. It starts at the revision that carries the file
/// with `etag` and walks down the retained revisions while they carry `nonce`. `None` when the
/// list cannot be read or does not hold that file; a restore then refuses every revision under
/// the retired nonce.
pub(crate) async fn retirement_revision(cx: &mut Cx, etag: &str, nonce: &[u8; 24]) -> Option<u64> {
    let resp = cx.request(Request::ListRevisions).await.ok()?;
    if resp.status != 200 {
        return None;
    }
    let list = parse_revisions(&resp.body).ok()?;
    let mut lowest = list.iter().find(|r| r.etag == etag)?.id;
    let mut ids: Vec<u64> = list.iter().map(|r| r.id).collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    let start = lowest;
    for id in ids.into_iter().filter(|id| *id < start) {
        let Ok(resp) = cx.request(Request::GetRevision(id)).await else {
            break;
        };
        let under_nonce =
            resp.status == 200 && read_header(&resp.body).is_ok_and(|h| h.wrap_nonce == *nonce);
        if !under_nonce {
            break;
        }
        lowest = id;
    }
    Some(lowest)
}

/// Display names of items a merge left out as expired.
pub(crate) fn item_names(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .map(|i| i.fields().map_or_else(|| i.id.clone(), |f| f.name.clone()))
        .collect()
}
