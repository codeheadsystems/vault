//! The `vault-client` procedures for Kotlin: `vault_client::session::Procedure` behind UniFFI
//! records, reading its keys and committing its saves and end through the [`Vault`]'s state
//! lock and host.

use crate::error::{Result, VaultError};
use crate::host::{Commits, KeySlot, OsRng, read_key, read_state, require_state, secret_key};
use crate::vault::{RestoreSummary, Vault};
use std::sync::{Arc, Mutex, MutexGuard};
use vault_client::commit::ApplyError;
use vault_client::passwd::{PasswdChange as CorePasswdChange, PasswdOptions};
use vault_client::restore::Revision;
use vault_client::session::{self, Event, Report as CoreReport, Session};
use vault_client::sync::{Mode, SyncOutcome as CoreSyncOutcome, SyncReport};
use vault_client::{
    Answer as CoreAnswer, ClientError, ClientState, Confirmation, Input as CoreInput, Keys,
    Precondition, Prompt as CorePrompt, Purpose as CorePurpose, Request as CoreRequest, Response,
    SavedKey, SecretKeyStore,
};
use vault_core::credentials::PendingKeyOutcome;
use vault_core::kdf::KdfParams;
use vault_core::secret::VaultKey;
use zeroize::Zeroizing;

/// The mode of a sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncMode {
    /// Never asks; a sync that needs a prompt records `stopped`.
    Background,
    /// May ask.
    Interactive,
    /// May ask, again after a declined pending secret key prompt.
    InteractiveAskAgain,
}

/// A credential change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PasswdChange {
    /// A new master password.
    NewPassword,
    /// A new vault key under the same credentials.
    Rekey,
    /// A new secret key.
    NewSecretKey,
    /// A new secret key and a new master password.
    NewSecretKeyAndPassword,
}

/// An HTTP request to make.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Request {
    /// `GET` or `PUT`.
    pub method: String,
    /// `/v1/vault`, `/v1/revisions`, or `/v1/revisions/<id>`.
    pub path: String,
    /// The `If-Match` value of a `PUT`.
    pub if_match: Option<String>,
    /// The `If-None-Match` value of a `PUT`, `*`.
    pub if_none_match: Option<String>,
    /// The body of a `PUT`.
    pub body: Option<Vec<u8>>,
}

/// Why a password prompt asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Purpose {
    /// To unlock.
    Unlock,
    /// The credentials changed on another device.
    CredentialsChanged,
    /// To settle a pending secret key.
    PendingSecretKey,
    /// For revisions under other credentials, in recovery.
    Recovery,
    /// For the revision being restored.
    Revision,
}

/// A yes or no question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConfirmKind {
    /// Discard local changes made under credentials that were not given.
    DiscardLocalChanges,
    /// Confirm that no credential change was made on another device.
    NoCredentialChange,
}

/// What a procedure asks the user.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Prompt {
    /// The master password; `failed` counts the wrong answers so far.
    MasterPassword {
        /// Why.
        purpose: Purpose,
        /// Earlier wrong answers.
        failed: u32,
    },
    /// The master password and the secret key from a newer emergency kit.
    MasterPasswordAndSecretKey {
        /// Why.
        purpose: Purpose,
    },
    /// The current master password, for a credential change.
    OldMasterPassword {
        /// Earlier wrong answers.
        failed: u32,
    },
    /// A new master password; `rejected` is the code of the rule the last answer broke.
    NewMasterPassword {
        /// The rule the last answer broke.
        rejected: Option<String>,
    },
    /// The secret key.
    SecretKey,
    /// The vault ID from the emergency kit, which may be left empty.
    KitVaultId,
    /// A yes or no question.
    Confirm {
        /// Which.
        confirmation: ConfirmKind,
        /// The question in words.
        description: String,
    },
}

/// The answer to a [`Prompt`].
#[derive(uniffi::Enum)]
pub enum Answer {
    /// For the password prompts.
    Password {
        /// The password.
        password: String,
    },
    /// For [`Prompt::MasterPasswordAndSecretKey`].
    PasswordAndSecretKey {
        /// The master password.
        password: String,
        /// The 16-byte secret key, from `decode_secret_key`.
        secret_key: Vec<u8>,
    },
    /// For [`Prompt::SecretKey`].
    SecretKey {
        /// The 16-byte secret key, from `decode_secret_key`.
        secret_key: Vec<u8>,
    },
    /// For [`Prompt::KitVaultId`]: 16 bytes, or `None` when left empty.
    VaultId {
        /// The vault ID.
        vault_id: Option<Vec<u8>>,
    },
    /// For [`Prompt::Confirm`].
    Confirmed {
        /// Yes or no.
        confirmed: bool,
    },
    /// Declines any prompt.
    Declined,
}

/// The input for the previous step.
#[derive(uniffi::Enum)]
pub enum Input {
    /// The response to a [`Request`].
    Response {
        /// The status.
        status: u16,
        /// The body.
        body: Vec<u8>,
        /// The `Date` header in ms.
        date: Option<u64>,
    },
    /// The request failed or timed out.
    Unreachable,
    /// The answer to a [`Prompt`].
    Answer {
        /// The answer.
        answer: Answer,
    },
    /// After a [`Step::Save`], once the kit was shown and `apply_save` ran.
    Saved,
}

/// What a sync did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncOutcome {
    /// The server holds the local file.
    UpToDate,
    /// The client adopted the server's file.
    Adopted,
    /// The client pushed a new generation.
    Pushed,
}

/// How a pending secret key was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PendingKey {
    /// The push landed; the pending key is now the secret key.
    Landed,
    /// The push did not land; the new emergency kit is void.
    NotLanded,
}

fn pending(p: Option<PendingKeyOutcome>) -> Option<PendingKey> {
    p.map(|p| match p {
        PendingKeyOutcome::Landed => PendingKey::Landed,
        PendingKeyOutcome::NotLanded => PendingKey::NotLanded,
    })
}

/// The result of a sync.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncResult {
    /// What the sync did.
    pub outcome: SyncOutcome,
    /// The accepted generation afterwards.
    pub generation: u64,
    /// Names of local items the merge dropped.
    pub expired: Vec<String>,
    /// Whether the sync took over a credential change made on another device.
    pub credentials_changed: bool,
    /// How a pending secret key was settled.
    pub pending_secret_key: Option<PendingKey>,
}

impl From<&SyncReport> for SyncResult {
    fn from(r: &SyncReport) -> Self {
        SyncResult {
            outcome: match r.outcome {
                CoreSyncOutcome::UpToDate => SyncOutcome::UpToDate,
                CoreSyncOutcome::Adopted => SyncOutcome::Adopted,
                CoreSyncOutcome::Pushed => SyncOutcome::Pushed,
            },
            generation: r.generation,
            expired: r.expired.clone(),
            credentials_changed: r.credentials_changed,
            pending_secret_key: pending(r.pending_secret_key),
        }
    }
}

/// An error as a code and a message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ErrorInfo {
    /// The stable code.
    pub code: String,
    /// A description for logs.
    pub message: String,
}

impl From<ClientError> for ErrorInfo {
    fn from(e: ClientError) -> Self {
        ErrorInfo {
            code: e.code().to_owned(),
            message: e.to_string(),
        }
    }
}

/// What a finished procedure reports.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Report {
    /// A sync.
    Sync {
        /// The result.
        sync: SyncResult,
    },
    /// An unlock: the sync that followed the pull, or why there was none.
    Unlock {
        /// The sync, when it ran.
        sync: Option<SyncResult>,
        /// Why there was no sync: the server was unreachable, or sync is stopped.
        sync_error: Option<ErrorInfo>,
    },
    /// A recovery.
    Recover {
        /// The generation pushed.
        generation: u64,
        /// The revision the local body was merged into, if any.
        revision: Option<u64>,
        /// Names of local items the merge dropped.
        expired: Vec<String>,
        /// Whether recovery took over a credential change made on another device.
        credentials_changed: bool,
        /// How a pending secret key was settled.
        pending_secret_key: Option<PendingKey>,
    },
    /// A credential change.
    Passwd {
        /// The generation of the new file.
        generation: u64,
        /// The revision recorded with the retired `wrap_nonce`, if the list could be read.
        retired_revision: Option<u64>,
        /// Names of local items dropped.
        expired: Vec<String>,
    },
    /// A setup.
    Setup,
    /// A token repair.
    RepairToken,
    /// A fetched revision, which stays in the procedure for `Vault.restore_preview` and
    /// `Vault.restore`.
    Revision {
        /// The revision ID.
        id: u64,
        /// The generation its header claims.
        generation: u64,
    },
}

impl From<&CoreReport> for Report {
    fn from(r: &CoreReport) -> Self {
        match r {
            CoreReport::Sync(s) => Report::Sync { sync: s.into() },
            CoreReport::Unlock(u) => match &u.sync {
                Ok(s) => Report::Unlock {
                    sync: Some(s.into()),
                    sync_error: None,
                },
                Err(e) => Report::Unlock {
                    sync: None,
                    sync_error: Some((*e).into()),
                },
            },
            CoreReport::Recover(r) => Report::Recover {
                generation: r.generation,
                revision: r.revision,
                expired: r.expired.clone(),
                credentials_changed: r.credentials_changed,
                pending_secret_key: pending(r.pending_secret_key),
            },
            CoreReport::Passwd(r) => Report::Passwd {
                generation: r.generation,
                retired_revision: r.retired_revision,
                expired: r.expired.clone(),
            },
            CoreReport::Setup => Report::Setup,
            CoreReport::RepairToken => Report::RepairToken,
            CoreReport::Revision(r) => Report::Revision {
                id: r.id,
                generation: r.generation,
            },
        }
    }
}

/// Whether a finished procedure pulled the server's state.
fn pulled(r: &CoreReport) -> bool {
    match r {
        CoreReport::Sync(_) | CoreReport::Recover(_) | CoreReport::Passwd(_) => true,
        CoreReport::Unlock(u) => u.sync.is_ok(),
        CoreReport::Setup | CoreReport::RepairToken | CoreReport::Revision(_) => false,
    }
}

/// What a procedure needs next, or its end.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Step {
    /// Send this request, then call `step` with its response.
    Request {
        /// The request.
        request: Request,
    },
    /// Ask the user, then call `step` with the answer.
    Prompt {
        /// The prompt.
        prompt: Prompt,
    },
    /// Show the emergency kit, call `apply_save`, then call `step` with [`Input::Saved`].
    Save {
        /// The slot the key goes to.
        slot: KeySlot,
        /// The secret key's text form, for the kit.
        kit: String,
        /// The vault ID, 32 lowercase hex characters, for the kit.
        vault_id: String,
    },
    /// The procedure succeeded; call `apply`.
    Done {
        /// What it reports.
        report: Report,
    },
    /// The procedure failed; call `apply`, which may still record `stopped`.
    Failed {
        /// Why.
        error: ErrorInfo,
    },
}

/// The result of `apply`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Applied {
    /// Whether a state was written.
    pub written: bool,
    /// Whether another sync committed first, so nothing was written.
    pub superseded: bool,
    /// Whether local changes made meanwhile were merged into the result.
    pub merged_local_changes: bool,
    /// Names of local items the merge at commit dropped.
    pub expired: Vec<String>,
    /// Whether a pending secret key nothing uses was left in its slot.
    pub pending_left: bool,
    /// Whether the commit changed `wrap_nonce`; the biometric wrap was deleted, and the app
    /// offers to wrap the new vault key.
    pub wrap_changed: bool,
    /// Whether a session is unlocked afterwards.
    pub unlocked: bool,
}

pub(crate) struct Running {
    proc: session::Procedure,
    /// The state the procedure started from, or the last save's; `None` for a setup.
    started: Option<ClientState>,
    /// The state of the last save step, which becomes `started` once applied.
    save_state: Option<ClientState>,
    /// Whether a session was unlocked when the procedure started.
    started_unlocked: bool,
    /// Whether the procedure unlocks the session when it ends (unlock and setup).
    opens_session: bool,
}

impl Running {
    /// The revision a finished `fetch_revision` opened.
    pub(crate) fn revision(&self) -> Result<&Revision> {
        self.proc
            .revision()
            .ok_or_else(|| VaultError::usage("not a finished fetch_revision procedure"))
    }
}

fn request(r: &CoreRequest) -> Request {
    let get = |path: String| Request {
        method: "GET".to_owned(),
        path,
        if_match: None,
        if_none_match: None,
        body: None,
    };
    match r {
        CoreRequest::GetVault => get("/v1/vault".to_owned()),
        CoreRequest::ListRevisions => get("/v1/revisions".to_owned()),
        CoreRequest::GetRevision(id) => get(format!("/v1/revisions/{id}")),
        CoreRequest::PutVault { condition, file } => Request {
            method: "PUT".to_owned(),
            path: "/v1/vault".to_owned(),
            if_match: match condition {
                Precondition::IfMatch(e) => Some(e.clone()),
                Precondition::IfNoneMatch => None,
            },
            if_none_match: matches!(condition, Precondition::IfNoneMatch).then(|| "*".to_owned()),
            body: Some(file.clone()),
        },
    }
}

fn purpose(p: CorePurpose) -> Purpose {
    match p {
        CorePurpose::Unlock => Purpose::Unlock,
        CorePurpose::CredentialsChanged => Purpose::CredentialsChanged,
        CorePurpose::PendingSecretKey => Purpose::PendingSecretKey,
        CorePurpose::Recovery => Purpose::Recovery,
        CorePurpose::Revision => Purpose::Revision,
    }
}

fn prompt(p: CorePrompt) -> Prompt {
    match p {
        CorePrompt::MasterPassword { purpose: p, failed } => Prompt::MasterPassword {
            purpose: purpose(p),
            failed,
        },
        CorePrompt::MasterPasswordAndSecretKey { purpose: p } => {
            Prompt::MasterPasswordAndSecretKey {
                purpose: purpose(p),
            }
        }
        CorePrompt::OldMasterPassword { failed } => Prompt::OldMasterPassword { failed },
        CorePrompt::NewMasterPassword { rejected } => Prompt::NewMasterPassword {
            rejected: rejected.map(|e| e.code().to_owned()),
        },
        CorePrompt::SecretKey => Prompt::SecretKey,
        CorePrompt::KitVaultId => Prompt::KitVaultId,
        CorePrompt::Confirm(c) => Prompt::Confirm {
            confirmation: match c {
                Confirmation::DiscardLocalChanges => ConfirmKind::DiscardLocalChanges,
                Confirmation::NoCredentialChange => ConfirmKind::NoCredentialChange,
            },
            description: c.description().to_owned(),
        },
    }
}

fn input(i: Input) -> Result<CoreInput> {
    Ok(match i {
        Input::Response { status, body, date } => {
            CoreInput::Response(Response { status, body, date })
        }
        Input::Unreachable => CoreInput::Unreachable,
        Input::Saved => CoreInput::Saved,
        Input::Answer { answer } => CoreInput::Answer(match answer {
            Answer::Password { password } => CoreAnswer::Password(Zeroizing::new(password)),
            Answer::PasswordAndSecretKey {
                password,
                secret_key: k,
            } => CoreAnswer::PasswordAndSecretKey(Zeroizing::new(password), secret_key(k)?),
            Answer::SecretKey { secret_key: k } => CoreAnswer::SecretKey(secret_key(k)?),
            Answer::VaultId { vault_id } => CoreAnswer::VaultId(
                vault_id
                    .map(|v| {
                        <[u8; 16]>::try_from(v)
                            .map_err(|_| VaultError::usage("a vault ID is not 16 bytes"))
                    })
                    .transpose()?,
            ),
            Answer::Confirmed { confirmed } => CoreAnswer::Confirmed(confirmed),
            Answer::Declined => CoreAnswer::Declined,
        }),
    })
}

fn apply_err(e: ApplyError<VaultError>) -> VaultError {
    match e {
        ApplyError::Client(e) => e.into(),
        ApplyError::Host(e) => e,
    }
}

/// A running `vault-client` procedure. It holds no lock while it runs; its saves and its end
/// commit under the vault's state lock.
#[derive(uniffi::Object)]
pub struct Procedure {
    vault: Arc<Vault>,
    running: Mutex<Running>,
}

/// What a procedure starts with.
enum Start {
    /// A procedure on the stored state, with the stored secret keys and, for `with_vault_key`,
    /// the session's vault key.
    Stored { with_vault_key: bool },
    /// A setup, with no stored state.
    Setup,
}

impl Procedure {
    /// Reads the state and the keys under the state lock, and builds the procedure.
    fn begin(
        vault: Arc<Vault>,
        start: Start,
        opens_session: bool,
        build: impl FnOnce(Option<ClientState>, Keys) -> session::Procedure,
    ) -> Result<Arc<Procedure>> {
        let g = vault.guard();
        let host = vault.host();
        let started_unlocked = g.session.is_some();
        let (state, keys) = match start {
            Start::Setup => {
                if read_state(host)?.is_some() {
                    return Err(VaultError::usage(
                        "a vault is set up; repair the token instead",
                    ));
                }
                (None, Keys::default())
            }
            Start::Stored { with_vault_key } => {
                let state = require_state(host)?;
                let keys = Keys {
                    vault_key: g
                        .session
                        .as_ref()
                        .filter(|_| with_vault_key)
                        .and_then(|s| s.vault_key().ok())
                        .map(VaultKey::clone_secret),
                    secret_key: read_key(host, KeySlot::Current)?,
                    pending_secret_key: if state.pending_secret_key {
                        read_key(host, KeySlot::Pending)?
                    } else {
                        None
                    },
                };
                (Some(state), keys)
            }
        };
        drop(g);
        Ok(Arc::new(Procedure {
            vault,
            running: Mutex::new(Running {
                proc: build(state.clone(), keys),
                started: state,
                save_state: None,
                started_unlocked,
                opens_session,
            }),
        }))
    }

    /// The running procedure; a panic in an earlier call leaves it unusable.
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Running>> {
        self.running
            .lock()
            .map_err(|_| VaultError::new("procedure.poisoned", "an earlier call panicked"))
    }
}

fn stored(state: Option<ClientState>) -> ClientState {
    state.expect("a stored procedure has a state")
}

/// The procedures a [`Vault`] begins (`Vault::begin_sync` and the others). They are not UniFFI
/// constructors, because a constructor would take the vault as an object argument, which the
/// generated Kotlin lowers without checking whether it was closed.
impl Procedure {
    /// A sync, with the session's vault key when unlocked.
    pub(crate) fn sync(vault: Arc<Vault>, mode: SyncMode) -> Result<Arc<Procedure>> {
        let mode = match mode {
            SyncMode::Background => Mode::Background,
            SyncMode::Interactive => Mode::Interactive { ask_again: false },
            SyncMode::InteractiveAskAgain => Mode::Interactive { ask_again: true },
        };
        let start = Start::Stored {
            with_vault_key: true,
        };
        Procedure::begin(vault, start, false, |s, keys| {
            session::Procedure::sync(stored(s), keys, mode, OsRng)
        })
    }

    /// An unlock with a typed master password, which pulls first. Once applied, the session is
    /// unlocked.
    pub(crate) fn unlock(vault: Arc<Vault>) -> Result<Arc<Procedure>> {
        let start = Start::Stored {
            with_vault_key: false,
        };
        Procedure::begin(vault, start, true, |s, keys| {
            session::Procedure::unlock(stored(s), keys, OsRng)
        })
    }

    /// Recovery after an integrity error.
    pub(crate) fn recover(vault: Arc<Vault>) -> Result<Arc<Procedure>> {
        let start = Start::Stored {
            with_vault_key: true,
        };
        Procedure::begin(vault, start, false, |s, keys| {
            session::Procedure::recover(stored(s), keys, OsRng)
        })
    }

    /// A credential change, with the KDF memory in MiB (64 when `None`).
    pub(crate) fn passwd(
        vault: Arc<Vault>,
        change: PasswdChange,
        kdf_memory_mib: Option<u32>,
    ) -> Result<Arc<Procedure>> {
        let change = match change {
            PasswdChange::NewPassword => CorePasswdChange::NewPassword,
            PasswdChange::Rekey => CorePasswdChange::Rekey,
            PasswdChange::NewSecretKey => CorePasswdChange::NewSecretKey {
                new_password: false,
            },
            PasswdChange::NewSecretKeyAndPassword => {
                CorePasswdChange::NewSecretKey { new_password: true }
            }
        };
        let options = PasswdOptions {
            change,
            kdf: KdfParams::with_memory_mib(kdf_memory_mib.unwrap_or(64))?,
            test_kdf: false,
        };
        let start = Start::Stored {
            with_vault_key: true,
        };
        Procedure::begin(vault, start, false, |s, keys| {
            session::Procedure::passwd(stored(s), keys, options, OsRng)
        })
    }

    /// Adds this phone to an existing vault. The app's key slots play the secret key file, so
    /// the state records the `file` store. Once applied, the session is unlocked.
    pub(crate) fn setup(vault: Arc<Vault>) -> Result<Arc<Procedure>> {
        Procedure::begin(vault, Start::Setup, true, |_, _| {
            session::Procedure::setup(SecretKeyStore::File, OsRng)
        })
    }

    /// Checks a new server token against the stored `vault_id`.
    pub(crate) fn repair_token(vault: Arc<Vault>) -> Result<Arc<Procedure>> {
        let start = Start::Stored {
            with_vault_key: false,
        };
        Procedure::begin(vault, start, false, |s, _| {
            session::Procedure::repair_token(stored(s), OsRng)
        })
    }

    /// Fetches and opens revision `id` for a restore.
    pub(crate) fn fetch_revision(vault: Arc<Vault>, id: u64) -> Result<Arc<Procedure>> {
        let start = Start::Stored {
            with_vault_key: true,
        };
        Procedure::begin(vault, start, false, |s, keys| {
            session::Procedure::fetch_revision(stored(s), keys, id, OsRng)
        })
    }
}

#[uniffi::export]
impl Procedure {
    /// Runs the procedure up to its first step.
    pub fn start(&self) -> Result<Step> {
        let now = self.vault.host().now_ms();
        let mut r = self.lock()?;
        let r = &mut *r;
        let event = r.proc.start(now);
        Ok(present_into(&mut r.save_state, event))
    }

    /// Feeds the input for the previous step and runs up to the next.
    pub fn step(&self, input: Input) -> Result<Step> {
        let i = self::input(input)?;
        let now = self.vault.host().now_ms();
        let mut r = self.lock()?;
        let r = &mut *r;
        let event = r.proc.step(i, now);
        Ok(present_into(&mut r.save_state, event))
    }

    /// After a [`Step::Save`]: stores the secret key in its slot, runs the commit rule, and
    /// writes the state, under the state lock.
    pub fn apply_save(&self) -> Result<()> {
        let mut r = self.lock()?;
        let saved = r
            .save_state
            .take()
            .ok_or_else(|| VaultError::usage("no save step to apply"))?;
        let started = r
            .started
            .clone()
            .ok_or_else(|| VaultError::usage("a setup has no save step"))?;
        let _g = self.vault.guard();
        let host = self.vault.host();
        let on_disk = require_state(host)?;
        let mut commits = Commits::new(host, Some(&on_disk));
        let applied =
            r.proc
                .apply_save(&started, &on_disk, host.now_ms(), &mut OsRng, &mut commits);
        if let Err(e) = applied {
            r.save_state = Some(saved);
            return Err(apply_err(e));
        }
        r.started = Some(saved);
        Ok(())
    }

    /// After [`Step::Done`] or [`Step::Failed`]: commits the procedure's end and its secret key
    /// change under the state lock, in the order `vault_client::commit::apply` gives, and takes
    /// the result into the session. A `background` commit records items its merge drops in the
    /// state's dropped names.
    pub fn apply(&self, background: bool) -> Result<Applied> {
        let r = self.lock()?;
        let Some(finished) = r.proc.finished() else {
            return Err(VaultError::usage("the procedure has not finished"));
        };
        let mut g = self.vault.guard();
        let host = self.vault.host();
        let on_disk = read_state(host)?;
        match (&r.started, &on_disk) {
            (None, Some(_)) => {
                return Err(VaultError::usage(
                    "a vault is set up; repair the token instead",
                ));
            }
            (Some(_), None) => return Err(VaultError::new("state.no_vault", "no vault is set up")),
            _ => {}
        }
        let mut commits = Commits::new(host, on_disk.as_ref());
        let a = r
            .proc
            .apply(
                r.started.as_ref(),
                on_disk.as_ref(),
                background,
                host.now_ms(),
                &mut OsRng,
                &mut commits,
            )
            .map_err(apply_err)?;
        let written = commits.written.take();
        let wrap_changed = written
            .as_ref()
            .is_some_and(|w| on_disk.as_ref().map(|d| d.wrap_nonce) != Some(w.wrap_nonce));
        let report = finished.result.as_ref().ok();
        let did_pull = report.is_some_and(pulled);
        let keys = [
            r.proc.vault_key(),
            g.session.as_ref().and_then(|s| s.vault_key().ok()),
        ];
        let reopened = |state: &ClientState| {
            keys.iter()
                .flatten()
                .find_map(|k| Session::reopen(state.clone(), k.clone_secret()).ok())
        };
        if g.session.is_some() {
            if let Some(w) = &written {
                match reopened(w) {
                    Some(s) => g.replace(s),
                    None => g.lock(),
                }
            }
            g.pulled |= did_pull && g.session.is_some();
        } else if r.opens_session && !r.started_unlocked && report.is_some() {
            let current = written.as_ref().or(on_disk.as_ref());
            if let Some(s) = current.and_then(reopened) {
                g.open(s, host.elapsed_realtime_ms());
                g.pulled = did_pull;
            }
        }
        let first = r.started.is_none();
        let unlocked = g.session.is_some();
        Ok(match a {
            None => Applied {
                written: false,
                superseded: !first,
                merged_local_changes: false,
                expired: Vec::new(),
                pending_left: false,
                wrap_changed,
                unlocked,
            },
            Some(a) => Applied {
                written: written.is_some(),
                superseded: false,
                merged_local_changes: a.commit.merged_local_changes,
                expired: a.commit.expired,
                pending_left: a.pending_left.is_some(),
                wrap_changed,
                unlocked,
            },
        })
    }
}

#[uniffi::export]
impl Procedure {
    /// What restoring item `item_id`, or the whole vault, from the revision this finished
    /// fetch-revision procedure opened would change.
    pub fn restore_preview(&self, item_id: Option<String>) -> Result<RestoreSummary> {
        let r = self.lock()?;
        let rev = r.revision()?;
        let g = self.vault.guard();
        Ok(g.session
            .as_ref()
            .ok_or(ClientError::Locked)?
            .restore_preview(rev, item_id.as_deref())?
            .into())
    }

    /// Restores item `item_id`, or the whole vault, from the revision this finished
    /// fetch-revision procedure opened, as a local edit through the vault.
    pub fn restore(&self, item_id: Option<String>) -> Result<RestoreSummary> {
        let r = self.lock()?;
        let rev = r.revision()?;
        self.vault.edit(|s, state, dev, now, rng| {
            let (next, summary) = s.restore(state, dev, now, rng, rev, item_id.as_deref())?;
            Ok((summary.into(), Some(next)))
        })
    }
}

/// Converts `event`, recording a save step's state in `save_state`.
fn present_into(save_state: &mut Option<ClientState>, event: Event<'_>) -> Step {
    if let Event::Save(s) = &event {
        *save_state = Some(s.state.clone());
    }
    present(event)
}

fn present(event: Event<'_>) -> Step {
    match event {
        Event::Request(r) => Step::Request {
            request: request(&r),
        },
        Event::Prompt(p) => Step::Prompt { prompt: prompt(p) },
        Event::Save(s) => {
            let (slot, key) = match &s.secret_key {
                SavedKey::Current(k) => (KeySlot::Current, k),
                SavedKey::Pending(k) => (KeySlot::Pending, k),
            };
            Step::Save {
                slot,
                kit: vault_core::secret_key_text::encode(key).as_str().to_owned(),
                vault_id: hex::encode(s.state.vault_id),
            }
        }
        Event::Done(f) => match &f.result {
            Ok(r) => Step::Done { report: r.into() },
            Err(e) => Step::Failed { error: (*e).into() },
        },
    }
}
