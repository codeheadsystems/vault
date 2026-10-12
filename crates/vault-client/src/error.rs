//! Errors of the client procedures. Like `vault-core`'s, they carry no item content, key material,
//! or tokens.

use crate::state::StopReason;
use core::fmt;

/// Why the server refused the first push of a new vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitRefusal {
    /// `412`: another vault was pushed first.
    VaultExists,
    /// `401`: the token is invalid or revoked.
    Token,
    /// Another status.
    Status(u16),
}

/// Every error a procedure or the local state returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// A `vault-core` error: an integrity error, wrong credentials, a clock refusal, or invalid
    /// input such as a new master password that breaks the rules.
    Core(vault_core::Error),
    /// Sync is stopped for this reason; reads and writes go on locally.
    Stopped(StopReason),
    /// The server answered `401`: the token is invalid or revoked.
    Token,
    /// The transport failed or timed out.
    Unreachable,
    /// The server answered with an unexpected status.
    Status(u16),
    /// A response body that does not parse, such as a malformed revision list.
    BadResponse,
    /// The server holds no vault.
    NoVault,
    /// `vault init` found a vault on the server.
    VaultExists,
    /// The sync gave up after the `412` limits.
    Conflicts,
    /// Another device changed the credentials; an interactive sync asks for them.
    CredentialsChanged,
    /// The remote carries a new `wrap_nonce` that opened with neither the master password and the
    /// stored secret key nor the master password and a new secret key.
    RemoteUnopenable,
    /// The remote carries a `wrap_nonce` that failed to open before; an explicit sync asks again.
    RefusedWrap,
    /// A credential change met another one that landed first.
    CredentialChangeWon,
    /// A pending secret key waits for an interactive sync, or its key is missing.
    PendingSecretKey,
    /// The response to a credential change push was lost; the next sync finds out whether it
    /// landed.
    OutcomeUnknown,
    /// The vault key is needed and no prompt is allowed.
    Locked,
    /// The user declined a confirmation or gave up a prompt.
    Cancelled,
    /// A revision under a retired `wrap_nonce`, written after it was retired.
    RevisionRefused,
    /// The server does not retain the revision.
    RevisionNotFound,
    /// The local state file does not parse.
    LocalState,
    /// Another sync committed while this one ran; nothing was written.
    Superseded,
    /// The caller passed an input the procedure did not ask for, or stepped a finished procedure.
    UnexpectedInput,
    /// `vault init` saved a vault that the server then refused; the caller deletes the saved
    /// state and secret key.
    UndoSave(InitRefusal),
}

impl ClientError {
    /// The stable name of the error. `vault-core` errors keep their own codes.
    pub fn code(self) -> &'static str {
        match self {
            ClientError::Core(e) => e.code(),
            ClientError::Stopped(_) => "sync.stopped",
            ClientError::Token => "server.token",
            ClientError::Unreachable => "server.unreachable",
            ClientError::Status(_) => "server.status",
            ClientError::BadResponse => "server.response",
            ClientError::NoVault => "sync.no_vault",
            ClientError::VaultExists => "sync.vault_exists",
            ClientError::Conflicts => "sync.conflicts",
            ClientError::CredentialsChanged => "sync.credentials_changed",
            ClientError::RemoteUnopenable => "sync.remote_unopenable",
            ClientError::RefusedWrap => "sync.refused_wrap",
            ClientError::CredentialChangeWon => "sync.credential_change_won",
            ClientError::PendingSecretKey => "sync.pending_secret_key",
            ClientError::OutcomeUnknown => "sync.outcome_unknown",
            ClientError::Locked => "sync.locked",
            ClientError::Cancelled => "cancelled",
            ClientError::RevisionRefused => "restore.revision_refused",
            ClientError::RevisionNotFound => "restore.revision_not_found",
            ClientError::LocalState => "state.invalid",
            ClientError::Superseded => "state.superseded",
            ClientError::UnexpectedInput => "usage.unexpected_input",
            ClientError::UndoSave(_) => "init.refused",
        }
    }
}

impl From<vault_core::Error> for ClientError {
    fn from(e: vault_core::Error) -> Self {
        ClientError::Core(e)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Core(e) => e.fmt(f),
            ClientError::Stopped(StopReason::Integrity) => {
                f.write_str("sync is stopped after an integrity error")
            }
            ClientError::Stopped(StopReason::Token) => {
                f.write_str("sync is stopped because the server refused the token")
            }
            ClientError::Stopped(StopReason::Credentials) => {
                f.write_str("sync is stopped until the new credentials are entered")
            }
            ClientError::Token => f.write_str("the server refused the token"),
            ClientError::Unreachable => f.write_str("the server is unreachable"),
            ClientError::Status(s) => write!(f, "the server answered with status {s}"),
            ClientError::BadResponse => f.write_str("the server's response does not parse"),
            ClientError::NoVault => f.write_str("the server holds no vault"),
            ClientError::VaultExists => f.write_str("the server already holds a vault"),
            ClientError::Conflicts => {
                f.write_str("other devices kept writing; the sync gave up and will run again")
            }
            ClientError::CredentialsChanged => {
                f.write_str("the credentials changed on another device")
            }
            ClientError::RemoteUnopenable => f.write_str(
                "the remote cannot be opened: the credentials changed on another device, or the \
                 remote is damaged",
            ),
            ClientError::RefusedWrap => {
                f.write_str("the remote cannot be opened with the credentials entered earlier")
            }
            ClientError::CredentialChangeWon => {
                f.write_str("another credential change landed first")
            }
            ClientError::PendingSecretKey => {
                f.write_str("a new secret key waits for an interactive sync")
            }
            ClientError::OutcomeUnknown => {
                f.write_str("the server's answer was lost; the next sync checks the outcome")
            }
            ClientError::Locked => f.write_str("the vault is locked"),
            ClientError::Cancelled => f.write_str("cancelled"),
            ClientError::RevisionRefused => f.write_str(
                "the revision uses retired credentials and was written after they were retired",
            ),
            ClientError::RevisionNotFound => f.write_str("the server does not retain the revision"),
            ClientError::LocalState => f.write_str("the local state file is malformed"),
            ClientError::Superseded => f.write_str("another sync committed first"),
            ClientError::UnexpectedInput => f.write_str("unexpected input to a procedure"),
            ClientError::UndoSave(r) => {
                f.write_str("the server refused the new vault (")?;
                match r {
                    InitRefusal::VaultExists => f.write_str("it already holds one")?,
                    InitRefusal::Token => f.write_str("the token was refused")?,
                    InitRefusal::Status(s) => write!(f, "status {s}")?,
                }
                f.write_str("); the saved state is removed")
            }
        }
    }
}

impl std::error::Error for ClientError {}
