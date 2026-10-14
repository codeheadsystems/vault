//! The one error that crosses into Kotlin: a stable code string and a message.

use std::fmt;
use vault_client::ClientError;

/// An error with a stable `code`: a `vault-core` or `vault-client` code (such as
/// `wrong_credentials`, `integrity.aead`, or `sync.locked`), `usage` for an argument of the wrong
/// shape, or the code a [`crate::Host`] method failed with.
#[derive(Debug, uniffi::Error)]
pub enum VaultError {
    /// The failure.
    Failed {
        /// The stable code.
        code: String,
        /// A description for logs, not for matching. Not `message`, which Kotlin's `Exception`
        /// already declares.
        detail: String,
    },
}

impl VaultError {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> VaultError {
        VaultError::Failed {
            code: code.to_owned(),
            detail: message.into(),
        }
    }

    /// An argument of the wrong shape.
    pub(crate) fn usage(message: impl Into<String>) -> VaultError {
        VaultError::new("usage", message)
    }

    /// The stable code.
    pub fn code(&self) -> &str {
        match self {
            VaultError::Failed { code, .. } => code,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Failed { code, detail } => write!(f, "{code}: {detail}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<ClientError> for VaultError {
    fn from(e: ClientError) -> Self {
        VaultError::new(e.code(), e.to_string())
    }
}

impl From<vault_core::Error> for VaultError {
    fn from(e: vault_core::Error) -> Self {
        VaultError::new(e.code(), e.to_string())
    }
}

/// A Kotlin exception from a [`crate::Host`] method other than a `VaultException`.
impl From<uniffi::UnexpectedUniFFICallbackError> for VaultError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        VaultError::new("host.unexpected", e.reason)
    }
}

pub(crate) type Result<T> = std::result::Result<T, VaultError>;
