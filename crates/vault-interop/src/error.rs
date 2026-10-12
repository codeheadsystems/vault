//! Errors. Like `vault-core`'s, the variants carry no strings or bytes from their inputs, so no
//! password, item content, or key material can reach an error message.
//!
//! The strings that [`Error::code`] returns are a public interface, as the CLI's JSON output
//! carries them: a code is never renamed or removed, and a new rule gets a new code.

use core::fmt;

/// Every error `vault-interop` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The file is larger than [`crate::MAX_EXPORT_SIZE`].
    TooLarge,
    /// The file, or a password-protected export's decrypted `data`, is not valid JSON: malformed,
    /// with a duplicate key, a lone surrogate escape, or nesting deeper than 128 levels.
    Json,
    /// The JSON is not a Bitwarden export: a key the format requires is missing or has the wrong
    /// type, or an encrypted string is malformed.
    NotAnExport,
    /// An account-restricted export, which opens only in a Bitwarden account.
    AccountRestricted,
    /// A password-protected export with a `kdfType` other than 0 (PBKDF2) or 1 (Argon2id).
    KdfType,
    /// A password-protected export with KDF parameters outside the accepted bounds.
    KdfParams,
    /// The export password does not open `encKeyValidation_DO_NOT_EDIT`.
    WrongPassword,
    /// The password opened `encKeyValidation_DO_NOT_EDIT` but `data` failed authentication or
    /// decryption: the file was altered.
    Corrupt,
    /// An error from `vault-core`, such as a failed random number generator.
    Core(vault_core::Error),
}

impl Error {
    /// The stable name of the error, such as `bitwarden.wrong_password`, or the `vault-core`
    /// code for [`Error::Core`].
    pub fn code(self) -> &'static str {
        match self {
            Error::TooLarge => "bitwarden.too_large",
            Error::Json => "bitwarden.json",
            Error::NotAnExport => "bitwarden.not_an_export",
            Error::AccountRestricted => "bitwarden.account_restricted",
            Error::KdfType => "bitwarden.kdf_type",
            Error::KdfParams => "bitwarden.kdf_params",
            Error::WrongPassword => "bitwarden.wrong_password",
            Error::Corrupt => "bitwarden.corrupt",
            Error::Core(e) => e.code(),
        }
    }
}

impl From<vault_core::Error> for Error {
    fn from(e: vault_core::Error) -> Self {
        Error::Core(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge => f.write_str("the export is larger than 64 MiB"),
            Error::Json => f.write_str("the export is not valid JSON"),
            Error::NotAnExport => f.write_str("the file is not a Bitwarden JSON export"),
            Error::AccountRestricted => f.write_str(
                "an account-restricted export opens only in a Bitwarden account; export again \
                 as plain JSON or with a password",
            ),
            Error::KdfType => f.write_str("the export uses an unsupported key derivation"),
            Error::KdfParams => f.write_str(
                "the export's key derivation parameters are outside the accepted bounds",
            ),
            Error::WrongPassword => f.write_str("wrong export password"),
            Error::Corrupt => f.write_str("the export's encrypted data was altered or damaged"),
            Error::Core(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// Result with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
