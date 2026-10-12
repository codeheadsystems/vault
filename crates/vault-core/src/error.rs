//! Errors. Variants carry no strings or bytes from their inputs, so no password, item content, or
//! key material can reach an error message.
//!
//! The strings that [`Error::code`], [`IntegrityKind::code`], and [`InputKind::code`] return are a
//! public interface: `spec/vectors/` and the CLI's JSON output (`docs/cli.md`) carry them. A code is
//! never renamed or removed; a new rule gets a new code.

use core::fmt;

/// Every error `vault-core` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A file, header, or body broke a decode rule or failed authentication, or a remote file
    /// failed a sync check. The operation fails and nothing is written.
    Integrity(IntegrityKind),
    /// The vault key wrap did not open: a wrong master password or secret key.
    WrongCredentials,
    /// A secret key's text form has a wrong check value or shape.
    SecretKeyTypo,
    /// A value supplied by the caller breaks a rule; nothing was produced.
    InvalidInput(InputKind),
    /// The body's `v` is greater than [`crate::body::BODY_VERSION`], so it opens read-only.
    ReadOnlyBody,
    /// The clock reads earlier than the build time.
    ClockBeforeBuildTime,
    /// The clock differs from the server's `Date` by more than a day.
    ClockSkew,
    /// The caller's random number generator failed.
    Rng,
}

/// The rule a file, header, body, or remote state broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityKind {
    /// The input is shorter than its structure requires.
    Truncated,
    /// The input is longer than its structure allows.
    TrailingBytes,
    /// The header magic is not `"VAULT"`.
    BadMagic,
    /// The header carries a `format_version` this client does not implement.
    FormatVersion,
    /// A flag bit other than `test_kdf` is set.
    UnknownFlags,
    /// The header `generation` is outside `[1, 2^48]`.
    Generation,
    /// The KDF parameters are outside the floor and ceiling.
    KdfParams,
    /// The header sets `test_kdf` and this build does not accept the test parameters.
    TestKdfInRelease,
    /// The file is larger than 16 MiB.
    SizeLimit,
    /// The plaintext length is not a positive multiple of 4,096.
    PaddedSize,
    /// The JSON length runs past the end of the plaintext.
    Length,
    /// A padding byte is not zero.
    Padding,
    /// The body ciphertext failed authentication.
    Aead,
    /// The body is not valid UTF-8 JSON.
    Json,
    /// The body starts with a byte order mark.
    Bom,
    /// An object has a duplicate key.
    DuplicateKey,
    /// Nesting goes deeper than 32 levels.
    Nesting,
    /// A number is not an integer in `[0, 2^53)` written without a fraction or exponent.
    Number,
    /// A key the schema requires is missing.
    MissingKey,
    /// A key the schema defines has a value of the wrong JSON type, such as an `origin` that is
    /// not an object.
    WrongType,
    /// A value is outside the bounds the schema states.
    BadValue,
    /// An `id` appears twice among items and tombstones.
    DuplicateId,
    /// A remote file names a different `vault_id`.
    VaultIdMismatch,
    /// A remote file's `generation` is lower than the accepted generation.
    GenerationRollback,
    /// A remote file has the accepted generation but a different SHA-256.
    GenerationFork,
    /// A remote file carries a retired `wrap_nonce`.
    RetiredWrapNonce,
}

/// The rule a caller-supplied value broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputKind {
    /// A new master password has fewer than 12 scalar values after NFKC.
    PasswordTooShort,
    /// A master password is longer than [`crate::kdf::MAX_PASSWORD_BYTES`].
    PasswordTooLong,
    /// A new master password contains a code point unassigned in this client's Unicode tables.
    PasswordUnassigned,
    /// KDF parameters chosen for writing are outside the floor and ceiling.
    KdfParams,
    /// Generator settings outside the allowed range.
    Generator,
    /// No item with that `id`.
    NotFound,
    /// The item has a `type` this client does not know, so it is never edited.
    UnsupportedItem,
    /// A header to be written does not decode.
    Header,
    /// A body to be written breaks the body rules.
    Body,
    /// A vault file to be written is larger than 16 MiB.
    TooLarge,
    /// The next generation would exceed `2^48`.
    GenerationLimit,
    /// Setup text that is malformed or lacks a required parameter.
    SetupText,
    /// A server URL that breaks the setup rules.
    ServerUrl,
    /// A token text form with a wrong shape.
    Token,
    /// A certificate fingerprint that is not 64 lowercase hex characters.
    Fingerprint,
}

impl IntegrityKind {
    /// The stable name of the rule, as `spec/vectors/` and other clients spell it.
    pub fn code(self) -> &'static str {
        match self {
            IntegrityKind::Truncated => "integrity.truncated",
            IntegrityKind::TrailingBytes => "integrity.trailing_bytes",
            IntegrityKind::BadMagic => "integrity.bad_magic",
            IntegrityKind::FormatVersion => "integrity.format_version",
            IntegrityKind::UnknownFlags => "integrity.unknown_flags",
            IntegrityKind::Generation => "integrity.generation",
            IntegrityKind::KdfParams => "integrity.kdf_params",
            IntegrityKind::TestKdfInRelease => "integrity.test_kdf_in_release",
            IntegrityKind::SizeLimit => "integrity.size_limit",
            IntegrityKind::PaddedSize => "integrity.padded_size",
            IntegrityKind::Length => "integrity.length",
            IntegrityKind::Padding => "integrity.padding",
            IntegrityKind::Aead => "integrity.aead",
            IntegrityKind::Json => "integrity.json",
            IntegrityKind::Bom => "integrity.bom",
            IntegrityKind::DuplicateKey => "integrity.duplicate_key",
            IntegrityKind::Nesting => "integrity.nesting",
            IntegrityKind::Number => "integrity.number",
            IntegrityKind::MissingKey => "integrity.missing_key",
            IntegrityKind::WrongType => "integrity.wrong_type",
            IntegrityKind::BadValue => "integrity.bad_value",
            IntegrityKind::DuplicateId => "integrity.duplicate_id",
            IntegrityKind::VaultIdMismatch => "integrity.vault_id_mismatch",
            IntegrityKind::GenerationRollback => "integrity.generation_rollback",
            IntegrityKind::GenerationFork => "integrity.generation_fork",
            IntegrityKind::RetiredWrapNonce => "integrity.retired_wrap_nonce",
        }
    }
}

impl InputKind {
    /// The stable name of the rule, as `spec/vectors/` and other clients spell it.
    pub fn code(self) -> &'static str {
        match self {
            InputKind::PasswordTooShort => "input.password_too_short",
            InputKind::PasswordTooLong => "input.password_too_long",
            InputKind::PasswordUnassigned => "input.password_unassigned",
            InputKind::KdfParams => "input.kdf_params",
            InputKind::Generator => "input.generator",
            InputKind::NotFound => "input.not_found",
            InputKind::UnsupportedItem => "input.unsupported_item",
            InputKind::Header => "input.header",
            InputKind::Body => "input.body",
            InputKind::TooLarge => "input.too_large",
            InputKind::GenerationLimit => "input.generation_limit",
            InputKind::SetupText => "input.setup_text",
            InputKind::ServerUrl => "input.server_url",
            InputKind::Token => "input.token",
            InputKind::Fingerprint => "input.fingerprint",
        }
    }
}

impl Error {
    /// The stable name of the error, as `spec/vectors/` and other clients spell it: for example
    /// `integrity.bad_magic`, `input.password_too_short`, or `wrong_credentials`. Codes are never
    /// renamed or removed, only added.
    pub fn code(self) -> &'static str {
        match self {
            Error::Integrity(k) => k.code(),
            Error::InvalidInput(k) => k.code(),
            Error::WrongCredentials => "wrong_credentials",
            Error::SecretKeyTypo => "secret_key_typo",
            Error::ReadOnlyBody => "read_only_body",
            Error::ClockBeforeBuildTime => "clock_before_build_time",
            Error::ClockSkew => "clock_skew",
            Error::Rng => "rng",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Integrity(k) => write!(f, "integrity error: {k:?}"),
            Error::WrongCredentials => f.write_str("wrong master password or secret key"),
            Error::SecretKeyTypo => f.write_str("the secret key has a typo"),
            Error::InvalidInput(k) => write!(f, "invalid input: {k:?}"),
            Error::ReadOnlyBody => {
                f.write_str("the vault was written by a newer client and opens read-only")
            }
            Error::ClockBeforeBuildTime => {
                f.write_str("the system clock reads earlier than this client's build time")
            }
            Error::ClockSkew => {
                f.write_str("the system clock differs from the server's clock by more than a day")
            }
            Error::Rng => f.write_str("the random number generator failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Result with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn integrity<T>(k: IntegrityKind) -> Result<T> {
    Err(Error::Integrity(k))
}

pub(crate) fn input<T>(k: InputKind) -> Result<T> {
    Err(Error::InvalidInput(k))
}
