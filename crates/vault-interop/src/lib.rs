//! vault-interop: Bitwarden JSON import and export. `docs/bitwarden.md` describes the mapping.
//!
//! Like `vault-core`, the crate does no file or network I/O and reads no clock and no operating
//! system randomness: the caller passes the time (`now`, in ms) and a [`vault_core::rng::Rng`]. It
//! builds for `wasm32-unknown-unknown`.
//!
//! # Import
//!
//! 1. [`parse`] reads the file into an [`Export`]. It refuses a file over [`MAX_EXPORT_SIZE`], an
//!    account-restricted export, and a password-protected export whose KDF is unknown or whose
//!    parameters are outside the bounds, all before any key derivation.
//! 2. An [`Export::Protected`] needs the export password: [`ProtectedExport::decrypt`] returns
//!    the [`PlainExport`] inside it, or [`Error::WrongPassword`].
//! 3. [`import`] applies a [`PlainExport`] to a [`vault_core::body::Body`] as local edits and
//!    returns an [`ImportReport`]. A dry run imports into a clone of the body.
//!
//! # Export
//!
//! [`export_bitwarden`] writes a plain Bitwarden JSON export of a body. The spec's own plain JSON
//! form of a body is [`vault_core::body::Body::to_checked_json`].
//!
//! # Zeroization
//!
//! - The parsed export ([`PlainExport`]) zeroizes its strings, number texts, and object keys on
//!   drop. The parser decodes each string into a buffer of the raw text's length, so no
//!   reallocation leaves a partial copy, and zeroizes what it has built when it fails.
//! - The decrypted `data`, the master key, and the encryption and MAC keys are zeroizing buffers.
//!   The `zeroize` features of `hmac` and `sha2` make the HMAC, HKDF, and PBKDF2 states zeroize on
//!   drop too.
//! - The body types of `vault-core` zeroize themselves, and the export file is returned in a
//!   `Zeroizing` buffer.
//!
//! The password the caller passes in is the caller's to zeroize. Argon2id's working memory is
//! zeroized by the `argon2` crate's `zeroize` feature.

mod crypto;
mod error;
mod export;
mod file;
mod import;
mod mapping;
mod source;
mod time;

pub use crypto::{
    ARGON2_ITERATIONS, ARGON2_MEMORY_MIB, ARGON2_PARALLELISM, Kdf, PBKDF2_ITERATIONS,
};
pub use error::{Error, Result};
pub use export::{BitwardenExport, export_bitwarden};
pub use file::{Export, MAX_EXPORT_SIZE, PlainExport, ProtectedExport, parse};
pub use import::{ImportOptions, ImportReport, SkipReason, Skipped, UNTITLED, import};
