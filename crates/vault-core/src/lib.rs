//! vault-core: the keys, the vault file, the item schema, the merge rule, and the sync decisions
//! that every vault client shares. `spec/format.md` is normative.
//!
//! The crate does no file or network I/O, has no async API, and reads no clock and no operating
//! system randomness. The caller passes the time (`now`, in ms) and a [`rng::Rng`], so every
//! function is deterministic for fixed inputs. It builds for `wasm32-unknown-unknown`.
//!
//! # Zeroization
//!
//! Every value that holds a secret or plaintext zeroizes its memory when dropped:
//!
//! - Keys and tokens ([`secret`]) are zeroizing byte arrays with no `Debug` or `Display`. A
//!   generated key is drawn straight into its value.
//! - A decrypted body is zeroized string by string: [`json::Value`] and every type in [`body`]
//!   zeroize their strings and object keys on drop, so clones and temporaries made by a merge, an
//!   edit, or the write path are zeroized too.
//! - Plaintext buffers (the decrypted body, the JSON text, the padded plaintext, a normalised
//!   password, and a decoded text form) are `Zeroizing` buffers sized once, so no reallocation
//!   leaves a copy behind.
//!
//! Public values (IDs, salts, nonces, headers, and ciphertext) are not zeroized. Copies that this
//! crate cannot reach are outside the policy: a string the caller passes in, serde_json's scratch
//! buffer for a string with escapes while parsing, and the stack copies the compiler makes when it
//! moves a value.

#[cfg(all(feature = "insecure-test-kdf", not(debug_assertions)))]
compile_error!(
    "the insecure-test-kdf feature accepts the test KDF parameters and is refused in builds \
     without debug assertions"
);

pub mod body;
pub mod clock;
pub mod credentials;
pub mod edit;
pub mod error;
pub mod file;
pub mod generate;
pub mod header;
pub mod json;
pub mod kdf;
pub mod keys;
pub mod merge;
mod prim;
pub mod rng;
pub mod secret;
pub mod secret_key_text;
pub mod setup;
pub mod sync;
mod textcodec;
pub mod token;

pub use error::{Error, InputKind, IntegrityKind, Result};
