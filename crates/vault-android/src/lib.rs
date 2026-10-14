//! vault-android: the UniFFI bindings over `vault-core` and `vault-client` that the Android app
//! loads (docs/android.md, Rust bindings). `API.md` describes the Kotlin-facing API.
//!
//! The operations are coarse, so secrets cross into Kotlin only where the app needs them: the
//! vault key for the biometric wrap, a password for one view, edit, copy, or fill, and the
//! secret key's text form for the kit. The unlocked body stays in Rust memory, in the one
//! [`Vault`] of the process, which also owns the state lock and the idle lock. Kotlin supplies
//! file and key-slot I/O and the clocks through [`Host`]; randomness comes from the operating
//! system.

#![forbid(unsafe_code)]

mod autofill;
mod error;
mod host;
mod misc;
mod procedure;
pub mod psl;
mod vault;

pub use autofill::{
    AppBinding, AppMatch, AppPage, Candidate, ItemUri, KnownSuffix, Outcome, Page, SaveOffer,
    WebPage, android_web_page, apps_after_fill, explicit_choice_allowed, known_suffix,
    page_candidates, page_save_offer,
};
pub use error::VaultError;
pub use host::{Host, KeySlot};
pub use misc::{
    Generated, PasswordOptions, RevisionInfo, SetupText, decode_secret_key, encode_secret_key,
    generate_passphrase, generate_password, parse_revisions, parse_setup_text, pin_matches,
};
pub use procedure::{
    Answer, Applied, ConfirmKind, ErrorInfo, Input, PasswdChange, PendingKey, Procedure, Prompt,
    Purpose, Report, Request, Step, SyncMode, SyncOutcome, SyncResult,
};
pub use vault::{
    Binding, Credential, DEFAULT_IDLE_MS, Entry, NewItem, RestoreSummary, StateSummary, Stopped,
    Vault, VaultKeyExport,
};

uniffi::setup_scaffolding!();
