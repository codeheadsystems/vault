//! vault-wasm: the `wasm-bindgen` bindings over `vault-core` and `vault-client` that the Firefox
//! extension loads (docs/firefox.md, WASM bindings). `API.md` describes the TypeScript-facing API.
//!
//! The operations are coarse, so secrets cross into JavaScript only where the extension needs
//! them: the vault key for `storage.session`, and a password for one view, edit, copy, or fill.
//! The unlocked body stays in WASM memory, in a [`Session`]. Randomness comes from
//! `crypto.getRandomValues`, and the time is passed in from JavaScript.

mod autofill;
mod convert;
mod misc;
mod procedure;
mod session;

pub use autofill::{frames_to_fill, match_uri, page_url, prepare_uri, registrable_domain};
pub use misc::{
    clear_dropped, decode_secret_key, encode_secret_key, generate_passphrase, generate_password,
    parse_revisions, parse_setup_text, state_summary,
};
pub use procedure::Procedure;
pub use session::Session;

/// `crypto.getRandomValues`, through getrandom's `js` backend.
pub(crate) struct WebRng;

impl vault_core::rng::Rng for WebRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        getrandom::getrandom(dest).map_err(|_| vault_core::Error::Rng)
    }
}
