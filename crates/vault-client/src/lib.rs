//! vault-client: the client state that changes with the local vault file, and the sync,
//! recovery, credential change, setup, unlock, and restore procedures as sans-I/O state machines.
//! `spec/format.md` is normative; `vault-core` makes the individual decisions and this crate
//! composes them into whole procedures.
//!
//! The crate does no file or network I/O, reads no clock, and draws randomness only from the
//! [`vault_core::rng::Rng`] its caller passes. It builds for `wasm32-unknown-unknown`. The CLI,
//! the Firefox extension, and the Android app supply the transport, the storage, and the prompts.
//!
//! # Driving a procedure
//!
//! Each procedure returns a [`Machine`]. The caller starts it and answers each [`Step`] until
//! [`Step::Done`], then commits the result under its lock with [`Finished::commit`]:
//!
//! ```no_run
//! # use vault_client::*;
//! # fn send(_: &Request) -> Option<Response> { None }
//! # fn ask(_: Prompt) -> Answer { Answer::Declined }
//! # fn save(_: Save) {}
//! # fn now() -> u64 { 0 }
//! # fn run(state: ClientState, keys: Keys, rng: impl vault_core::rng::Rng + Send + 'static) {
//! let mut machine = sync::sync(state.clone(), keys, sync::Mode::Background, rng);
//! let mut step = machine.start(now());
//! let finished = loop {
//!     step = match step {
//!         Step::Request(r) => match send(&r) {
//!             Some(resp) => machine.step(Input::Response(resp), now()),
//!             None => machine.step(Input::Unreachable, now()),
//!         },
//!         Step::Prompt(p) => machine.step(Input::Answer(ask(p)), now()),
//!         Step::Save(s) => {
//!             save(s);
//!             machine.step(Input::Saved, now())
//!         }
//!         Step::Done(f) => break f,
//!     };
//! };
//! // Under the lock: read the state on disk, then
//! // finished.commit(&state, &on_disk, now(), &mut rng)
//! # }
//! ```

pub mod commit;
pub mod error;
pub mod machine;
pub mod passwd;
pub mod recover;
pub mod restore;
pub mod revisions;
mod run;
pub mod setup;
pub mod state;
pub mod sync;
pub mod unlock;

pub use error::{ClientError, InitRefusal};
pub use machine::{
    Answer, Confirmation, Finished, Input, Machine, Precondition, Prompt, Purpose, Request,
    Response, Save, SavedKey, SecretKeyChange, Step,
};
pub use run::Keys;
pub use state::{ClientState, Retired, SecretKeyStore, StopReason, Stopped};
