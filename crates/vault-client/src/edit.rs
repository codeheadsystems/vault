//! Local edits: a change to the body of the local vault file, sealed under the file's header so
//! the generation stays the one the file is based on. The next sync pushes it.

use crate::error::ClientError;
use crate::state::ClientState;
use vault_core::body::Body;
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::file::{open_file, seal_file_with_rng};
use vault_core::rng::Rng;
use vault_core::secret::VaultKey;

/// Why [`local_edit`] failed.
#[derive(Debug)]
pub enum EditError<E> {
    /// The clock check, opening, or sealing the file failed.
    Client(ClientError),
    /// The caller's edit failed; nothing changed.
    Edit(E),
}

impl<E> From<vault_core::Error> for EditError<E> {
    fn from(e: vault_core::Error) -> Self {
        EditError::Client(e.into())
    }
}

/// Applies `edit` to the body of `state`'s file and returns `edit`'s value with the state to
/// write, or `None` when the body did not change. Call it under the lock, with `state` read
/// under that lock, so that no other write lands in between.
///
/// The clock is checked against the build time first (spec Merge rule), `vault_key` opens the
/// file, and `edit` runs with `now` and `device_id` for its stamps. A changed body is sealed
/// under the same header with a fresh `body_nonce` drawn from `rng`.
pub fn local_edit<R, E>(
    state: &ClientState,
    vault_key: &VaultKey,
    device_id: &[u8; 16],
    now: u64,
    rng: &mut dyn Rng,
    edit: impl FnOnce(&mut Body, u64, &[u8; 16]) -> Result<R, E>,
) -> Result<(R, Option<ClientState>), EditError<E>> {
    check_clock(now, BUILD_TIME_MS, None)?;
    let (header, mut body) = open_file(&state.file, vault_key)?;
    let before = body.clone();
    let r = edit(&mut body, now, device_id).map_err(EditError::Edit)?;
    if body == before {
        return Ok((r, None));
    }
    let mut next = state.clone();
    next.file = seal_file_with_rng(rng, &header, vault_key, &body)?;
    Ok((r, Some(next)))
}
