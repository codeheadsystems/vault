//! The commit rule. A caller reads the state, runs a procedure without holding its lock, and
//! commits the result under the lock. Commands may have changed the state on disk meanwhile.

use crate::error::ClientError;
use crate::machine::{Finished, Save};
use crate::run::item_names;
use crate::state::ClientState;
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::file::{open_file, seal_file_with_rng};
use vault_core::merge::{merge, same_content};
use vault_core::rng::Rng;
use vault_core::secret::VaultKey;

/// What to write after a procedure.
pub struct Commit {
    /// The state to write, or `None` when nothing changed.
    pub state: Option<ClientState>,
    /// Whether local changes made while the procedure ran were merged into the result; they stay
    /// local and unpushed until the next sync.
    pub merged_local_changes: bool,
    /// Names of local items that merge dropped because they predate the purge horizon.
    pub expired: Vec<String>,
}

/// The vault keys a commit needs when it merges local changes into the result.
#[derive(Clone, Copy, Default)]
pub struct CommitKeys<'a> {
    /// Opens the file the procedure started from, and so the file on disk.
    pub started: Option<&'a VaultKey>,
    /// Opens the result's file.
    pub result: Option<&'a VaultKey>,
}

impl<T> Finished<T> {
    /// Commits this end of a procedure that started from `started`; see [`commit`]. Nothing is
    /// written when the procedure has no state to commit.
    pub fn commit(
        &self,
        started: &ClientState,
        on_disk: &ClientState,
        background: bool,
        now: u64,
        rng: &mut dyn Rng,
    ) -> Result<Commit, ClientError> {
        match &self.state {
            None => Ok(Commit {
                state: None,
                merged_local_changes: false,
                expired: Vec::new(),
            }),
            Some(result) => {
                let keys = CommitKeys {
                    started: self.started_vault_key.as_ref(),
                    result: self.vault_key.as_ref(),
                };
                commit(started, on_disk, result, keys, background, now, rng)
            }
        }
    }
}

impl Save {
    /// Commits this save in a procedure that started from `started`; see [`commit`].
    pub fn commit(
        &self,
        started: &ClientState,
        on_disk: &ClientState,
        now: u64,
        rng: &mut dyn Rng,
    ) -> Result<Commit, ClientError> {
        let keys = CommitKeys {
            started: Some(&self.vault_key),
            result: Some(&self.vault_key),
        };
        commit(started, on_disk, &self.state, keys, false, now, rng)
    }
}

/// Produces the state to write from the state a procedure started from, the state now on disk,
/// and the procedure's result. Call it under the lock.
///
/// - When nothing changed on disk, the result is the procedure's state.
/// - When the sync state on disk changed (the accepted file, the wraps, or the pending secret
///   key), another sync or credential change committed first. The result is
///   [`ClientError::Superseded`] and nothing is written; the next sync starts afresh.
/// - When a command changed the local file meanwhile, the current local body is merged into the
///   result under the result's header, so the change stays local and unpushed. This needs both
///   vault keys.
/// - `dropped`, `refused`, and `stopped` keep the changes made on disk and add the procedure's.
///   For a `background` caller, items that the merge at commit drops are added to `dropped` too;
///   an interactive caller shows [`Commit::expired`] instead.
pub fn commit(
    started: &ClientState,
    on_disk: &ClientState,
    result: &ClientState,
    keys: CommitKeys<'_>,
    background: bool,
    now: u64,
    rng: &mut dyn Rng,
) -> Result<Commit, ClientError> {
    if sync_part(on_disk) != sync_part(started) {
        return Err(ClientError::Superseded);
    }
    let mut out = result.clone();
    out.secret_key_store = on_disk.secret_key_store;
    out.dropped = on_disk.dropped.clone();
    out.dropped.extend(
        result
            .dropped
            .iter()
            .filter(|n| !started.dropped.contains(n))
            .cloned(),
    );
    out.refused = on_disk
        .refused
        .iter()
        .filter(|n| !started.refused.contains(n) || result.refused.contains(n))
        .copied()
        .collect();
    for n in &result.refused {
        if !started.refused.contains(n) {
            out.refuse(*n);
        }
    }
    if result.stopped == started.stopped {
        out.stopped = on_disk.stopped.clone();
    }
    out.last_sync = result.last_sync.max(on_disk.last_sync);

    let mut merged_local_changes = false;
    let mut expired = Vec::new();
    if on_disk.file != started.file {
        if result.file == started.file {
            out.file = on_disk.file.clone();
        } else {
            check_clock(now, BUILD_TIME_MS, None)?;
            let local_key = keys.started.ok_or(ClientError::Locked)?;
            let result_key = keys.result.ok_or(ClientError::Locked)?;
            let (_, local) = open_file(&on_disk.file, local_key)?;
            let (header, remote) = open_file(&result.file, result_key)?;
            let m = merge(&local, &remote, now);
            expired = item_names(&m.expired);
            if background {
                out.dropped.extend(expired.iter().cloned());
            }
            if !same_content(&m.body, &remote) {
                out.file = seal_file_with_rng(rng, &header, result_key, &m.body)?;
                merged_local_changes = true;
            }
        }
    }
    Ok(Commit {
        state: (out != *on_disk).then_some(out),
        merged_local_changes,
        expired,
    })
}

/// The part of the state only a sync or a credential change writes.
fn sync_part(
    s: &ClientState,
) -> (
    &[u8; 16],
    &Option<vault_core::sync::Accepted>,
    &[u8; 24],
    &[crate::state::Retired],
    bool,
) {
    (
        &s.vault_id,
        &s.accepted,
        &s.wrap_nonce,
        &s.retired,
        s.pending_secret_key,
    )
}
