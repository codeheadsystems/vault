//! The commit rule. A caller reads the state, runs a procedure without holding its lock, and
//! commits the result under the lock. Commands may have changed the state on disk meanwhile.
//! [`apply`] carries out a commit together with its secret key change, in a safe order, through
//! the storage a host supplies.

use crate::error::ClientError;
use crate::machine::{Finished, Save, SavedKey, SecretKeyChange};
use crate::run::item_names;
use crate::state::{ClientState, SecretKeyStore};
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::file::{open_file, seal_file_with_rng};
use vault_core::merge::{merge, same_content};
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, VaultKey};

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

/// The storage a host supplies to [`apply`]: the secret key store and the state file. The host
/// holds its lock around the whole call.
pub trait CommitHost {
    /// The host's storage error.
    type Error;
    /// Stores `key` as the current secret key of `vault_id` in `store`.
    fn store_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), Self::Error>;
    /// Stores `key` as the pending secret key of `vault_id` in `store`, for a `--new-secret-key`
    /// change that has not pushed yet.
    fn store_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), Self::Error>;
    /// Copies the pending secret key of `vault_id` to the current slot, keeping the pending
    /// slot. Fails when there is no pending key.
    fn copy_pending_to_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), Self::Error>;
    /// Deletes the pending secret key of `vault_id`; an empty slot is not an error.
    fn delete_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), Self::Error>;
    /// Writes the state atomically.
    fn write_state(&mut self, state: &ClientState) -> Result<(), Self::Error>;
}

/// Why [`apply`] failed. Nothing after the failed write ran.
#[derive(Debug)]
pub enum ApplyError<E> {
    /// The commit rule refused, other than for [`ClientError::Superseded`]; nothing was written.
    Client(ClientError),
    /// The host's storage failed before the state was written.
    Host(E),
}

impl<E> From<ClientError> for ApplyError<E> {
    fn from(e: ClientError) -> Self {
        ApplyError::Client(e)
    }
}

/// A commit that [`apply`] carried out.
pub struct Applied<E> {
    /// What was committed.
    pub commit: Commit,
    /// The error of the last step, deleting the pending secret key, when it failed after the
    /// state was written. The commit stands; the pending slot holds a key nothing uses, which
    /// the next `--new-secret-key` replaces.
    pub pending_left: Option<E>,
}

/// Commits the end of a procedure and its secret key change through `host`. Call it under the
/// host's lock, with `on_disk` read under that lock.
///
/// The writes run in this order:
///
/// 1. The key the new state needs: a new current secret key ([`SecretKeyChange::Replace`] and
///    [`SecretKeyChange::ReplaceAndDiscardPending`]), or a copy of the pending key to the
///    current slot ([`SecretKeyChange::PromotePending`]).
/// 2. The state, unless the state on disk already equals the result; the key writes of steps 1
///    and 3 run either way.
/// 3. Deleting the pending key ([`SecretKeyChange::PromotePending`],
///    [`SecretKeyChange::DiscardPending`], and [`SecretKeyChange::ReplaceAndDiscardPending`]).
///
/// What the order guarantees when the host stops after any write:
///
/// - After step 1 alone, the current slot holds the key that opens the remote's wrap, and the
///   state on disk is the one the procedure started from. With a pending key, the pending slot
///   still holds the same key, so the next sync settles it as landed. After a replaced key, the
///   next sync finds the remote under a wrap that the stored key opens. In both cases the local
///   file on disk is still under the old wrap, and the old secret key is gone from the store:
///   local changes that the remote does not hold open only with a cached vault key, and
///   without one the next sync asks to discard them.
/// - After step 2, the state needs only the current key; a pending key left in its slot is
///   unused.
///
/// Returns `None` when another sync or credential change committed first
/// ([`ClientError::Superseded`]): nothing is written, and the caller reports the procedure's
/// own result.
pub fn apply<T, H: CommitHost>(
    finished: &Finished<T>,
    started: &ClientState,
    on_disk: &ClientState,
    background: bool,
    now: u64,
    rng: &mut dyn Rng,
    host: &mut H,
) -> Result<Option<Applied<H::Error>>, ApplyError<H::Error>> {
    let c = match finished.commit(started, on_disk, background, now, rng) {
        Err(ClientError::Superseded) => return Ok(None),
        r => r?,
    };
    let target = c.state.as_ref().unwrap_or(on_disk);
    let (store, id) = (target.secret_key_store, target.vault_id);
    let delete_pending = match &finished.secret_key {
        None => false,
        Some(SecretKeyChange::Replace(sk)) => {
            host.store_current(store, &id, sk)
                .map_err(ApplyError::Host)?;
            false
        }
        Some(SecretKeyChange::ReplaceAndDiscardPending(sk)) => {
            host.store_current(store, &id, sk)
                .map_err(ApplyError::Host)?;
            true
        }
        Some(SecretKeyChange::PromotePending) => {
            host.copy_pending_to_current(store, &id)
                .map_err(ApplyError::Host)?;
            true
        }
        Some(SecretKeyChange::DiscardPending) => true,
    };
    if let Some(s) = &c.state {
        host.write_state(s).map_err(ApplyError::Host)?;
    }
    let pending_left = if delete_pending {
        host.delete_pending(store, &id).err()
    } else {
        None
    };
    Ok(Some(Applied {
        commit: c,
        pending_left,
    }))
}

/// Carries out a [`Save`] through `host`. Call it under the host's lock, with `on_disk` read under
/// that lock; `started` is the state the procedure started from, or the previous save's state.
///
/// The commit rule runs first, from `started` and `on_disk` to the saved state, and writes
/// nothing: its refusals ([`ClientError::Superseded`] when another sync committed meanwhile, a
/// clock before the build time) leave the host untouched. Then the writes run in this order:
///
/// 1. The saved secret key, in the slot [`SavedKey`] names: the current slot for `vault init`,
///    the pending slot for `vault passwd --new-secret-key`.
/// 2. The state, unless the state on disk already equals the result.
///
/// The host contract: when a write fails ([`ApplyError::Host`]) after the key write, the key write
/// has already been issued. A host that queues its writes in a transaction (the extension's
/// IndexedDB) discards every queued write when the call returns an error. A host that writes
/// straight to storage (the CLI's files) is left with a pending key that the state on disk does
/// not name; nothing uses it, and the next `--new-secret-key` replaces it. A save's state
/// becomes the procedure's start for the next save and for [`apply`].
pub fn apply_save<H: CommitHost>(
    save: &Save,
    started: &ClientState,
    on_disk: &ClientState,
    now: u64,
    rng: &mut dyn Rng,
    host: &mut H,
) -> Result<Commit, ApplyError<H::Error>> {
    let c = save.commit(started, on_disk, now, rng)?;
    let (store, id) = (save.state.secret_key_store, save.state.vault_id);
    match &save.secret_key {
        SavedKey::Current(k) => host.store_current(store, &id, k),
        SavedKey::Pending(k) => host.store_pending(store, &id, k),
    }
    .map_err(ApplyError::Host)?;
    if let Some(s) = &c.state {
        host.write_state(s).map_err(ApplyError::Host)?;
    }
    Ok(c)
}

/// Writes the first state of a client that holds none, after `vault setup`: the secret key the
/// procedure gives ([`SecretKeyChange::Replace`]), then the state. Call it under the host's
/// lock, after checking that no state is stored. A finished procedure without a state writes
/// nothing. Any other secret key change is refused before any write, because only a client that
/// holds a state has a pending key.
///
/// When the state write fails after the key write, the key write has already been issued: a
/// transactional host discards every queued write when the call returns an error, and a host
/// that writes straight to storage keeps a current key with no state, which the next setup
/// overwrites.
pub fn apply_first<T, H: CommitHost>(
    finished: &Finished<T>,
    host: &mut H,
) -> Result<Option<Applied<H::Error>>, ApplyError<H::Error>> {
    let Some(state) = &finished.state else {
        return Ok(None);
    };
    match &finished.secret_key {
        Some(SecretKeyChange::Replace(k)) => host
            .store_current(state.secret_key_store, &state.vault_id, k)
            .map_err(ApplyError::Host)?,
        None => {}
        Some(_) => return Err(ApplyError::Client(ClientError::UnexpectedInput)),
    }
    host.write_state(state).map_err(ApplyError::Host)?;
    Ok(Some(Applied {
        commit: Commit {
            state: Some(state.clone()),
            merged_local_changes: false,
            expired: Vec::new(),
        },
        pending_left: None,
    }))
}
