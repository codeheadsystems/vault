//! An unlock with a typed master password, which pulls first.

use crate::error::ClientError;
use crate::machine::{Machine, Request};
use crate::run::{Keys, Run};
use crate::state::{ClientState, StopReason};
use crate::sync::{Mode, SyncReport, run_sync};
use vault_core::rng::Rng;
use vault_core::sync::{WrapStatus, check_remote};

/// The result of an unlock: the vault key is in [`crate::Finished::vault_key`].
pub struct UnlockReport {
    /// The sync that followed the pull, or why there was none: the server was unreachable, or
    /// sync is stopped for an integrity error or the token.
    pub sync: Result<SyncReport, ClientError>,
}

/// Unlocks with a typed master password. It pulls first; the caller bounds the pull with its
/// unlock time limit and feeds [`crate::Input::Unreachable`] when the server does not answer.
///
/// When the remote carries a `wrap_nonce` that is neither current nor retired, the unlock runs
/// the credential change on another device flow instead of trying the local file. Otherwise it
/// asks for the master password, opens the local file, and syncs with the pulled file. A failed
/// sync leaves the unlock in place; it fails only when no vault key was obtained.
pub fn unlock(
    state: ClientState,
    keys: Keys,
    rng: impl Rng + Send + 'static,
) -> Machine<UnlockReport> {
    Machine::new(rng, move |mut cx| async move {
        let mut run = Run::new(state, keys);
        let skip = run
            .started
            .stopped
            .as_ref()
            .is_some_and(|s| s.reason != StopReason::Credentials);
        let pulled = if skip {
            None
        } else {
            Some(cx.request(Request::GetVault).await)
        };
        // A refused wrap does not replace the local file; the sync reports it (spec, Opening a
        // file).
        let changed = match &pulled {
            Some(Ok(r)) if r.status == 200 => check_remote(&run.started.sync_state(), &r.body)
                .is_ok_and(|c| {
                    c.wrap == WrapStatus::Changed
                        && !run.started.refused.contains(&c.header.wrap_nonce)
                }),
            _ => false,
        };
        if !changed && let Err(e) = run.unlock_local(&mut cx).await {
            return run.finish(Err(e), false);
        }
        let policy = Mode::Interactive { ask_again: false }.policy();
        let sync = match pulled {
            Some(Ok(resp)) => run_sync(&mut cx, &mut run, policy, Some(resp)).await,
            Some(Err(e)) => Err(e),
            None => Err(ClientError::Stopped(
                run.started
                    .stopped
                    .as_ref()
                    .map_or(StopReason::Integrity, |s| s.reason),
            )),
        };
        // A takeover of new credentials whose push failed is kept in the failure outcome, with
        // its vault key.
        let took_over = run
            .changed
            .as_ref()
            .is_some_and(|c| c.nonce == run.fail.wrap_nonce);
        match sync {
            Ok(report) => run.finish(Ok(UnlockReport { sync: Ok(report) }), true),
            Err(e) if run.vault_key.is_none() && !took_over => run.finish(Err(e), false),
            Err(e) => run.finish(Ok(UnlockReport { sync: Err(e) }), false),
        }
    })
}
