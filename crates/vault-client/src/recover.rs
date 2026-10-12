//! `vault sync --recover`: repairs sync after an integrity error from the server's retained
//! revisions.

use crate::error::ClientError;
use crate::machine::{Confirmation, Cx, Machine, Precondition, Purpose, Request};
use crate::revisions::parse_revisions;
use crate::run::{Changed, Keys, Opened, Run, item_names};
use crate::state::{ClientState, StopReason};
use crate::sync::{Mode, seal};
use vault_core::credentials::PendingKeyOutcome;
use vault_core::file::{Unlocked, open_file, read_header};
use vault_core::merge::merge;
use vault_core::rng::Rng;
use vault_core::secret::SecretKey;
use vault_core::sync::{
    PutCondition, Recovery, Retry, RetryCounter, etag, next_generation, plan_recovery,
    recovery_generation,
};

/// The most revisions recovery fetches.
pub const RECOVERY_REVISIONS: usize = 100;

/// The result of a recovery.
pub struct RecoverReport {
    /// The generation pushed.
    pub generation: u64,
    /// The revision the local body was merged into, or `None` when the local file was pushed on
    /// its own.
    pub revision: Option<u64>,
    /// Whether recovery took over a credential change made on another device.
    pub credentials_changed: bool,
    /// Names of local items the merge dropped because they predate the purge horizon.
    pub expired: Vec<String>,
    /// How a pending secret key was settled.
    pub pending_secret_key: Option<PendingKeyOutcome>,
}

/// Recovers after an integrity error. Always interactive: it may ask for the master password,
/// for new credentials, and once per run for the confirmation that no credential change was made.
pub fn recover(
    state: ClientState,
    keys: Keys,
    rng: impl Rng + Send + 'static,
) -> Machine<RecoverReport> {
    Machine::new(rng, move |mut cx| async move {
        let mut run = Run::new(state, keys);
        let result = run_recover(&mut cx, &mut run).await;
        let ok = result.is_ok();
        run.finish(result, ok)
    })
}

async fn run_recover(cx: &mut Cx, run: &mut Run) -> Result<RecoverReport, ClientError> {
    if let Some(s) = &run.started.stopped
        && s.reason == StopReason::Token
    {
        return Err(ClientError::Stopped(s.reason));
    }
    let policy = Mode::Interactive { ask_again: true }.policy();
    cx.check_clock()?;
    let mut retries = RetryCounter::new();
    let mut confirmed = false;
    loop {
        let revisions = fetch_revisions(cx, run).await?;
        cx.check_clock()?;
        let now = cx.now();
        // The newest retained revision is the current one.
        let condition = match revisions.first() {
            Some((_, f)) => Precondition::IfMatch(etag(f)),
            // A server with no revision has no ETag (spec, Recovery after an integrity error,
            // step 5).
            None => Precondition::IfNoneMatch,
        };
        let refs: Vec<(u64, &[u8])> = revisions.iter().map(|(i, f)| (*i, &f[..])).collect();
        let file_of = |id: u64| refs.iter().find(|(i, _)| *i == id).map(|(_, f)| *f);
        let state = run.next.sync_state();
        let mut plan = plan_recovery(&state, &refs, confirmed);
        let mut push = None;
        if let Recovery::CredentialChange(ids) = &plan {
            let files: Vec<&[u8]> = ids.iter().filter_map(|id| file_of(*id)).collect();
            // A new wrap opened before a `412` opens again with its vault key, without a prompt.
            let reopened = run.changed.as_ref().and_then(|c| {
                files.iter().enumerate().find_map(|(index, f)| {
                    let (header, body) = open_file(f, &c.vault_key).ok()?;
                    (header.wrap_nonce == c.nonce).then(|| Opened {
                        index,
                        unlocked: Unlocked {
                            header,
                            vault_key: c.vault_key.clone_secret(),
                            body,
                        },
                        new_secret_key: c.new_secret_key.as_ref().map(SecretKey::clone_secret),
                    })
                })
            });
            let opened = match reopened {
                Some(o) => Some(o),
                None => run.open_new_wrap(cx, &files, Purpose::Recovery).await?,
            };
            match opened {
                Some(o) => {
                    let id = ids[o.index];
                    let u = o.unlocked;
                    let nonce = u.header.wrap_nonce;
                    // The wrap was retired at the first revision that carries the new one.
                    let first = refs
                        .iter()
                        .filter(|(_, f)| read_header(f).is_ok_and(|h| h.wrap_nonce == nonce))
                        .map(|(i, _)| *i)
                        .min();
                    run.changed = Some(Changed {
                        nonce,
                        vault_key: u.vault_key.clone_secret(),
                        new_secret_key: o.new_secret_key,
                        etag: etag(files[o.index]),
                        revision: first.or(Some(id)),
                    });
                    let merged = match run.local_body(cx).await? {
                        Some(local) => {
                            let m = merge(&local, &u.body, now);
                            run.expired = item_names(&m.expired);
                            m.body
                        }
                        None => u.body.clone(),
                    };
                    // One more than the greater of the revision's and the accepted generation
                    // (spec, Recovery after an integrity error, step 2).
                    let base = state.accepted.as_ref().map_or(u.header.generation, |a| {
                        a.generation.max(u.header.generation)
                    });
                    let generation = next_generation(base)?;
                    let file = seal(
                        cx,
                        &u.header.with_generation(generation),
                        &u.vault_key,
                        &merged,
                    )?;
                    push = Some((file, generation, Some(id)));
                }
                None => {
                    if !cx.confirm(Confirmation::NoCredentialChange).await? {
                        return Err(ClientError::Cancelled);
                    }
                    confirmed = true;
                    for f in &files {
                        if let Ok(h) = read_header(f) {
                            run.refuse(h.wrap_nonce);
                        }
                    }
                    plan = plan_recovery(&state, &refs, true);
                }
            }
        }
        let (file, generation, revision) = match push {
            Some(p) => p,
            None => {
                let Recovery::Candidates(ids) = plan else {
                    unreachable!("planned past unknown wraps")
                };
                let vk = run.current_key(cx, policy).await?;
                let chosen = ids.iter().find_map(|id| {
                    let f = file_of(*id)?;
                    open_file(f, &vk).ok().map(|(h, b)| (*id, h, b))
                });
                let local = run.local_body(cx).await?.ok_or(ClientError::Locked)?;
                match chosen {
                    Some((id, header, body)) => {
                        let m = merge(&local, &body, now);
                        run.expired = item_names(&m.expired);
                        let generation = recovery_generation(&state, Some(header.generation))?;
                        let file = seal(cx, &header.with_generation(generation), &vk, &m.body)?;
                        (file, generation, Some(id))
                    }
                    None => {
                        let generation = recovery_generation(&state, None)?;
                        let header = run.started.header()?.with_generation(generation);
                        (seal(cx, &header, &vk, &local)?, generation, None)
                    }
                }
            }
        };
        let kind = match condition {
            Precondition::IfMatch(_) => PutCondition::IfMatch,
            Precondition::IfNoneMatch => PutCondition::IfNoneMatch,
        };
        let resp = cx
            .request(Request::PutVault {
                condition,
                file: file.clone(),
            })
            .await?;
        match resp.status {
            200 => {
                run.next.accept(generation, file);
                run.complete_change(cx).await?;
                run.settle_pending();
                run.next.stopped = None;
                run.next.last_sync = Some(cx.now());
                return Ok(RecoverReport {
                    generation,
                    revision,
                    credentials_changed: run.changed.is_some(),
                    expired: run.expired.clone(),
                    pending_secret_key: run.pending_outcome,
                });
            }
            412 => match retries.precondition_failed(kind) {
                Retry::Again => continue,
                Retry::GiveUp => return Err(ClientError::Conflicts),
            },
            401 => return Err(run.token(cx.now())),
            s => return Err(ClientError::Status(s)),
        }
    }
}

/// Lists the retained revisions and fetches the newest 100, newest first. A revision deleted
/// between the list and the fetch is skipped.
async fn fetch_revisions(cx: &mut Cx, run: &mut Run) -> Result<Vec<(u64, Vec<u8>)>, ClientError> {
    let resp = cx.request(Request::ListRevisions).await?;
    match resp.status {
        200 => {}
        401 => return Err(run.token(cx.now())),
        s => return Err(ClientError::Status(s)),
    }
    let mut ids: Vec<u64> = parse_revisions(&resp.body)?.iter().map(|r| r.id).collect();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.dedup();
    ids.truncate(RECOVERY_REVISIONS);
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let resp = cx.request(Request::GetRevision(id)).await?;
        match resp.status {
            200 => out.push((id, resp.body)),
            404 => {}
            401 => return Err(run.token(cx.now())),
            s => return Err(ClientError::Status(s)),
        }
    }
    Ok(out)
}
