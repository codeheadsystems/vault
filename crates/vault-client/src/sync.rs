//! Sync: pull, check, open, merge, and adopt or push, with the `412` and `404` rules, a credential
//! change on another device, and a pending secret key.

use crate::error::ClientError;
use crate::machine::{Answer, Cx, Machine, Precondition, Prompt, Purpose, Request, Response};
use crate::run::{Changed, Keys, OnChanged, Policy, Run, Takeover, item_names};
use crate::state::{ClientState, StopReason};
use vault_core::Error;
use vault_core::body::Body;
use vault_core::credentials::{PendingKeyOutcome, resolve_pending_secret_key};
use vault_core::file::{Unlocked, open_file, seal_file_with_rng, unlock};
use vault_core::header::Header;
use vault_core::merge::{merge, same_content};
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::sync::{
    NotFoundAction, PutCondition, RemoteCheck, Retry, RetryCounter, SyncAction, WrapStatus,
    adopt_or_push, check_remote, on_not_found,
};

/// Whether a sync may ask the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Never prompts. Anything that needs a prompt records `stopped` and fails, and items a
    /// merge drops are added to `dropped`.
    Background,
    /// Asks for whatever the sync needs. A `wrap_nonce` that failed to open before is reported
    /// without a prompt unless `ask_again` is set, as for a sync the user asked for.
    Interactive {
        /// Ask again for a `wrap_nonce` on the refused list.
        ask_again: bool,
    },
}

impl Mode {
    pub(crate) fn policy(self) -> Policy {
        match self {
            Mode::Background => Policy {
                prompts: false,
                on_changed: OnChanged::Stop,
            },
            Mode::Interactive { ask_again } => Policy {
                prompts: true,
                on_changed: OnChanged::Prompt { ask_again },
            },
        }
    }
}

/// What a successful sync did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The server holds the local file.
    UpToDate,
    /// The client adopted the server's file.
    Adopted,
    /// The client pushed a new generation.
    Pushed,
}

/// The result of a sync.
pub struct SyncReport {
    /// What the sync did.
    pub outcome: SyncOutcome,
    /// The accepted generation afterwards.
    pub generation: u64,
    /// Names of local items the merge dropped because they predate the purge horizon.
    pub expired: Vec<String>,
    /// Whether the sync took over a credential change made on another device.
    pub credentials_changed: bool,
    /// How a pending secret key was settled. `NotLanded` means the newly printed emergency kit is
    /// void and `vault passwd --new-secret-key` must run again.
    pub pending_secret_key: Option<PendingKeyOutcome>,
}

/// Syncs the local file with the server.
///
/// `keys.vault_key` opens the local file without a prompt. In interactive mode the procedure
/// asks for the master password when it lacks the vault key, for credentials when another device
/// changed them, and for the master password to settle a pending secret key.
pub fn sync(
    state: ClientState,
    keys: Keys,
    mode: Mode,
    rng: impl Rng + Send + 'static,
) -> Machine<SyncReport> {
    Machine::new(rng, move |mut cx| async move {
        let mut run = Run::new(state, keys);
        let result = run_sync(&mut cx, &mut run, mode.policy(), None).await;
        let ok = result.is_ok();
        run.finish(result, ok)
    })
}

/// What step 5 decided for one pulled file.
enum Plan {
    Adopt {
        file: Vec<u8>,
        generation: u64,
    },
    Push {
        file: Vec<u8>,
        generation: u64,
        condition: Precondition,
    },
}

/// The sync procedure. `pulled` is a `GET /v1/vault` response the caller already has.
pub(crate) async fn run_sync(
    cx: &mut Cx,
    run: &mut Run,
    policy: Policy,
    pulled: Option<Response>,
) -> Result<SyncReport, ClientError> {
    if let Some(s) = &run.started.stopped
        && (s.reason != StopReason::Credentials || !policy.prompts)
    {
        return Err(ClientError::Stopped(s.reason));
    }
    if run.started.pending_secret_key && !policy.prompts {
        run.stop(
            StopReason::Credentials,
            ClientError::PendingSecretKey.code(),
            cx.now(),
        );
        return Err(ClientError::PendingSecretKey);
    }
    cx.check_clock()?;
    let outcome = match rounds(cx, run, policy, pulled).await {
        Ok(o) => o,
        Err(e) => {
            run.keep_takeover(cx).await;
            return Err(e);
        }
    };
    run.complete_change(cx).await?;
    run.settle_pending();
    let now = cx.now();
    run.next.stopped = None;
    run.next.last_sync = Some(now);
    if !policy.prompts {
        run.next.dropped.extend(run.expired.iter().cloned());
    }
    Ok(SyncReport {
        outcome,
        generation: run.next.accepted.as_ref().map_or(0, |a| a.generation),
        expired: run.expired.clone(),
        credentials_changed: run.changed.is_some(),
        pending_secret_key: run.pending_outcome,
    })
}

/// Steps 1 to 6, repeated after each `412` within the limits.
async fn rounds(
    cx: &mut Cx,
    run: &mut Run,
    policy: Policy,
    mut pulled: Option<Response>,
) -> Result<SyncOutcome, ClientError> {
    let mut retries = RetryCounter::new();
    loop {
        let resp = match pulled.take() {
            Some(r) => r,
            None => cx.request(Request::GetVault).await?,
        };
        let plan = match resp.status {
            200 => integrate(cx, run, policy, resp.body).await?,
            404 => {
                run.takeover = None;
                repush(cx, run, policy).await?
            }
            401 => return Err(run.token(cx.now())),
            s => return Err(ClientError::Status(s)),
        };
        match plan {
            Plan::Adopt { file, generation } => {
                let up_to_date = file == run.started.file;
                run.next.accept(generation, file);
                return Ok(if up_to_date {
                    SyncOutcome::UpToDate
                } else {
                    SyncOutcome::Adopted
                });
            }
            Plan::Push {
                file,
                generation,
                condition,
            } => {
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
                        return Ok(SyncOutcome::Pushed);
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
    }
}

/// Steps 2 to 5 for a pulled file.
async fn integrate(
    cx: &mut Cx,
    run: &mut Run,
    policy: Policy,
    file: Vec<u8>,
) -> Result<Plan, ClientError> {
    let now = cx.now();
    let check =
        check_remote(&run.next.sync_state(), &file).map_err(|e| run.remote_error(e, now))?;
    cx.check_clock()?;
    let Unlocked {
        header,
        vault_key,
        body: remote,
    } = match check.wrap {
        WrapStatus::Current => {
            if run.started.pending_secret_key {
                // The remote still carries the current wrap, so the push did not land, without
                // any key derivation (spec, Credential change).
                run.pending_outcome = Some(PendingKeyOutcome::NotLanded);
            }
            // A new wrap opened before a `412` is no longer the remote's.
            run.changed = None;
            run.takeover = None;
            let vk = run.current_key(cx, policy).await?;
            let (header, body) = open_file(&file, &vk).map_err(|e| run.remote_error(e, now))?;
            Unlocked {
                header,
                vault_key: vk,
                body,
            }
        }
        WrapStatus::Changed => open_changed(cx, run, policy, &file, &check).await?,
    };
    let merged = match run.local_body(cx).await? {
        Some(local) => {
            let m = merge(&local, &remote, now);
            run.expired = item_names(&m.expired);
            m.body
        }
        None => remote.clone(),
    };
    if check.wrap == WrapStatus::Changed {
        let local_file = if same_content(&merged, &remote) {
            file.clone()
        } else {
            seal(cx, &header, &vault_key, &merged)?
        };
        run.takeover = Some(Takeover {
            generation: header.generation,
            remote_hash: check.file_hash,
            local_file,
        });
    }
    Ok(match adopt_or_push(&merged, &remote, header.generation)? {
        SyncAction::Adopt => Plan::Adopt {
            file,
            generation: header.generation,
        },
        SyncAction::Push { generation } => Plan::Push {
            file: seal(cx, &header.with_generation(generation), &vault_key, &merged)?,
            generation,
            condition: Precondition::IfMatch(check.etag),
        },
    })
}

/// A remote under a `wrap_nonce` that is neither current nor retired.
async fn open_changed(
    cx: &mut Cx,
    run: &mut Run,
    policy: Policy,
    file: &[u8],
    check: &RemoteCheck,
) -> Result<Unlocked, ClientError> {
    let now = cx.now();
    let nonce = check.header.wrap_nonce;
    if let Some(c) = &run.changed
        && c.nonce == nonce
    {
        // Opened earlier in this run, before a `412`.
        let vk = c.vault_key.clone_secret();
        let (header, body) = open_file(file, &vk).map_err(|e| run.remote_error(e, now))?;
        return Ok(Unlocked {
            header,
            vault_key: vk,
            body,
        });
    }
    match policy.on_changed {
        OnChanged::Abort => return Err(ClientError::CredentialsChanged),
        OnChanged::Stop => {
            run.stop(
                StopReason::Credentials,
                ClientError::CredentialsChanged.code(),
                now,
            );
            return Err(ClientError::CredentialsChanged);
        }
        OnChanged::Prompt { ask_again } => {
            if !ask_again && run.started.refused.contains(&nonce) {
                return Err(ClientError::RefusedWrap);
            }
        }
    }
    let opened = if run.started.pending_secret_key {
        resolve_pending(cx, run, file, &check.header).await?
    } else {
        run.open_new_wrap(cx, &[file], Purpose::CredentialsChanged)
            .await?
            .map(|o| (o.unlocked, o.new_secret_key))
    };
    let Some((unlocked, new_secret_key)) = opened else {
        run.refuse(nonce);
        run.stop(
            StopReason::Credentials,
            ClientError::RemoteUnopenable.code(),
            now,
        );
        return Err(ClientError::RemoteUnopenable);
    };
    run.changed = Some(Changed {
        nonce,
        vault_key: unlocked.vault_key.clone_secret(),
        new_secret_key,
        etag: check.etag.clone(),
        revision: None,
    });
    Ok(unlocked)
}

/// A pending secret key and a remote under a new wrap: asks for the master password up to three
/// times and tries it with the old and the pending secret key, then asks for the master password
/// and a new secret key as in the credential change on another device flow. `None` means
/// nothing opened.
async fn resolve_pending(
    cx: &mut Cx,
    run: &mut Run,
    file: &[u8],
    header: &Header,
) -> Result<Option<(Unlocked, Option<SecretKey>)>, ClientError> {
    let (Some(old), Some(pending)) = (
        run.secret_key.as_ref().map(|k| k.clone_secret()),
        run.pending_secret_key.as_ref().map(|k| k.clone_secret()),
    ) else {
        return Err(ClientError::PendingSecretKey);
    };
    for failed in 0..crate::run::ATTEMPTS {
        let pw = cx
            .password(Prompt::MasterPassword {
                purpose: Purpose::PendingSecretKey,
                failed,
            })
            .await?;
        let outcome = match resolve_pending_secret_key(header, &pw, &old, &pending) {
            Ok(o) => o,
            Err(Error::WrongCredentials) => continue,
            Err(e) => return Err(e.into()),
        };
        let sk = match outcome {
            PendingKeyOutcome::Landed => &pending,
            PendingKeyOutcome::NotLanded => &old,
        };
        let now = cx.now();
        let unlocked = unlock(file, &pw, sk).map_err(|e| run.remote_error(e, now))?;
        run.pending_outcome = Some(outcome);
        run.typed.push(pw);
        return Ok(Some((unlocked, None)));
    }
    // Neither key opens it: another device changed the secret key, or the remote is damaged.
    let (pw, sk) = match cx
        .prompt(Prompt::MasterPasswordAndSecretKey {
            purpose: Purpose::PendingSecretKey,
        })
        .await?
    {
        Answer::PasswordAndSecretKey(pw, sk) => (pw, sk),
        Answer::Declined => return Ok(None),
        _ => return Err(ClientError::UnexpectedInput),
    };
    match unlock(file, &pw, &sk) {
        Ok(unlocked) => {
            run.pending_outcome = Some(PendingKeyOutcome::NotLanded);
            run.typed.push(pw);
            Ok(Some((unlocked, Some(sk))))
        }
        Err(Error::WrongCredentials) => Ok(None),
        Err(e) => Err(run.remote_error(e, cx.now())),
    }
}

/// A `404` on the pull: pushes the local file to a server that lost its data.
async fn repush(cx: &mut Cx, run: &mut Run, policy: Policy) -> Result<Plan, ClientError> {
    cx.check_clock()?;
    match on_not_found(Some(&run.next.sync_state()))? {
        NotFoundAction::NoVault => Err(ClientError::NoVault),
        NotFoundAction::Push { generation } => {
            let vk = run.current_key(cx, policy).await?;
            let body = run.local_body(cx).await?.ok_or(ClientError::Locked)?;
            let header = run.started.header()?.with_generation(generation);
            Ok(Plan::Push {
                file: seal(cx, &header, &vk, &body)?,
                generation,
                condition: Precondition::IfNoneMatch,
            })
        }
    }
}

pub(crate) fn seal(
    cx: &mut Cx,
    header: &Header,
    vk: &VaultKey,
    body: &Body,
) -> Result<Vec<u8>, ClientError> {
    Ok(seal_file_with_rng(cx.rng(), header, vk, body)?)
}
