//! `vault passwd` in its three forms: a new master password, `--rekey`, and `--new-secret-key`.

use crate::error::ClientError;
use crate::machine::{Cx, Machine, Precondition, Prompt, Request, Save, SavedKey};
use crate::run::{
    ATTEMPTS, Changed, Keys, OnChanged, Policy, Run, item_names, retirement_revision,
};
use crate::state::ClientState;
use crate::sync::run_sync;
use vault_core::credentials::{
    PasswdConflict, PasswordChange, PendingKeyOutcome, change_credentials, passwd_conflict,
};
use vault_core::file::open_file;
use vault_core::kdf::{KdfParams, validate_new_password};
use vault_core::merge::merge;
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, SecretString};
use vault_core::sync::{PutCondition, Retry, RetryCounter, check_remote, etag};

/// What a credential change replaces besides the vault key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdChange {
    /// A new master password (`vault passwd`).
    NewPassword,
    /// Only the vault key (`vault passwd --rekey`).
    Rekey,
    /// A new secret key, and a new master password when `new_password` is set
    /// (`vault passwd --new-secret-key`).
    NewSecretKey {
        /// Whether the master password changes too.
        new_password: bool,
    },
}

/// The options of a credential change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswdOptions {
    /// What changes.
    pub change: PasswdChange,
    /// The KDF parameters of the new wrap.
    pub kdf: KdfParams,
    /// Whether `kdf` is the test set; only test builds accept it.
    pub test_kdf: bool,
}

/// The result of a credential change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdReport {
    /// The generation of the new file.
    pub generation: u64,
    /// The revision recorded with the retired `wrap_nonce`, or `None` when the revision list
    /// could not be read.
    pub retired_revision: Option<u64>,
    /// Names of local items the sync or a merge after a `412` dropped because they predate the
    /// purge horizon.
    pub expired: Vec<String>,
}

/// Changes the credentials. It runs only online: it syncs first, builds the new file at the
/// synced generation plus one, and pushes it with `If-Match`.
///
/// With `keys.vault_key` the procedure asks only for the new master password; without it, it asks
/// for the current one first. `--rekey`, and `--new-secret-key` without a new password, always
/// ask for the current master password, which the new wrap keeps. `--new-secret-key` hands out a
/// [`Save`] with the pending key before it pushes. On success the caller ends any agent.
pub fn passwd(
    state: ClientState,
    keys: Keys,
    options: PasswdOptions,
    rng: impl Rng + Send + 'static,
) -> Machine<PasswdReport> {
    Machine::new(rng, move |mut cx| async move {
        let mut run = Run::new(state, keys);
        let result = run_passwd(&mut cx, &mut run, options).await;
        let ok = result.is_ok();
        run.finish(result, ok)
    })
}

async fn run_passwd(
    cx: &mut Cx,
    run: &mut Run,
    options: PasswdOptions,
) -> Result<PasswdReport, ClientError> {
    if run.started.pending_secret_key {
        return Err(ClientError::PendingSecretKey);
    }
    if let Some(s) = &run.started.stopped {
        return Err(ClientError::Stopped(s.reason));
    }
    let new_password = match options.change {
        PasswdChange::NewPassword => true,
        PasswdChange::Rekey => false,
        PasswdChange::NewSecretKey { new_password } => new_password,
    };
    if run.vault_key.is_none() || !new_password {
        run.unlock_local(cx).await?;
    }
    let password: SecretString = if new_password {
        ask_new_password(cx).await?
    } else {
        run.typed.last().expect("typed by unlock_local").clone()
    };
    let password = if new_password {
        PasswordChange::New(&password)
    } else {
        PasswordChange::Kept(&password)
    };

    // 1. Sync.
    // A credential change on another device found here stops the command (spec, Credential
    // change, step 1); `vault sync` takes it over first.
    let policy = Policy {
        prompts: true,
        on_changed: OnChanged::Abort,
    };
    run_sync(cx, run, policy, None).await?;
    run.fail = run.next.clone();
    let vk = run.vault_key.as_ref().expect("synced").clone_secret();
    let mut synced_etag = etag(&run.next.file);
    let (mut synced_header, mut synced_body) = open_file(&run.next.file, &vk)?;

    let sk = match options.change {
        PasswdChange::NewSecretKey { .. } => {
            let new = SecretKey::generate(cx.rng())?;
            run.next.pending_secret_key = true;
            cx.save(Save {
                state: run.next.clone(),
                secret_key: SavedKey::Pending(new.clone_secret()),
                vault_key: vk.clone_secret(),
            })
            .await?;
            run.started = run.next.clone();
            run.fail = run.next.clone();
            new
        }
        _ => run
            .secret_key
            .as_ref()
            .ok_or(ClientError::Locked)?
            .clone_secret(),
    };
    let pending = run.next.pending_secret_key;
    // The push did not land: a pending key is void.
    let not_landed = |run: &mut Run| {
        if pending {
            run.fail.pending_secret_key = false;
            run.keys_fail.pending = Some(PendingKeyOutcome::NotLanded);
        }
    };

    // 2. Build and push; 3. on `412`, pull, check, and merge or abort.
    let mut retries = RetryCounter::new();
    let change = loop {
        let change = change_credentials(
            cx.rng(),
            &synced_header,
            &synced_body,
            password,
            &sk,
            options.kdf,
            options.test_kdf,
        )?;
        let resp = match cx
            .request(Request::PutVault {
                condition: Precondition::IfMatch(synced_etag.clone()),
                file: change.file.clone(),
            })
            .await
        {
            Ok(r) => r,
            // The saved state keeps a pending secret key for the next sync to settle. Without
            // one, a push that landed reaches this device as a credential change on another
            // device, which the new password opens.
            Err(ClientError::Unreachable) => return Err(ClientError::OutcomeUnknown),
            Err(e) => return Err(e),
        };
        match resp.status {
            200 => break change,
            412 => {}
            401 => {
                not_landed(run);
                return Err(run.token(cx.now()));
            }
            s => return Err(ClientError::Status(s)),
        }
        not_landed(run);
        if retries.precondition_failed(PutCondition::IfMatch) == Retry::GiveUp {
            return Err(ClientError::Conflicts);
        }
        let resp = cx.request(Request::GetVault).await?;
        let now = cx.now();
        match resp.status {
            200 => {}
            401 => return Err(run.token(now)),
            404 => return Err(ClientError::NoVault),
            s => return Err(ClientError::Status(s)),
        }
        let check = check_remote(&run.next.sync_state(), &resp.body)
            .map_err(|e| run.remote_error(e, now))?;
        cx.check_clock()?;
        if passwd_conflict(&check) == PasswdConflict::Abort {
            return Err(ClientError::CredentialChangeWon);
        }
        let (header, remote) = open_file(&resp.body, &vk).map_err(|e| run.remote_error(e, now))?;
        let m = merge(&synced_body, &remote, now);
        run.expired.extend(item_names(&m.expired));
        synced_body = m.body;
        synced_header = header;
        synced_etag = check.etag;
        // Back to an unknown outcome until the next response.
        if pending {
            run.fail.pending_secret_key = true;
            run.keys_fail.pending = None;
        }
    };

    // 4. Retire the old wrap at the revision that carries the new one.
    let generation = change.header.generation;
    let new_etag = etag(&change.file);
    let revision = retirement_revision(cx, &new_etag, &change.header.wrap_nonce).await;
    run.next.accept(generation, change.file);
    run.next
        .rotate_wrap_nonce(change.header.wrap_nonce, revision)?;
    run.next.pending_secret_key = false;
    if pending {
        run.keys_ok.pending = Some(PendingKeyOutcome::Landed);
    }
    run.changed = Some(Changed {
        nonce: change.header.wrap_nonce,
        vault_key: change.vault_key,
        new_secret_key: None,
        etag: new_etag,
        revision,
    });
    Ok(PasswdReport {
        generation,
        retired_revision: revision,
        expired: run.expired.clone(),
    })
}

/// Asks for a new master password until one meets the password-setting rules.
pub(crate) async fn ask_new_password(cx: &mut Cx) -> Result<SecretString, ClientError> {
    let mut rejected = None;
    for _ in 0..ATTEMPTS {
        let pw = cx.password(Prompt::NewMasterPassword { rejected }).await?;
        match validate_new_password(&pw) {
            Ok(()) => return Ok(pw),
            Err(e) => rejected = Some(e),
        }
    }
    Err(rejected.expect("three attempts").into())
}
