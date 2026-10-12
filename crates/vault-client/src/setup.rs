//! Device setup: `vault init` creates a vault, `vault setup` adds a device to one, and the token
//! repair checks a new server token on a device that already has the vault.

use crate::error::{ClientError, InitRefusal};
use crate::machine::{
    Answer, Cx, Finished, Machine, Precondition, Prompt, Request, Save, SavedKey, SecretKeyChange,
};
use crate::passwd::ask_new_password;
use crate::run::ATTEMPTS;
use crate::state::{ClientState, SecretKeyStore, StopReason};
use vault_core::credentials::create_vault;
use vault_core::file::{read_header, unlock};
use vault_core::kdf::KdfParams;
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::sync::{NotFoundAction, check_remote_for_setup, on_not_found};
use vault_core::{Error, IntegrityKind};

/// The result of `vault init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    /// The new vault's ID.
    pub vault_id: [u8; 16],
}

/// Creates a vault: checks that the server holds none, asks for a new master password, creates
/// the vault, hands out a [`Save`] with the state and the new secret key (the caller prints the
/// emergency kit then), and pushes generation 1 with `If-None-Match: *`.
///
/// When the server refuses that push (`412`, `401`, or another status), the result is
/// [`ClientError::UndoSave`]: the saved vault is not on the server, and the caller deletes the
/// saved state and secret key. When the push fails in transport ([`ClientError::Unreachable`]),
/// the saved state stands, and the next sync pushes it after a `404` or adopts it.
pub fn init(
    kdf: KdfParams,
    test_kdf: bool,
    secret_key_store: SecretKeyStore,
    rng: impl Rng + Send + 'static,
) -> Machine<InitReport> {
    Machine::new(rng, move |mut cx| async move {
        let mut vault_key = None;
        let result = run_init(&mut cx, kdf, test_kdf, secret_key_store, &mut vault_key).await;
        let state = match &result {
            Ok((_, state)) => Some(state.clone()),
            Err(_) => None,
        };
        Finished {
            result: result.map(|(report, _)| report),
            state,
            started_vault_key: vault_key.as_ref().map(VaultKey::clone_secret),
            vault_key,
            secret_key: None,
        }
    })
}

async fn run_init(
    cx: &mut Cx,
    kdf: KdfParams,
    test_kdf: bool,
    store: SecretKeyStore,
    vault_key: &mut Option<VaultKey>,
) -> Result<(InitReport, ClientState), ClientError> {
    match cx.request(Request::GetVault).await?.status {
        404 => {}
        200 => return Err(ClientError::VaultExists),
        401 => return Err(ClientError::Token),
        s => return Err(ClientError::Status(s)),
    }
    let password = ask_new_password(cx).await?;
    let vault = create_vault(cx.rng(), &password, kdf, test_kdf)?;
    let vault_id = vault.state.vault_id;
    let mut state = ClientState::new(vault.state, vault.file, store);
    cx.save(Save {
        state: state.clone(),
        secret_key: SavedKey::Current(vault.secret_key),
        vault_key: vault.vault_key.clone_secret(),
    })
    .await?;
    *vault_key = Some(vault.vault_key);
    let resp = cx
        .request(Request::PutVault {
            condition: Precondition::IfNoneMatch,
            file: state.file.clone(),
        })
        .await?;
    match resp.status {
        200 => {}
        412 => return Err(ClientError::UndoSave(InitRefusal::VaultExists)),
        401 => return Err(ClientError::UndoSave(InitRefusal::Token)),
        s => return Err(ClientError::UndoSave(InitRefusal::Status(s))),
    }
    let file = std::mem::take(&mut state.file);
    state.accept(1, file);
    state.last_sync = Some(cx.now());
    Ok((InitReport { vault_id }, state))
}

/// Adds this device to an existing vault: pulls the vault, asks for the secret key and the kit's
/// vault ID, and unlocks with the master password, allowing three attempts. The result carries
/// the state to store; [`Finished::secret_key`] holds the secret key to store.
pub fn setup(secret_key_store: SecretKeyStore, rng: impl Rng + Send + 'static) -> Machine<()> {
    Machine::new(rng, move |mut cx| async move {
        match run_setup(&mut cx, secret_key_store).await {
            Ok((state, vault_key, sk)) => Finished {
                result: Ok(()),
                state: Some(state),
                vault_key: Some(vault_key),
                started_vault_key: None,
                secret_key: Some(SecretKeyChange::Replace(sk)),
            },
            Err(e) => Finished::error(e),
        }
    })
}

async fn run_setup(
    cx: &mut Cx,
    store: SecretKeyStore,
) -> Result<(ClientState, VaultKey, SecretKey), ClientError> {
    let resp = cx.request(Request::GetVault).await?;
    let file = match resp.status {
        200 => resp.body,
        404 => {
            return match on_not_found(None)? {
                NotFoundAction::NoVault => Err(ClientError::NoVault),
                NotFoundAction::Push { .. } => Err(ClientError::UnexpectedInput),
            };
        }
        401 => return Err(ClientError::Token),
        s => return Err(ClientError::Status(s)),
    };
    let sk = match cx.prompt(Prompt::SecretKey).await? {
        Answer::SecretKey(sk) => sk,
        Answer::Declined => return Err(ClientError::Cancelled),
        _ => return Err(ClientError::UnexpectedInput),
    };
    let kit = match cx.prompt(Prompt::KitVaultId).await? {
        Answer::VaultId(id) => id,
        Answer::Declined => None,
        _ => return Err(ClientError::UnexpectedInput),
    };
    let header = check_remote_for_setup(&file, kit.as_ref())?;
    for failed in 0..ATTEMPTS {
        let pw = cx
            .password(Prompt::MasterPassword {
                purpose: crate::machine::Purpose::Unlock,
                failed,
            })
            .await?;
        match unlock(&file, &pw, &sk) {
            Ok(u) => {
                let mut state = ClientState::new(
                    vault_core::sync::SyncState {
                        vault_id: header.vault_id,
                        accepted: None,
                        wrap_nonce: header.wrap_nonce,
                        retired_wrap_nonces: Vec::new(),
                    },
                    Vec::new(),
                    store,
                );
                state.accept(header.generation, file);
                state.last_sync = Some(cx.now());
                return Ok((state, u.vault_key, sk));
            }
            Err(Error::WrongCredentials) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::WrongCredentials.into())
}

/// Checks a new server token on a device that already has the vault: the server's vault must
/// have the same `vault_id`. On success the caller replaces its stored URL, token, and
/// fingerprint, and a `stopped` for the token is cleared.
pub fn repair_token(state: ClientState, rng: impl Rng + Send + 'static) -> Machine<()> {
    Machine::new(rng, move |mut cx| async move {
        let result = async {
            let resp = cx.request(Request::GetVault).await?;
            match resp.status {
                200 => {
                    if read_header(&resp.body)?.vault_id != state.vault_id {
                        return Err(Error::Integrity(IntegrityKind::VaultIdMismatch).into());
                    }
                    Ok(())
                }
                // A server that lost its data; the next sync pushes the local file (spec, Sync).
                404 => Ok(()),
                401 => Err(ClientError::Token),
                s => Err(ClientError::Status(s)),
            }
        }
        .await;
        let mut next = state.clone();
        if result.is_ok()
            && next
                .stopped
                .as_ref()
                .is_some_and(|s| s.reason == StopReason::Token)
        {
            next.stopped = None;
        }
        Finished {
            result,
            state: (next != state).then_some(next),
            vault_key: None,
            started_vault_key: None,
            secret_key: None,
        }
    })
}
