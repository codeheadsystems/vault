//! `vault restore`: fetches and opens a revision, and restores the whole vault or one item from it
//! as a local edit.

use crate::error::ClientError;
use crate::machine::{Answer, Cx, Finished, Machine, Prompt, Purpose, Request};
use crate::run::ATTEMPTS;
use crate::run::Keys;
use crate::state::{ClientState, StopReason, Stopped};
use vault_core::body::Body;
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::edit::{delete_item, restore_all, restore_item};
use vault_core::file::{open_file, read_header, seal_file_with_rng, unlock};
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::{Error, InputKind, IntegrityKind};

/// An opened revision.
pub struct Revision {
    /// The revision ID.
    pub id: u64,
    /// The generation its header claims.
    pub generation: u64,
    /// Its body.
    pub body: Body,
    /// The `Date` of the server's response in ms, for the clock check of the restore.
    pub server_date: Option<u64>,
}

/// Fetches revision `id`, checks its `vault_id`, and opens it: with the cached vault key when it
/// is under the current wrap, and otherwise with that revision's credentials, which the
/// procedure asks for. A revision under a retired `wrap_nonce` with an ID above the one at which
/// that nonce was retired is refused before anything is asked. A `401` records `stopped` for the
/// token.
pub fn fetch_revision(
    state: ClientState,
    keys: Keys,
    id: u64,
    rng: impl Rng + Send + 'static,
) -> Machine<Revision> {
    Machine::new(rng, move |mut cx| async move {
        let result = async {
            let resp = cx.request(Request::GetRevision(id)).await?;
            match resp.status {
                200 => {}
                404 => return Err(ClientError::RevisionNotFound),
                401 => return Err(ClientError::Token),
                s => return Err(ClientError::Status(s)),
            }
            let file = resp.body;
            let header = read_header(&file)?;
            if header.vault_id != state.vault_id {
                return Err(Error::Integrity(IntegrityKind::VaultIdMismatch).into());
            }
            // Above the record, or with no record, the revision is refused (spec, Credential
            // change on another device).
            if let Some(r) = state.retirement(&header.wrap_nonce)
                && r.revision.is_none_or(|retired_at| id > retired_at)
            {
                return Err(ClientError::RevisionRefused);
            }
            let body = match &keys.vault_key {
                Some(vk) if header.wrap_nonce == state.wrap_nonce => open_file(&file, vk)?.1,
                _ => open_with_credentials(&mut cx, &file, keys.secret_key.as_ref()).await?,
            };
            Ok(Revision {
                id,
                generation: header.generation,
                body,
                server_date: resp.date,
            })
        }
        .await;
        let stopped = matches!(result, Err(ClientError::Token)).then(|| {
            let mut next = state.clone();
            next.stopped = Some(Stopped {
                reason: StopReason::Token,
                code: ClientError::Token.code().to_owned(),
                at: cx.now(),
            });
            next
        });
        Finished {
            result,
            state: stopped,
            vault_key: None,
            started_vault_key: None,
            secret_key: None,
        }
    })
}

/// Opens a revision with typed credentials: the master password with the stored secret key,
/// asked for up to three times, then the master password and the secret key of that revision.
async fn open_with_credentials(
    cx: &mut Cx,
    file: &[u8],
    sk: Option<&SecretKey>,
) -> Result<Body, ClientError> {
    if let Some(sk) = sk {
        for failed in 0..ATTEMPTS {
            let pw = cx
                .password(Prompt::MasterPassword {
                    purpose: Purpose::Revision,
                    failed,
                })
                .await?;
            match unlock(file, &pw, sk) {
                Ok(u) => return Ok(u.body),
                Err(Error::WrongCredentials) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    match cx
        .prompt(Prompt::MasterPasswordAndSecretKey {
            purpose: Purpose::Revision,
        })
        .await?
    {
        Answer::PasswordAndSecretKey(pw, sk) => Ok(unlock(file, &pw, &sk)?.body),
        Answer::Declined => Err(ClientError::Cancelled),
        _ => Err(ClientError::UnexpectedInput),
    }
}

/// What a restore changes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreSummary {
    /// Items restored that were absent or deleted locally.
    pub added: usize,
    /// Items restored over a local item.
    pub changed: usize,
    /// Local items the revision does not hold, deleted by a restore of the whole vault.
    pub removed: usize,
}

/// What to restore from a revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreScope<'a> {
    /// Every item of the revision.
    All,
    /// The item with this `id`, selected by the caller in the revision.
    Item(&'a str),
}

/// Counts what restoring `scope` from `revision` would change, without changing anything, so
/// the caller can ask for confirmation.
pub fn restore_preview(
    local: &Body,
    revision: &Revision,
    scope: RestoreScope<'_>,
) -> Result<RestoreSummary, ClientError> {
    let mut s = RestoreSummary::default();
    for item in restored_items(revision, scope)? {
        if local.item(&item.id).is_some() {
            s.changed += 1;
        } else {
            s.added += 1;
        }
    }
    s.removed = removed_ids(local, revision, scope).len();
    Ok(s)
}

/// Restores `scope` from `revision` into the local file as a local edit stamped `now` and
/// `device_id`, and returns the state to commit. A restore of the whole vault also deletes the
/// local items the revision does not hold. The caller then syncs. `vault_key` opens the local
/// file.
pub fn restore(
    state: &ClientState,
    vault_key: &VaultKey,
    revision: &Revision,
    scope: RestoreScope<'_>,
    device_id: &[u8; 16],
    now: u64,
    rng: &mut dyn Rng,
) -> Result<(ClientState, RestoreSummary), ClientError> {
    check_clock(now, BUILD_TIME_MS, revision.server_date)?;
    let (header, mut body) = open_file(&state.file, vault_key)?;
    let summary = restore_preview(&body, revision, scope)?;
    match scope {
        RestoreScope::All => {
            restore_all(&mut body, &revision.body, now, device_id);
            for id in removed_ids(&body, revision, scope) {
                delete_item(&mut body, &id, now, device_id)?;
            }
        }
        RestoreScope::Item(_) => {
            for item in restored_items(revision, scope)? {
                restore_item(&mut body, item, now, device_id);
            }
        }
    }
    let mut next = state.clone();
    next.file = seal_file_with_rng(rng, &header, vault_key, &body)?;
    Ok((next, summary))
}

/// The local items a restore of the whole vault deletes: those the revision does not hold.
// A restore of the whole vault makes the local body match the revision (spec, Credential change on
// another device); one item at a time removes nothing.
fn removed_ids(local: &Body, revision: &Revision, scope: RestoreScope<'_>) -> Vec<String> {
    match scope {
        RestoreScope::All => local
            .items
            .iter()
            .filter(|i| revision.body.item(&i.id).is_none())
            .map(|i| i.id.clone())
            .collect(),
        RestoreScope::Item(_) => Vec::new(),
    }
}

fn restored_items<'a>(
    revision: &'a Revision,
    scope: RestoreScope<'_>,
) -> Result<Vec<&'a vault_core::body::Item>, ClientError> {
    match scope {
        RestoreScope::All => Ok(revision.body.items.iter().collect()),
        RestoreScope::Item(id) => match revision.body.item(id) {
            Some(i) => Ok(vec![i]),
            None => Err(Error::InvalidInput(InputKind::NotFound).into()),
        },
    }
}
