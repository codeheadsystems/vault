//! `vault init` and credential changes: a new vault key, a new `kdf_salt`, a new `wrap_nonce`, a
//! new wrap, and the body re-encrypted under the new `K_body`; and the decisions around them.

use crate::body::Body;
use crate::error::{Error, Result};
use crate::file::seal_file;
use crate::header::Header;
use crate::kdf::{KdfParams, pw_key, validate_new_password};
use crate::keys::{derive_kek, kek_from_pw_key};
use crate::rng::{Rng, draw};
use crate::secret::{SecretKey, VaultKey};
use crate::sync::{RemoteCheck, SyncState, WrapStatus, next_generation};

/// The master password for a credential change.
#[derive(Clone, Copy)]
pub enum PasswordChange<'a> {
    /// A new password, checked against the password-setting rules.
    New(&'a str),
    /// The current password, kept (`--rekey`, or `--new-secret-key` without a new password).
    /// The caller has already checked that it opens the current wrap.
    Kept(&'a str),
}

/// A vault created by `vault init`.
pub struct NewVault {
    /// The new secret key, for the emergency kit.
    pub secret_key: SecretKey,
    /// The vault key.
    pub vault_key: VaultKey,
    /// The header at generation 1.
    pub header: Header,
    /// The vault file, with an empty body.
    pub file: Vec<u8>,
    /// The state to store with the file. It has no accepted generation until the first push.
    pub state: SyncState,
}

/// Creates a vault for `vault init`. The password must meet the password-setting rules and the
/// parameters must be within the bounds. The file is sealed by [`seal_file`], which checks the
/// body against every body rule first.
///
/// Draws, in order: the secret key (16 bytes), `vault_id` (16), the vault key (32), `kdf_salt`
/// (16), `wrap_nonce` (24), and `body_nonce` (24).
pub fn create_vault(
    rng: &mut dyn Rng,
    password: &str,
    kdf: KdfParams,
    test_kdf: bool,
) -> Result<NewVault> {
    validate_new_password(password)?;
    kdf.check_for_writing(test_kdf)?;
    let secret_key = SecretKey::generate(rng)?;
    let vault_id: [u8; 16] = draw(rng)?;
    let vault_key = VaultKey::generate(rng)?;
    let kdf_salt: [u8; 16] = draw(rng)?;
    let wrap_nonce: [u8; 24] = draw(rng)?;
    let body_nonce: [u8; 24] = draw(rng)?;
    let kek = derive_kek(password, &secret_key, &vault_id, &kdf, test_kdf, &kdf_salt)?;
    let header = Header::wrap(
        test_kdf, vault_id, 1, kdf, kdf_salt, wrap_nonce, &kek, &vault_key,
    );
    let file = seal_file(&header, &vault_key, &body_nonce, &Body::default())?;
    Ok(NewVault {
        secret_key,
        vault_key,
        state: SyncState {
            vault_id,
            accepted: None,
            wrap_nonce,
            retired_wrap_nonces: Vec::new(),
        },
        header,
        file,
    })
}

/// A credential change built and ready to push.
pub struct CredentialChange {
    /// The new vault key.
    pub vault_key: VaultKey,
    /// The new header, at the synced generation plus one.
    pub header: Header,
    /// The new vault file, to send with `If-Match` set to the synced file's `ETag`.
    pub file: Vec<u8>,
}

/// Builds the new file for `vault passwd` from the synced header and the synced body: a new vault
/// key, a new `kdf_salt`, a new `wrap_nonce`, a new wrap under the KEK from `password` and `sk`,
/// and the body re-encrypted, at the synced generation plus one. `vault_id` stays the same. For
/// `--new-secret-key`, `sk` is the new secret key. A body that breaks a body rule is refused with
/// [`crate::InputKind::Body`] before anything is sealed.
///
/// Draws, in order: the vault key (32 bytes), `kdf_salt` (16), `wrap_nonce` (24), and
/// `body_nonce` (24).
pub fn change_credentials(
    rng: &mut dyn Rng,
    synced: &Header,
    body: &Body,
    password: PasswordChange<'_>,
    sk: &SecretKey,
    kdf: KdfParams,
    test_kdf: bool,
) -> Result<CredentialChange> {
    let password = match password {
        PasswordChange::New(p) => {
            validate_new_password(p)?;
            p
        }
        PasswordChange::Kept(p) => p,
    };
    kdf.check_for_writing(test_kdf)?;
    let generation = next_generation(synced.generation)?;
    let vault_key = VaultKey::generate(rng)?;
    let kdf_salt: [u8; 16] = draw(rng)?;
    let wrap_nonce: [u8; 24] = draw(rng)?;
    let body_nonce: [u8; 24] = draw(rng)?;
    let kek = derive_kek(password, sk, &synced.vault_id, &kdf, test_kdf, &kdf_salt)?;
    let header = Header::wrap(
        test_kdf,
        synced.vault_id,
        generation,
        kdf,
        kdf_salt,
        wrap_nonce,
        &kek,
        &vault_key,
    );
    let file = seal_file(&header, &vault_key, &body_nonce, body)?;
    Ok(CredentialChange {
        vault_key,
        header,
        file,
    })
}

/// What `vault passwd` does after a `412`, once the pulled file passed the sync checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdConflict {
    /// The remote `wrap_nonce` is still the old one: merge, rebuild under the new keys, and retry.
    Retry,
    /// The remote `wrap_nonce` changed: another credential change won. Abort and report it.
    Abort,
}

/// Credential change step 3.
pub fn passwd_conflict(remote: &RemoteCheck) -> PasswdConflict {
    match remote.wrap {
        WrapStatus::Current => PasswdConflict::Retry,
        WrapStatus::Changed => PasswdConflict::Abort,
    }
}

/// Which secret key opened the remote after a `--new-secret-key` push with an unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKeyOutcome {
    /// The pending key opened the remote: the push landed. The pending key replaces the old one.
    Landed,
    /// The old key opened the remote: the push did not land. The newly printed emergency kit is
    /// void, the pending key is discarded, and `--new-secret-key` must run again.
    NotLanded,
}

/// Tries the old and the pending secret key on the remote header, running Argon2id once. Neither
/// opening is [`Error::WrongCredentials`]. The caller calls it once per candidate master password
/// (the password typed now, and the previous one when the push also changed the password), and
/// stops at the first that opens.
pub fn resolve_pending_secret_key(
    remote: &Header,
    password: &str,
    old: &SecretKey,
    pending: &SecretKey,
) -> Result<PendingKeyOutcome> {
    let pk = pw_key(password, &remote.kdf, remote.test_kdf, &remote.kdf_salt)?;
    if remote
        .unwrap(&kek_from_pw_key(&pk, pending, &remote.vault_id))
        .is_ok()
    {
        return Ok(PendingKeyOutcome::Landed);
    }
    if remote
        .unwrap(&kek_from_pw_key(&pk, old, &remote.vault_id))
        .is_ok()
    {
        return Ok(PendingKeyOutcome::NotLanded);
    }
    Err(Error::WrongCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{InputKind, IntegrityKind as K};
    use crate::file::{open_file, unlock};
    use crate::kdf::FLOOR;
    use crate::rng::{BufferRng, CountingRng};
    use crate::sync::{WrapStatus, check_remote};

    const PW: &str = "correct horse battery";

    #[test]
    fn create_vault_draw_order_and_contents() {
        let mut rng = BufferRng::new(&[&[1; 16], &[2; 16], &[3; 32], &[4; 16], &[5; 24], &[6; 24]]);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        rng.assert_consumed();
        assert_eq!(v.secret_key.expose(), &[1; 16]);
        assert_eq!(v.header.vault_id, [2; 16]);
        assert_eq!(v.vault_key.expose(), &[3; 32]);
        assert_eq!(v.header.kdf_salt, [4; 16]);
        assert_eq!(v.header.wrap_nonce, [5; 24]);
        assert_eq!(&v.file[133..157], &[6; 24]);
        assert_eq!(v.header.generation, 1);
        assert_eq!(v.state.wrap_nonce, [5; 24]);
        assert_eq!(v.state.accepted, None);
        let u = unlock(&v.file, PW, &v.secret_key).unwrap();
        assert!(u.body == Body::default());
    }

    #[test]
    fn create_vault_refuses_weak_passwords_and_bad_parameters() {
        let mut rng = CountingRng(1);
        assert_eq!(
            create_vault(&mut rng, "short", FLOOR, false).err(),
            Some(Error::InvalidInput(InputKind::PasswordTooShort))
        );
        let low = KdfParams {
            m_kib: 1024,
            ..FLOOR
        };
        assert_eq!(
            create_vault(&mut rng, PW, low, false).err(),
            Some(Error::InvalidInput(InputKind::KdfParams))
        );
    }

    #[test]
    fn change_replaces_every_key_and_keeps_the_vault_id() {
        let mut rng = CountingRng(7);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let body = Body::default();
        let new_pw = "a different passphrase";
        let c = change_credentials(
            &mut rng,
            &v.header,
            &body,
            PasswordChange::New(new_pw),
            &v.secret_key,
            FLOOR,
            false,
        )
        .unwrap();
        assert_eq!(c.header.vault_id, v.header.vault_id);
        assert_eq!(c.header.generation, 2);
        assert_ne!(c.header.kdf_salt, v.header.kdf_salt);
        assert_ne!(c.header.wrap_nonce, v.header.wrap_nonce);
        assert_ne!(c.vault_key.expose(), v.vault_key.expose());
        assert!(unlock(&c.file, new_pw, &v.secret_key).is_ok());
        assert_eq!(
            unlock(&c.file, PW, &v.secret_key).err(),
            Some(Error::WrongCredentials)
        );
        // The old vault key opens only the old file.
        assert!(open_file(&v.file, &v.vault_key).is_ok());
        assert_eq!(
            open_file(&c.file, &v.vault_key).err(),
            Some(Error::Integrity(K::Aead))
        );
        // The old header, with the old credentials, opens only revisions before the change.
        let old_vk = v.header.unwrap(
            &derive_kek(
                PW,
                &v.secret_key,
                &v.header.vault_id,
                &FLOOR,
                false,
                &v.header.kdf_salt,
            )
            .unwrap(),
        );
        assert!(open_file(&c.file, &old_vk.unwrap()).is_err());
        assert_eq!(
            change_credentials(
                &mut rng,
                &v.header,
                &body,
                PasswordChange::New("short"),
                &v.secret_key,
                FLOOR,
                false,
            )
            .err(),
            Some(Error::InvalidInput(InputKind::PasswordTooShort))
        );
    }

    #[test]
    fn rekey_with_the_old_password_is_refused_through_the_retired_list() {
        let mut rng = CountingRng(11);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let mut state = v.state.clone();
        state.accept(1, &v.file);
        let c = change_credentials(
            &mut rng,
            &v.header,
            &Body::default(),
            PasswordChange::Kept(PW),
            &v.secret_key,
            FLOOR,
            false,
        )
        .unwrap();
        state.rotate_wrap_nonce(c.header.wrap_nonce).unwrap();
        state.accept(2, &c.file);
        // Someone with the old vault key builds a valid-looking file under the old wrap at a
        // higher generation; the old password would still open the old wrap.
        let forged = seal_file(
            &v.header.with_generation(3),
            &v.vault_key,
            &[0; 24],
            &Body::default(),
        )
        .unwrap();
        assert!(unlock(&forged, PW, &v.secret_key).is_ok());
        assert_eq!(
            check_remote(&state, &forged).err(),
            Some(Error::Integrity(K::RetiredWrapNonce))
        );
    }

    #[test]
    fn a_credential_change_refuses_a_body_that_breaks_the_rules() {
        let mut rng = CountingRng(31);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let mut b = Body::from_json(
            br#"{"v":1,"horizon":0,"items":[{"id":"00000000-0000-4000-8000-000000000001","type":"note","name":"n","folder":"","favourite":false,"notes":"","fields":[],"password_history":[],"created":0,"modified":1,"modified_by":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"tombstones":[]}"#,
        )
        .unwrap();
        b.items[0].fields_mut().unwrap().name.clear();
        assert_eq!(
            change_credentials(
                &mut rng,
                &v.header,
                &b,
                PasswordChange::Kept(PW),
                &v.secret_key,
                FLOOR,
                false
            )
            .err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
        assert_eq!(
            crate::file::seal_file(&v.header, &v.vault_key, &[0; 24], &b).err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
    }

    #[test]
    fn conflict_during_passwd() {
        let mut rng = CountingRng(13);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let mut state = v.state.clone();
        state.accept(1, &v.file);
        // Another device wrote a routine edit: same wrap, higher generation.
        let routine = seal_file(
            &v.header.with_generation(2),
            &v.vault_key,
            &[1; 24],
            &Body::default(),
        )
        .unwrap();
        let check = check_remote(&state, &routine).unwrap();
        assert_eq!(passwd_conflict(&check), PasswdConflict::Retry);
        // Another device changed the credentials first.
        let other = change_credentials(
            &mut rng,
            &v.header,
            &Body::default(),
            PasswordChange::Kept(PW),
            &v.secret_key,
            FLOOR,
            false,
        )
        .unwrap();
        let check = check_remote(&state, &other.file).unwrap();
        assert_eq!(passwd_conflict(&check), PasswdConflict::Abort);
    }

    #[test]
    fn lost_new_secret_key_response() {
        let mut rng = CountingRng(17);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let pending = SecretKey::generate(&mut rng).unwrap();
        let landed = change_credentials(
            &mut rng,
            &v.header,
            &Body::default(),
            PasswordChange::Kept(PW),
            &pending,
            FLOOR,
            false,
        )
        .unwrap();
        assert_eq!(
            resolve_pending_secret_key(&landed.header, PW, &v.secret_key, &pending),
            Ok(PendingKeyOutcome::Landed)
        );
        assert_eq!(
            resolve_pending_secret_key(&v.header, PW, &v.secret_key, &pending),
            Ok(PendingKeyOutcome::NotLanded)
        );
        assert_eq!(
            resolve_pending_secret_key(&v.header, "wrong password!", &v.secret_key, &pending),
            Err(Error::WrongCredentials)
        );
        // The full flow on real files: the push landed, so the remote is the new file.
        assert!(unlock(&landed.file, PW, &pending).is_ok());
        assert_eq!(
            unlock(&landed.file, PW, &v.secret_key).err(),
            Some(Error::WrongCredentials)
        );
        // The push did not land, so the remote is still the old file.
        assert!(unlock(&v.file, PW, &v.secret_key).is_ok());
        assert_eq!(
            unlock(&v.file, PW, &pending).err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn conflict_during_passwd_with_a_retired_wrap_nonce() {
        let mut rng = CountingRng(23);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        let mut state = v.state.clone();
        state.accept(1, &v.file);
        let first = change_credentials(
            &mut rng,
            &v.header,
            &Body::default(),
            PasswordChange::Kept(PW),
            &v.secret_key,
            FLOOR,
            false,
        )
        .unwrap();
        state.rotate_wrap_nonce(first.header.wrap_nonce).unwrap();
        state.accept(2, &first.file);
        // A second `passwd` gets a 412; the remote now carries the retired wrap at a higher
        // generation. That is an integrity error, not a retry or an abort.
        let stale = seal_file(
            &v.header.with_generation(3),
            &v.vault_key,
            &[2; 24],
            &Body::default(),
        )
        .unwrap();
        assert_eq!(
            check_remote(&state, &stale).err(),
            Some(Error::Integrity(K::RetiredWrapNonce))
        );
    }

    #[test]
    fn a_stale_device_sees_the_changed_wrap() {
        let mut rng = CountingRng(29);
        let v = create_vault(&mut rng, PW, FLOOR, false).unwrap();
        // Device B synced at generation 1 and holds the old vault key.
        let mut b_state = v.state.clone();
        b_state.accept(1, &v.file);
        let new_pw = "a brand new passphrase";
        let changed = change_credentials(
            &mut rng,
            &v.header,
            &Body::default(),
            PasswordChange::New(new_pw),
            &v.secret_key,
            FLOOR,
            false,
        )
        .unwrap();
        let check = check_remote(&b_state, &changed.file).unwrap();
        assert_eq!(check.wrap, WrapStatus::Changed);
        assert_eq!(
            open_file(&changed.file, &v.vault_key).err(),
            Some(Error::Integrity(K::Aead)),
            "the cached vault key no longer opens the remote"
        );
        assert_eq!(
            unlock(&changed.file, PW, &v.secret_key).err(),
            Some(Error::WrongCredentials)
        );
        let u = unlock(&changed.file, new_pw, &v.secret_key).unwrap();
        b_state.rotate_wrap_nonce(u.header.wrap_nonce).unwrap();
        assert!(b_state.is_retired(&v.header.wrap_nonce));
    }

    #[cfg(feature = "insecure-test-kdf")]
    #[test]
    fn test_parameters_work_in_a_test_build() {
        let mut rng = CountingRng(19);
        let v = create_vault(&mut rng, PW, crate::kdf::TEST, true).unwrap();
        assert!(v.header.test_kdf);
        assert!(unlock(&v.file, PW, &v.secret_key).is_ok());
    }

    #[cfg(not(feature = "insecure-test-kdf"))]
    #[test]
    fn test_parameters_are_refused_without_the_feature() {
        let mut rng = CountingRng(19);
        assert_eq!(
            create_vault(&mut rng, PW, crate::kdf::TEST, true).err(),
            Some(Error::InvalidInput(InputKind::KdfParams))
        );
    }
}
