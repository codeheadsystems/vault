//! The key-encryption key and the body key.

use crate::error::Result;
use crate::kdf::{KdfParams, pw_key};
use crate::prim::hkdf32;
use crate::secret::{BodyKey, Kek, SecretKey, VaultKey};
use zeroize::Zeroizing;

/// `KEK = HKDF(ikm = pw_key || secret_key, salt = vault_id, info = "vault/v1/kek")`.
pub fn kek_from_pw_key(pw_key: &[u8; 32], sk: &SecretKey, vault_id: &[u8; 16]) -> Kek {
    let mut ikm = Zeroizing::new([0u8; 48]);
    ikm[..32].copy_from_slice(pw_key);
    ikm[32..].copy_from_slice(sk.expose());
    Kek::from_zeroizing(hkdf32(ikm.as_ref(), vault_id, b"vault/v1/kek"))
}

/// Derives the KEK from the master password and the secret key. The parameters are checked
/// before Argon2id runs.
pub fn derive_kek(
    password: &str,
    sk: &SecretKey,
    vault_id: &[u8; 16],
    params: &KdfParams,
    test_kdf: bool,
    kdf_salt: &[u8; 16],
) -> Result<Kek> {
    let pk = pw_key(password, params, test_kdf, kdf_salt)?;
    Ok(kek_from_pw_key(&pk, sk, vault_id))
}

/// `K_body = HKDF(ikm = VK, salt = vault_id, info = "vault/v1/body")`.
pub fn body_key(vk: &VaultKey, vault_id: &[u8; 16]) -> BodyKey {
    BodyKey::from_zeroizing(hkdf32(vk.expose(), vault_id, b"vault/v1/body"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::Sha256;

    fn reference_hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(salt), ikm)
            .expand(info, &mut out)
            .unwrap();
        out
    }

    #[test]
    fn kek_inputs_and_label() {
        let pk = [3u8; 32];
        let sk = SecretKey::from_bytes([4; 16]);
        let vid = [5u8; 16];
        let mut ikm = pk.to_vec();
        ikm.extend_from_slice(&[4; 16]);
        assert_eq!(
            kek_from_pw_key(&pk, &sk, &vid).expose(),
            &reference_hkdf(&ikm, &vid, b"vault/v1/kek")
        );
        let other = kek_from_pw_key(&pk, &SecretKey::from_bytes([6; 16]), &vid);
        assert_ne!(other.expose(), kek_from_pw_key(&pk, &sk, &vid).expose());
    }

    #[test]
    fn body_key_inputs_and_label() {
        let vk = VaultKey::from_bytes([7; 32]);
        let vid = [8u8; 16];
        assert_eq!(
            body_key(&vk, &vid).expose(),
            &reference_hkdf(&[7; 32], &vid, b"vault/v1/body")
        );
        assert_ne!(
            body_key(&vk, &[9; 16]).expose(),
            body_key(&vk, &vid).expose()
        );
    }
}
