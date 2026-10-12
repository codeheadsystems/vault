//! Thin wrappers over the RustCrypto primitives the spec names.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// HKDF-SHA256 with a 32-byte output.
pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    // A 32-byte output is always within HKDF's limit.
    hk.expand(info, okm.as_mut()).expect("32-byte HKDF output");
    okm
}

/// XChaCha20-Poly1305 seal: ciphertext followed by the 16-byte tag.
pub(crate) fn seal(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let c = XChaCha20Poly1305::new(&(*key).into());
    c.encrypt(&(*nonce).into(), Payload { msg: pt, aad: ad })
        .expect("XChaCha20-Poly1305 encryption of in-memory data cannot fail")
}

/// XChaCha20-Poly1305 open, or `None` when authentication fails.
pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ct: &[u8],
    ad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let c = XChaCha20Poly1305::new(&(*key).into());
    c.decrypt(&(*nonce).into(), Payload { msg: ct, aad: ad })
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case_1_prefix() {
        // RFC 5869 test case 1, first 32 bytes of the 42-byte OKM.
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        assert_eq!(
            hex::encode(hkdf32(&ikm, &salt, &info).as_ref()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn seal_open_round_trip_and_tamper() {
        let ct = seal(&[1; 32], &[2; 24], b"plain", b"ad");
        assert_eq!(ct.len(), 5 + 16);
        assert_eq!(
            open(&[1; 32], &[2; 24], &ct, b"ad").unwrap().as_slice(),
            b"plain"
        );
        assert!(open(&[1; 32], &[2; 24], &ct, b"AD").is_none());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&[1; 32], &[2; 24], &bad, b"ad").is_none());
    }
}
