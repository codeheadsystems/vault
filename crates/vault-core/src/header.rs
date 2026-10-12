//! The 133-byte vault file header and the vault key wrap.

use crate::error::{Error, IntegrityKind as K, Result, integrity};
use crate::kdf::KdfParams;
use crate::prim::{open, seal};
use crate::secret::{Kek, VaultKey};

/// Length of an encoded header.
pub const HEADER_LEN: usize = 133;
/// The header magic.
pub const MAGIC: &[u8; 5] = b"VAULT";
/// The one `format_version` this client implements.
pub const FORMAT_VERSION: u16 = 1;
/// The greatest valid `generation`, `2^48`.
pub const MAX_GENERATION: u64 = 1 << 48;
/// Flag bit 0, `test_kdf`.
const FLAG_TEST_KDF: u16 = 1;
/// Length of `wrap_ad`.
const WRAP_AD_LEN: usize = 53;

/// A decoded header. It holds no secret: `wrapped_vk` is ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Flag bit 0: the KDF parameters are the test set.
    pub test_kdf: bool,
    /// Random at `vault init`; constant for the life of the vault.
    pub vault_id: [u8; 16],
    /// In `[1, 2^48]`; `1` at `vault init`.
    pub generation: u64,
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// Argon2id salt.
    pub kdf_salt: [u8; 16],
    /// Nonce of the vault key wrap; identifies one credential state.
    pub wrap_nonce: [u8; 24],
    /// The wrapped vault key and its tag.
    pub wrapped_vk: [u8; 48],
}

impl Header {
    /// Builds a header and wraps `vk` under `kek`:
    /// `wrapped_vk = AEAD(KEK, wrap_nonce, VK, wrap_ad)`.
    #[allow(clippy::too_many_arguments)]
    pub fn wrap(
        test_kdf: bool,
        vault_id: [u8; 16],
        generation: u64,
        kdf: KdfParams,
        kdf_salt: [u8; 16],
        wrap_nonce: [u8; 24],
        kek: &Kek,
        vk: &VaultKey,
    ) -> Header {
        let mut h = Header {
            test_kdf,
            vault_id,
            generation,
            kdf,
            kdf_salt,
            wrap_nonce,
            wrapped_vk: [0; 48],
        };
        let ct = seal(kek.expose(), &wrap_nonce, vk.expose(), &h.wrap_ad());
        h.wrapped_vk.copy_from_slice(&ct);
        h
    }

    /// Opens `wrapped_vk` with `kek`. A failure means a wrong master password or secret key.
    pub fn unwrap(&self, kek: &Kek) -> Result<VaultKey> {
        let pt = open(
            kek.expose(),
            &self.wrap_nonce,
            &self.wrapped_vk,
            &self.wrap_ad(),
        )
        .ok_or(Error::WrongCredentials)?;
        Ok(VaultKey::from_slice(&pt))
    }

    /// The same header at another generation. The wrap stays valid, because `wrap_ad` leaves out
    /// the generation.
    pub fn with_generation(&self, generation: u64) -> Header {
        Header {
            generation,
            ..self.clone()
        }
    }

    fn flags(&self) -> u16 {
        if self.test_kdf { FLAG_TEST_KDF } else { 0 }
    }

    /// `wrap_ad = magic || format_version || flags || vault_id || m_kib || t || p || kdf_salt`.
    pub fn wrap_ad(&self) -> [u8; WRAP_AD_LEN] {
        let mut ad = [0u8; WRAP_AD_LEN];
        ad[0..5].copy_from_slice(MAGIC);
        ad[5..7].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        ad[7..9].copy_from_slice(&self.flags().to_be_bytes());
        ad[9..25].copy_from_slice(&self.vault_id);
        ad[25..29].copy_from_slice(&self.kdf.m_kib.to_be_bytes());
        ad[29..33].copy_from_slice(&self.kdf.t.to_be_bytes());
        ad[33..37].copy_from_slice(&self.kdf.p.to_be_bytes());
        ad[37..53].copy_from_slice(&self.kdf_salt);
        ad
    }

    /// Encodes the 133 header bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..5].copy_from_slice(MAGIC);
        b[5..7].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        b[7..9].copy_from_slice(&self.flags().to_be_bytes());
        b[9..25].copy_from_slice(&self.vault_id);
        b[25..33].copy_from_slice(&self.generation.to_be_bytes());
        b[33..37].copy_from_slice(&self.kdf.m_kib.to_be_bytes());
        b[37..41].copy_from_slice(&self.kdf.t.to_be_bytes());
        b[41..45].copy_from_slice(&self.kdf.p.to_be_bytes());
        b[45..61].copy_from_slice(&self.kdf_salt);
        b[61..85].copy_from_slice(&self.wrap_nonce);
        b[85..133].copy_from_slice(&self.wrapped_vk);
        b
    }

    /// Decodes exactly 133 bytes strictly and checks the KDF parameters: a wrong magic, an
    /// unknown `format_version`, an unknown flag bit, a `generation` outside `[1, 2^48]`,
    /// parameters outside the bounds, and `test_kdf` in a build that refuses it are integrity
    /// errors.
    pub fn decode(b: &[u8]) -> Result<Header> {
        if b.len() < HEADER_LEN {
            return integrity(K::Truncated);
        }
        if b.len() > HEADER_LEN {
            return integrity(K::TrailingBytes);
        }
        if &b[0..5] != MAGIC {
            return integrity(K::BadMagic);
        }
        if u16::from_be_bytes([b[5], b[6]]) != FORMAT_VERSION {
            return integrity(K::FormatVersion);
        }
        let flags = u16::from_be_bytes([b[7], b[8]]);
        if flags & !FLAG_TEST_KDF != 0 {
            return integrity(K::UnknownFlags);
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().expect("4 bytes"));
        let h = Header {
            test_kdf: flags & FLAG_TEST_KDF != 0,
            vault_id: b[9..25].try_into().expect("16 bytes"),
            generation: u64::from_be_bytes(b[25..33].try_into().expect("8 bytes")),
            kdf: KdfParams {
                m_kib: u32_at(33),
                t: u32_at(37),
                p: u32_at(41),
            },
            kdf_salt: b[45..61].try_into().expect("16 bytes"),
            wrap_nonce: b[61..85].try_into().expect("24 bytes"),
            wrapped_vk: b[85..133].try_into().expect("48 bytes"),
        };
        if !(1..=MAX_GENERATION).contains(&h.generation) {
            return integrity(K::Generation);
        }
        h.kdf.check(h.test_kdf)?;
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::FLOOR;

    fn sample() -> Header {
        Header::wrap(
            false,
            [1; 16],
            7,
            FLOOR,
            [2; 16],
            [3; 24],
            &Kek::from_bytes([4; 32]),
            &VaultKey::from_bytes([5; 32]),
        )
    }

    #[test]
    fn layout() {
        let h = sample();
        let b = h.encode();
        assert_eq!(&b[0..5], b"VAULT");
        assert_eq!(&b[5..9], &[0, 1, 0, 0]);
        assert_eq!(&b[9..25], &[1; 16]);
        assert_eq!(&b[25..33], &7u64.to_be_bytes());
        assert_eq!(&b[33..45], &[0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]);
        assert_eq!(&b[45..61], &[2; 16]);
        assert_eq!(&b[61..85], &[3; 24]);
        assert_eq!(Header::decode(&b).unwrap(), h);
        let mut ad = b[0..25].to_vec();
        ad.extend_from_slice(&b[33..61]);
        assert_eq!(
            h.wrap_ad().as_slice(),
            ad.as_slice(),
            "wrap_ad skips generation"
        );
    }

    #[test]
    fn wrap_round_trip_and_wrong_key() {
        let h = sample();
        assert_eq!(
            h.unwrap(&Kek::from_bytes([4; 32])).unwrap().expose(),
            &[5; 32]
        );
        assert_eq!(
            h.unwrap(&Kek::from_bytes([9; 32])).err(),
            Some(Error::WrongCredentials)
        );
        // The wrap survives a generation change, because wrap_ad leaves it out.
        let g = h.with_generation(8);
        assert!(g.unwrap(&Kek::from_bytes([4; 32])).is_ok());
    }

    #[test]
    fn wrap_ad_binds_every_field_but_generation() {
        let kek = Kek::from_bytes([4; 32]);
        let base = sample();
        let mut variants = Vec::new();
        let mut h = base.clone();
        h.vault_id[0] ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.kdf.m_kib += 1;
        variants.push(h);
        let mut h = base.clone();
        h.kdf.t += 1;
        variants.push(h);
        let mut h = base.clone();
        h.kdf.p += 1;
        variants.push(h);
        let mut h = base.clone();
        h.kdf_salt[0] ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.wrap_nonce[0] ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.test_kdf = true;
        variants.push(h);
        for v in variants {
            assert_eq!(v.unwrap(&kek).err(), Some(Error::WrongCredentials));
        }
    }

    #[test]
    fn strict_decode() {
        let good = sample().encode();
        let with = |i: usize, v: u8| {
            let mut b = good;
            b[i] = v;
            Header::decode(&b).err()
        };
        assert_eq!(with(0, b'X'), Some(Error::Integrity(K::BadMagic)));
        assert_eq!(with(6, 2), Some(Error::Integrity(K::FormatVersion)));
        assert_eq!(with(5, 1), Some(Error::Integrity(K::FormatVersion)));
        assert_eq!(with(8, 2), Some(Error::Integrity(K::UnknownFlags)));
        assert_eq!(with(7, 0x80), Some(Error::Integrity(K::UnknownFlags)));
        assert_eq!(with(34, 0), Some(Error::Integrity(K::KdfParams)));
        assert_eq!(
            Header::decode(&good[..132]).err(),
            Some(Error::Integrity(K::Truncated))
        );
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(
            Header::decode(&long).err(),
            Some(Error::Integrity(K::TrailingBytes))
        );
    }

    #[test]
    fn generation_bounds() {
        let h = sample();
        assert_eq!(
            Header::decode(&h.with_generation(0).encode()).err(),
            Some(Error::Integrity(K::Generation))
        );
        assert!(Header::decode(&h.with_generation(1).encode()).is_ok());
        assert!(Header::decode(&h.with_generation(MAX_GENERATION).encode()).is_ok());
        assert_eq!(
            Header::decode(&h.with_generation(MAX_GENERATION + 1).encode()).err(),
            Some(Error::Integrity(K::Generation))
        );
        assert_eq!(
            Header::decode(&h.with_generation(u64::MAX).encode()).err(),
            Some(Error::Integrity(K::Generation))
        );
    }

    #[test]
    fn test_kdf_header_follows_the_build() {
        let mut h = sample();
        h.test_kdf = true;
        h.kdf = crate::kdf::TEST;
        let r = Header::decode(&h.encode());
        if crate::kdf::TEST_KDF_ALLOWED {
            assert!(r.is_ok());
        } else {
            assert_eq!(r.err(), Some(Error::Integrity(K::TestKdfInRelease)));
        }
    }
}
