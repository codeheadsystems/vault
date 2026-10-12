//! Password-protected exports: the KDF and its bounds, the encryption and MAC keys, and the
//! `2.<iv>|<ciphertext>|<mac>` encrypted strings (AES-256-CBC with PKCS#7 padding, authenticated
//! by HMAC-SHA256 over the IV and ciphertext).

use crate::error::{Error, Result};
use crate::source::Json;
use aes::Aes256;
use base64ct::{Base64, Encoding};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// PBKDF2 iterations accepted, inclusive.
pub const PBKDF2_ITERATIONS: (u32, u32) = (5_000, 2_000_000);
/// Argon2id memory accepted, in MiB, inclusive. The upper bound is the spec's ceiling.
pub const ARGON2_MEMORY_MIB: (u32, u32) = (16, 256);
/// Argon2id iterations accepted, inclusive. The upper bound is the spec's ceiling.
pub const ARGON2_ITERATIONS: (u32, u32) = (2, 10);
/// Argon2id parallelism accepted, inclusive.
pub const ARGON2_PARALLELISM: (u32, u32) = (1, 16);

/// The key derivation of a password-protected export, with parameters inside the bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// `kdfType` 0: PBKDF2-HMAC-SHA256.
    Pbkdf2 {
        /// `kdfIterations`.
        iterations: u32,
    },
    /// `kdfType` 1: Argon2id with the SHA-256 of the salt as its salt.
    Argon2id {
        /// `kdfMemory`, in MiB.
        memory_mib: u32,
        /// `kdfIterations`.
        iterations: u32,
        /// `kdfParallelism`.
        parallelism: u32,
    },
}

fn bounded(v: Option<&Json>, (lo, hi): (u32, u32)) -> Result<u32> {
    match v {
        Some(Json::Number(_)) => {}
        _ => return Err(Error::NotAnExport),
    }
    v.and_then(Json::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (lo..=hi).contains(n))
        .ok_or(Error::KdfParams)
}

impl Kdf {
    /// Reads `kdfType` and its parameters from the export's top-level object and checks them
    /// against the bounds. Nothing is derived.
    pub(crate) fn from_export(root: &Json) -> Result<Kdf> {
        let kdf_type = match root.get("kdfType") {
            Some(t @ Json::Number(_)) => t.as_u64(),
            _ => return Err(Error::NotAnExport),
        };
        match kdf_type {
            Some(0) => Ok(Kdf::Pbkdf2 {
                iterations: bounded(root.get("kdfIterations"), PBKDF2_ITERATIONS)?,
            }),
            Some(1) => Ok(Kdf::Argon2id {
                memory_mib: bounded(root.get("kdfMemory"), ARGON2_MEMORY_MIB)?,
                iterations: bounded(root.get("kdfIterations"), ARGON2_ITERATIONS)?,
                parallelism: bounded(root.get("kdfParallelism"), ARGON2_PARALLELISM)?,
            }),
            _ => Err(Error::KdfType),
        }
    }
}

/// An encrypted string of type 2.
#[derive(Clone)]
pub(crate) struct EncString {
    iv: [u8; 16],
    ct: Vec<u8>,
    mac: [u8; 32],
}

impl EncString {
    /// Parses `2.<iv>|<ciphertext>|<mac>`. Another encryption type, notably the unauthenticated
    /// type 0, is refused.
    pub(crate) fn parse(s: &str) -> Result<EncString> {
        let rest = s.strip_prefix("2.").ok_or(Error::NotAnExport)?;
        let mut parts = rest.split('|');
        let (Some(iv), Some(ct), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::NotAnExport);
        };
        let decode = |p: &str| Base64::decode_vec(p).map_err(|_| Error::NotAnExport);
        let ct = decode(ct)?;
        if ct.is_empty() || ct.len() % 16 != 0 {
            return Err(Error::NotAnExport);
        }
        Ok(EncString {
            iv: decode(iv)?.try_into().map_err(|_| Error::NotAnExport)?,
            ct,
            mac: decode(mac)?.try_into().map_err(|_| Error::NotAnExport)?,
        })
    }
}

/// The encryption key and the MAC key.
pub(crate) struct Keys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

/// Derives the master key from `password` and `salt` (the salt text's UTF-8 bytes), then the
/// encryption and MAC keys with HKDF-Expand.
pub(crate) fn derive(password: &str, salt: &str, kdf: Kdf) -> Result<Keys> {
    let mut master = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                iterations,
                master.as_mut(),
            );
        }
        Kdf::Argon2id {
            memory_mib,
            iterations,
            parallelism,
        } => {
            let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                .map_err(|_| Error::KdfParams)?;
            let salt = Sha256::digest(salt.as_bytes());
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, master.as_mut())
                .map_err(|_| Error::KdfParams)?;
        }
    }
    let hk = Hkdf::<Sha256>::from_prk(master.as_ref()).map_err(|_| Error::KdfParams)?;
    let mut keys = Keys {
        enc: Zeroizing::new([0u8; 32]),
        mac: Zeroizing::new([0u8; 32]),
    };
    hk.expand(b"enc", keys.enc.as_mut())
        .and_then(|()| hk.expand(b"mac", keys.mac.as_mut()))
        .map_err(|_| Error::KdfParams)?;
    Ok(keys)
}

/// Why an encrypted string did not open.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// The MAC did not verify; nothing was decrypted.
    Mac,
    /// The MAC verified but the padding is wrong.
    Padding,
}

/// Verifies the MAC in constant time, then decrypts.
pub(crate) fn open(
    keys: &Keys,
    e: &EncString,
) -> core::result::Result<Zeroizing<Vec<u8>>, OpenError> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(keys.mac.as_ref()).map_err(|_| OpenError::Mac)?;
    mac.update(&e.iv);
    mac.update(&e.ct);
    mac.verify_slice(&e.mac).map_err(|_| OpenError::Mac)?;
    let mut buf = Zeroizing::new(e.ct.clone());
    let len = cbc::Decryptor::<Aes256>::new_from_slices(keys.enc.as_ref(), &e.iv)
        .map_err(|_| OpenError::Padding)?
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| OpenError::Padding)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse;

    fn root(s: &str) -> Json {
        parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn kdf_bounds() {
        let ok = [
            (
                r#"{"kdfType":0,"kdfIterations":5000}"#,
                Kdf::Pbkdf2 { iterations: 5000 },
            ),
            (
                r#"{"kdfType":0,"kdfIterations":2000000,"kdfMemory":null}"#,
                Kdf::Pbkdf2 {
                    iterations: 2_000_000,
                },
            ),
            (
                r#"{"kdfType":1,"kdfIterations":10,"kdfMemory":256,"kdfParallelism":16}"#,
                Kdf::Argon2id {
                    memory_mib: 256,
                    iterations: 10,
                    parallelism: 16,
                },
            ),
            (
                r#"{"kdfType":1,"kdfIterations":2,"kdfMemory":16,"kdfParallelism":1}"#,
                Kdf::Argon2id {
                    memory_mib: 16,
                    iterations: 2,
                    parallelism: 1,
                },
            ),
        ];
        for (j, k) in ok {
            assert_eq!(Kdf::from_export(&root(j)), Ok(k), "{j}");
        }
        let params = [
            r#"{"kdfType":0,"kdfIterations":4999}"#,
            r#"{"kdfType":0,"kdfIterations":2000001}"#,
            r#"{"kdfType":0,"kdfIterations":600000.0}"#,
            r#"{"kdfType":0,"kdfIterations":-1}"#,
            r#"{"kdfType":0,"kdfIterations":99999999999999999999}"#,
            r#"{"kdfType":1,"kdfIterations":3,"kdfMemory":15,"kdfParallelism":4}"#,
            r#"{"kdfType":1,"kdfIterations":3,"kdfMemory":257,"kdfParallelism":4}"#,
            r#"{"kdfType":1,"kdfIterations":1,"kdfMemory":64,"kdfParallelism":4}"#,
            r#"{"kdfType":1,"kdfIterations":11,"kdfMemory":64,"kdfParallelism":4}"#,
            r#"{"kdfType":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":0}"#,
            r#"{"kdfType":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":17}"#,
        ];
        for j in params {
            assert_eq!(Kdf::from_export(&root(j)), Err(Error::KdfParams), "{j}");
        }
        for j in [
            r#"{"kdfType":2,"kdfIterations":3}"#,
            r#"{"kdfType":-1}"#,
            r#"{"kdfType":0.5}"#,
        ] {
            assert_eq!(Kdf::from_export(&root(j)), Err(Error::KdfType), "{j}");
        }
        for j in [
            r#"{"kdfIterations":5000}"#,
            r#"{"kdfType":"0","kdfIterations":5000}"#,
            r#"{"kdfType":0,"kdfIterations":null}"#,
            r#"{"kdfType":0,"kdfIterations":"5000"}"#,
            r#"{"kdfType":1,"kdfIterations":3,"kdfMemory":null,"kdfParallelism":4}"#,
        ] {
            assert_eq!(Kdf::from_export(&root(j)), Err(Error::NotAnExport), "{j}");
        }
    }

    #[test]
    fn enc_string_shapes() {
        let b = |n: usize| Base64::encode_string(&vec![7u8; n]);
        let good = format!("2.{}|{}|{}", b(16), b(32), b(32));
        assert!(EncString::parse(&good).is_ok());
        for bad in [
            format!("0.{}|{}", b(16), b(32)),
            format!("2.{}|{}", b(16), b(32)),
            format!("2.{}|{}|{}|{}", b(16), b(32), b(32), b(1)),
            format!("2.{}|{}|{}", b(15), b(32), b(32)),
            format!("2.{}|{}|{}", b(16), b(31), b(32)),
            format!("2.{}|{}|{}", b(16), b(0), b(32)),
            format!("2.{}|{}|{}", b(16), b(32), b(31)),
            format!("2.{}|!!!!|{}", b(16), b(32)),
        ] {
            assert!(EncString::parse(&bad).is_err(), "{bad}");
        }
    }
}
