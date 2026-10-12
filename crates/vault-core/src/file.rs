//! The vault file: `header || body_nonce || body_ct`, sealed and opened.

use crate::body::Body;
use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use crate::header::{HEADER_LEN, Header};
use crate::keys::{body_key, derive_kek};
use crate::prim::{open, seal};
use crate::rng::{Rng, draw};
use crate::secret::{SecretKey, VaultKey};
use zeroize::Zeroizing;

/// The largest vault file, 16 MiB.
pub const MAX_FILE_LEN: usize = 16 * 1024 * 1024;
/// The plaintext is padded to a multiple of this many bytes.
pub const PAD_BLOCK: usize = 4096;
/// Length of `body_nonce`.
pub const BODY_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// A file opened with typed credentials.
pub struct Unlocked {
    /// The file's header.
    pub header: Header,
    /// The vault key the header wraps.
    pub vault_key: VaultKey,
    /// The body.
    pub body: Body,
}

/// Seals `body` under `header` with the vault key and `body_nonce`:
/// `body_ct = AEAD(K_body, body_nonce, u32(len(json)) || json || zero padding, ad = header)`.
///
/// Refuses a header that does not decode, a body that breaks the body rules or has a `v` greater
/// than this client implements, and a result over 16 MiB. The body check re-reads the JSON the
/// body serialises to under every body rule, so no client writes a file that a client cannot
/// open; every path that produces a vault file goes through this function.
pub fn seal_file(
    header: &Header,
    vk: &VaultKey,
    body_nonce: &[u8; BODY_NONCE_LEN],
    body: &Body,
) -> Result<Vec<u8>> {
    let hb = header.encode();
    if Header::decode(&hb).is_err() {
        return input(InputKind::Header);
    }
    let json = body.to_checked_json()?;
    let padded = (4 + json.len()).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    if HEADER_LEN + BODY_NONCE_LEN + padded + TAG_LEN > MAX_FILE_LEN {
        return input(InputKind::TooLarge);
    }
    let mut pt = Zeroizing::new(Vec::with_capacity(padded));
    pt.extend_from_slice(&(json.len() as u32).to_be_bytes());
    pt.extend_from_slice(&json);
    pt.resize(padded, 0);
    let ct = seal(
        body_key(vk, &header.vault_id).expose(),
        body_nonce,
        &pt,
        &hb,
    );
    let mut out = Vec::with_capacity(HEADER_LEN + BODY_NONCE_LEN + ct.len());
    out.extend_from_slice(&hb);
    out.extend_from_slice(body_nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// [`seal_file`] with a fresh `body_nonce`. Draws 24 bytes.
pub fn seal_file_with_rng(
    rng: &mut dyn Rng,
    header: &Header,
    vk: &VaultKey,
    body: &Body,
) -> Result<Vec<u8>> {
    seal_file(header, vk, &draw(rng)?, body)
}

/// Parses a vault file's header and checks its KDF parameters, after checking the file's size.
/// Nothing in the header is authenticated yet.
pub fn read_header(file: &[u8]) -> Result<Header> {
    if file.len() > MAX_FILE_LEN {
        return integrity(K::SizeLimit);
    }
    match file.get(..HEADER_LEN) {
        Some(h) => Header::decode(h),
        None => integrity(K::Truncated),
    }
}

/// Opens a vault file with the vault key: parses the header, derives `K_body`, opens `body_ct`,
/// checks the padding, and parses the body. Every failure is an integrity error.
pub fn open_file(file: &[u8], vk: &VaultKey) -> Result<(Header, Body)> {
    let header = read_header(file)?;
    let rest = &file[HEADER_LEN..];
    if rest.len() < BODY_NONCE_LEN {
        return integrity(K::Truncated);
    }
    let (nonce, ct) = rest.split_at(BODY_NONCE_LEN);
    let pt_len = ct.len().saturating_sub(TAG_LEN);
    if ct.len() < TAG_LEN || pt_len == 0 || pt_len % PAD_BLOCK != 0 {
        return integrity(K::PaddedSize);
    }
    let nonce: &[u8; BODY_NONCE_LEN] = nonce.try_into().expect("24 bytes");
    let pt = open(
        body_key(vk, &header.vault_id).expose(),
        nonce,
        ct,
        &file[..HEADER_LEN],
    )
    .ok_or(Error::Integrity(K::Aead))?;
    let json_len = u32::from_be_bytes(pt[..4].try_into().expect("4 bytes")) as usize;
    let Some(json_end) = json_len.checked_add(4).filter(|&e| e <= pt.len()) else {
        return integrity(K::Length);
    };
    if pt[json_end..].iter().any(|&b| b != 0) {
        return integrity(K::Padding);
    }
    let body = Body::from_json(&pt[4..json_end])?;
    Ok((header, body))
}

/// Opens a vault file with typed credentials: checks the header, derives the KEK, opens the wrap,
/// and opens the body. A wrap that does not open is [`Error::WrongCredentials`]; a body that does
/// not open afterwards is an integrity error.
pub fn unlock(file: &[u8], password: &str, sk: &SecretKey) -> Result<Unlocked> {
    let header = read_header(file)?;
    let kek = derive_kek(
        password,
        sk,
        &header.vault_id,
        &header.kdf,
        header.test_kdf,
        &header.kdf_salt,
    )?;
    let vault_key = header.unwrap(&kek)?;
    let (header, body) = open_file(file, &vault_key)?;
    Ok(Unlocked {
        header,
        vault_key,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::tests::{DEV_A, ID1, login_json};
    use crate::header::MAX_GENERATION;
    use crate::kdf::{FLOOR, KdfParams};
    use crate::prim;
    use crate::secret::Kek;

    fn vk() -> VaultKey {
        VaultKey::from_bytes([5; 32])
    }

    fn header() -> Header {
        Header::wrap(
            false,
            [1; 16],
            3,
            FLOOR,
            [2; 16],
            [3; 24],
            &Kek::from_bytes([4; 32]),
            &vk(),
        )
    }

    fn body() -> Body {
        let j = format!(
            r#"{{"v":1,"horizon":0,"items":[{}],"tombstones":[]}}"#,
            login_json(ID1, 5, DEV_A, "pw")
        );
        Body::from_json(j.as_bytes()).unwrap()
    }

    /// Builds a file from a raw plaintext, authenticated, to reach the post-decryption rules.
    fn raw_file(pt: &[u8]) -> Vec<u8> {
        let h = header();
        let hb = h.encode();
        let ct = prim::seal(body_key(&vk(), &h.vault_id).expose(), &[6; 24], pt, &hb);
        [&hb[..], &[6; 24], &ct].concat()
    }

    fn plaintext(json: &[u8], len_field: u32, total: usize) -> Vec<u8> {
        let mut pt = len_field.to_be_bytes().to_vec();
        pt.extend_from_slice(json);
        pt.resize(total, 0);
        pt
    }

    #[test]
    fn round_trip_and_layout() {
        let f = seal_file(&header(), &vk(), &[6; 24], &body()).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 24 + PAD_BLOCK + 16);
        assert_eq!(&f[..HEADER_LEN], &header().encode());
        assert_eq!(&f[HEADER_LEN..HEADER_LEN + 24], &[6; 24]);
        let (h, b) = open_file(&f, &vk()).unwrap();
        assert_eq!(h, header());
        assert!(b == body());
    }

    #[test]
    fn padding_rounds_up_to_the_next_block() {
        let json_len = body().to_json().len();
        let mut b = body();
        // Grow the notes so that 4 + len(json) is exactly two blocks.
        let grow = 2 * PAD_BLOCK - 4 - json_len;
        b.items[0].fields_mut().unwrap().notes = "x".repeat(grow);
        let f = seal_file(&header(), &vk(), &[6; 24], &b).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 24 + 2 * PAD_BLOCK + 16);
        b.items[0].fields_mut().unwrap().notes.push('x');
        let f = seal_file(&header(), &vk(), &[6; 24], &b).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 24 + 3 * PAD_BLOCK + 16);
    }

    #[test]
    fn extra_zero_padding_is_accepted() {
        let json = Body::default().to_json();
        let f = raw_file(&plaintext(&json, json.len() as u32, 3 * PAD_BLOCK));
        assert!(open_file(&f, &vk()).unwrap().1 == Body::default());
    }

    #[test]
    fn decode_rules_after_authentication() {
        let json = Body::default().to_json();
        let n = json.len() as u32;
        let mut pt = plaintext(&json, n, PAD_BLOCK);
        pt[PAD_BLOCK - 1] = 1;
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::Padding))
        );
        let pt = plaintext(&json, PAD_BLOCK as u32 - 3, PAD_BLOCK);
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::Length))
        );
        let pt = plaintext(&json, u32::MAX, PAD_BLOCK);
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::Length))
        );
        // The JSON length may fill the plaintext exactly.
        let pt = plaintext(&json, PAD_BLOCK as u32 - 4, PAD_BLOCK);
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::Json)),
            "the zero bytes become part of the JSON text"
        );
        let pt = plaintext(&json, n, PAD_BLOCK + 1);
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::PaddedSize))
        );
        assert_eq!(
            open_file(&raw_file(&[]), &vk()).err(),
            Some(Error::Integrity(K::PaddedSize))
        );
        let dup = br#"{"v":1,"v":1,"horizon":0,"items":[],"tombstones":[]}"#;
        let pt = plaintext(dup, dup.len() as u32, PAD_BLOCK);
        assert_eq!(
            open_file(&raw_file(&pt), &vk()).err(),
            Some(Error::Integrity(K::DuplicateKey))
        );
    }

    /// What a flipped byte must cause.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Want {
        /// The header decoder refuses it with this kind.
        Kind(K),
        /// The header decodes but the wrap no longer opens (`WrongCredentials` through `unlock`;
        /// through `open_file`, which skips the wrap, the body fails with `Aead`).
        Wrap,
        /// The header decodes and the wrap opens, but the body fails with `Aead`.
        Body,
    }

    fn within_bounds(p: &KdfParams) -> bool {
        (65_536..=262_144).contains(&p.m_kib) && (3..=10).contains(&p.t) && (1..=4).contains(&p.p)
    }

    /// The expected outcome of XOR-ing `mask` into byte `i` of a file whose header is `h`, by
    /// region, independent of the decoder's code.
    fn want(h: &Header, i: usize, mask: u8) -> Want {
        let mut b = h.encode();
        let flip = |b: &mut [u8; HEADER_LEN]| b[i] ^= mask;
        let kdf_ok = |p: &KdfParams, test_kdf: bool| {
            if test_kdf {
                crate::kdf::TEST_KDF_ALLOWED && *p == crate::kdf::TEST
            } else {
                within_bounds(p)
            }
        };
        match i {
            0..5 => Want::Kind(K::BadMagic),
            5..7 => Want::Kind(K::FormatVersion),
            7 => Want::Kind(K::UnknownFlags),
            8 if mask & !1 != 0 => Want::Kind(K::UnknownFlags),
            8 => {
                let test_kdf = !h.test_kdf;
                if test_kdf && !crate::kdf::TEST_KDF_ALLOWED {
                    Want::Kind(K::TestKdfInRelease)
                } else if kdf_ok(&h.kdf, test_kdf) {
                    Want::Wrap
                } else {
                    Want::Kind(K::KdfParams)
                }
            }
            9..25 => Want::Wrap,
            25..33 => {
                flip(&mut b);
                let g = u64::from_be_bytes(b[25..33].try_into().unwrap());
                if (1..=MAX_GENERATION).contains(&g) {
                    Want::Body
                } else {
                    Want::Kind(K::Generation)
                }
            }
            33..45 => {
                flip(&mut b);
                let at = |j: usize| u32::from_be_bytes(b[j..j + 4].try_into().unwrap());
                let p = KdfParams {
                    m_kib: at(33),
                    t: at(37),
                    p: at(41),
                };
                if kdf_ok(&p, h.test_kdf) {
                    Want::Wrap
                } else {
                    Want::Kind(K::KdfParams)
                }
            }
            45..HEADER_LEN => Want::Wrap,
            _ => Want::Body,
        }
    }

    const MASKS: [u8; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 0xff];

    /// Byte positions outside the header: every nonce byte, and a sample of the ciphertext and
    /// the tag.
    fn body_positions(len: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (HEADER_LEN..HEADER_LEN + 24).collect();
        v.extend([
            157,
            158,
            160,
            1000,
            2048,
            4000,
            len - 17,
            len - 16,
            len - 8,
            len - 1,
        ]);
        v
    }

    #[test]
    fn tamper_table_through_open_file() {
        let h = header();
        let f = seal_file(&h, &vk(), &[6; 24], &body()).unwrap();
        let positions: Vec<usize> = (0..HEADER_LEN).chain(body_positions(f.len())).collect();
        let mut seen = std::collections::BTreeSet::new();
        for i in positions {
            for mask in MASKS {
                let mut t = f.clone();
                t[i] ^= mask;
                let w = want(&h, i, mask);
                let expected = match w {
                    Want::Kind(k) => Error::Integrity(k),
                    Want::Wrap | Want::Body => Error::Integrity(K::Aead),
                };
                assert_eq!(
                    open_file(&t, &vk()).err(),
                    Some(expected),
                    "byte {i} mask {mask:#x}"
                );
                seen.insert(format!("{w:?}"));
            }
        }
        // Every region produced its outcome at least once.
        for w in [
            "Kind(BadMagic)",
            "Kind(FormatVersion)",
            "Kind(UnknownFlags)",
            "Kind(Generation)",
            "Kind(KdfParams)",
            "Wrap",
            "Body",
        ] {
            assert!(seen.contains(w), "{w}");
        }
    }

    /// The same table through `unlock` with the password and the secret key. The test build
    /// with the feature runs every byte with the test parameters; a build without it runs the
    /// first and last byte of each region at the floor, because each case runs Argon2id.
    #[test]
    fn tamper_table_through_unlock() {
        let pw = "correct horse battery";
        let sk = SecretKey::from_bytes([8; 16]);
        let (test_kdf, params) = if crate::kdf::TEST_KDF_ALLOWED {
            (true, crate::kdf::TEST)
        } else {
            (false, FLOOR)
        };
        let kek = derive_kek(pw, &sk, &[1; 16], &params, test_kdf, &[2; 16]).unwrap();
        let h = Header::wrap(test_kdf, [1; 16], 3, params, [2; 16], [3; 24], &kek, &vk());
        let f = seal_file(&h, &vk(), &[6; 24], &body()).unwrap();
        assert!(unlock(&f, pw, &sk).is_ok());
        let (positions, masks): (Vec<usize>, &[u8]) = if crate::kdf::TEST_KDF_ALLOWED {
            (
                (0..HEADER_LEN).chain(body_positions(f.len())).collect(),
                &MASKS,
            )
        } else {
            let edges = [
                0, 4, 5, 6, 7, 8, 9, 24, 25, 32, 33, 44, 45, 60, 61, 84, 85, 132,
            ];
            (edges.into_iter().chain([133, f.len() - 1]).collect(), &[1])
        };
        for i in positions {
            for &mask in masks {
                let mut t = f.clone();
                t[i] ^= mask;
                let expected = match want(&h, i, mask) {
                    Want::Kind(k) => Error::Integrity(k),
                    Want::Wrap => Error::WrongCredentials,
                    Want::Body => Error::Integrity(K::Aead),
                };
                assert_eq!(
                    unlock(&t, pw, &sk).err(),
                    Some(expected),
                    "byte {i} mask {mask:#x}"
                );
            }
        }
    }

    #[test]
    fn header_moved_onto_another_body_is_rejected() {
        let a = seal_file(&header(), &vk(), &[6; 24], &body()).unwrap();
        let b = seal_file(&header().with_generation(4), &vk(), &[7; 24], &body()).unwrap();
        let swapped = [&b[..HEADER_LEN], &a[HEADER_LEN..]].concat();
        assert_eq!(
            open_file(&swapped, &vk()).err(),
            Some(Error::Integrity(K::Aead))
        );
    }

    #[test]
    fn size_limits() {
        let f = seal_file(&header(), &vk(), &[6; 24], &body()).unwrap();
        assert_eq!(
            open_file(&f[..HEADER_LEN + 10], &vk()).err(),
            Some(Error::Integrity(K::Truncated))
        );
        assert_eq!(
            open_file(&f[..100], &vk()).err(),
            Some(Error::Integrity(K::Truncated))
        );
        let mut huge = f.clone();
        huge.resize(MAX_FILE_LEN + 1, 0);
        assert_eq!(
            open_file(&huge, &vk()).err(),
            Some(Error::Integrity(K::SizeLimit))
        );
        let mut b = body();
        b.items[0].fields_mut().unwrap().notes = "x".repeat(MAX_FILE_LEN);
        assert_eq!(
            seal_file(&header(), &vk(), &[6; 24], &b).err(),
            Some(Error::InvalidInput(InputKind::TooLarge))
        );
        // The largest padded plaintext that fits: 16 MiB minus the header, nonce, and tag,
        // rounded down to a block.
        let max_pt = (MAX_FILE_LEN - HEADER_LEN - 24 - 16) / PAD_BLOCK * PAD_BLOCK;
        let base = body().to_json().len();
        b.items[0].fields_mut().unwrap().notes = "x".repeat(max_pt - 4 - base);
        let f = seal_file(&header(), &vk(), &[6; 24], &b).unwrap();
        assert!(f.len() <= MAX_FILE_LEN);
        assert!(open_file(&f, &vk()).is_ok());
    }

    #[test]
    fn seal_refuses_bad_headers_and_newer_bodies() {
        assert_eq!(
            seal_file(&header().with_generation(0), &vk(), &[6; 24], &body()).err(),
            Some(Error::InvalidInput(InputKind::Header))
        );
        let mut b = body();
        b.v = 2;
        assert_eq!(
            seal_file(&header(), &vk(), &[6; 24], &b).err(),
            Some(Error::ReadOnlyBody)
        );
    }

    #[test]
    fn unlock_with_floor_parameters() {
        let sk = SecretKey::from_bytes([8; 16]);
        let kek = derive_kek(
            "correct horse battery",
            &sk,
            &[1; 16],
            &FLOOR,
            false,
            &[2; 16],
        )
        .unwrap();
        let h = Header::wrap(false, [1; 16], 1, FLOOR, [2; 16], [3; 24], &kek, &vk());
        let f = seal_file(&h, &vk(), &[6; 24], &body()).unwrap();
        let u = unlock(&f, "correct horse battery", &sk).unwrap();
        assert_eq!(u.vault_key.expose(), vk().expose());
        assert!(u.body == body());
        assert_eq!(
            unlock(&f, "correct horse batterY", &sk).err(),
            Some(Error::WrongCredentials)
        );
        assert_eq!(
            unlock(&f, "correct horse battery", &SecretKey::from_bytes([9; 16])).err(),
            Some(Error::WrongCredentials)
        );
    }
}
