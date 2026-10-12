//! Argon2id parameters and their bounds, password normalisation, the password-setting rules, and
//! `pw_key`.

use crate::error::{Error, InputKind, IntegrityKind as K, Result, input, integrity};
use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Argon2id parameters as a header stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// The floor: 64 MiB, `t = 3`, `p = 1`. `vault init` and `vault passwd` write it by default.
pub const FLOOR: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};
/// The ceiling: 256 MiB, `t = 10`, `p = 4`.
pub const CEILING: KdfParams = KdfParams {
    m_kib: 262_144,
    t: 10,
    p: 4,
};
/// The test set: 64 KiB, `t = 1`, `p = 1`. Only a build with the `insecure-test-kdf` feature
/// accepts it, and only in a header with `test_kdf` set.
pub const TEST: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

/// Whether this build accepts `test_kdf` headers: a debug build with the `insecure-test-kdf`
/// feature. A build without `debug_assertions` and with the feature fails to compile.
pub const TEST_KDF_ALLOWED: bool = cfg!(feature = "insecure-test-kdf");

/// The fewest Unicode scalar values a new master password has after NFKC.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// The longest master password, in bytes of UTF-8, that a client normalises.
pub const MAX_PASSWORD_BYTES: usize = 4096;

fn check_length(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return input(InputKind::PasswordTooLong);
    }
    Ok(())
}

impl KdfParams {
    /// The parameters `--kdf-memory` selects: the floor's `t` and `p` with 64, 128, or 256 MiB.
    pub fn with_memory_mib(mib: u32) -> Result<KdfParams> {
        match mib {
            64 | 128 | 256 => Ok(KdfParams {
                m_kib: mib * 1024,
                ..FLOOR
            }),
            _ => input(InputKind::KdfParams),
        }
    }

    fn within_bounds(&self) -> bool {
        (FLOOR.m_kib..=CEILING.m_kib).contains(&self.m_kib)
            && (FLOOR.t..=CEILING.t).contains(&self.t)
            && (FLOOR.p..=CEILING.p).contains(&self.p)
    }

    /// Checks parameters read from any source (a header, an imported file, or a backup) against
    /// the floor and the ceiling before Argon2id runs. `test_kdf` is the source's flag.
    pub fn check(&self, test_kdf: bool) -> Result<()> {
        self.check_with(test_kdf, TEST_KDF_ALLOWED)
    }

    /// With `test_kdf` set, a test build accepts only the test set and a release build refuses
    /// the header outright.
    pub(crate) fn check_with(&self, test_kdf: bool, allow_test: bool) -> Result<()> {
        let ok = match (test_kdf, allow_test) {
            (true, false) => return integrity(K::TestKdfInRelease),
            (true, true) => *self == TEST,
            (false, _) => self.within_bounds(),
        };
        if ok { Ok(()) } else { integrity(K::KdfParams) }
    }

    /// The check for parameters a client is about to write: the same bounds, reported as a
    /// caller error.
    pub(crate) fn check_for_writing(&self, test_kdf: bool) -> Result<()> {
        self.check(test_kdf).map_err(|e| match e {
            Error::Integrity(_) => Error::InvalidInput(InputKind::KdfParams),
            e => e,
        })
    }
}

/// The master password normalised to NFKC, as UTF-8. The password is not trimmed.
pub fn nfkc(password: &str) -> Zeroizing<String> {
    // NFKC expands a UTF-8 string by at most a factor of 11 (U+FDFA); reserving that much means
    // the buffer never reallocates and leaves no unzeroized copy behind.
    let mut out = Zeroizing::new(String::with_capacity(password.len() * 11 + 4));
    out.extend(password.nfkc());
    out
}

/// The rules for setting a master password (`vault init`, `vault passwd`): at least 12 Unicode
/// scalar values after NFKC, and no code point unassigned in this client's Unicode tables.
/// Unlocking applies neither rule.
pub fn validate_new_password(password: &str) -> Result<()> {
    check_length(password)?;
    if nfkc(password).chars().count() < MIN_PASSWORD_CHARS {
        return input(InputKind::PasswordTooShort);
    }
    if !password.chars().all(is_assigned) {
        return input(InputKind::PasswordUnassigned);
    }
    Ok(())
}

/// Whether `c` is assigned in this client's Unicode tables: a public assigned code point or a
/// private-use one. Private-use code points are assigned (general category `Co`) and have no
/// decomposition, so NFKC leaves them unchanged in every Unicode version.
fn is_assigned(c: char) -> bool {
    unicode_normalization::char::is_public_assigned(c)
        || matches!(c, '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}')
}

/// `pw_key = Argon2id(NFKC(password), kdf_salt, m_kib, t, p)`, 32 bytes. The parameters are
/// checked first.
pub fn pw_key(
    password: &str,
    params: &KdfParams,
    test_kdf: bool,
    kdf_salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    params.check(test_kdf)?;
    check_length(password)?;
    argon2id(password, params, kdf_salt)
}

fn argon2id(password: &str, params: &KdfParams, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::Integrity(K::KdfParams))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(nfkc(password).as_bytes(), salt, out.as_mut())
        .map_err(|_| Error::Integrity(K::KdfParams))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(m_kib: u32, t: u32, p: u32) -> KdfParams {
        KdfParams { m_kib, t, p }
    }

    #[test]
    fn bounds() {
        for ok in [FLOOR, CEILING, p(131_072, 5, 2)] {
            assert!(ok.check_with(false, false).is_ok());
        }
        for bad in [
            p(65_535, 3, 1),
            p(65_536, 2, 1),
            p(65_536, 3, 0),
            p(262_145, 3, 1),
            p(65_536, 11, 1),
            p(65_536, 3, 5),
            TEST,
        ] {
            assert_eq!(
                bad.check_with(false, true),
                Err(Error::Integrity(K::KdfParams))
            );
        }
    }

    #[test]
    fn test_kdf_flag() {
        assert_eq!(
            TEST.check_with(true, false),
            Err(Error::Integrity(K::TestKdfInRelease))
        );
        assert_eq!(
            FLOOR.check_with(true, false),
            Err(Error::Integrity(K::TestKdfInRelease)),
            "a release build refuses test_kdf outright"
        );
        assert!(TEST.check_with(true, true).is_ok());
        assert_eq!(
            FLOOR.check_with(true, true),
            Err(Error::Integrity(K::KdfParams)),
            "test_kdf accepts only the test set"
        );
        assert_eq!(
            p(32, 1, 1).check_with(true, true),
            Err(Error::Integrity(K::KdfParams))
        );
    }

    #[test]
    fn this_build_refuses_test_kdf_without_the_feature() {
        assert_eq!(TEST_KDF_ALLOWED, cfg!(feature = "insecure-test-kdf"));
        if !TEST_KDF_ALLOWED {
            assert_eq!(
                pw_key("pw", &TEST, true, &[0; 16]).err(),
                Some(Error::Integrity(K::TestKdfInRelease))
            );
        }
    }

    #[test]
    fn out_of_bounds_parameters_are_refused_before_argon2id() {
        // A ceiling breach this large would take 4 TiB if Argon2id ran.
        assert_eq!(
            pw_key("pw", &p(u32::MAX, 3, 1), false, &[0; 16]).err(),
            Some(Error::Integrity(K::KdfParams))
        );
    }

    #[test]
    fn password_length_is_bounded() {
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert_eq!(
            validate_new_password(&long),
            Err(Error::InvalidInput(InputKind::PasswordTooLong))
        );
        assert_eq!(
            pw_key(&long, &FLOOR, false, &[0; 16]).err(),
            Some(Error::InvalidInput(InputKind::PasswordTooLong))
        );
        assert!(validate_new_password(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
        // The bound counts bytes, not characters.
        let wide = "\u{e9}".repeat(MAX_PASSWORD_BYTES / 2 + 1);
        assert_eq!(
            validate_new_password(&wide),
            Err(Error::InvalidInput(InputKind::PasswordTooLong))
        );
    }

    #[test]
    fn memory_choices() {
        assert_eq!(KdfParams::with_memory_mib(64).unwrap(), FLOOR);
        assert_eq!(KdfParams::with_memory_mib(256).unwrap().m_kib, 262_144);
        assert_eq!(KdfParams::with_memory_mib(128).unwrap().t, 3);
        assert!(KdfParams::with_memory_mib(512).is_err());
        assert!(KdfParams::with_memory_mib(32).is_err());
    }

    #[test]
    fn nfkc_composes_and_decomposes() {
        // "é" precomposed and as "e" plus a combining acute accent normalise to the same bytes.
        assert_eq!(nfkc("caf\u{e9}").as_str(), nfkc("cafe\u{301}").as_str());
        // NFKC folds compatibility characters: the "ﬁ" ligature becomes "fi".
        assert_eq!(nfkc("\u{fb01}").as_str(), "fi");
        // No trimming.
        assert_eq!(nfkc(" pw ").as_str(), " pw ");
    }

    #[test]
    fn new_password_rules() {
        assert!(validate_new_password("correct hors").is_ok());
        assert_eq!(
            validate_new_password("correct hor"),
            Err(Error::InvalidInput(InputKind::PasswordTooShort))
        );
        // Eleven characters, one of which NFKC expands to two: twelve after normalisation.
        assert!(validate_new_password("abcdefghij\u{fb01}").is_ok());
        // Twelve characters before NFKC, eleven after: "e" plus U+0301 composes to one.
        assert_eq!(
            validate_new_password("abcdefghije\u{301}"),
            Err(Error::InvalidInput(InputKind::PasswordTooShort))
        );
        assert_eq!(
            validate_new_password("twelve chars\u{e0000}x"),
            Err(Error::InvalidInput(InputKind::PasswordUnassigned))
        );
        // Private-use code points are assigned (category Co); noncharacters are not.
        assert!(validate_new_password("twelve chars\u{e000}").is_ok());
        assert!(validate_new_password("twelve chars\u{10fffd}").is_ok());
        assert_eq!(
            validate_new_password("twelve chars\u{fdd0}"),
            Err(Error::InvalidInput(InputKind::PasswordUnassigned))
        );
    }

    #[test]
    fn floor_derivation_is_deterministic() {
        let a = pw_key("correct horse", &FLOOR, false, &[1; 16]).unwrap();
        let b = pw_key("correct horse", &FLOOR, false, &[1; 16]).unwrap();
        let c = pw_key("correct horse", &FLOOR, false, &[2; 16]).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
        // NFKC runs before Argon2id.
        let d = pw_key("cafe\u{301}", &FLOOR, false, &[1; 16]).unwrap();
        let e = pw_key("caf\u{e9}", &FLOOR, false, &[1; 16]).unwrap();
        assert_eq!(d.as_ref(), e.as_ref());
    }

    #[test]
    fn argon2id_known_answers() {
        // Reference values from argon2-cffi (the reference C implementation), Argon2id v0x13,
        // 32-byte output.
        let test_set = argon2id("password", &TEST, &[0; 16]).unwrap();
        assert_eq!(
            hex::encode(test_set.as_ref()),
            "bf90633c7d73304cf8e7f9e9265de4fd1035057e216f692f2759eab420b79e91"
        );
        let floor = pw_key("cafe\u{301}", &FLOOR, false, &[1; 16]).unwrap();
        assert_eq!(
            hex::encode(floor.as_ref()),
            "48ef419c67f5a442a3a65c0b8be6e7b3c58685badf00b12f96863c1ee3802f6d"
        );
    }
}
