//! Runs against the library built without `cfg(test)`, as a client is. Unless
//! `VAULT_EXPECT_TEST_KDF=1` is set, the build must refuse `test_kdf` headers before any key
//! derivation; a failure here means the `insecure-test-kdf` feature leaked into the build, for
//! example through a dev-dependency and feature unification. The CI run that enables the feature
//! on purpose sets the variable.

use vault_core::header::Header;
use vault_core::kdf::{FLOOR, TEST, TEST_KDF_ALLOWED};
use vault_core::secret::{Kek, SecretKey, VaultKey};
use vault_core::{Error, InputKind, IntegrityKind};

const REFUSED: Option<Error> = Some(Error::Integrity(IntegrityKind::TestKdfInRelease));
const OUT_OF_BOUNDS: Option<Error> = Some(Error::Integrity(IntegrityKind::KdfParams));

fn expect_test_kdf() -> bool {
    std::env::var("VAULT_EXPECT_TEST_KDF").as_deref() == Ok("1")
}

#[test]
fn test_kdf_is_allowed_only_when_expected() {
    assert_eq!(
        TEST_KDF_ALLOWED,
        expect_test_kdf(),
        "TEST_KDF_ALLOWED does not match VAULT_EXPECT_TEST_KDF; has insecure-test-kdf leaked?"
    );
}

/// A file whose header carries `test_kdf` and `params`, with an all-zero body.
fn file(test_kdf: bool, params: vault_core::kdf::KdfParams) -> Vec<u8> {
    let vk = VaultKey::from_bytes([5; 32]);
    let h = Header::wrap(
        test_kdf,
        [1; 16],
        1,
        params,
        [2; 16],
        [3; 24],
        &Kek::from_bytes([4; 32]),
        &vk,
    );
    let mut file = h.encode().to_vec();
    file.extend_from_slice(&[0; 24 + 4096 + 16]);
    file
}

#[test]
fn test_kdf_header_is_refused() {
    if expect_test_kdf() {
        return;
    }
    let file = file(true, TEST);
    assert_eq!(Header::decode(&file[..133]).err(), REFUSED);
    assert_eq!(vault_core::file::read_header(&file).err(), REFUSED);
    assert_eq!(
        vault_core::file::unlock(&file, "any password", &SecretKey::from_bytes([0; 16])).err(),
        REFUSED
    );
    assert_eq!(
        vault_core::file::open_file(&file, &VaultKey::from_bytes([5; 32])).err(),
        REFUSED
    );
}

/// Negative control: the test set without the flag is an ordinary bounds error in every build,
/// not the release refusal.
#[test]
fn test_set_without_the_flag_is_out_of_bounds() {
    let file = file(false, TEST);
    assert_eq!(vault_core::file::read_header(&file).err(), OUT_OF_BOUNDS);
}

/// Negative control: the flag with floor parameters is refused in every build: as a release
/// refusal here, and because only the test set goes with the flag in a test build.
#[test]
fn flag_with_floor_parameters_is_refused() {
    let expected = if expect_test_kdf() {
        OUT_OF_BOUNDS
    } else {
        REFUSED
    };
    assert_eq!(
        vault_core::file::read_header(&file(true, FLOOR)).err(),
        expected
    );
}

#[test]
fn test_parameters_are_refused_for_writing() {
    if expect_test_kdf() {
        return;
    }
    let mut rng = Fixed(0);
    assert_eq!(
        vault_core::credentials::create_vault(&mut rng, "correct horse battery", TEST, true).err(),
        Some(Error::InvalidInput(InputKind::KdfParams))
    );
}

/// The gate refuses only the test parameters: a vault at the floor works in a release-like build.
#[test]
fn floor_parameters_work() {
    let mut rng = Fixed(1);
    let v = vault_core::credentials::create_vault(&mut rng, "correct horse battery", FLOOR, false)
        .unwrap();
    assert!(vault_core::file::unlock(&v.file, "correct horse battery", &v.secret_key).is_ok());
}

/// The `compile_fail` doctests in `secret.rs` must fail only for the missing `Debug` or `Display`,
/// so the same expressions must compile here without formatting.
#[test]
fn secret_type_paths_exist() {
    let _ = VaultKey::from_bytes([0u8; 32]);
    let _ = SecretKey::from_bytes([0u8; 16]);
    let _ = Kek::from_bytes([0u8; 32]);
    let _ = vault_core::secret::BodyKey::from_bytes([0u8; 32]);
    let _ = vault_core::secret::Token::from_bytes([0u8; 20]);
}

struct Fixed(u8);

impl vault_core::rng::Rng for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}
