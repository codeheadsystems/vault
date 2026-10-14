//! The release gate against the library as the app ships it: run with
//! `cargo test -p vault-android --profile android --test release_gate`. A `test_kdf` header is
//! refused before any key derivation, by every entry point that opens a file. The floor unlock
//! time is printed (`-- --nocapture`).

mod common;

use common::{Counter, MemHost, PW, Server, code, new_vault, run};
use std::time::Instant;
use vault_android::{Step, SyncMode, Vault};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::header::Header;
use vault_core::kdf::{TEST, TEST_KDF_ALLOWED};
use vault_core::secret::{Kek, VaultKey};
use vault_core::sync::SyncState;

const REFUSED: &str = "integrity.test_kdf_in_release";

/// A file whose header sets `test_kdf` with the test parameters, and an all-zero body.
fn test_kdf_file() -> Vec<u8> {
    let vk = VaultKey::from_bytes([5; 32]);
    let h = Header::wrap(
        true,
        [1; 16],
        1,
        TEST,
        [2; 16],
        [3; 24],
        &Kek::from_bytes([4; 32]),
        &vk,
    );
    let mut file = h.encode().to_vec();
    file.extend_from_slice(&[0; 24 + 4096 + 16]);
    file
}

fn vault(file: Vec<u8>, vault_id: [u8; 16], wrap: [u8; 24]) -> std::sync::Arc<Vault> {
    let host = MemHost::new();
    host.set_state(&ClientState::new(
        SyncState {
            vault_id,
            accepted: None,
            wrap_nonce: wrap,
            retired_wrap_nonces: Vec::new(),
        },
        file,
        SecretKeyStore::File,
    ));
    *host.current.lock().unwrap() = Some(vec![0; 16]);
    Vault::new(host)
}

#[test]
fn the_library_refuses_test_kdf_headers() {
    // The build fails when the insecure-test-kdf feature leaks into the library.
    const {
        assert!(
            !TEST_KDF_ALLOWED,
            "the insecure-test-kdf feature leaked into the library"
        )
    };
    let v = vault(test_kdf_file(), [1; 16], [3; 24]);
    assert_eq!(code(v.unlock("any password".into())), REFUSED);
    assert_eq!(code(v.secret_key_text("any password".into())), REFUSED);
    assert_eq!(code(v.reopen(vec![5; 32], vec![3; 24])), REFUSED);
    // An unlock procedure refuses the local file, and a remote with the flag stops a sync as an
    // integrity error.
    let p = v.clone().begin_unlock().unwrap();
    match run(&p, None, vec![common::password("any password")]) {
        Step::Failed { error } => assert_eq!(error.code, REFUSED),
        s => panic!("{s:?}"),
    }

    let real = new_vault(9);
    let (host, v) = common::vault_with(&real);
    common::reopen(&host, &v, &real.vault_key);
    let p = v.begin_sync(SyncMode::Background).unwrap();
    let mut server = Server {
        files: vec![test_kdf_file()],
    };
    match run(&p, Some(&mut server), vec![]) {
        Step::Failed { error } => assert_eq!(error.code, REFUSED),
        s => panic!("{s:?}"),
    }
}

#[test]
fn floor_unlock_time() {
    let v =
        vault_core::credentials::create_vault(&mut Counter(0), PW, vault_core::kdf::FLOOR, false)
            .unwrap();
    let host = MemHost::new();
    host.set_state(&ClientState::new(
        SyncState {
            vault_id: v.state.vault_id,
            accepted: None,
            wrap_nonce: v.state.wrap_nonce,
            retired_wrap_nonces: Vec::new(),
        },
        v.file,
        SecretKeyStore::File,
    ));
    *host.current.lock().unwrap() = Some(v.secret_key.expose().to_vec());
    let vault = Vault::new(host);
    let mut times = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        vault.unlock(PW.into()).unwrap();
        times.push(t.elapsed().as_millis());
    }
    let k = vault.vault_key().unwrap();
    let t = Instant::now();
    vault.reopen(k.vault_key, k.wrap_nonce).unwrap();
    let reopen = t.elapsed().as_micros();
    println!("floor unlock: {times:?} ms; reopen from the vault key: {reopen} us");
}
