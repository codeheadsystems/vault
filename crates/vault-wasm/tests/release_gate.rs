//! The release gate against the module as the extension ships it: run with
//! `cargo test -p vault-wasm --target wasm32-unknown-unknown --profile wasm --test release_gate`.
//! A `test_kdf` header is refused before any key derivation, by every entry point that opens a
//! file. The floor unlock time under Node is printed (`-- --nocapture`).

#![cfg(target_arch = "wasm32")]

use js_sys::{Reflect, Uint8Array};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::header::Header;
use vault_core::kdf::{FLOOR, TEST, TEST_KDF_ALLOWED};
use vault_core::secret::{Kek, VaultKey};
use vault_core::sync::SyncState;
use vault_wasm::{Procedure, Session};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

const REFUSED: &str = "integrity.test_kdf_in_release";

fn code(e: JsValue) -> String {
    Reflect::get(&e, &"code".into())
        .unwrap()
        .as_string()
        .unwrap()
}

fn state(file: Vec<u8>, vault_id: [u8; 16], wrap: [u8; 24]) -> String {
    let s = ClientState::new(
        SyncState {
            vault_id,
            accepted: None,
            wrap_nonce: wrap,
            retired_wrap_nonces: Vec::new(),
        },
        file,
        SecretKeyStore::File,
    );
    String::from_utf8(s.to_json()).unwrap()
}

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

#[wasm_bindgen_test]
fn the_module_refuses_test_kdf_headers() {
    // The build fails when the insecure-test-kdf feature leaks into the module.
    const {
        assert!(
            !TEST_KDF_ALLOWED,
            "the insecure-test-kdf feature leaked into the module"
        )
    };
    let st = state(test_kdf_file(), [1; 16], [3; 24]);
    let sk: JsValue = Uint8Array::from(&[0u8; 16][..]).into();
    let vk: JsValue = Uint8Array::from(&[5u8; 32][..]).into();
    assert_eq!(
        code(Session::unlock(&st, &sk, "any password").err().unwrap()),
        REFUSED
    );
    assert_eq!(code(Session::reopen(&st, &vk).err().unwrap()), REFUSED);
    // A remote with the flag stops a sync as an integrity error.
    let accepted = state(test_kdf_file(), [1; 16], [3; 24]);
    let keys = js_sys::Object::new();
    Reflect::set(&keys, &"vaultKey".into(), &vk).unwrap();
    let mut p = Procedure::sync(&accepted, &keys, "background").unwrap();
    p.start(1_800_000_000_000.0);
    let resp = js_sys::Object::new();
    Reflect::set(&resp, &"type".into(), &"response".into()).unwrap();
    Reflect::set(&resp, &"status".into(), &200.into()).unwrap();
    Reflect::set(
        &resp,
        &"body".into(),
        &Uint8Array::from(&test_kdf_file()[..]),
    )
    .unwrap();
    let done = p.step(&resp, 1_800_000_000_000.0).unwrap();
    let error = Reflect::get(&done, &"error".into()).unwrap();
    assert_eq!(code(error), REFUSED);
}

#[wasm_bindgen_test]
fn floor_unlock_time() {
    let v = vault_core::credentials::create_vault(
        &mut Counter(0),
        "correct horse battery staple",
        FLOOR,
        false,
    )
    .unwrap();
    let st = state(v.file, v.state.vault_id, v.state.wrap_nonce);
    let sk: JsValue = Uint8Array::from(&v.secret_key.expose()[..]).into();
    let mut times = Vec::new();
    let mut last = None;
    for _ in 0..3 {
        let t = js_sys::Date::now();
        let s = Session::unlock(&st, &sk, "correct horse battery staple").unwrap();
        times.push(js_sys::Date::now() - t);
        last = Some(s);
    }
    let vk: JsValue = last.unwrap().vault_key().unwrap().into();
    let r = js_sys::Date::now();
    Session::reopen(&st, &vk).unwrap();
    let reopen = js_sys::Date::now() - r;
    console_log!("floor unlock under Node: {times:?} ms; reopen from the vault key: {reopen} ms");
}

/// Deterministic bytes, so the test needs no randomness for the vault.
struct Counter(u8);

impl vault_core::rng::Rng for Counter {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}
