//! Writes the known-answer vectors in `spec/vectors/` from fixed inputs. Running it twice writes
//! identical bytes.
//!
//! ```text
//! cargo run -p vault-core --example gen-vectors --features insecure-test-kdf
//! ```

use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::path::PathBuf;
use vault_core::body::Body;
use vault_core::credentials::{
    PasswordChange, change_credentials, create_vault, passwd_conflict, resolve_pending_secret_key,
};
use vault_core::header::{HEADER_LEN, Header};
use vault_core::kdf::{CEILING, FLOOR, KdfParams, TEST};
use vault_core::keys::{body_key, kek_from_pw_key};
use vault_core::merge::{DAY, cutoff, merge};
use vault_core::secret::{Kek, SecretKey, Token, VaultKey};
use vault_core::sync::{
    Accepted, PutCondition, Recovery, Retry, RetryCounter, SyncAction, SyncState, WrapStatus,
    adopt_or_push, check_remote, check_remote_for_setup, etag, file_hash, on_not_found,
    plan_recovery, recovery_generation,
};
use vault_core::{Error, Result, clock, edit, file, kdf, secret_key_text, setup, token};

// Fixed inputs shared by several files.
const PASSWORD: &str = "correct horse battery staple";
const NOW: u64 = 1_800_000_000_000;
const DEV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DEVICE: [u8; 16] = [0xdd; 16];

/// `n` bytes counting up from `start`, wrapping: readable and distinct per input.
fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn secret_key() -> [u8; 16] {
    seq(0x00)
}
fn vault_id() -> [u8; 16] {
    seq(0x10)
}
fn vault_key() -> [u8; 32] {
    seq(0x20)
}
fn kdf_salt() -> [u8; 16] {
    seq(0x40)
}
fn wrap_nonce() -> [u8; 24] {
    seq(0x50)
}
fn body_nonce() -> [u8; 24] {
    seq(0x70)
}
/// The fixed KEK of files that are opened with the vault key and never with a password.
fn fixed_kek() -> [u8; 32] {
    seq(0x90)
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn params(p: &KdfParams) -> Value {
    json!({"m_kib": p.m_kib, "t": p.t, "p": p.p})
}

fn err(e: Error) -> Value {
    Value::String(e.code().into())
}

fn result_code<T>(r: &Result<T>) -> Value {
    match r {
        Ok(_) => Value::String("ok".into()),
        Err(e) => err(*e),
    }
}

/// Serves queued bytes, as a client's random source would produce them.
struct Replay(VecDeque<u8>);

impl Replay {
    fn new(parts: &[&[u8]]) -> Self {
        Replay(parts.concat().into())
    }
}

impl vault_core::rng::Rng for Replay {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest {
            *b = self.0.pop_front().expect("enough replay bytes");
        }
        Ok(())
    }
}

fn write(name: &str, description: &str, cases: Vec<Value>, extra: Map<String, Value>) {
    let mut top = Map::new();
    top.insert("description".into(), description.into());
    top.extend(extra);
    top.insert("cases".into(), Value::Array(cases));
    let mut text = serde_json::to_string_pretty(&Value::Object(top)).unwrap();
    text.push('\n');
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), text).unwrap();
}

fn main() {
    secret_key_file();
    token_file();
    etag_file();
    kdf_file();
    vault_file();
    merge_file();
    sync_file();
    credentials_file();
    tamper_file();
    malformed_file();
    setup_file();
}

// secret-key.json

fn secret_key_file() {
    let mut cases = Vec::new();
    for (name, sk) in [
        ("counting bytes", secret_key()),
        ("all zero", [0u8; 16]),
        ("all ones", [0xff; 16]),
    ] {
        let k = SecretKey::from_bytes(sk);
        cases.push(json!({
            "name": name, "op": "encode", "secret_key": hx(&sk),
            "check": hx(&secret_key_text::check_value(&k)),
            "text": secret_key_text::encode(&k).as_str(),
        }));
    }
    let text = secret_key_text::encode(&SecretKey::from_bytes(secret_key())).to_string();
    let lower = text.to_ascii_lowercase();
    let spaced = format!("vlt1-{}", text[5..].replace('-', " "));
    let subst = format!("VLT1-{}", text[5..].replace('0', "O").replace('1', "I"));
    let mut typo: Vec<char> = text.chars().collect();
    typo[6] = if typo[6] == 'A' { 'B' } else { 'A' };
    let typo: String = typo.into_iter().collect();
    for (name, input) in [
        ("lower case", lower),
        ("spaces instead of dashes", spaced),
        ("O for 0 and I for 1", subst),
        ("surrounding whitespace", format!("  {text}\n")),
        ("one character changed", typo),
        ("missing prefix", text[5..].to_owned()),
        ("wrong prefix", text.replace("VLT1", "VLT2")),
        ("one character short", text[..text.len() - 1].to_owned()),
        ("one character extra", format!("{text}0")),
        (
            "character outside the alphabet",
            text.replacen('-', "-U", 1)[..44].to_owned(),
        ),
        (
            "spec example",
            "VLT1-7XH6-NSCF-5P9Y-QKXJ-J745-SZYF-BEQY-C51A".to_owned(),
        ),
    ] {
        let mut c = json!({"name": name, "op": "decode", "input": input});
        match secret_key_text::decode(&input) {
            Ok(sk) => c["secret_key"] = hx(sk.expose()).into(),
            Err(e) => c["error"] = err(e),
        }
        cases.push(c);
    }
    write(
        "secret-key.json",
        "Secret key text form: VLT1- and crock(secret_key || check), with the decoder's \
         substitutions and typo rejection.",
        cases,
        Map::new(),
    );
}

// token.json

fn token_file() {
    let mut cases = Vec::new();
    for (name, t) in [("counting bytes", seq::<20>(0x30)), ("all zero", [0u8; 20])] {
        let tok = Token::from_bytes(t);
        cases.push(json!({
            "name": name, "op": "encode", "token": hx(&t),
            "text": token::encode(&tok).as_str(), "stored_hash": hx(&token::stored_hash(&tok)),
        }));
    }
    let text = token::encode(&Token::from_bytes(seq(0x30))).to_string();
    for (name, input) in [
        ("lower case", text.to_ascii_lowercase()),
        ("with dashes and substitutions", {
            let s = text.replace('0', "o").replace('1', "l");
            format!("{}-{}", &s[..16], &s[16..])
        }),
        ("too short", text[..31].to_owned()),
        ("outside the alphabet", format!("U{}", &text[1..])),
    ] {
        let mut c = json!({"name": name, "op": "decode", "input": input});
        match token::decode(&input) {
            Ok(t) => {
                c["token"] = hx(t.expose()).into();
                c["stored_hash"] = hx(&token::stored_hash(&t)).into();
            }
            Err(e) => c["error"] = err(e),
        }
        cases.push(c);
    }
    write(
        "token.json",
        "Token text form crock(token) in upper case, decoding with the secret key decoder's \
         substitutions, and the stored SHA-256.",
        cases,
        Map::new(),
    );
}

// etag.json

fn etag_file() {
    let file = floor_file(vault_id(), 1, wrap_nonce(), body_nonce(), &Body::default());
    let mut cases = Vec::new();
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("abc", b"abc".to_vec()),
        ("a vault file", file),
    ] {
        cases.push(json!({"name": name, "op": "etag", "bytes": hx(&bytes), "etag": etag(&bytes)}));
    }
    write(
        "etag.json",
        "ETag: the lowercase hex SHA-256 of the file bytes, quoted.",
        cases,
        Map::new(),
    );
}

// kdf.json

fn kdf_file() {
    let mut cases = Vec::new();
    for (name, pw) in [
        ("composed", "caf\u{e9} au lait 12"),
        ("decomposed", "cafe\u{301} au lait 12"),
        ("compatibility ligature", "\u{fb01}ve fine words"),
        ("not trimmed", "  spaces kept  "),
    ] {
        cases.push(json!({
            "name": name, "op": "nfkc", "password": pw, "password_hex": hx(pw.as_bytes()),
            "nfkc_hex": hx(kdf::nfkc(pw).as_bytes()),
        }));
    }
    let long = "a".repeat(kdf::MAX_PASSWORD_BYTES + 1);
    for (name, pw) in [
        ("twelve characters", "correct hors".to_owned()),
        ("eleven characters", "correct hor".to_owned()),
        (
            "twelve after NFKC from eleven",
            "abcdefghij\u{fb01}".to_owned(),
        ),
        (
            "eleven after NFKC from twelve",
            "abcdefghije\u{301}".to_owned(),
        ),
        ("unassigned code point", "twelve chars\u{e0000}x".to_owned()),
        ("noncharacter", "twelve chars\u{fdd0}".to_owned()),
        ("private use is assigned", "twelve chars\u{e000}".to_owned()),
        ("4,096 bytes", "a".repeat(kdf::MAX_PASSWORD_BYTES)),
        ("4,097 bytes", long.clone()),
    ] {
        cases.push(json!({
            "name": name, "op": "validate_new_password", "password_hex": hx(pw.as_bytes()),
            "result": result_code(&kdf::validate_new_password(&pw)),
        }));
    }
    let derive = |name: &str, pw: &str, p: KdfParams, test_kdf: bool| {
        let sk = SecretKey::from_bytes(secret_key());
        let mut c = json!({
            "name": name, "op": "derive", "password_hex": hx(pw.as_bytes()),
            "secret_key": hx(&secret_key()), "vault_id": hx(&vault_id()),
            "params": params(&p), "test_kdf": test_kdf, "kdf_salt": hx(&kdf_salt()),
        });
        match kdf::pw_key(pw, &p, test_kdf, &kdf_salt()) {
            Ok(pk) => {
                c["nfkc_hex"] = hx(kdf::nfkc(pw).as_bytes()).into();
                c["pw_key"] = hx(pk.as_ref()).into();
                c["kek"] = hx(kek_from_pw_key(&pk, &sk, &vault_id()).expose()).into();
            }
            Err(e) => c["error"] = err(e),
        }
        if test_kdf {
            c["release_error"] = "integrity.test_kdf_in_release".into();
        }
        c
    };
    cases.push(derive("test parameters", PASSWORD, TEST, true));
    cases.push(derive(
        "test parameters, composed",
        "caf\u{e9} au lait 12",
        TEST,
        true,
    ));
    cases.push(derive(
        "test parameters, decomposed",
        "cafe\u{301} au lait 12",
        TEST,
        true,
    ));
    cases.push(derive("floor parameters", PASSWORD, FLOOR, false));
    cases.push(derive("password over 4,096 bytes", &long, TEST, true));
    cases.push(derive(
        "below the floor",
        PASSWORD,
        KdfParams {
            m_kib: 65_535,
            ..FLOOR
        },
        false,
    ));
    let check = |name: &str, p: KdfParams, test_kdf: bool| {
        let test_build = p.check(test_kdf);
        let release = if test_kdf {
            Err(Error::Integrity(
                vault_core::IntegrityKind::TestKdfInRelease,
            ))
        } else {
            test_build
        };
        json!({
            "name": name, "op": "check_params", "params": params(&p), "test_kdf": test_kdf,
            "test_build": result_code(&test_build), "release_build": result_code(&release),
        })
    };
    for (name, p, t) in [
        ("floor", FLOOR, false),
        ("ceiling", CEILING, false),
        (
            "128 MiB",
            KdfParams {
                m_kib: 131_072,
                ..FLOOR
            },
            false,
        ),
        (
            "memory below the floor",
            KdfParams {
                m_kib: 65_535,
                ..FLOOR
            },
            false,
        ),
        (
            "iterations below the floor",
            KdfParams { t: 2, ..FLOOR },
            false,
        ),
        ("zero lanes", KdfParams { p: 0, ..FLOOR }, false),
        (
            "memory above the ceiling",
            KdfParams {
                m_kib: 262_145,
                ..FLOOR
            },
            false,
        ),
        (
            "iterations above the ceiling",
            KdfParams { t: 11, ..FLOOR },
            false,
        ),
        (
            "lanes above the ceiling",
            KdfParams { p: 5, ..FLOOR },
            false,
        ),
        ("test set without the flag", TEST, false),
        ("test set with the flag", TEST, true),
        ("floor with the flag", FLOOR, true),
    ] {
        cases.push(check(name, p, t));
    }
    write(
        "kdf.json",
        "NFKC, the password-setting rules, pw_key = Argon2id(NFKC(password), kdf_salt), KEK = \
         HKDF(pw_key || secret_key, vault_id, \"vault/v1/kek\"), and the parameter bounds in test \
         and release builds.",
        cases,
        Map::new(),
    );
}

// vault-file.json

fn floor_header(vid: [u8; 16], generation: u64, wrap: [u8; 24]) -> Header {
    Header::wrap(
        false,
        vid,
        generation,
        FLOOR,
        kdf_salt(),
        wrap,
        &Kek::from_bytes(fixed_kek()),
        &VaultKey::from_bytes(vault_key()),
    )
}

/// A file at the floor parameters under the fixed KEK, opened with the vault key only.
fn floor_file(
    vid: [u8; 16],
    generation: u64,
    wrap: [u8; 24],
    nonce: [u8; 24],
    body: &Body,
) -> Vec<u8> {
    file::seal_file(
        &floor_header(vid, generation, wrap),
        &VaultKey::from_bytes(vault_key()),
        &nonce,
        body,
    )
    .unwrap()
}

fn body_text(b: &Body) -> String {
    String::from_utf8(b.to_json().to_vec()).unwrap()
}

fn body_of(v: &Value) -> Body {
    Body::from_json(&serde_json::to_vec(v).unwrap()).unwrap()
}

fn body_value(b: &Body) -> Value {
    serde_json::from_slice(&b.to_json()).unwrap()
}

/// Seals a raw plaintext under `header` with the vault key, without any check, for files that
/// break a rule after authentication.
fn raw_file(header: &[u8; HEADER_LEN], vid: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    use chacha20poly1305::XChaCha20Poly1305;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let kb = body_key(&VaultKey::from_bytes(vault_key()), vid);
    let c = XChaCha20Poly1305::new(&(*kb.expose()).into());
    let ct = c
        .encrypt(
            &body_nonce().into(),
            Payload {
                msg: pt,
                aad: header,
            },
        )
        .unwrap();
    [&header[..], &body_nonce(), &ct].concat()
}

fn plaintext(json: &[u8], len_field: u32, total: usize) -> Vec<u8> {
    let mut pt = len_field.to_be_bytes().to_vec();
    pt.extend_from_slice(json);
    pt.resize(total, 0);
    pt
}

fn vault_file() {
    let mut cases = Vec::new();
    let one_item = body_of(&json!({"v": 1, "horizon": 0, "tombstones": [],
        "items": [login(&id(1), NOW, DEV_A, "hunter2", &[("old", NOW - DAY)])], "x": [1]}));
    for (name, p, test_kdf, body) in [
        ("test parameters, empty body", TEST, true, Body::default()),
        ("test parameters, one login", TEST, true, one_item.clone()),
        (
            "test parameters, controls escaped in the body JSON",
            TEST,
            true,
            body_of(&json!({"v": 1, "horizon": 0, "tombstones": [],
                "items": [with(note(&id(2), NOW, DEV_A, &[]), "notes",
                    json!("tab\t del\u{7f} c1\u{85}\u{9f} nbsp\u{a0} ls\u{2028} ps\u{2029} nl\n"))],
                "c1\u{80}key": "\u{1}"})),
        ),
        ("floor parameters, one login", FLOOR, false, one_item),
    ] {
        let sk = SecretKey::from_bytes(secret_key());
        let vk = VaultKey::from_bytes(vault_key());
        let pk = kdf::pw_key(PASSWORD, &p, test_kdf, &kdf_salt()).unwrap();
        let kek = kek_from_pw_key(&pk, &sk, &vault_id());
        let h = Header::wrap(
            test_kdf,
            vault_id(),
            7,
            p,
            kdf_salt(),
            wrap_nonce(),
            &kek,
            &vk,
        );
        let f = file::seal_file(&h, &vk, &body_nonce(), &body).unwrap();
        let json = body.to_json();
        let mut c = json!({
            "name": name, "op": "seal",
            "password_hex": hx(PASSWORD.as_bytes()), "secret_key": hx(&secret_key()),
            "vault_id": hx(&vault_id()), "generation": 7, "params": params(&p),
            "test_kdf": test_kdf, "kdf_salt": hx(&kdf_salt()), "wrap_nonce": hx(&wrap_nonce()),
            "vault_key": hx(&vault_key()), "body_nonce": hx(&body_nonce()),
            "body_json": body_text(&body),
            "pw_key": hx(pk.as_ref()), "kek": hx(kek.expose()), "wrap_ad": hx(&h.wrap_ad()),
            "wrapped_vk": hx(&h.wrapped_vk), "header": hx(&h.encode()),
            "body_key": hx(body_key(&vk, &vault_id()).expose()),
            "plaintext_len": (4 + json.len()).div_ceil(4096) * 4096,
            "file": hx(&f), "etag": etag(&f),
        });
        if test_kdf {
            c["release_error"] = "integrity.test_kdf_in_release".into();
        }
        cases.push(c);
    }
    // Extra zero padding: two blocks for a body that fits in one.
    let h = floor_header(vault_id(), 7, wrap_nonce());
    let json = Body::default().to_json();
    let f = raw_file(
        &h.encode(),
        &vault_id(),
        &plaintext(&json, json.len() as u32, 8192),
    );
    cases.push(json!({
        "name": "extra zero padding", "op": "open", "vault_key": hx(&vault_key()),
        "file": hx(&f), "body_json": body_text(&Body::default()),
        "result": result_code(&file::open_file(&f, &VaultKey::from_bytes(vault_key()))),
    }));
    write(
        "vault-file.json",
        "Complete vault files: header, vault key wrap, body key, padding, and body ciphertext.",
        cases,
        Map::new(),
    );
}

// merge.json

fn id(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn history(h: &[(&str, u64)]) -> Value {
    h.iter()
        .map(|(p, r)| json!({"password": p, "retired": r}))
        .collect()
}

fn login(id: &str, modified: u64, by: &str, pw: &str, h: &[(&str, u64)]) -> Value {
    json!({"id": id, "type": "login", "name": "n", "folder": "", "favourite": false,
        "notes": "", "fields": [], "password_history": history(h), "created": 0,
        "modified": modified, "modified_by": by,
        "login": {"username": "u", "password": pw, "uris": [], "apps": [], "totp": null,
            "passkeys": []}})
}

fn note(id: &str, modified: u64, by: &str, h: &[(&str, u64)]) -> Value {
    json!({"id": id, "type": "note", "name": "n", "folder": "", "favourite": false,
        "notes": "", "fields": [], "password_history": history(h), "created": 0,
        "modified": modified, "modified_by": by})
}

fn card(id: &str, modified: u64, by: &str, number: u64) -> Value {
    json!({"id": id, "type": "card", "modified": modified, "modified_by": by,
        "number": number, "password_history": [{"retired": NOW + 5 * DAY}]})
}

fn tomb(id: &str, modified: u64, by: &str) -> Value {
    json!({"id": id, "modified": modified, "modified_by": by})
}

fn body(horizon: u64, items: Vec<Value>, tombstones: Vec<Value>) -> Value {
    json!({"v": 1, "horizon": horizon, "items": items, "tombstones": tombstones})
}

fn with(mut b: Value, key: &str, v: Value) -> Value {
    b[key] = v;
    b
}

fn merge_case(name: &str, local: Value, remote: Value, now: u64) -> Value {
    let m = merge(&body_of(&local), &body_of(&remote), now);
    let expired: Vec<Value> = m
        .expired
        .iter()
        .map(|i| serde_json::from_slice(&vault_core::json::to_vec(&i.to_value())).unwrap())
        .collect();
    json!({"name": name, "op": "merge", "now": now, "local": local, "remote": remote,
        "result": body_value(&m.body), "expired": expired})
}

fn merge_file() {
    let (i1, i2, i3) = (id(1), id(2), id(3));
    let c = cutoff(NOW);
    let mut cases = vec![
        merge_case(
            "concurrent edits keep the losing password",
            body(
                0,
                vec![login(&i1, NOW - 10, DEV_A, "local", &[("old", 5)])],
                vec![],
            ),
            body(
                0,
                vec![login(&i1, NOW - 20, DEV_B, "remote", &[("older", 1)])],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "history tie order: equal retired sorts by password bytes",
            body(
                0,
                vec![login(&i1, 100, DEV_A, "x", &[("c", 40), ("\u{e9}", 40)])],
                vec![],
            ),
            body(
                0,
                vec![login(
                    &i1,
                    200,
                    DEV_B,
                    "y",
                    &[("b", 40), ("a", 40), ("B", 40)],
                )],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "history is cut to 10",
            body(
                0,
                vec![login(
                    &i1,
                    100,
                    DEV_A,
                    "x",
                    &(0..10)
                        .map(|i| {
                            (
                                ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"][i],
                                1000 - i as u64,
                            )
                        })
                        .collect::<Vec<_>>(),
                )],
                vec![],
            ),
            body(
                0,
                vec![login(&i1, 200, DEV_B, "y", &[("zz", 5000)])],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "a local password change wins and keeps its history",
            body(
                0,
                vec![login(&i1, NOW - 5, DEV_A, "new", &[("old", NOW - 5)])],
                vec![],
            ),
            body(0, vec![login(&i1, 100, DEV_B, "old", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "edit against a newer delete",
            body(0, vec![login(&i1, NOW - 100, DEV_A, "pw", &[])], vec![]),
            body(0, vec![], vec![tomb(&i1, NOW - 50, DEV_B)]),
            NOW,
        ),
        merge_case(
            "edit against an older delete",
            body(0, vec![login(&i1, NOW - 100, DEV_A, "pw", &[])], vec![]),
            body(0, vec![], vec![tomb(&i1, NOW - 150, DEV_B)]),
            NOW,
        ),
        merge_case(
            "full tie: the remote entry wins",
            body(0, vec![login(&i1, NOW - 100, DEV_A, "local", &[])], vec![]),
            body(0, vec![login(&i1, NOW - 100, DEV_A, "remote", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "full tie between an item and a tombstone: the remote tombstone wins",
            body(0, vec![login(&i1, NOW - 100, DEV_A, "local", &[])], vec![]),
            body(0, vec![], vec![tomb(&i1, NOW - 100, DEV_A)]),
            NOW,
        ),
        merge_case(
            "modified_by breaks a tie on modified",
            body(0, vec![login(&i1, 100, DEV_B, "b", &[])], vec![]),
            body(0, vec![login(&i1, 100, DEV_A, "a", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "clamping of stamps, retired, and horizon",
            body(
                NOW + DAY + 1,
                vec![login(
                    &i1,
                    NOW + DAY + 1,
                    DEV_A,
                    "pw",
                    &[("old", NOW + 2 * DAY), ("mid", NOW + DAY / 2)],
                )],
                vec![tomb(&i2, NOW + 3 * DAY, DEV_A)],
            ),
            body(0, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "now + DAY exactly is not clamped",
            body(
                c + DAY,
                vec![login(&i1, NOW + DAY, DEV_A, "pw", &[])],
                vec![],
            ),
            body(0, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "a clock in 1970",
            body(
                NOW,
                vec![login(&i1, NOW, DEV_A, "pw", &[])],
                vec![tomb(&i2, NOW - DAY, DEV_A)],
            ),
            body(
                NOW,
                vec![login(&i1, NOW, DEV_A, "pw", &[])],
                vec![tomb(&i2, NOW - DAY, DEV_A)],
            ),
            1000,
        ),
        merge_case(
            "now under 180 days: cutoff saturates at 0",
            body(0, vec![], vec![tomb(&i2, 0, DEV_A)]),
            body(0, vec![], vec![tomb(&i2, 0, DEV_A)]),
            15_552_000_000 - 1,
        ),
        merge_case(
            "expiry: a local-only item older than the remote horizon",
            body(
                0,
                vec![
                    login(&i1, c - 10 * DAY - 1, DEV_A, "pw", &[]),
                    login(&i2, c - 10 * DAY, DEV_A, "pw", &[]),
                ],
                vec![],
            ),
            body(c - 10 * DAY, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "expiry uses the other side's horizon",
            body(0, vec![], vec![]),
            body(
                c - 10 * DAY,
                vec![login(&i1, c - 10 * DAY - 1, DEV_A, "pw", &[])],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "an item paired with a tombstone never expires",
            body(0, vec![login(&i1, c - 20 * DAY, DEV_A, "pw", &[])], vec![]),
            body(c - 10 * DAY, vec![], vec![tomb(&i1, c - 21 * DAY, DEV_B)]),
            NOW,
        ),
        merge_case(
            "purge raises the horizon to cutoff",
            body(
                5,
                vec![],
                vec![tomb(&i1, c - 1, DEV_A), tomb(&i2, c, DEV_A)],
            ),
            body(7, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "no purge: the greater horizon",
            body(5, vec![], vec![tomb(&i2, c, DEV_A)]),
            body(7, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "unknown item type merges whole; only modified is clamped",
            body(0, vec![card(&i1, NOW + 2 * DAY, DEV_A, 1)], vec![]),
            body(0, vec![card(&i1, 200, DEV_B, 2)], vec![]),
            NOW,
        ),
        merge_case(
            "unknown item type, the newer wins",
            body(0, vec![card(&i1, 100, DEV_A, 1)], vec![]),
            body(0, vec![card(&i1, 200, DEV_A, 2)], vec![]),
            NOW,
        ),
        merge_case(
            "unknown top-level fields: remote values, plus local-only keys",
            with(
                with(body(0, vec![], vec![]), "a", json!(1)),
                "only_local",
                json!({"x": []}),
            ),
            with(
                with(body(0, vec![], vec![]), "a", json!(2)),
                "only_remote",
                json!(true),
            ),
            NOW,
        ),
        merge_case(
            "the greater v",
            with(body(0, vec![], vec![]), "v", json!(2)),
            body(0, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "equal bodies merge to the same content",
            with(
                body(
                    3,
                    vec![
                        login(&i1, NOW - 1, DEV_A, "pw", &[("old", 5)]),
                        card(&i2, 9, DEV_A, 4),
                    ],
                    vec![tomb(&i3, NOW - DAY, DEV_B)],
                ),
                "z",
                json!([1]),
            ),
            with(
                body(
                    3,
                    vec![
                        login(&i1, NOW - 1, DEV_A, "pw", &[("old", 5)]),
                        card(&i2, 9, DEV_A, 4),
                    ],
                    vec![tomb(&i3, NOW - DAY, DEV_B)],
                ),
                "z",
                json!([1]),
            ),
            NOW,
        ),
        merge_case(
            "a note history is normalised after clamping",
            body(
                0,
                vec![note(
                    &i1,
                    100,
                    DEV_A,
                    &[("x", NOW + 2 * DAY), ("y", NOW + DAY / 2), ("", 1)],
                )],
                vec![],
            ),
            body(0, vec![], vec![]),
            NOW,
        ),
        merge_case(
            "an unsorted history from another client is normalised",
            body(0, vec![], vec![]),
            body(
                0,
                vec![login(
                    &i1,
                    100,
                    DEV_B,
                    "cur",
                    &[("a", 1), ("b", 9), ("cur", 5), ("a", 3)],
                )],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "a losing password equal to the winner's is not kept",
            body(
                0,
                vec![login(&i1, 100, DEV_A, "same", &[("same", 50)])],
                vec![],
            ),
            body(0, vec![login(&i1, 200, DEV_B, "same", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "an empty losing password is not kept",
            body(
                0,
                vec![login(&i1, 100, DEV_A, "", &[("", 7), ("old", 5)])],
                vec![],
            ),
            body(0, vec![login(&i1, 200, DEV_B, "new", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "origin travels with the winning item, verbatim",
            body(
                0,
                vec![with(
                    login(&i1, 100, DEV_A, "pw", &[]),
                    "origin",
                    json!({"bitwarden": {"id": "local", "fields": [{"type": 3, "value": null}]}}),
                )],
                vec![],
            ),
            body(
                0,
                vec![with(
                    login(&i1, 200, DEV_B, "pw", &[]),
                    "origin",
                    json!({"bitwarden": {"id": "remote", "n": [1, {}]}, "other": {}}),
                )],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "an unknown type keeps a non-object origin, unchecked",
            body(
                0,
                vec![with(card(&i1, 300, DEV_A, 1), "origin", json!("x"))],
                vec![],
            ),
            body(
                0,
                vec![with(
                    card(&i1, 200, DEV_B, 2),
                    "origin",
                    json!([1, {"a": null}]),
                )],
                vec![],
            ),
            NOW,
        ),
        merge_case(
            "a winner without origin does not take the loser's",
            body(
                0,
                vec![with(
                    login(&i1, 100, DEV_A, "pw", &[]),
                    "origin",
                    json!({"bitwarden": {}}),
                )],
                vec![],
            ),
            body(0, vec![login(&i1, 200, DEV_B, "pw", &[])], vec![]),
            NOW,
        ),
        merge_case(
            "a login that loses to a note loses its password",
            body(0, vec![login(&i1, 100, DEV_A, "pw", &[])], vec![]),
            body(0, vec![note(&i1, 200, DEV_B, &[])], vec![]),
            NOW,
        ),
    ];
    cases.extend(edit_cases());
    write(
        "merge.json",
        "The merge rule and local edits. Compare items, tombstones, and expired items as sets \
         keyed by id.",
        cases,
        Map::new(),
    );
}

fn edit_case(name: &str, action: &str, before: Value, args: Value, now: u64) -> Value {
    let mut b = body_of(&before);
    let dev = DEVICE;
    let fields_of = |item: &Value| {
        let one = body_of(&body(0, vec![item.clone()], vec![]));
        one.items[0].fields().unwrap().clone()
    };
    let r = match action {
        "update" => edit::update_item(
            &mut b,
            args["id"].as_str().unwrap(),
            fields_of(&args["item"]),
            now,
            &dev,
        ),
        "import" => {
            let rng = hex::decode(args["rng"].as_str().unwrap()).unwrap();
            let item = &args["item"];
            edit::import_item(
                &mut b,
                &mut Replay::new(&[&rng]),
                item["type"].as_str().unwrap(),
                fields_of(item),
                now,
                &dev,
            )
            .map(|_| ())
        }
        "delete" => edit::delete_item(&mut b, args["id"].as_str().unwrap(), now, &dev),
        "restore" => {
            let old = body_of(&body(0, vec![args["item"].clone()], vec![]));
            edit::restore_item(&mut b, &old.items[0], now, &dev);
            Ok(())
        }
        _ => unreachable!(),
    };
    let mut c = json!({"name": name, "op": "edit", "action": action, "now": now,
        "device_id": hx(&dev), "body": before, "args": args});
    match r {
        Ok(()) => c["result"] = body_value(&b),
        Err(e) => c["error"] = err(e),
    }
    c
}

fn edit_cases() -> Vec<Value> {
    let i1 = id(1);
    vec![
        edit_case(
            "a password change adds the old password",
            "update",
            body(0, vec![login(&i1, 10, DEV_A, "A", &[])], vec![]),
            json!({"id": i1, "item": login(&i1, 10, DEV_A, "B", &[])}),
            NOW,
        ),
        edit_case(
            "A to B to A leaves no A in history",
            "update",
            body(0, vec![login(&i1, 20, DEV_A, "B", &[("A", 20)])], vec![]),
            json!({"id": i1, "item": login(&i1, 20, DEV_A, "A", &[("A", 20)])}),
            NOW,
        ),
        edit_case(
            "an edit removes review",
            "update",
            with(
                body(
                    0,
                    vec![with(
                        login(&i1, 10, DEV_A, "A", &[]),
                        "review",
                        json!("clamped"),
                    )],
                    vec![],
                ),
                "k",
                json!(0),
            ),
            json!({"id": i1, "item": with(login(&i1, 10, DEV_A, "A", &[]), "name", json!("renamed"))}),
            NOW,
        ),
        edit_case(
            "an unknown type is never edited",
            "update",
            body(0, vec![card(&i1, 10, DEV_A, 1)], vec![]),
            json!({"id": i1, "item": login(&i1, 10, DEV_A, "A", &[])}),
            NOW,
        ),
        edit_case(
            "import stamps modified and keeps created",
            "import",
            body(0, vec![], vec![]),
            json!({"rng": hx(&seq::<16>(0xa0)), "item": with(login(&id(9), 5, DEV_B, "imported", &[]), "created", json!(1_234))}),
            NOW,
        ),
        edit_case(
            "restore keeps the current password in history",
            "restore",
            body(0, vec![login(&i1, 40, DEV_A, "B", &[("A", 40)])], vec![]),
            json!({"item": login(&i1, 10, DEV_B, "A", &[])}),
            NOW,
        ),
        edit_case(
            "restore merges password histories",
            "restore",
            body(
                0,
                vec![login(&i1, 40, DEV_A, "p3", &[("p2", 30), ("p1", 20)])],
                vec![],
            ),
            json!({"item": login(&i1, 10, DEV_B, "p1", &[("p0", 5)])}),
            NOW,
        ),
        edit_case(
            "restore replaces a tombstone",
            "restore",
            body(0, vec![], vec![tomb(&i1, 50, DEV_A)]),
            json!({"item": with(login(&i1, 10, DEV_B, "A", &[]), "review", json!("clamped"))}),
            NOW,
        ),
        edit_case(
            "delete leaves a stamped tombstone",
            "delete",
            body(0, vec![card(&i1, 10, DEV_A, 1)], vec![]),
            json!({"id": i1}),
            NOW,
        ),
        edit_case(
            "delete of a missing item",
            "delete",
            body(0, vec![], vec![]),
            json!({"id": i1}),
            NOW,
        ),
    ]
}

// sync.json

fn state_json(s: &SyncState) -> Value {
    json!({
        "vault_id": hx(&s.vault_id),
        "accepted": s.accepted.as_ref().map(|a| json!({"generation": a.generation, "file_hash": hx(&a.file_hash)})),
        "wrap_nonce": hx(&s.wrap_nonce),
        "retired_wrap_nonces": s.retired_wrap_nonces.iter().map(|n| hx(n)).collect::<Vec<_>>(),
    })
}

fn sync_file() {
    let vk = VaultKey::from_bytes(vault_key());
    let wrap = wrap_nonce();
    let old_wrap: [u8; 24] = seq(0xb0);
    let new_wrap: [u8; 24] = seq(0xc8);
    let f = |g: u64, w: [u8; 24], n: u8| floor_file(vault_id(), g, w, seq(n), &Body::default());
    let accepted = f(5, wrap, 1);
    let state = SyncState {
        vault_id: vault_id(),
        accepted: Some(Accepted {
            generation: 5,
            file_hash: file_hash(&accepted),
        }),
        wrap_nonce: wrap,
        retired_wrap_nonces: vec![old_wrap],
    };
    let mut garbage = f(1 << 48, wrap, 1);
    let last = garbage.len() - 1;
    garbage[last] ^= 1;
    let mut cases = Vec::new();
    let fresh = SyncState {
        accepted: None,
        ..state.clone()
    };
    for (name, s, file) in [
        ("the accepted file itself", &state, accepted.clone()),
        ("a higher generation", &state, f(6, wrap, 2)),
        ("a lower generation", &state, f(4, wrap, 1)),
        ("equal generation, different hash", &state, f(5, wrap, 2)),
        (
            "a different vault_id",
            &state,
            floor_file(seq(0xe0), 6, wrap, seq(1), &Body::default()),
        ),
        ("a retired wrap_nonce", &state, f(6, old_wrap, 1)),
        ("a changed wrap_nonce", &state, f(6, new_wrap, 1)),
        ("garbage at generation 2^48", &state, garbage.clone()),
        ("no accepted generation", &fresh, f(1, wrap, 1)),
        ("not a vault file", &state, b"garbage".to_vec()),
    ] {
        let mut c = json!({"name": name, "op": "check_remote", "state": state_json(s),
            "file": hx(&file), "vault_key": hx(&vault_key())});
        match check_remote(s, &file) {
            Ok(r) => {
                c["wrap"] = match r.wrap {
                    WrapStatus::Current => "current",
                    WrapStatus::Changed => "changed",
                }
                .into();
                c["etag"] = r.etag.into();
                c["open"] = result_code(&file::open_file(&file, &vk));
            }
            Err(e) => c["error"] = err(e),
        }
        cases.push(c);
    }
    for (name, kit) in [
        ("no kit", None),
        ("kit with the same vault_id", Some(vault_id())),
        ("kit with another vault_id", Some(seq::<16>(0xe0))),
    ] {
        let file = f(9, wrap, 1);
        let mut c = json!({"name": name, "op": "check_setup", "file": hx(&file),
            "kit_vault_id": kit.map(|k| hx(&k))});
        c["result"] = result_code(&check_remote_for_setup(&file, kit.as_ref()));
        cases.push(c);
    }
    let remote = with(body(0, vec![], vec![]), "future", json!({"a": 1}));
    for (name, local) in [
        (
            "an unknown top-level key from the remote: adopt",
            body(0, vec![], vec![]),
        ),
        (
            "a local-only top-level key: push",
            with(body(0, vec![], vec![]), "local_only", json!(1)),
        ),
        (
            "a local edit: push",
            body(0, vec![login(&id(1), NOW - 1, DEV_A, "pw", &[])], vec![]),
        ),
    ] {
        let merged = merge(&body_of(&local), &body_of(&remote), NOW).body;
        let action = match adopt_or_push(&merged, &body_of(&remote), 7).unwrap() {
            SyncAction::Adopt => json!({"action": "adopt"}),
            SyncAction::Push { generation } => json!({"action": "push", "generation": generation}),
        };
        cases.push(
            json!({"name": name, "op": "adopt", "now": NOW, "local": local,
            "remote": remote, "remote_generation": 7, "result": action}),
        );
    }
    for (name, s) in [
        ("a client being set up", None),
        ("after vault init, never pushed", Some(&fresh)),
        ("an accepted generation", Some(&state)),
    ] {
        let action = match on_not_found(s).unwrap() {
            vault_core::sync::NotFoundAction::NoVault => json!({"action": "no_vault"}),
            vault_core::sync::NotFoundAction::Push { generation } => {
                json!({"action": "push", "generation": generation, "if_none_match": "*"})
            }
        };
        cases.push(
            json!({"name": name, "op": "not_found", "state": s.map(state_json), "result": action}),
        );
    }
    let honest6 = f(6, wrap, 2);
    let honest7 = f(7, wrap, 3);
    let recovery = |name: &str, revs: Vec<(u64, Vec<u8>)>, past: bool| {
        let refs: Vec<(u64, &[u8])> = revs.iter().map(|(i, b)| (*i, &b[..])).collect();
        let plan = plan_recovery(&state, &refs, past);
        let (kind, ids) = match &plan {
            Recovery::CredentialChange(v) => ("credential_change", v.clone()),
            Recovery::Candidates(v) => ("candidates", v.clone()),
        };
        let mut c = json!({"name": name, "op": "recovery", "state": state_json(&state),
            "vault_key": hx(&vault_key()), "past_unknown_wraps": past,
            "revisions": revs.iter().map(|(i, b)| json!({"id": i, "file": hx(b)})).collect::<Vec<_>>(),
            "plan": kind, "plan_revisions": ids});
        if let Recovery::Candidates(ids) = plan {
            let chosen = ids.iter().find_map(|i| {
                let b = &revs.iter().find(|(j, _)| j == i).unwrap().1;
                file::open_file(b, &vk)
                    .ok()
                    .map(|(h, _)| (*i, h.generation))
            });
            c["chosen"] = chosen.map(|(i, _)| i).into();
            c["push_generation"] = recovery_generation(&state, chosen.map(|(_, g)| g))
                .unwrap()
                .into();
        }
        c
    };
    cases.push(recovery(
        "the highest qualifying generation",
        vec![
            (10, f(4, wrap, 1)),
            (11, accepted.clone()),
            (12, honest7.clone()),
            (13, honest6.clone()),
            (14, floor_file(seq(0xe0), 9, wrap, seq(1), &Body::default())),
            (15, f(8, old_wrap, 1)),
            (16, b"garbage".to_vec()),
        ],
        false,
    ));
    cases.push(recovery(
        "an unknown wrap_nonce stops recovery",
        vec![
            (20, honest6.clone()),
            (21, f(7, new_wrap, 1)),
            (22, f(3, seq(0xf0), 1)),
        ],
        false,
    ));
    cases.push(recovery(
        "past an unknown wrap_nonce after confirmation",
        vec![(20, honest6.clone()), (21, f(7, new_wrap, 1))],
        true,
    ));
    cases.push(recovery(
        "garbage at 2^48 is tried first and never chosen",
        vec![(30, garbage.clone()), (31, honest6.clone())],
        false,
    ));
    cases.push(recovery(
        "nothing opens: the accepted generation plus one",
        vec![(30, garbage.clone())],
        false,
    ));
    // A fixed build time, so the vectors do not depend on SOURCE_DATE_EPOCH.
    let build = 1_791_763_200_000;
    for (name, now, date) in [
        ("at build time, offline", build, None),
        ("before build time", build - 1, None),
        ("a 1970 clock with a server that agrees", 0, Some(0)),
        (
            "a day ahead of the server",
            build + 10 * DAY,
            Some(build + 9 * DAY),
        ),
        (
            "more than a day ahead of the server",
            build + 10 * DAY + 1,
            Some(build + 9 * DAY),
        ),
        (
            "more than a day behind the server",
            build + 10 * DAY,
            Some(build + 11 * DAY + 1),
        ),
    ] {
        cases.push(
            json!({"name": name, "op": "clock", "now": now, "build_time": build,
            "server_date": date, "result": result_code(&clock::check_clock(now, build, date))}),
        );
    }
    for (name, seq) in [
        ("five 412 responses on If-Match", vec!["if_match"; 5]),
        ("404 then 412 twice in a row", vec!["if_none_match"; 2]),
        (
            "an If-Match 412 ends a run of 404 then 412",
            vec![
                "if_none_match",
                "if_match",
                "if_none_match",
                "if_match",
                "if_match",
            ],
        ),
    ] {
        let mut counter = RetryCounter::new();
        let decisions: Vec<&str> = seq
            .iter()
            .map(|c| {
                let cond = if *c == "if_match" {
                    PutCondition::IfMatch
                } else {
                    PutCondition::IfNoneMatch
                };
                match counter.precondition_failed(cond) {
                    Retry::Again => "again",
                    Retry::GiveUp => "give_up",
                }
            })
            .collect();
        cases.push(json!({"name": name, "op": "retry", "conditions": seq, "decisions": decisions}));
    }
    write(
        "sync.json",
        "Sync decisions: remote header checks against stored state, the setup check, adopt or \
         push, the 404 cases, recovery, the clock checks, and retry limits. Files use the floor \
         parameters and a fixed KEK, and open with the given vault key.",
        cases,
        Map::new(),
    );
}

// credentials.json

fn credentials_file() {
    let sk = secret_key();
    let base_rng: Vec<Vec<u8>> = vec![
        sk.to_vec(),
        vault_id().to_vec(),
        vault_key().to_vec(),
        kdf_salt().to_vec(),
        wrap_nonce().to_vec(),
        body_nonce().to_vec(),
    ];
    let base_refs: Vec<&[u8]> = base_rng.iter().map(|b| &b[..]).collect();
    let base = create_vault(&mut Replay::new(&base_refs), PASSWORD, TEST, true).unwrap();
    let old_sk = SecretKey::from_bytes(sk);
    let new_pw = "a brand new passphrase";
    let new_sk: [u8; 16] = seq(0x60);
    let change_rng = |n: u8| -> Vec<Vec<u8>> {
        vec![
            seq::<32>(n).to_vec(),
            seq::<16>(n.wrapping_add(0x20)).to_vec(),
            seq::<24>(n.wrapping_add(0x30)).to_vec(),
            seq::<24>(n.wrapping_add(0x50)).to_vec(),
        ]
    };
    let draws = |n: u8| change_rng(n).iter().map(|b| hx(b)).collect::<Vec<_>>();
    let change = |n: u8, pw: PasswordChange<'_>, key: &SecretKey| {
        let parts = change_rng(n);
        let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        change_credentials(
            &mut Replay::new(&refs),
            &base.header,
            &Body::default(),
            pw,
            key,
            TEST,
            true,
        )
        .unwrap()
    };
    let unlock = |file: &[u8], pw: &str, key: &[u8; 16]| {
        json!({"action": "unlock", "file": hx(file), "password_hex": hx(pw.as_bytes()), "secret_key": hx(key),
            "result": result_code(&file::unlock(file, pw, &SecretKey::from_bytes(*key)))})
    };
    let open = |file: &[u8], vk: &[u8; 32]| {
        json!({"action": "open", "file": hx(file), "vault_key": hx(vk),
            "result": result_code(&file::open_file(file, &VaultKey::from_bytes(*vk)))})
    };
    let mut cases = Vec::new();
    cases.push(
        json!({"name": "vault init", "op": "create", "password_hex": hx(PASSWORD.as_bytes()),
        "params": params(&TEST), "test_kdf": true,
        "draws": base_rng.iter().map(|b| hx(b)).collect::<Vec<_>>(),
        "file": hx(&base.file), "release_error": "integrity.test_kdf_in_release"}),
    );
    let c1 = change(0x00, PasswordChange::New(new_pw), &old_sk);
    cases.push(
        json!({"name": "passwd: the old header opens only old revisions", "op": "change",
        "base_file": hx(&base.file), "password_hex": hx(new_pw.as_bytes()), "secret_key": hx(&sk),
        "params": params(&TEST), "test_kdf": true, "draws": draws(0x00), "file": hx(&c1.file),
        "vault_key": hx(c1.vault_key.expose()), "release_error": "integrity.test_kdf_in_release",
        "checks": [
            unlock(&c1.file, new_pw, &sk), unlock(&c1.file, PASSWORD, &sk),
            open(&c1.file, base.vault_key.expose()), open(&base.file, base.vault_key.expose()),
            open(&c1.file, c1.vault_key.expose()),
        ]}),
    );
    let c2 = change(0x80, PasswordChange::Kept(PASSWORD), &old_sk);
    let mut st = base.state.clone();
    st.accept(1, &base.file);
    st.rotate_wrap_nonce(c2.header.wrap_nonce).unwrap();
    st.accept(2, &c2.file);
    let forged = file::seal_file(
        &base.header.with_generation(3),
        &base.vault_key,
        &seq(0x11),
        &Body::default(),
    )
    .unwrap();
    cases.push(json!({"name": "--rekey: the old password still opens the old wrap, refused through the retired list",
        "op": "rekey", "base_file": hx(&base.file), "password_hex": hx(PASSWORD.as_bytes()), "secret_key": hx(&sk),
        "params": params(&TEST), "test_kdf": true, "draws": draws(0x80), "file": hx(&c2.file),
        "state_after": state_json(&st), "forged": hx(&forged),
        "forged_check": result_code(&check_remote(&st, &forged)),
        "release_error": "integrity.test_kdf_in_release",
        "checks": [unlock(&forged, PASSWORD, &sk), unlock(&c2.file, PASSWORD, &sk)]}));
    let c3 = change(
        0x40,
        PasswordChange::Kept(PASSWORD),
        &SecretKey::from_bytes(new_sk),
    );
    cases.push(json!({"name": "--new-secret-key", "op": "change", "base_file": hx(&base.file),
        "password_hex": hx(PASSWORD.as_bytes()), "secret_key": hx(&new_sk), "params": params(&TEST),
        "test_kdf": true, "draws": draws(0x40), "file": hx(&c3.file), "vault_key": hx(c3.vault_key.expose()),
        "release_error": "integrity.test_kdf_in_release",
        "checks": [unlock(&c3.file, PASSWORD, &new_sk), unlock(&c3.file, PASSWORD, &sk)]}));
    let mut synced = base.state.clone();
    synced.accept(1, &base.file);
    let routine = file::seal_file(
        &base.header.with_generation(2),
        &base.vault_key,
        &seq(0x22),
        &Body::default(),
    )
    .unwrap();
    for (name, remote) in [
        ("412 during passwd, the old wrap_nonce: retry", &routine),
        ("412 during passwd, a new wrap_nonce: abort", &c1.file),
    ] {
        let mut c = json!({"name": name, "op": "passwd_conflict", "state": state_json(&synced),
            "remote": hx(remote), "release_error": "integrity.test_kdf_in_release"});
        match check_remote(&synced, remote) {
            Ok(r) => {
                c["result"] = match passwd_conflict(&r) {
                    vault_core::credentials::PasswdConflict::Retry => "retry",
                    vault_core::credentials::PasswdConflict::Abort => "abort",
                }
                .into()
            }
            Err(e) => c["result"] = err(e),
        }
        cases.push(c);
    }
    let rekeyed_state = st.clone();
    let mut c = json!({"name": "412 during passwd, a retired wrap_nonce: integrity error", "op": "passwd_conflict",
        "state": state_json(&rekeyed_state), "remote": hx(&forged), "release_error": "integrity.test_kdf_in_release"});
    c["result"] = result_code(&check_remote(&rekeyed_state, &forged));
    cases.push(c);
    for (name, remote) in [
        ("lost --new-secret-key response: the push landed", &c3.file),
        (
            "lost --new-secret-key response: the push did not land",
            &base.file,
        ),
    ] {
        let h = file::read_header(remote).unwrap();
        let r = resolve_pending_secret_key(&h, PASSWORD, &old_sk, &SecretKey::from_bytes(new_sk));
        let outcome = match r {
            Ok(vault_core::credentials::PendingKeyOutcome::Landed) => "landed".into(),
            Ok(vault_core::credentials::PendingKeyOutcome::NotLanded) => "not_landed".into(),
            Err(e) => err(e),
        };
        cases.push(json!({"name": name, "op": "pending_secret_key", "remote": hx(remote),
            "password_hex": hx(PASSWORD.as_bytes()), "old_secret_key": hx(&sk), "pending_secret_key": hx(&new_sk),
            "result": outcome, "release_error": "integrity.test_kdf_in_release"}));
    }
    write(
        "credentials.json",
        "vault init and credential changes with the test parameters. Draws are the random bytes \
         in the order the client takes them: for vault init the secret key, vault_id, vault key, \
         kdf_salt, wrap_nonce, and body_nonce; for a change the vault key, kdf_salt, wrap_nonce, \
         and body_nonce.",
        cases,
        Map::new(),
    );
}

// tamper.json

/// What a release build reports for a tampered file whose test build result is `test_result`.
/// The header decoder checks the size, the magic, the version, the flags, and the generation, in
/// that order, before the KDF parameters; a header that reaches the KDF check with `test_kdf`
/// set is refused by a release build.
fn release_result(file: &[u8], test_result: &Value) -> Value {
    let Ok(h) = <[u8; HEADER_LEN]>::try_from(file.get(..HEADER_LEN).unwrap_or(&[])) else {
        return "integrity.truncated".into();
    };
    let flags = u16::from_be_bytes([h[7], h[8]]);
    let generation = u64::from_be_bytes(h[25..33].try_into().unwrap());
    if &h[..5] != b"VAULT" {
        "integrity.bad_magic".into()
    } else if h[5..7] != [0, 1] {
        "integrity.format_version".into()
    } else if flags & !1 != 0 {
        "integrity.unknown_flags".into()
    } else if !(1..=1 << 48).contains(&generation) {
        "integrity.generation".into()
    } else if flags & 1 == 1 {
        "integrity.test_kdf_in_release".into()
    } else {
        test_result.clone()
    }
}

fn tamper_file() {
    let sk = SecretKey::from_bytes(secret_key());
    let vk = VaultKey::from_bytes(vault_key());
    let pk = kdf::pw_key(PASSWORD, &TEST, true, &kdf_salt()).unwrap();
    let kek = kek_from_pw_key(&pk, &sk, &vault_id());
    let h = Header::wrap(
        true,
        vault_id(),
        3,
        TEST,
        kdf_salt(),
        wrap_nonce(),
        &kek,
        &vk,
    );
    let body = body_of(&body(0, vec![login(&id(1), NOW, DEV_A, "pw", &[])], vec![]));
    let base = file::seal_file(&h, &vk, &body_nonce(), &body).unwrap();
    let mut cases = Vec::new();
    let len = base.len();
    for (name, offset, xor) in [
        ("magic", 0, 0x01),
        ("format_version high byte", 5, 0x01),
        ("format_version low byte", 6, 0x02),
        ("flags high byte", 7, 0x80),
        ("flags bit 1", 8, 0x02),
        ("flags bit 0 (test_kdf cleared)", 8, 0x01),
        ("vault_id", 9, 0x01),
        ("generation high byte", 25, 0x01),
        ("generation bit 48", 26, 0x01),
        ("generation low byte", 32, 0x01),
        ("m_kib", 36, 0x01),
        ("t", 40, 0x02),
        ("p", 44, 0x02),
        ("kdf_salt", 45, 0x01),
        ("wrap_nonce", 61, 0x01),
        ("wrapped_vk", 85, 0x01),
        ("wrapped_vk tag", 132, 0x80),
        ("body_nonce", 133, 0x01),
        ("body ciphertext", 157, 0x01),
        ("body ciphertext middle", 2000, 0x40),
        ("body tag", len - 1, 0x01),
    ] {
        let mut t = base.clone();
        t[offset] ^= xor;
        let open = result_code(&file::open_file(&t, &vk));
        let unlock = result_code(&file::unlock(&t, PASSWORD, &sk));
        cases.push(json!({"name": name, "offset": offset, "xor": xor,
            "error_open": open, "error_unlock": unlock,
            "release_error_open": release_result(&t, &open), "release_error_unlock": release_result(&t, &unlock)}));
    }
    for (name, t) in [
        ("one byte short", base[..len - 1].to_vec()),
        ("one byte extra", [&base[..], &[0]].concat()),
        ("header only", base[..HEADER_LEN].to_vec()),
    ] {
        let open = result_code(&file::open_file(&t, &vk));
        let unlock = result_code(&file::unlock(&t, PASSWORD, &sk));
        cases.push(json!({"name": name, "file": hx(&t), "error_open": open, "error_unlock": unlock,
            "release_error_open": release_result(&t, &open), "release_error_unlock": release_result(&t, &unlock)}));
    }
    let mut extra = Map::new();
    extra.insert("file".into(), hx(&base).into());
    extra.insert("password_hex".into(), hx(PASSWORD.as_bytes()).into());
    extra.insert("secret_key".into(), hx(&secret_key()).into());
    extra.insert("vault_key".into(), hx(&vault_key()).into());
    extra.insert("kek".into(), hx(kek.expose()).into());
    write(
        "tamper.json",
        "A vault file with the test parameters, with one byte XOR-ed per header field and in the \
         body (offset and xor), or a whole replacement file. error_open is the result of opening \
         with the vault key; error_unlock of opening with the password and secret key. Release \
         builds expect the release_ fields.",
        cases,
        extra,
    );
}

// malformed.json

fn malformed_file() {
    let vid = vault_id();
    let good = floor_header(vid, 3, wrap_nonce());
    let mut cases = Vec::new();
    let empty = Body::default().to_json();
    let pt = |json: &[u8]| plaintext(json, json.len() as u32, 4096);
    let mut bad_header = |name: &str, h: Header| {
        let f = raw_file(&h.encode(), &vid, &pt(&empty));
        cases.push((name.to_owned(), f));
    };
    bad_header("generation 0", good.with_generation(0));
    bad_header("generation 2^48 + 1", good.with_generation((1 << 48) + 1));
    let mut flags = good.encode();
    flags[8] |= 0x02;
    let f = raw_file(&flags, &vid, &pt(&empty));
    cases.push(("unknown flags".into(), f));
    let hb = good.encode();
    let raw = |pt: Vec<u8>| raw_file(&hb, &vid, &pt);
    let mut padded = pt(&empty);
    padded[4095] = 1;
    cases.push(("non-zero padding".into(), raw(padded)));
    cases.push((
        "a length past the end".into(),
        raw(plaintext(&empty, 4093, 4096)),
    ));
    cases.push((
        "a plaintext that is not a multiple of 4,096".into(),
        raw(plaintext(&empty, empty.len() as u32, 4097)),
    ));
    let item = |id: &str| serde_json::to_string(&login(id, 5, DEV_A, "pw", &[])).unwrap();
    let doc = |items: &str| format!(r#"{{"horizon":0,"items":[{items}],"tombstones":[],"v":1}}"#);
    for (name, json) in [
        (
            "duplicate item IDs",
            doc(&format!("{},{}", item(&id(1)), item(&id(1)))),
        ),
        (
            "an ID in items and tombstones",
            format!(
                r#"{{"horizon":0,"items":[{}],"tombstones":[{}],"v":1}}"#,
                item(&id(1)),
                serde_json::to_string(&tomb(&id(1), 1, DEV_A)).unwrap()
            ),
        ),
        (
            "duplicate JSON keys",
            r#"{"horizon":0,"items":[],"tombstones":[],"v":1,"v":1}"#.to_owned(),
        ),
        (
            "a float",
            r#"{"horizon":0.0,"items":[],"tombstones":[],"v":1}"#.to_owned(),
        ),
        (
            "an exponent",
            r#"{"horizon":1e3,"items":[],"tombstones":[],"v":1}"#.to_owned(),
        ),
        (
            "a number of 2^53",
            r#"{"horizon":9007199254740992,"items":[],"tombstones":[],"v":1}"#.to_owned(),
        ),
        (
            "a negative number",
            r#"{"horizon":0,"items":[],"tombstones":[],"v":1,"x":-1}"#.to_owned(),
        ),
        (
            "-0",
            r#"{"horizon":0,"items":[],"tombstones":[],"v":1,"x":-0}"#.to_owned(),
        ),
        (
            "an origin that is not an object",
            doc(&item(&id(1)).replace(r#""name":"n""#, r#""name":"n","origin":"x""#)),
        ),
        (
            "an origin that is not an object, on a note",
            doc(
                &serde_json::to_string(&with(note(&id(1), 5, DEV_A, &[]), "origin", json!("x")))
                    .unwrap(),
            ),
        ),
        (
            "an upper-case UUID",
            doc(&item(&id(1).replace("4000", "4ABC"))),
        ),
        (
            "nesting past 32",
            format!(
                r#"{{"horizon":0,"items":[],"tombstones":[],"v":1,"x":{}0{}}}"#,
                "[".repeat(32),
                "]".repeat(32)
            ),
        ),
        (
            "nesting of exactly 32",
            format!(
                r#"{{"horizon":0,"items":[],"tombstones":[],"v":1,"x":{}0{}}}"#,
                "[".repeat(31),
                "]".repeat(31)
            ),
        ),
        ("a byte order mark", format!("\u{feff}{}", doc(""))),
        (
            "v 0",
            r#"{"horizon":0,"items":[],"tombstones":[],"v":0}"#.to_owned(),
        ),
        (
            "a missing key",
            r#"{"horizon":0,"items":[],"v":1}"#.to_owned(),
        ),
        (
            "an empty name",
            doc(&item(&id(1)).replace(r#""name":"n""#, r#""name":"""#)),
        ),
        (
            "eleven history entries",
            doc(&serde_json::to_string(&login(
                &id(1),
                5,
                DEV_A,
                "pw",
                &(0..11)
                    .map(|i| {
                        (
                            ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"][i],
                            1,
                        )
                    })
                    .collect::<Vec<_>>(),
            ))
            .unwrap()),
        ),
        (
            "a lone surrogate",
            r#"{"horizon":0,"items":[],"tombstones":[],"v":1,"x":"\ud800"}"#.to_owned(),
        ),
    ] {
        cases.push((name.to_owned(), raw(pt(json.as_bytes()))));
    }
    let vk = VaultKey::from_bytes(vault_key());
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, f)| json!({"name": name, "file": hx(&f), "result": result_code(&file::open_file(&f, &vk))}))
        .collect();
    let mut extra = Map::new();
    extra.insert("vault_key".into(), hx(&vault_key()).into());
    write(
        "malformed.json",
        "Authenticated files, at the floor parameters, that break a decode rule; open each with \
         the vault key.",
        cases,
        extra,
    );
}

// setup.json

fn setup_file() {
    let tok = Token::from_bytes(seq(0x30));
    let tok_text = token::encode(&tok).to_string();
    let fp: [u8; 32] = seq(0xc0);
    let mut cases = Vec::new();
    for (name, url, fp) in [
        ("https with fp", "https://vault.example:8443/base", Some(fp)),
        ("https without fp", "https://vault.example", None),
        ("loopback http drops fp", "http://[::1]:8080", Some(fp)),
        (
            "a path with a space and a plus",
            "https://vault.example/a b+c?q=1",
            None,
        ),
        ("refused: non-loopback http", "http://vault.example", None),
    ] {
        let mut c = json!({"name": name, "op": "format", "url": url, "token": hx(tok.expose()), "fp": fp.map(|f| hx(&f))});
        match setup::format_setup(url, &tok, fp.as_ref()) {
            Ok(t) => c["text"] = t.as_str().into(),
            Err(e) => c["error"] = err(e),
        }
        cases.push(c);
    }
    let enc = |u: &str| {
        u.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    let text =
        |u: &str, extra: &str| format!("vault://setup?url={}&token={tok_text}{extra}", enc(u));
    let fp_param = format!("&fp={}", hx(&fp));
    for (name, input) in [
        ("[::1]", text("http://[::1]:8080", "")),
        ("127.1 parses to 127.0.0.1", text("http://127.1:8080", "")),
        ("LOCALHOST lower-cased", text("http://LOCALHOST", "")),
        (
            "localhost. is not loopback",
            text("http://localhost.:8080", ""),
        ),
        ("user information", text("https://user@vault.example", "")),
        ("a fragment", text("https://vault.example/#frag", "")),
        ("an empty fragment", text("https://vault.example/#", "")),
        ("https without fp", text("https://vault.example", "")),
        ("https with fp", text("https://vault.example", &fp_param)),
        (
            "an unknown parameter",
            text("https://vault.example", "&future=1&x"),
        ),
        ("non-loopback http", text("http://vault.example", "")),
        ("fp on loopback http", text("http://127.0.0.1", &fp_param)),
        (
            "upper-case fp",
            text(
                "https://vault.example",
                &fp_param.to_uppercase().replace("&FP=", "&fp="),
            ),
        ),
        (
            "a repeated url",
            text("https://a.example", "&url=https%3A%2F%2Fb.example"),
        ),
        (
            "plus is literal",
            "vault://setup?url=https%3A%2F%2Fvault.example%2Fa+b&token=".to_owned() + &tok_text,
        ),
        (
            "a bad percent escape",
            format!("vault://setup?url=%zz&token={tok_text}"),
        ),
        (
            "a lower-case token",
            text("https://vault.example", "").replace(&tok_text, &tok_text.to_ascii_lowercase()),
        ),
        (
            "missing token",
            format!("vault://setup?url={}", enc("https://vault.example")),
        ),
        ("not setup text", "https://vault.example".to_owned()),
        ("host *", text("https://*", "")),
        ("host *.example", text("https://*.example", "")),
        ("_ in a label", text("https://vault_1.example", "")),
        ("an empty label", text("https://a..b", "")),
        ("a trailing dot", text("https://vault.example.", "")),
        (
            "a 64-character label",
            text(&format!("https://{}.example", "a".repeat(64)), ""),
        ),
        (
            "a 63-character label",
            text(&format!("https://{}.example", "a".repeat(63)), ""),
        ),
        ("an xn-- host", text("https://xn--bcher-kva.example", "")),
        (
            "a Unicode host parses to xn--",
            text("https://b\u{fc}cher.example", ""),
        ),
        (
            "upper case and a hyphen",
            text("https://VAULT-1.Example:8443", ""),
        ),
        ("an IPv6 host", text("https://[fe80::1]:8443", "")),
        (
            "fullwidth \u{ff0a} maps to *",
            text("https://\u{ff0a}.example", ""),
        ),
        (
            "upper-case Unicode is lower-cased",
            text("https://B\u{dc}CHER.example", ""),
        ),
        ("an empty host", text("https://", "")),
        ("a percent-encoded *", text("https://%2a.example", "")),
        (
            "a label with a leading hyphen",
            text("https://-a.example", ""),
        ),
    ] {
        let mut c = json!({"name": name, "op": "parse", "input": input});
        match setup::parse_setup(&input) {
            Ok(s) => {
                c["url"] = s.url.clone().into();
                c["token"] = hx(s.token.expose()).into();
                c["fp"] = s.fp.map(|f| hx(&f)).into();
            }
            Err(e) => c["error"] = err(e),
        }
        cases.push(c);
    }
    let der = b"a certificate's DER bytes".to_vec();
    let real = setup::cert_fingerprint(&der);
    for (name, pin, cert) in [
        ("the pinned certificate", real, der.clone()),
        (
            "a certificate that fails the pin",
            real,
            b"another certificate".to_vec(),
        ),
    ] {
        cases.push(json!({"name": name, "op": "pin", "fp": hx(&pin), "cert_der": hx(&cert), "matches": setup::pin_matches(&pin, &cert)}));
    }
    write(
        "setup.json",
        "Setup text vault://setup?url=...&token=...&fp=...: formatting, parsing with WHATWG URL \
         rules for the server URL, and the certificate pin.",
        cases,
        Map::new(),
    );
}
