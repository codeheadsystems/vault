//! Checks every case in `spec/vectors/` against the library. A build that refuses the test KDF
//! parameters checks the `release_` expectations of cases that use them.

use serde_json::Value;
use std::collections::BTreeMap;
use vault_core::body::Body;
use vault_core::header::Header;
use vault_core::kdf::{KdfParams, TEST_KDF_ALLOWED};
use vault_core::secret::{SecretKey, Token, VaultKey};
use vault_core::sync::{
    Accepted, PutCondition, Recovery, Retry, RetryCounter, SyncAction, SyncState, WrapStatus,
};
use vault_core::{Error, Result, clock, credentials, edit, file, kdf, keys, merge, sync};

fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases(name: &str) -> Vec<Value> {
    load(name)["cases"].as_array().unwrap().clone()
}

fn s<'a>(c: &'a Value, k: &str) -> &'a str {
    c[k].as_str()
        .unwrap_or_else(|| panic!("{k} in {}", c["name"]))
}

fn b(c: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(c, k)).unwrap()
}

fn arr<const N: usize>(c: &Value, k: &str) -> [u8; N] {
    b(c, k).try_into().unwrap()
}

fn u(c: &Value, k: &str) -> u64 {
    c[k].as_u64().unwrap()
}

fn pw(c: &Value) -> String {
    String::from_utf8(b(c, "password_hex")).unwrap()
}

fn params(c: &Value) -> KdfParams {
    let p = &c["params"];
    KdfParams {
        m_kib: p["m_kib"].as_u64().unwrap() as u32,
        t: p["t"].as_u64().unwrap() as u32,
        p: p["p"].as_u64().unwrap() as u32,
    }
}

fn code<T>(r: &Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code().into(),
    }
}

/// The expected error for this build: `release_error` (or `release_<key>`) when the case uses the
/// test parameters and this build refuses them.
fn expected(c: &Value, key: &str) -> Option<String> {
    if !TEST_KDF_ALLOWED {
        for k in [format!("release_{key}"), "release_error".to_owned()] {
            if let Some(v) = c.get(&k) {
                return Some(v.as_str().unwrap().to_owned());
            }
        }
    }
    c.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn uses_test_kdf(c: &Value) -> bool {
    !TEST_KDF_ALLOWED && c.get("release_error").is_some()
}

fn body(v: &Value) -> Body {
    Body::from_json(&serde_json::to_vec(v).unwrap()).unwrap()
}

fn body_value(b: &Body) -> Value {
    serde_json::from_slice(&b.to_json()).unwrap()
}

/// Items and tombstones as maps keyed by id, and the rest of the body as given.
fn keyed(v: &Value) -> (BTreeMap<String, Value>, BTreeMap<String, Value>, Value) {
    let by_id = |k: &str| {
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|x| (x["id"].as_str().unwrap().to_owned(), x.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let mut rest = v.clone();
    rest.as_object_mut().unwrap().remove("items");
    rest.as_object_mut().unwrap().remove("tombstones");
    (by_id("items"), by_id("tombstones"), rest)
}

fn state(v: &Value) -> SyncState {
    SyncState {
        vault_id: arr(v, "vault_id"),
        accepted: v["accepted"].as_object().map(|a| Accepted {
            generation: a["generation"].as_u64().unwrap(),
            file_hash: hex::decode(a["file_hash"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        }),
        wrap_nonce: arr(v, "wrap_nonce"),
        retired_wrap_nonces: v["retired_wrap_nonces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                hex::decode(n.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect(),
    }
}

#[test]
fn secret_key() {
    for c in cases("secret-key.json") {
        match s(&c, "op") {
            "encode" => {
                let sk = SecretKey::from_bytes(arr(&c, "secret_key"));
                assert_eq!(
                    hex::encode(vault_core::secret_key_text::check_value(&sk)),
                    s(&c, "check")
                );
                assert_eq!(
                    vault_core::secret_key_text::encode(&sk).as_str(),
                    s(&c, "text")
                );
            }
            "decode" => {
                let r = vault_core::secret_key_text::decode(s(&c, "input"));
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap(), "{}", c["name"]),
                    None => assert_eq!(hex::encode(r.unwrap().expose()), s(&c, "secret_key")),
                }
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn token() {
    for c in cases("token.json") {
        match s(&c, "op") {
            "encode" => {
                let t = Token::from_bytes(arr(&c, "token"));
                assert_eq!(vault_core::token::encode(&t).as_str(), s(&c, "text"));
                assert_eq!(
                    hex::encode(vault_core::token::stored_hash(&t)),
                    s(&c, "stored_hash")
                );
            }
            "decode" => {
                let r = vault_core::token::decode(s(&c, "input"));
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap()),
                    None => {
                        let t = r.unwrap();
                        assert_eq!(hex::encode(t.expose()), s(&c, "token"));
                        assert_eq!(
                            hex::encode(vault_core::token::stored_hash(&t)),
                            s(&c, "stored_hash")
                        );
                    }
                }
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn etag() {
    for c in cases("etag.json") {
        assert_eq!(sync::etag(&b(&c, "bytes")), s(&c, "etag"));
    }
}

#[test]
fn kdf_vectors() {
    for c in cases("kdf.json") {
        let name = &c["name"];
        match s(&c, "op") {
            "nfkc" => {
                assert_eq!(
                    s(&c, "password").as_bytes(),
                    b(&c, "password_hex").as_slice()
                );
                assert_eq!(
                    hex::encode(kdf::nfkc(s(&c, "password")).as_bytes()),
                    s(&c, "nfkc_hex")
                );
            }
            "validate_new_password" => {
                assert_eq!(
                    code(&kdf::validate_new_password(&pw(&c))),
                    s(&c, "result"),
                    "{name}"
                );
            }
            "derive" => {
                let r = kdf::pw_key(
                    &pw(&c),
                    &params(&c),
                    c["test_kdf"].as_bool().unwrap(),
                    &arr(&c, "kdf_salt"),
                );
                match expected(&c, "error") {
                    Some(e) => assert_eq!(code(&r), e, "{name}"),
                    None => {
                        let pk = r.unwrap();
                        assert_eq!(hex::encode(pk.as_ref()), s(&c, "pw_key"), "{name}");
                        let kek = keys::kek_from_pw_key(
                            &pk,
                            &SecretKey::from_bytes(arr(&c, "secret_key")),
                            &arr(&c, "vault_id"),
                        );
                        assert_eq!(hex::encode(kek.expose()), s(&c, "kek"), "{name}");
                    }
                }
            }
            "check_params" => {
                let key = if TEST_KDF_ALLOWED {
                    "test_build"
                } else {
                    "release_build"
                };
                assert_eq!(
                    code(&params(&c).check(c["test_kdf"].as_bool().unwrap())),
                    s(&c, key),
                    "{name}"
                );
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn vault_file() {
    for c in cases("vault-file.json") {
        let name = &c["name"];
        let vk = VaultKey::from_bytes(arr(&c, "vault_key"));
        match s(&c, "op") {
            "seal" => {
                let f = b(&c, "file");
                assert_eq!(sync::etag(&f), s(&c, "etag"));
                if uses_test_kdf(&c) {
                    assert_eq!(
                        code(&file::unlock(
                            &f,
                            &pw(&c),
                            &SecretKey::from_bytes(arr(&c, "secret_key"))
                        )),
                        s(&c, "release_error")
                    );
                    continue;
                }
                let test_kdf = c["test_kdf"].as_bool().unwrap();
                let pk = kdf::pw_key(&pw(&c), &params(&c), test_kdf, &arr(&c, "kdf_salt")).unwrap();
                assert_eq!(hex::encode(pk.as_ref()), s(&c, "pw_key"));
                let kek = keys::kek_from_pw_key(
                    &pk,
                    &SecretKey::from_bytes(arr(&c, "secret_key")),
                    &arr(&c, "vault_id"),
                );
                assert_eq!(hex::encode(kek.expose()), s(&c, "kek"));
                let h = Header::wrap(
                    test_kdf,
                    arr(&c, "vault_id"),
                    u(&c, "generation"),
                    params(&c),
                    arr(&c, "kdf_salt"),
                    arr(&c, "wrap_nonce"),
                    &kek,
                    &vk,
                );
                assert_eq!(hex::encode(h.wrap_ad()), s(&c, "wrap_ad"));
                assert_eq!(hex::encode(h.wrapped_vk), s(&c, "wrapped_vk"));
                assert_eq!(hex::encode(h.encode()), s(&c, "header"));
                assert_eq!(
                    hex::encode(keys::body_key(&vk, &arr(&c, "vault_id")).expose()),
                    s(&c, "body_key")
                );
                let bd = Body::from_json(s(&c, "body_json").as_bytes()).unwrap();
                assert_eq!(
                    String::from_utf8(bd.to_json().to_vec()).unwrap(),
                    s(&c, "body_json")
                );
                let sealed = file::seal_file(&h, &vk, &arr(&c, "body_nonce"), &bd).unwrap();
                assert_eq!(hex::encode(&sealed), s(&c, "file"), "{name}");
                assert_eq!(
                    sealed.len() - 133 - 24 - 16,
                    u(&c, "plaintext_len") as usize
                );
                let un = file::unlock(&f, &pw(&c), &SecretKey::from_bytes(arr(&c, "secret_key")))
                    .unwrap();
                assert!(un.body == bd);
            }
            "open" => {
                let (_, bd) = file::open_file(&b(&c, "file"), &vk).unwrap();
                assert_eq!(
                    String::from_utf8(bd.to_json().to_vec()).unwrap(),
                    s(&c, "body_json")
                );
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn merge_vectors() {
    for c in cases("merge.json") {
        let name = &c["name"];
        match s(&c, "op") {
            "merge" => {
                let m = merge::merge(&body(&c["local"]), &body(&c["remote"]), u(&c, "now"));
                assert_eq!(keyed(&body_value(&m.body)), keyed(&c["result"]), "{name}");
                let mut got: Vec<Value> = m
                    .expired
                    .iter()
                    .map(|i| {
                        serde_json::from_slice(&vault_core::json::to_vec(&i.to_value())).unwrap()
                    })
                    .collect();
                let mut want = c["expired"].as_array().unwrap().clone();
                let by_id = |v: &Value| v["id"].as_str().unwrap().to_owned();
                got.sort_by_key(by_id);
                want.sort_by_key(by_id);
                assert_eq!(got, want, "{name}");
            }
            "edit" => {
                let mut bd = body(&c["body"]);
                let now = u(&c, "now");
                let dev: [u8; 16] = arr(&c, "device_id");
                let args = &c["args"];
                let fields = |item: &Value| {
                    let one = body(
                        &serde_json::json!({"v": 1, "horizon": 0, "items": [item], "tombstones": []}),
                    );
                    one.items[0].fields().unwrap().clone()
                };
                let r = match s(&c, "action") {
                    "update" => {
                        edit::update_item(&mut bd, s(args, "id"), fields(&args["item"]), now, &dev)
                    }
                    "import" => edit::import_item(
                        &mut bd,
                        &mut Replay(b(args, "rng")),
                        s(&args["item"], "type"),
                        fields(&args["item"]),
                        now,
                        &dev,
                    )
                    .map(|_| ()),
                    "delete" => edit::delete_item(&mut bd, s(args, "id"), now, &dev),
                    "restore" => {
                        let old = body(
                            &serde_json::json!({"v": 1, "horizon": 0, "items": [args["item"]], "tombstones": []}),
                        );
                        edit::restore_item(&mut bd, &old.items[0], now, &dev);
                        Ok(())
                    }
                    a => panic!("{a}"),
                };
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap(), "{name}"),
                    None => {
                        r.unwrap();
                        assert_eq!(keyed(&body_value(&bd)), keyed(&c["result"]), "{name}");
                    }
                }
            }
            op => panic!("{op}"),
        }
    }
}

struct Replay(Vec<u8>);

impl vault_core::rng::Rng for Replay {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

#[test]
fn sync_vectors() {
    for c in cases("sync.json") {
        let name = &c["name"];
        match s(&c, "op") {
            "check_remote" => {
                let f = b(&c, "file");
                let r = sync::check_remote(&state(&c["state"]), &f);
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap(), "{name}"),
                    None => {
                        let r = r.unwrap();
                        let w = match r.wrap {
                            WrapStatus::Current => "current",
                            WrapStatus::Changed => "changed",
                        };
                        assert_eq!(w, s(&c, "wrap"), "{name}");
                        assert_eq!(r.etag, s(&c, "etag"));
                        let vk = VaultKey::from_bytes(arr(&c, "vault_key"));
                        assert_eq!(code(&file::open_file(&f, &vk)), s(&c, "open"), "{name}");
                    }
                }
            }
            "check_setup" => {
                let kit: Option<[u8; 16]> =
                    c["kit_vault_id"].as_str().map(|_| arr(&c, "kit_vault_id"));
                assert_eq!(
                    code(&sync::check_remote_for_setup(&b(&c, "file"), kit.as_ref())),
                    s(&c, "result"),
                    "{name}"
                );
            }
            "adopt" => {
                let remote = body(&c["remote"]);
                let merged = merge::merge(&body(&c["local"]), &remote, u(&c, "now")).body;
                let got = match sync::adopt_or_push(&merged, &remote, u(&c, "remote_generation"))
                    .unwrap()
                {
                    SyncAction::Adopt => serde_json::json!({"action": "adopt"}),
                    SyncAction::Push { generation } => {
                        serde_json::json!({"action": "push", "generation": generation})
                    }
                };
                assert_eq!(got, c["result"], "{name}");
            }
            "not_found" => {
                let st = c["state"].as_object().map(|_| state(&c["state"]));
                let got = match sync::on_not_found(st.as_ref()).unwrap() {
                    sync::NotFoundAction::NoVault => serde_json::json!({"action": "no_vault"}),
                    sync::NotFoundAction::Push { generation } => {
                        serde_json::json!({"action": "push", "generation": generation, "if_none_match": "*"})
                    }
                };
                assert_eq!(got, c["result"], "{name}");
            }
            "recovery" => {
                let st = state(&c["state"]);
                let revs: Vec<(u64, Vec<u8>)> = c["revisions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| (r["id"].as_u64().unwrap(), b(r, "file")))
                    .collect();
                let refs: Vec<(u64, &[u8])> = revs.iter().map(|(i, f)| (*i, &f[..])).collect();
                let plan =
                    sync::plan_recovery(&st, &refs, c["past_unknown_wraps"].as_bool().unwrap());
                let want: Vec<u64> = c["plan_revisions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap())
                    .collect();
                match plan {
                    Recovery::CredentialChange(ids) => {
                        assert_eq!(s(&c, "plan"), "credential_change");
                        assert_eq!(ids, want);
                    }
                    Recovery::Candidates(ids) => {
                        assert_eq!(s(&c, "plan"), "candidates");
                        assert_eq!(ids, want);
                        let vk = VaultKey::from_bytes(arr(&c, "vault_key"));
                        let chosen = ids.iter().find_map(|i| {
                            let f = &revs.iter().find(|(j, _)| j == i).unwrap().1;
                            file::open_file(f, &vk)
                                .ok()
                                .map(|(h, _)| (*i, h.generation))
                        });
                        assert_eq!(chosen.map(|(i, _)| i), c["chosen"].as_u64(), "{name}");
                        assert_eq!(
                            sync::recovery_generation(&st, chosen.map(|(_, g)| g)).unwrap(),
                            u(&c, "push_generation")
                        );
                    }
                }
            }
            "clock" => {
                let r = clock::check_clock(
                    u(&c, "now"),
                    u(&c, "build_time"),
                    c["server_date"].as_u64(),
                );
                assert_eq!(code(&r), s(&c, "result"), "{name}");
            }
            "retry" => {
                let mut counter = RetryCounter::new();
                for (cond, want) in c["conditions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(c["decisions"].as_array().unwrap())
                {
                    let cond = if cond == "if_match" {
                        PutCondition::IfMatch
                    } else {
                        PutCondition::IfNoneMatch
                    };
                    let got = match counter.precondition_failed(cond) {
                        Retry::Again => "again",
                        Retry::GiveUp => "give_up",
                    };
                    assert_eq!(got, want.as_str().unwrap(), "{name}");
                }
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn credentials_vectors() {
    for c in cases("credentials.json") {
        let name = &c["name"];
        let release = !TEST_KDF_ALLOWED;
        match s(&c, "op") {
            "create" | "change" | "rekey" if release => {
                assert_eq!(
                    code(&file::read_header(&b(&c, "file"))),
                    s(&c, "release_error"),
                    "{name}"
                );
            }
            "create" => {
                let draws: Vec<u8> = c["draws"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|d| hex::decode(d.as_str().unwrap()).unwrap())
                    .collect();
                let v = credentials::create_vault(&mut Replay(draws), &pw(&c), params(&c), true)
                    .unwrap();
                assert_eq!(hex::encode(&v.file), s(&c, "file"), "{name}");
            }
            "change" | "rekey" => {
                let base = file::read_header(&b(&c, "base_file")).unwrap();
                let draws: Vec<u8> = c["draws"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|d| hex::decode(d.as_str().unwrap()).unwrap())
                    .collect();
                let p = pw(&c);
                let ch = credentials::change_credentials(
                    &mut Replay(draws),
                    &base,
                    &Body::default(),
                    credentials::PasswordChange::Kept(&p),
                    &SecretKey::from_bytes(arr(&c, "secret_key")),
                    params(&c),
                    true,
                )
                .unwrap();
                assert_eq!(hex::encode(&ch.file), s(&c, "file"), "{name}");
                if s(&c, "op") == "rekey" {
                    assert_eq!(
                        code(&sync::check_remote(
                            &state(&c["state_after"]),
                            &b(&c, "forged")
                        )),
                        s(&c, "forged_check")
                    );
                }
                for k in c["checks"].as_array().unwrap() {
                    let f = b(k, "file");
                    let r = match s(k, "action") {
                        "unlock" => code(&file::unlock(
                            &f,
                            &pw(k),
                            &SecretKey::from_bytes(arr(k, "secret_key")),
                        )),
                        "open" => code(&file::open_file(
                            &f,
                            &VaultKey::from_bytes(arr(k, "vault_key")),
                        )),
                        a => panic!("{a}"),
                    };
                    assert_eq!(r, s(k, "result"), "{name}");
                }
            }
            "passwd_conflict" => {
                let r = sync::check_remote(&state(&c["state"]), &b(&c, "remote"));
                let got = match r {
                    Ok(r) => match credentials::passwd_conflict(&r) {
                        credentials::PasswdConflict::Retry => "retry".to_owned(),
                        credentials::PasswdConflict::Abort => "abort".to_owned(),
                    },
                    Err(e) => e.code().to_owned(),
                };
                assert_eq!(got, expected(&c, "result").unwrap(), "{name}");
            }
            "pending_secret_key" => {
                let h = file::read_header(&b(&c, "remote"));
                let got = h.and_then(|h| {
                    credentials::resolve_pending_secret_key(
                        &h,
                        &pw(&c),
                        &SecretKey::from_bytes(arr(&c, "old_secret_key")),
                        &SecretKey::from_bytes(arr(&c, "pending_secret_key")),
                    )
                });
                let got = match got {
                    Ok(credentials::PendingKeyOutcome::Landed) => "landed".to_owned(),
                    Ok(credentials::PendingKeyOutcome::NotLanded) => "not_landed".to_owned(),
                    Err(e) => e.code().to_owned(),
                };
                assert_eq!(got, expected(&c, "result").unwrap(), "{name}");
            }
            op => panic!("{op}"),
        }
    }
}

#[test]
fn tamper() {
    let top = load("tamper.json");
    let base = b(&top, "file");
    let vk = VaultKey::from_bytes(arr(&top, "vault_key"));
    let sk = SecretKey::from_bytes(arr(&top, "secret_key"));
    let password = pw(&top);
    for c in cases("tamper.json") {
        let f = match c.get("file") {
            Some(_) => b(&c, "file"),
            None => {
                let mut t = base.clone();
                t[u(&c, "offset") as usize] ^= u(&c, "xor") as u8;
                t
            }
        };
        let (open_key, unlock_key) = if TEST_KDF_ALLOWED {
            ("error_open", "error_unlock")
        } else {
            ("release_error_open", "release_error_unlock")
        };
        assert_eq!(
            code(&file::open_file(&f, &vk)),
            s(&c, open_key),
            "{}",
            c["name"]
        );
        assert_eq!(
            code(&file::unlock(&f, &password, &sk)),
            s(&c, unlock_key),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn malformed() {
    let top = load("malformed.json");
    let vk = VaultKey::from_bytes(arr(&top, "vault_key"));
    for c in cases("malformed.json") {
        assert_eq!(
            code(&file::open_file(&b(&c, "file"), &vk)),
            s(&c, "result"),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn setup() {
    for c in cases("setup.json") {
        let name = &c["name"];
        match s(&c, "op") {
            "format" => {
                let fp: Option<[u8; 32]> = c["fp"].as_str().map(|_| arr(&c, "fp"));
                let r = vault_core::setup::format_setup(
                    s(&c, "url"),
                    &Token::from_bytes(arr(&c, "token")),
                    fp.as_ref(),
                );
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap(), "{name}"),
                    None => assert_eq!(r.unwrap().as_str(), s(&c, "text"), "{name}"),
                }
            }
            "parse" => {
                let r = vault_core::setup::parse_setup(s(&c, "input"));
                match c.get("error") {
                    Some(e) => assert_eq!(code(&r), e.as_str().unwrap(), "{name}"),
                    None => {
                        let p = r.unwrap();
                        assert_eq!(p.url, s(&c, "url"), "{name}");
                        assert_eq!(hex::encode(p.token.expose()), s(&c, "token"));
                        assert_eq!(p.fp.map(hex::encode), c["fp"].as_str().map(str::to_owned));
                    }
                }
            }
            "pin" => {
                let fp: [u8; 32] = arr(&c, "fp");
                assert_eq!(
                    hex::encode(vault_core::setup::cert_fingerprint(&b(&c, "cert_der")))
                        == s(&c, "fp"),
                    c["matches"].as_bool().unwrap()
                );
                assert_eq!(
                    vault_core::setup::pin_matches(&fp, &b(&c, "cert_der")),
                    c["matches"].as_bool().unwrap(),
                    "{name}"
                );
            }
            op => panic!("{op}"),
        }
    }
}

/// Every file in the spec's table exists and has cases.
#[test]
fn every_file_is_present() {
    for f in [
        "secret-key.json",
        "kdf.json",
        "vault-file.json",
        "merge.json",
        "sync.json",
        "credentials.json",
        "tamper.json",
        "malformed.json",
        "setup.json",
        "token.json",
        "etag.json",
    ] {
        assert!(!cases(f).is_empty(), "{f}");
        assert!(load(f)["description"].is_string(), "{f}");
    }
}

#[allow(dead_code)]
fn _error_is_used(e: Error) -> &'static str {
    e.code()
}
