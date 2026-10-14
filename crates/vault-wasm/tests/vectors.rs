//! The spec vectors through the WASM bindings, under Node: secret key text, setup text, file
//! opening and unlocking (with a build's release expectations, since the bindings never accept the
//! test KDF parameters), the sync header checks through a sync procedure, and every autofill
//! case. Run with `cargo test -p vault-wasm --target wasm32-unknown-unknown`.

#![cfg(target_arch = "wasm32")]

use js_sys::{Function, Reflect, Uint8Array};
use serde_json::{Value, json};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::body::Body;
use vault_core::header::Header;
use vault_core::kdf::FLOOR;
use vault_core::secret::{Kek, VaultKey};
use vault_core::sync::SyncState;
use vault_wasm::{Procedure, Session};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

fn cases(file: &str) -> Vec<Value> {
    let text = match file {
        "secret-key" => include_str!("../../../spec/vectors/secret-key.json"),
        "setup" => include_str!("../../../spec/vectors/setup.json"),
        "tamper" => include_str!("../../../spec/vectors/tamper.json"),
        "malformed" => include_str!("../../../spec/vectors/malformed.json"),
        "vault-file" => include_str!("../../../spec/vectors/vault-file.json"),
        "credentials" => include_str!("../../../spec/vectors/credentials.json"),
        "sync" => include_str!("../../../spec/vectors/sync.json"),
        "autofill" => include_str!("../../../spec/vectors/autofill.json"),
        _ => panic!("{file}"),
    };
    let v: Value = serde_json::from_str(text).unwrap();
    let mut out = v["cases"].as_array().unwrap().clone();
    // Top-level inputs travel with each case.
    for c in &mut out {
        for (k, x) in v.as_object().unwrap() {
            if k != "cases" && c.get(k).is_none() {
                c[k] = x.clone();
            }
        }
    }
    out
}

fn h(c: &Value, k: &str) -> Vec<u8> {
    hex::decode(c[k].as_str().unwrap_or_else(|| panic!("{k}"))).unwrap()
}

fn s(c: &Value, k: &str) -> String {
    c[k].as_str().unwrap_or_else(|| panic!("{k}")).to_owned()
}

fn code(e: JsValue) -> String {
    Reflect::get(&e, &"code".into())
        .unwrap()
        .as_string()
        .unwrap_or_else(|| "no code".into())
}

fn outcome<T>(r: Result<T, JsValue>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => code(e),
    }
}

fn bytes(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}

fn js(v: &Value) -> JsValue {
    js_sys::JSON::parse(&v.to_string()).unwrap()
}

fn json_of(v: &JsValue) -> Value {
    serde_json::from_str(&js_sys::JSON::stringify(v).unwrap().as_string().unwrap()).unwrap()
}

/// A state whose local file is `file`, for opening; the sync fields are placeholders.
fn state_with(file: Vec<u8>) -> String {
    let s = ClientState::new(
        SyncState {
            vault_id: [0; 16],
            accepted: None,
            wrap_nonce: [0; 24],
            retired_wrap_nonces: Vec::new(),
        },
        file,
        SecretKeyStore::File,
    );
    String::from_utf8(s.to_json()).unwrap()
}

/// What a build without the test KDF parameters expects: the `release_` field when present.
fn expected(c: &Value, key: &str) -> String {
    c.get(format!("release_{key}"))
        .or_else(|| {
            c.get("release_error")
                .filter(|_| key == "error" || key == "result")
        })
        .or_else(|| c.get(key))
        .and_then(Value::as_str)
        .unwrap_or("ok")
        .to_owned()
}

#[wasm_bindgen_test]
fn secret_key_text() {
    for c in cases("secret-key") {
        let name = s(&c, "name");
        if c["op"] == "encode" {
            let text = vault_wasm::encode_secret_key(&bytes(&h(&c, "secret_key"))).unwrap();
            assert_eq!(text, s(&c, "text"), "{name}");
        } else {
            match vault_wasm::decode_secret_key(&s(&c, "input")) {
                Ok(k) => assert_eq!(k.to_vec(), h(&c, "secret_key"), "{name}"),
                Err(e) => assert_eq!(code(e), s(&c, "error"), "{name}"),
            }
        }
    }
}

#[wasm_bindgen_test]
fn setup_text() {
    for c in cases("setup").into_iter().filter(|c| c["op"] == "parse") {
        let name = s(&c, "name");
        match vault_wasm::parse_setup_text(&s(&c, "input")) {
            Ok(v) => {
                let v = json_of(&v);
                let token =
                    vault_core::secret::Token::from_bytes(h(&c, "token").try_into().unwrap());
                assert_eq!(v["url"], c["url"], "{name}");
                assert_eq!(
                    v["token"],
                    vault_core::token::encode(&token).as_str(),
                    "{name}"
                );
                assert_eq!(v["fp"], c["fp"], "{name}");
            }
            Err(e) => assert_eq!(code(e), s(&c, "error"), "{name}"),
        }
    }
}

#[wasm_bindgen_test]
fn opening_files() {
    for c in cases("tamper") {
        let name = s(&c, "name");
        // A case without its own file flips one byte of the shared file.
        let mut file = h(&c, "file");
        if let Some(off) = c.get("offset").and_then(Value::as_u64) {
            file[off as usize] ^= c["xor"].as_u64().unwrap() as u8;
        }
        let st = state_with(file);
        let open = outcome(Session::reopen(&st, &bytes(&h(&c, "vault_key"))));
        assert_eq!(open, expected(&c, "error_open"), "tamper {name}");
        let pw = String::from_utf8(h(&c, "password_hex")).unwrap();
        let unlock = outcome(Session::unlock(&st, &bytes(&h(&c, "secret_key")), &pw));
        assert_eq!(unlock, expected(&c, "error_unlock"), "tamper {name}");
    }
    for c in cases("malformed") {
        let st = state_with(h(&c, "file"));
        let r = outcome(Session::reopen(&st, &bytes(&h(&c, "vault_key"))));
        assert_eq!(r, s(&c, "result"), "malformed {}", s(&c, "name"));
    }
    for c in cases("vault-file")
        .into_iter()
        .filter(|c| c["op"] == "open")
    {
        let st = state_with(h(&c, "file"));
        let r = outcome(Session::reopen(&st, &bytes(&h(&c, "vault_key"))));
        assert_eq!(r, expected(&c, "result"), "vault-file {}", s(&c, "name"));
    }
    // Credential change files use the test parameters, which the bindings refuse.
    for c in cases("credentials")
        .into_iter()
        .filter(|c| c.get("file").is_some())
    {
        let st = state_with(h(&c, "file"));
        let pw = String::from_utf8(h(&c, "password_hex")).unwrap_or_default();
        let r = outcome(Session::unlock(&st, &bytes(&[0; 16]), &pw));
        assert_eq!(r, s(&c, "release_error"), "credentials {}", s(&c, "name"));
    }
}

/// Runs a procedure, answering `GET /v1/vault` with `remote` and every `PUT` with `200`.
fn run_against(p: &mut Procedure, remote: &[u8]) -> Value {
    let mut step = p.start(1_800_000_000_000.0);
    loop {
        let v = json_of(&step);
        match v["type"].as_str().unwrap() {
            "request" => {
                let input = js(&json!({"type": "response", "status": 200}));
                if v["method"] == "GET" {
                    Reflect::set(&input, &"body".into(), &bytes(remote)).unwrap();
                }
                step = p.step(&input, 1_800_000_000_000.0).unwrap();
            }
            "done" => return v,
            t => panic!("unexpected step {t}"),
        }
    }
}

#[wasm_bindgen_test]
fn sync_header_checks_through_a_procedure() {
    let all = cases("sync");
    let accepted = all
        .iter()
        .find(|c| c["name"] == "the accepted file itself")
        .unwrap();
    for c in all.iter().filter(|c| c["op"] == "check_remote") {
        let name = s(c, "name");
        let st = &c["state"];
        let mut state = ClientState::new(
            SyncState {
                vault_id: h(st, "vault_id").try_into().unwrap(),
                accepted: (!st["accepted"].is_null()).then(|| vault_core::sync::Accepted {
                    generation: st["accepted"]["generation"].as_u64().unwrap(),
                    file_hash: h(&st["accepted"], "file_hash").try_into().unwrap(),
                }),
                wrap_nonce: h(st, "wrap_nonce").try_into().unwrap(),
                retired_wrap_nonces: st["retired_wrap_nonces"]
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
            },
            h(accepted, "file"),
            SecretKeyStore::File,
        );
        state.last_sync = None;
        let text = String::from_utf8(state.to_json()).unwrap();
        let keys = js_sys::Object::new();
        Reflect::set(&keys, &"vaultKey".into(), &bytes(&h(c, "vault_key"))).unwrap();
        let mut p = Procedure::sync(&text, &keys, "background").unwrap();
        let done = run_against(&mut p, &h(c, "file"));
        let error = c["error"]
            .as_str()
            .or(c["open"].as_str().filter(|o| *o != "ok"))
            .or((c["wrap"] == "changed").then_some("sync.credentials_changed"));
        match error {
            Some(code) => assert_eq!(done["error"]["code"], code, "{name}"),
            None => assert_eq!(done["ok"], true, "{name}: {done}"),
        }
    }
}

/// The vectors' known-suffix lookup as a JavaScript function.
fn suffix_function(c: &Value) -> JsValue {
    let body = format!(
        "const answers = {}; const table = {};\n\
         if (Object.prototype.hasOwnProperty.call(answers, host)) return answers[host];\n\
         let best = null;\n\
         for (const t of table) if ((host === t || host.endsWith('.' + t)) && (best === null || t.length > best.length)) best = t;\n\
         return best;",
        c["suffix_answers"], c["known_suffixes"]
    );
    Function::new_with_args("host", &body).into()
}

/// A session whose body holds the vectors' compact items.
fn session_with(items: &Value) -> Session {
    let full: Vec<Value> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let mut item = json!({
                "id": i["id"], "type": i["type"], "name": i["name"], "folder": "",
                "favourite": false, "notes": "", "fields": [], "password_history": [],
                "created": 0, "modified": 0, "modified_by": "00".repeat(16),
            });
            if i["type"] == "login" {
                item["login"] = json!({
                    "username": i["username"], "password": i["password"], "uris": i["uris"],
                    "apps": [], "totp": null, "passkeys": [],
                });
            }
            item
        })
        .collect();
    let body = Body::from_json(
        json!({"v": 1, "horizon": 0, "items": full, "tombstones": []})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let vk = VaultKey::from_bytes([7; 32]);
    let header = Header::wrap(
        false,
        [1; 16],
        1,
        FLOOR,
        [2; 16],
        [3; 24],
        &Kek::from_bytes([4; 32]),
        &vk,
    );
    let file = vault_core::file::seal_file(&header, &vk, &[5; 24], &body).unwrap();
    Session::reopen(&state_with(file), &bytes(&[7; 32])).unwrap()
}

#[wasm_bindgen_test]
fn autofill_vectors() {
    let all = cases("autofill");
    for c in &all {
        let name = s(c, "name");
        let ks = suffix_function(c);
        let got = match c["op"].as_str().unwrap() {
            "prepare" => prepared(json_of(&vault_wasm::prepare_uri(&s(c, "uri")))),
            "page" => prepared(json_of(&vault_wasm::page_url(&s(c, "url")))),
            "registrable" => json_of(&vault_wasm::registrable_domain(&s(c, "url"), ks).unwrap()),
            "match" => json!(
                vault_wasm::match_uri(&s(c, "page"), &s(c, "uri"), &s(c, "match"), ks).unwrap()
            ),
            "items" => {
                let session = session_with(&c["items"]);
                let v = json_of(&session.candidates(&s(c, "page"), ks).unwrap());
                json!(
                    v.as_array()
                        .unwrap()
                        .iter()
                        .map(|x| json!({"id": x["id"], "outcome": x["outcome"]}))
                        .collect::<Vec<_>>()
                )
            }
            "frames" => {
                let frames: Vec<Value> = c["frames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| json!({"frameId": f["id"], "url": f["url"]}))
                    .collect();
                let ids = vault_wasm::frames_to_fill(&s(c, "top"), &js(&json!(frames))).unwrap();
                json_of(&ids)
            }
            "save" => {
                let session = session_with(&c["items"]);
                json_of(
                    &session
                        .save_offer(&s(c, "page"), &s(c, "username"), &s(c, "password"), ks)
                        .unwrap(),
                )
            }
            op => android_case(c).unwrap_or_else(|| panic!("unknown op {op}")),
        };
        assert_eq!(got, c["result"], "{name}");
    }
    assert!(all.len() >= 200);
}

/// The vectors' known-suffix lookup in Rust: the longest table entry that equals the host or a
/// sequence of its trailing labels, unless `suffix_answers` lists the host.
struct Table<'a>(&'a Value);

impl vault_client::autofill::SuffixList for Table<'_> {
    fn known_suffix(&self, host: &str) -> Option<String> {
        if let Some(a) = self.0["suffix_answers"].get(host) {
            return a.as_str().map(str::to_owned);
        }
        self.0["known_suffixes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| host == *t || host.ends_with(&format!(".{t}")))
            .max_by_key(|t| t.len())
            .map(str::to_owned)
    }
}

/// The vectors' compact items as body items, `apps` included.
fn body_items(items: &Value) -> Vec<vault_core::body::Item> {
    let full: Vec<Value> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let mut item = json!({
                "id": i["id"], "type": i["type"], "name": i["name"], "folder": "",
                "favourite": false, "notes": "", "fields": [], "password_history": [],
                "created": 0, "modified": 0, "modified_by": "00".repeat(16),
            });
            if i["type"] == "login" {
                item["login"] = json!({
                    "username": i["username"], "password": i["password"], "uris": i["uris"],
                    "apps": i.get("apps").cloned().unwrap_or(json!([])), "totp": null,
                    "passkeys": [],
                });
            }
            item
        })
        .collect();
    let body = json!({"v": 1, "horizon": 0, "items": full, "tombstones": []});
    Body::from_json(body.to_string().as_bytes())
        .unwrap()
        .items
        .clone()
}

/// The Android web and app cases. The extension has no bindings for them, so they run through
/// `vault_client::autofill` compiled for `wasm32-unknown-unknown`.
fn android_case(c: &Value) -> Option<Value> {
    use vault_client::autofill::{
        AppPage, Offer, Page, android_web_page, app_match, apps_after_fill, item_outcome,
        page_candidates, page_save_offer,
    };
    let table = Table(c);
    let app = |v: &Value| {
        let list = |k: &str| -> Vec<String> {
            v[k].as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_str().unwrap().to_owned())
                .collect()
        };
        AppPage::new(
            s(v, "package"),
            list("signers"),
            list("history"),
            v["multiple_signers"].as_bool().unwrap(),
        )
        .unwrap()
    };
    let offer = |o: Offer| match o {
        Offer::None => json!({"action": "none"}),
        Offer::Update { id } => json!({"action": "update", "id": id}),
        Offer::New(n) => json!({
            "action": "new",
            "name": n.name,
            "uris": n.uris.iter().map(|u| json!({"uri": u.uri, "match": u.match_value})).collect::<Vec<_>>(),
            "apps": n.apps.iter().map(|a| json!({"package": a.package, "cert_sha256": a.cert_sha256})).collect::<Vec<_>>(),
        }),
    };
    let web = || android_web_page(&s(c, "scheme"), &s(c, "host")).map(Page::AndroidWeb);
    let name = |o: vault_client::autofill::Outcome| vault_wasm_outcome(o);
    Some(match c["op"].as_str().unwrap() {
        "android_page" => match android_web_page(&s(c, "scheme"), &s(c, "host")) {
            None => Value::Null,
            Some(p) => json!({
                "scheme": p.scheme, "host": p.host.text(), "port": p.port,
                "path_query": p.path_query, "origin": p.origin(),
            }),
        },
        "android_match" => {
            let item = body_items(&json!([{
                "id": "00000000-0000-4000-8000-000000000001", "type": "login", "name": "n",
                "username": "u", "password": "p",
                "uris": [{"uri": c["uri"], "match": c["match"]}],
            }]));
            json!(web().map_or("none", |p| name(item_outcome(&p, &item[0], &table))))
        }
        "android_items" => {
            let its = body_items(&c["items"]);
            json!(web().map_or(Vec::new(), |p| {
                page_candidates(&p, &its, &table)
                    .into_iter()
                    .map(|(i, o)| json!({"id": i.id, "outcome": name(o)}))
                    .collect()
            }))
        }
        "android_save" => {
            let its = body_items(&c["items"]);
            web().map_or(json!({"action": "none"}), |p| {
                offer(page_save_offer(
                    &p,
                    &s(c, "username"),
                    &s(c, "password"),
                    &its,
                    &table,
                ))
            })
        }
        "app_items" => {
            let its = body_items(&c["items"]);
            let a = app(&c["app"]);
            json!(
                page_candidates(&Page::App(a.clone()), &its, &table)
                    .into_iter()
                    .map(|(i, o)| json!({
                        "id": i.id, "outcome": name(o), "kind": app_match(i, &a).unwrap().code(),
                    }))
                    .collect::<Vec<_>>()
            )
        }
        "app_bind" => {
            let its = body_items(&json!([c["item"]]));
            apps_after_fill(&its[0], &app(&c["app"])).map_or(Value::Null, |apps| {
                json!(
                    apps.iter()
                        .map(|a| json!({"package": a.package, "cert_sha256": a.cert_sha256}))
                        .collect::<Vec<_>>()
                )
            })
        }
        "app_save" => {
            let its = body_items(&c["items"]);
            let page = Page::App(app(&c["app"]));
            offer(page_save_offer(
                &page,
                &s(c, "username"),
                &s(c, "password"),
                &its,
                &table,
            ))
        }
        _ => return None,
    })
}

fn vault_wasm_outcome(o: vault_client::autofill::Outcome) -> &'static str {
    match o {
        vault_client::autofill::Outcome::Fill => "fill",
        vault_client::autofill::Outcome::Confirm => "confirm",
        vault_client::autofill::Outcome::None => "none",
    }
}

/// The bindings name the path and query `pathQuery`; the vectors `path_query`.
fn prepared(v: Value) -> Value {
    if v.is_null() {
        return v;
    }
    json!({
        "scheme": v["scheme"], "host": v["host"], "port": v["port"],
        "path_query": v["pathQuery"], "origin": v["origin"],
    })
}

#[wasm_bindgen_test]
fn known_suffix_answers_from_javascript() {
    let page = "https://www.bank.com/";
    let check = |ks: JsValue| {
        vault_wasm::registrable_domain(page, ks)
            .unwrap()
            .as_string()
    };
    let record = js(&json!({"www.bank.com": "com"}));
    assert_eq!(check(record).as_deref(), Some("bank.com"));
    let none = js(&json!({"www.bank.com": null}));
    assert_eq!(check(none).as_deref(), Some("www.bank.com"));
    let missing = js(&json!({}));
    assert_eq!(check(missing), None, "a missing host is a failed answer");
    let throws = Function::new_with_args("host", "throw new Error('bad host')");
    assert_eq!(check(throws.into()), None, "a throw is a failed answer");
    let promise = Function::new_with_args("host", "return Promise.resolve('com')");
    assert_eq!(check(promise.into()), None, "a Promise is a failed answer");
    let number = Function::new_with_args("host", "return 7");
    assert_eq!(check(number.into()), None);
    assert!(vault_wasm::registrable_domain(page, JsValue::from(3)).is_err());
}
