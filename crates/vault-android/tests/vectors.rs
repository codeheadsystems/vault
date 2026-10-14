//! The spec vectors through the binding layer's Rust API: secret key text, setup text, file
//! opening and unlocking (with a build's release expectations, since the bindings never accept
//! the test KDF parameters), the sync header checks through a sync procedure, and the Android
//! web and app autofill cases. The compiled-in Public Suffix List is checked against the
//! vectors' known-suffix table on every host the autofill vectors use.

mod common;

use common::{MemHost, Server, code, run};
use serde_json::{Value, json};
use std::sync::Arc;
use vault_android::{AppPage, KnownSuffix, Outcome, Page, SaveOffer, Step, SyncMode, Vault};
use vault_client::autofill::{self as core_autofill, SuffixList};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::sync::SyncState;

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

/// A vault over a state whose local file is `file`, with `secret_key` stored.
fn vault_over(file: Vec<u8>, sync: SyncState, secret_key: &[u8]) -> Arc<Vault> {
    let host = MemHost::new();
    host.set_state(&ClientState::new(sync, file, SecretKeyStore::File));
    *host.current.lock().unwrap() = Some(secret_key.to_vec());
    Vault::new(host)
}

fn placeholder() -> SyncState {
    SyncState {
        vault_id: [0; 16],
        accepted: None,
        wrap_nonce: [0; 24],
        retired_wrap_nonces: Vec::new(),
    }
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

#[test]
fn secret_key_text() {
    for c in cases("secret-key") {
        let name = s(&c, "name");
        if c["op"] == "encode" {
            let text = vault_android::encode_secret_key(h(&c, "secret_key")).unwrap();
            assert_eq!(text, s(&c, "text"), "{name}");
        } else {
            match vault_android::decode_secret_key(s(&c, "input")) {
                Ok(k) => assert_eq!(k, h(&c, "secret_key"), "{name}"),
                Err(e) => assert_eq!(e.code(), s(&c, "error"), "{name}"),
            }
        }
    }
    assert_eq!(code(vault_android::encode_secret_key(vec![0; 15])), "usage");
}

#[test]
fn setup_text() {
    for c in cases("setup").into_iter().filter(|c| c["op"] == "parse") {
        let name = s(&c, "name");
        match vault_android::parse_setup_text(s(&c, "input")) {
            Ok(v) => {
                let token =
                    vault_core::secret::Token::from_bytes(h(&c, "token").try_into().unwrap());
                assert_eq!(json!(v.url), c["url"], "{name}");
                assert_eq!(
                    v.token,
                    vault_core::token::encode(&token).as_str(),
                    "{name}"
                );
                assert_eq!(json!(v.fp), c["fp"], "{name}");
            }
            Err(e) => assert_eq!(e.code(), s(&c, "error"), "{name}"),
        }
    }
}

#[test]
fn opening_files() {
    let reopen = |file: Vec<u8>, vk: Vec<u8>| {
        code(vault_over(file, placeholder(), &[0; 16]).reopen(vk, vec![0; 24]))
    };
    for c in cases("tamper") {
        let name = s(&c, "name");
        // A case without its own file flips one byte of the shared file.
        let mut file = h(&c, "file");
        if let Some(off) = c.get("offset").and_then(Value::as_u64) {
            file[off as usize] ^= c["xor"].as_u64().unwrap() as u8;
        }
        let open = reopen(file.clone(), h(&c, "vault_key"));
        assert_eq!(open, expected(&c, "error_open"), "tamper {name}");
        let pw = String::from_utf8(h(&c, "password_hex")).unwrap();
        let unlock = code(vault_over(file, placeholder(), &h(&c, "secret_key")).unlock(pw));
        assert_eq!(unlock, expected(&c, "error_unlock"), "tamper {name}");
    }
    for c in cases("malformed") {
        let r = reopen(h(&c, "file"), h(&c, "vault_key"));
        assert_eq!(r, s(&c, "result"), "malformed {}", s(&c, "name"));
    }
    for c in cases("vault-file")
        .into_iter()
        .filter(|c| c["op"] == "open")
    {
        let r = reopen(h(&c, "file"), h(&c, "vault_key"));
        assert_eq!(r, expected(&c, "result"), "vault-file {}", s(&c, "name"));
    }
    // Credential change files use the test parameters, which the bindings refuse.
    for c in cases("credentials")
        .into_iter()
        .filter(|c| c.get("file").is_some())
    {
        let pw = String::from_utf8(h(&c, "password_hex")).unwrap_or_default();
        let r = code(vault_over(h(&c, "file"), placeholder(), &[0; 16]).unlock(pw));
        assert_eq!(r, s(&c, "release_error"), "credentials {}", s(&c, "name"));
    }
}

#[test]
fn sync_header_checks_through_a_procedure() {
    let all = cases("sync");
    let accepted = all
        .iter()
        .find(|c| c["name"] == "the accepted file itself")
        .unwrap();
    for c in all.iter().filter(|c| c["op"] == "check_remote") {
        let name = s(c, "name");
        let st = &c["state"];
        let sync = SyncState {
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
        };
        let wrap = sync.wrap_nonce.to_vec();
        let vault = vault_over(h(accepted, "file"), sync, &[0; 16]);
        // The sync takes the vault key from the unlocked session.
        vault.reopen(h(c, "vault_key"), wrap).unwrap();
        let p = vault.begin_sync(SyncMode::Background).unwrap();
        let mut server = Server {
            files: vec![h(c, "file")],
        };
        let done = run(&p, Some(&mut server), vec![]);
        let error = c["error"]
            .as_str()
            .or(c["open"].as_str().filter(|o| *o != "ok"))
            .or((c["wrap"] == "changed").then_some("sync.credentials_changed"));
        match (error, &done) {
            (Some(want), Step::Failed { error }) => assert_eq!(error.code, want, "{name}"),
            (None, Step::Done { .. }) => {}
            _ => panic!("{name}: {done:?}"),
        }
    }
}

/// The vectors' known-suffix lookup: the longest table entry that equals the host or a sequence
/// of its trailing labels, unless `suffix_answers` lists the host.
struct Table(Value);

impl Table {
    fn answer(&self, host: &str) -> Option<String> {
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

impl KnownSuffix for Table {
    fn known_suffix(&self, host: String) -> Option<String> {
        self.answer(&host)
    }
}

impl SuffixList for Table {
    fn known_suffix(&self, host: &str) -> Option<String> {
        self.answer(host)
    }
}

/// The vectors' compact items as a JSON array of body-schema items, `apps` included.
fn items_json(items: &Value) -> String {
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
    json!(full).to_string()
}

fn app(v: &Value) -> AppPage {
    let list = |k: &str| -> Vec<String> {
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect()
    };
    AppPage {
        package_name: s(v, "package"),
        signers: list("signers"),
        history: list("history"),
        multiple_signers: v["multiple_signers"].as_bool().unwrap(),
    }
}

fn outcome(o: Outcome) -> &'static str {
    match o {
        Outcome::Fill => "fill",
        Outcome::Confirm => "confirm",
    }
}

fn offer(o: SaveOffer) -> Value {
    match o {
        SaveOffer::None => json!({"action": "none"}),
        SaveOffer::Update { id } => json!({"action": "update", "id": id}),
        SaveOffer::New { name, uris, apps } => json!({
            "action": "new",
            "name": name,
            "uris": uris.iter().map(|u| json!({"uri": u.uri, "match": u.match_value})).collect::<Vec<_>>(),
            "apps": apps.iter().map(|a| json!({"package": a.package_name, "cert_sha256": a.cert_sha256})).collect::<Vec<_>>(),
        }),
    }
}

/// An Android case through the free functions with `suffixes`, or `None` for a web case.
fn android_case(c: &Value, suffixes: Option<Arc<dyn KnownSuffix>>) -> Option<Value> {
    let web = || Page::AndroidWeb {
        scheme: s(c, "scheme"),
        host: s(c, "host"),
    };
    let candidates = |page: Page, items: &Value| {
        vault_android::page_candidates(page, items_json(items), suffixes.clone()).unwrap()
    };
    Some(match c["op"].as_str().unwrap() {
        "android_page" => match vault_android::android_web_page(s(c, "scheme"), s(c, "host")) {
            None => Value::Null,
            Some(p) => json!({
                "scheme": p.scheme, "host": p.host, "port": null, "path_query": "/",
                "origin": p.origin,
            }),
        },
        "android_match" => {
            let item = json!([{
                "id": "00000000-0000-4000-8000-000000000001", "type": "login", "name": "n",
                "username": "u", "password": "p",
                "uris": [{"uri": c["uri"], "match": c["match"]}],
            }]);
            json!(
                candidates(web(), &item)
                    .first()
                    .map_or("none", |x| outcome(x.outcome))
            )
        }
        "android_items" => json!(
            candidates(web(), &c["items"])
                .iter()
                .map(|x| json!({"id": x.id, "outcome": outcome(x.outcome)}))
                .collect::<Vec<_>>()
        ),
        "android_save" => offer(
            vault_android::page_save_offer(
                web(),
                s(c, "username"),
                s(c, "password"),
                items_json(&c["items"]),
                suffixes.clone(),
            )
            .unwrap(),
        ),
        "app_items" => json!(
            candidates(
                Page::App {
                    app: app(&c["app"])
                },
                &c["items"]
            )
            .iter()
            .map(|x| {
                let kind = match x.app_match.unwrap() {
                    vault_android::AppMatch::Fill => "fill",
                    vault_android::AppMatch::Rebind => "rebind",
                    vault_android::AppMatch::SignatureChanged => "signature_changed",
                    vault_android::AppMatch::Bind => "bind",
                    vault_android::AppMatch::Unverified => "unverified",
                };
                json!({"id": x.id, "outcome": outcome(x.outcome), "kind": kind})
            })
            .collect::<Vec<_>>()
        ),
        "app_bind" => {
            let item = items_json(&json!([c["item"]]));
            let item = item
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            vault_android::apps_after_fill(item, app(&c["app"]))
                .unwrap()
                .map_or(Value::Null, |apps| {
                    json!(
                        apps.iter()
                            .map(
                                |a| json!({"package": a.package_name, "cert_sha256": a.cert_sha256})
                            )
                            .collect::<Vec<_>>()
                    )
                })
        }
        "app_save" => offer(
            vault_android::page_save_offer(
                Page::App {
                    app: app(&c["app"]),
                },
                s(c, "username"),
                s(c, "password"),
                items_json(&c["items"]),
                suffixes.clone(),
            )
            .unwrap(),
        ),
        _ => return None,
    })
}

#[test]
fn android_autofill_vectors() {
    let mut n = 0;
    for c in cases("autofill") {
        let table: Option<Arc<dyn KnownSuffix>> = Some(Arc::new(Table(c.clone())));
        if let Some(got) = android_case(&c, table) {
            assert_eq!(got, c["result"], "{}", s(&c, "name"));
            n += 1;
        }
    }
    assert!(n >= 60, "{n} Android cases");
}

/// Every domain an autofill case names: page, frame, and browser hosts, and item URI hosts.
fn hosts(c: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut add = |p: Option<core_autofill::Prepared>| {
        if let Some(core_autofill::Prepared {
            host: core_autofill::UrlHost::Domain(d),
            ..
        }) = p
        {
            out.push(d);
        }
    };
    for k in ["url", "page", "top"] {
        if let Some(u) = c[k].as_str() {
            add(core_autofill::page_url(u));
        }
    }
    if let Some(u) = c["uri"].as_str() {
        add(core_autofill::prepare_uri(u));
    }
    if let (Some(sch), Some(host)) = (c["scheme"].as_str(), c["host"].as_str()) {
        add(core_autofill::android_web_page(sch, host));
    }
    for i in c["items"].as_array().into_iter().flatten() {
        for u in i["uris"].as_array().into_iter().flatten() {
            add(core_autofill::prepare_uri(u["uri"].as_str().unwrap()));
        }
    }
    out
}

#[test]
fn the_compiled_in_list_agrees_with_the_vectors_table() {
    let list = vault_android::psl::list();
    let mut checked = 0;
    for c in cases("autofill") {
        let table = Table(c.clone());
        for host in hosts(&c) {
            if c["suffix_answers"].get(&host).is_some() {
                continue;
            }
            // The list has a rule for home.arpa (RFC 8375); the vectors' table stops at arpa.
            let want = if host == "home.arpa" || host.ends_with(".home.arpa") {
                Some("home.arpa".to_owned())
            } else {
                table.answer(&host)
            };
            assert_eq!(list.known_suffix(&host), want, "{}: {host}", s(&c, "name"));
            checked += 1;
        }
    }
    assert!(checked > 300, "{checked} hosts");

    // So the Android cases give the same results with the compiled-in list, except where a
    // case's table answer is a deliberate failure.
    for c in cases("autofill") {
        if hosts(&c)
            .iter()
            .any(|h| c["suffix_answers"].get(h).is_some())
        {
            continue;
        }
        if let Some(got) = android_case(&c, None) {
            assert_eq!(got, c["result"], "{}", s(&c, "name"));
        }
    }
    assert_eq!(
        vault_android::known_suffix("a.b.example.co.uk".into()).as_deref(),
        Some("co.uk")
    );
}
