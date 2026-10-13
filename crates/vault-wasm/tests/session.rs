//! The session and the procedures through the bindings, under Node: unlocking, listing without
//! secrets, edits that merge onto a changed item, locking, a sync and a `--new-secret-key`
//! credential change against an in-test server, and commits through a JavaScript host that
//! records its calls.

#![cfg(target_arch = "wasm32")]

use js_sys::{Array, Function, Reflect, Uint8Array};
use serde_json::{Value, json};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::kdf::FLOOR;
use vault_core::sync::{SyncState, etag};
use vault_wasm::{Procedure, Session};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const PW: &str = "correct horse battery staple";
const NOW: f64 = 1_800_000_000_000.0;

fn js(v: &Value) -> JsValue {
    js_sys::JSON::parse(&v.to_string()).unwrap()
}

fn json_of(v: &JsValue) -> Value {
    serde_json::from_str(&js_sys::JSON::stringify(v).unwrap().as_string().unwrap()).unwrap()
}

fn bytes(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}

fn code(e: JsValue) -> String {
    Reflect::get(&e, &"code".into())
        .unwrap()
        .as_string()
        .unwrap()
}

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

/// A new vault at the floor parameters, never pushed: its state text and secret key.
fn new_vault() -> (String, Vec<u8>) {
    let v = vault_core::credentials::create_vault(&mut Counter(0), PW, FLOOR, false).unwrap();
    let s = ClientState::new(
        SyncState {
            vault_id: v.state.vault_id,
            accepted: None,
            wrap_nonce: v.state.wrap_nonce,
            retired_wrap_nonces: Vec::new(),
        },
        v.file,
        SecretKeyStore::File,
    );
    (
        String::from_utf8(s.to_json()).unwrap(),
        v.secret_key.expose().to_vec(),
    )
}

/// A JavaScript `CommitHost` that records each call as `[method, ...args]` in `host.calls`, with
/// keys as arrays of numbers.
fn recording_host() -> JsValue {
    let make = Function::new_no_args(
        "const calls = [];\n\
         const rec = (name) => (...args) => calls.push([name, ...args.map(a => a instanceof Uint8Array ? Array.from(a) : a)]);\n\
         return { calls, storeCurrent: rec('storeCurrent'), storePending: rec('storePending'),\n\
                  deletePending: rec('deletePending'), writeState: rec('writeState') };",
    );
    make.call0(&JsValue::NULL).unwrap()
}

fn calls(host: &JsValue) -> Vec<Value> {
    json_of(&Reflect::get(host, &"calls".into()).unwrap())
        .as_array()
        .unwrap()
        .clone()
}

fn last_state(host: &JsValue) -> String {
    calls(host)
        .iter()
        .rev()
        .find(|c| c[0] == "writeState")
        .map(|c| c[1].as_str().unwrap().to_owned())
        .expect("a state was written")
}

/// The spec Server API over one current file, with revision IDs.
#[derive(Default)]
struct Server {
    revisions: Vec<Vec<u8>>,
}

impl Server {
    fn answer(&mut self, req: &Value, body: Option<Vec<u8>>) -> JsValue {
        let path = req["path"].as_str().unwrap();
        let (status, out): (u16, Vec<u8>) = match (req["method"].as_str().unwrap(), path) {
            ("GET", "/v1/vault") => match self.revisions.last() {
                Some(f) => (200, f.clone()),
                None => (404, Vec::new()),
            },
            ("PUT", "/v1/vault") => {
                let ok = match (&req["ifMatch"], self.revisions.last()) {
                    (Value::String(e), Some(cur)) => *e == etag(cur),
                    (Value::Null, cur) => req["ifNoneMatch"] == "*" && cur.is_none(),
                    _ => false,
                };
                if ok {
                    self.revisions.push(body.unwrap());
                    (200, Vec::new())
                } else {
                    (412, Vec::new())
                }
            }
            ("GET", "/v1/revisions") => {
                let list: Vec<Value> = self
                    .revisions
                    .iter()
                    .enumerate()
                    .rev()
                    .map(|(i, f)| {
                        json!({"id": i + 1, "etag": etag(f), "size": f.len(),
                               "created": "2026-10-12T00:00:00Z", "token": "firefox"})
                    })
                    .collect();
                (200, json!({"revisions": list}).to_string().into_bytes())
            }
            _ => (404, Vec::new()),
        };
        let r = js(&json!({"type": "response", "status": status, "date": NOW}));
        Reflect::set(&r, &"body".into(), &bytes(&out)).unwrap();
        r
    }
}

/// Runs a procedure to `done`, answering prompts from `answers` and saves through `host`, and
/// returns the done step and the state each save started from.
fn drive(
    p: &mut Procedure,
    server: &mut Server,
    started: &mut String,
    host: &JsValue,
    mut answers: Vec<Value>,
) -> Value {
    let mut step = p.start(NOW);
    loop {
        let v = json_of(&step);
        let input = match v["type"].as_str().unwrap() {
            "request" => {
                let body = Reflect::get(&step, &"body".into())
                    .ok()
                    .filter(|b| !b.is_undefined())
                    .map(|b| Uint8Array::new(&b).to_vec());
                server.answer(&v, body)
            }
            "prompt" => js(&answers.remove(0)),
            "save" => {
                p.apply_save(started, started, NOW, host).unwrap();
                *started = v["state"].as_str().unwrap().to_owned();
                js(&json!({"type": "saved"}))
            }
            "done" => return v,
            t => panic!("{t}"),
        };
        step = p.step(&input, NOW).unwrap();
    }
}

#[wasm_bindgen_test]
fn session_items_and_edits() {
    let (state, sk) = new_vault();
    let device = bytes(&[9; 16]);
    assert_eq!(
        code(Session::unlock(&state, &bytes(&sk), "wrong").err().unwrap()),
        "wrong_credentials"
    );
    let mut s = Session::unlock(&state, &bytes(&sk), PW).unwrap();
    let added = json_of(
        &s.add(
            &state,
            &device,
            NOW,
            &js(
                &json!({"type": "login", "name": "GitHub", "folder": "Work/Code",
                        "username": "ned", "password": "hunter2-hunter2",
                        "uris": [{"uri": "github.com", "match": "base_domain"}]}),
            ),
        )
        .unwrap(),
    );
    let id = added["id"].as_str().unwrap().to_owned();
    let state = added["state"].as_str().unwrap().to_owned();
    let list = json_of(&s.list(JsValue::UNDEFINED).unwrap());
    assert_eq!(list[0]["name"], "GitHub");
    assert_eq!(list[0]["username"], "ned");
    assert!(
        !list.to_string().contains("hunter2"),
        "list entries carry no password"
    );
    assert_eq!(
        s.folders().unwrap(),
        vec!["Work".to_owned(), "Work/Code".to_owned()]
    );
    let found = json_of(&s.list(js(&json!({"text": "git"}))).unwrap());
    assert_eq!(found.as_array().unwrap().len(), 1);
    let none = json_of(&s.list(js(&json!({"folder": "Home"}))).unwrap());
    assert!(none.as_array().unwrap().is_empty());

    // The user edits the username while a sync changes the password: both survive.
    let base = s.item(&id).unwrap();
    let mut edited = json_of(&base);
    edited["login"]["username"] = json!("ned2");
    let synced = json_of(
        &s.update(&state, &device, NOW + 1.0, &id, &base, &{
            let mut e = json_of(&base);
            e["login"]["password"] = json!("from-a-sync-1");
            js(&e)
        })
        .unwrap(),
    );
    let state = synced["state"].as_str().unwrap().to_owned();
    let merged = json_of(
        &s.update(&state, &device, NOW + 2.0, &id, &base, &js(&edited))
            .unwrap(),
    );
    let state = merged["state"].as_str().unwrap().to_owned();
    let cred = json_of(&s.credential(&id).unwrap());
    assert_eq!(
        cred,
        json!({"username": "ned2", "password": "from-a-sync-1"})
    );
    let unchanged = json_of(
        &s.update(&state, &device, NOW + 3.0, &id, &base, &base)
            .unwrap(),
    );
    assert!(
        unchanged["state"].is_null(),
        "an unchanged edit writes nothing"
    );

    // Autofill through the session.
    let ks = Function::new_with_args(
        "host",
        "return host.endsWith('.com') || host === 'com' ? 'com' : null",
    );
    let c = json_of(
        &s.candidates("https://github.com/login", ks.clone().into())
            .unwrap(),
    );
    assert_eq!(
        c,
        json!([{"id": id, "name": "GitHub", "username": "ned2", "outcome": "fill"}])
    );
    assert_eq!(
        s.suffix_hosts("https://github.com/x").unwrap(),
        vec!["github.com".to_owned()]
    );
    let offer = json_of(
        &s.save_offer("https://github.com/", "ned2", "new-password", ks.into())
            .unwrap(),
    );
    assert_eq!(offer, json!({"action": "update", "id": id}));

    // The vault key reopens the state; another device's state reloads.
    let vk = s.vault_key().unwrap();
    let reopened = Session::reopen(&state, &vk.into()).unwrap();
    assert_eq!(
        json_of(&reopened.list(JsValue::UNDEFINED).unwrap())
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let removed = json_of(&s.remove(&state, &device, NOW + 4.0, &id).unwrap());
    let after = removed["state"].as_str().unwrap().to_owned();
    let mut other = reopened;
    other.reload(&after).unwrap();
    assert!(
        json_of(&other.list(JsValue::UNDEFINED).unwrap())
            .as_array()
            .unwrap()
            .is_empty()
    );

    s.lock();
    assert_eq!(
        code(s.list(JsValue::UNDEFINED).err().unwrap()),
        "sync.locked"
    );
    assert_eq!(code(s.vault_key().err().unwrap()), "sync.locked");
}

#[wasm_bindgen_test]
fn sync_and_a_new_secret_key_through_procedures() {
    let (mut state, sk) = new_vault();
    let mut server = Server::default();
    let s = Session::unlock(&state, &bytes(&sk), PW).unwrap();
    let vk = s.vault_key().unwrap().to_vec();

    // The first sync pushes generation 1 with If-None-Match.
    let keys = js(&json!({}));
    Reflect::set(&keys, &"vaultKey".into(), &bytes(&vk)).unwrap();
    let mut p = Procedure::sync(&state, &keys, "background").unwrap();
    let host = recording_host();
    let done = drive(&mut p, &mut server, &mut state.clone(), &host, vec![]);
    assert_eq!(done["result"]["outcome"], "pushed", "{done}");
    let applied = json_of(
        &p.apply(Some(state.clone()), Some(state.clone()), true, NOW, &host)
            .unwrap(),
    );
    assert_eq!(applied["written"], true);
    state = last_state(&host);
    assert_eq!(server.revisions.len(), 1);

    // --new-secret-key with the current password kept: the pending key is saved first, then
    // promoted and deleted at the commit.
    let keys = js(&json!({}));
    Reflect::set(&keys, &"vaultKey".into(), &bytes(&vk)).unwrap();
    Reflect::set(&keys, &"secretKey".into(), &bytes(&sk)).unwrap();
    let mut p = Procedure::passwd(&state, &keys, "new-secret-key", None).unwrap();
    let host = recording_host();
    let mut started = state.clone();
    let done = drive(
        &mut p,
        &mut server,
        &mut started,
        &host,
        vec![json!({"type": "answer", "password": PW})],
    );
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(done["result"]["retiredRevision"], 2);
    let saved = calls(&host);
    assert_eq!(saved[0][0], "storePending");
    let pending = saved[0][2].clone();
    assert_eq!(saved[1][0], "writeState");
    let on_disk = last_state(&host);
    p.apply(
        Some(started.clone()),
        Some(on_disk.clone()),
        false,
        NOW,
        &host,
    )
    .unwrap();
    let all = calls(&host);
    let names: Vec<&str> = all.iter().map(|c| c[0].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "storePending",
            "writeState",
            "storeCurrent",
            "writeState",
            "deletePending"
        ]
    );
    assert_eq!(all[2][2], pending, "the pending key became current");
    let new_key: Vec<u8> = pending
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let state = last_state(&host);
    let s = Session::unlock(&state, &bytes(&new_key), PW).unwrap();
    assert_eq!(
        code(Session::unlock(&state, &bytes(&sk), PW).err().unwrap()),
        "wrong_credentials"
    );
    let vk2: Vec<u8> = p.vault_key().dyn_into::<Uint8Array>().unwrap().to_vec();
    assert_eq!(vk2, s.vault_key().unwrap().to_vec());
    let summary = json_of(&vault_wasm::state_summary(&state).unwrap());
    assert_eq!(summary["generation"], 2);
    assert_eq!(summary["pendingSecretKey"], false);
}

#[wasm_bindgen_test]
fn setup_writes_the_first_state() {
    // A vault on the server, pushed by a first device.
    let (state, sk) = new_vault();
    let mut server = Server::default();
    let s = Session::unlock(&state, &bytes(&sk), PW).unwrap();
    let keys = js(&json!({}));
    Reflect::set(&keys, &"vaultKey".into(), &s.vault_key().unwrap()).unwrap();
    let mut p = Procedure::sync(&state, &keys, "background").unwrap();
    drive(
        &mut p,
        &mut server,
        &mut state.clone(),
        &recording_host(),
        vec![],
    );

    // This browser: secret key, no kit vault ID, a wrong password, then the right one.
    let mut p = Procedure::setup();
    let host = recording_host();
    let answer_key = js(&json!({"type": "answer"}));
    Reflect::set(&answer_key, &"secretKey".into(), &bytes(&sk)).unwrap();
    let mut step = p.start(NOW);
    let mut prompts = Vec::new();
    let done = loop {
        let v = json_of(&step);
        let input = match v["type"].as_str().unwrap() {
            "request" => server.answer(&v, None),
            "prompt" => {
                prompts.push(v["prompt"].clone());
                match v["prompt"]["kind"].as_str().unwrap() {
                    "secret_key" => answer_key.clone(),
                    "kit_vault_id" => js(&json!({"type": "answer", "vaultId": null})),
                    "master_password" if v["prompt"]["failed"] == 0 => {
                        js(&json!({"type": "answer", "password": "wrong"}))
                    }
                    "master_password" => js(&json!({"type": "answer", "password": PW})),
                    k => panic!("{k}"),
                }
            }
            "done" => break v,
            t => panic!("{t}"),
        };
        step = p.step(&input, NOW).unwrap();
    };
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(prompts.len(), 4);
    assert_eq!(
        prompts[3],
        json!({"kind": "master_password", "purpose": "unlock", "failed": 1})
    );
    // No earlier state: null for both, and the key and the state are written as they are.
    assert!(
        p.apply(None, Some(state.clone()), false, NOW, &host)
            .is_err()
    );
    let applied = json_of(&p.apply(None, None, false, NOW, &host).unwrap());
    assert_eq!(applied["written"], true);
    let names: Vec<String> = calls(&host)
        .iter()
        .map(|c| c[0].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["storeCurrent", "writeState"]);
    let stored = last_state(&host);
    let vk: Vec<u8> = p.vault_key().dyn_into::<Uint8Array>().unwrap().to_vec();
    let session = Session::reopen(&stored, &bytes(&vk)).unwrap();
    assert!(!session.read_only().unwrap());
    let summary = json_of(&vault_wasm::state_summary(&stored).unwrap());
    assert_eq!(summary["generation"], 1);
    assert_eq!(summary["unpushed"], false);
}

#[wasm_bindgen_test]
fn generation_and_text_forms() {
    let p = json_of(
        &vault_wasm::generate_password(&js(&json!({"length": 20, "upper": true, "lower": true,
            "digits": true, "symbols": false, "avoidAmbiguous": true})))
        .unwrap(),
    );
    let value = p["value"].as_str().unwrap();
    assert_eq!(value.len(), 20);
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !"IOl01".contains(c))
    );
    assert!(p["bits"].as_f64().unwrap() > 100.0);
    let words = json_of(&vault_wasm::generate_passphrase(6, "-").unwrap());
    assert_eq!(words["value"].as_str().unwrap().split('-').count(), 6);
    assert!(vault_wasm::generate_passphrase(1, "-").is_err());
    let list = vault_wasm::parse_revisions(
        br#"{"revisions":[{"id":3,"etag":"\"x\"","size":9,"created":"c","token":"t"}]}"#,
    )
    .unwrap();
    assert_eq!(json_of(&list)[0]["id"], 3);
    let a = Array::new();
    a.push(&js(&json!({"frameId": 0, "url": "https://a.com/"})));
    a.push(&js(&json!({"frameId": 7, "url": "https://b.com/"})));
    let ids = vault_wasm::frames_to_fill("https://a.com/x", &a.into()).unwrap();
    assert!(js_sys::Array::is_array(&ids), "a plain array");
    assert_eq!(json_of(&ids), json!([0]));
    assert!(vault_wasm::frames_to_fill("https://a.com/", &js(&json!({}))).is_err());
}

#[wasm_bindgen_test]
fn unlock_falls_back_to_the_local_file_when_the_server_is_unreachable() {
    let (state, sk) = new_vault();
    let keys = js(&json!({}));
    Reflect::set(&keys, &"secretKey".into(), &bytes(&sk)).unwrap();
    let mut p = Procedure::unlock(&state, &keys).unwrap();
    let step = json_of(&p.start(NOW));
    assert_eq!(step["path"], "/v1/vault");
    let step = json_of(&p.step(&js(&json!({"type": "unreachable"})), NOW).unwrap());
    assert_eq!(
        step["prompt"],
        json!({"kind": "master_password", "purpose": "unlock", "failed": 0})
    );
    let done = json_of(
        &p.step(&js(&json!({"type": "answer", "password": PW})), NOW)
            .unwrap(),
    );
    assert_eq!(done["ok"], true);
    assert_eq!(
        done["result"]["sync"]["error"]["code"],
        "server.unreachable"
    );
    let vk = p.vault_key();
    assert!(Session::reopen(&state, &vk).is_ok());
}
