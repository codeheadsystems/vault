//! Checks `spec/vectors/autofill.json` against `vault_client::autofill`.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use vault_client::autofill::{
    AppPage, Offer, Outcome, Page, Prepared, SaveOffer, android_web_page, app_match,
    apps_after_fill, candidates, frames_to_fill, item_outcome, match_uri, page_candidates,
    page_save_offer, page_url, prepare_uri, registrable_domain, save_offer,
};
use vault_core::body::{Body, Item, LoginUri};

fn load() -> Value {
    let path = format!(
        "{}/../../spec/vectors/autofill.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The vectors' known-suffix lookup: the longest table entry that equals the host or a sequence
/// of its trailing labels, unless `suffix_answers` lists the host.
struct Table {
    suffixes: Vec<String>,
    answers: BTreeMap<String, String>,
}

impl vault_client::autofill::SuffixList for Table {
    fn known_suffix(&self, host: &str) -> Option<String> {
        if let Some(a) = self.answers.get(host) {
            return Some(a.clone());
        }
        self.suffixes
            .iter()
            .filter(|s| host == s.as_str() || host.ends_with(&format!(".{s}")))
            .max_by_key(|s| s.len())
            .cloned()
    }
}

fn prepared(p: Option<Prepared>) -> Value {
    match p {
        None => Value::Null,
        Some(p) => json!({
            "scheme": p.scheme,
            "host": p.host.text(),
            "port": p.port,
            "path_query": p.path_query,
            "origin": p.origin(),
        }),
    }
}

fn outcome(o: Outcome) -> &'static str {
    match o {
        Outcome::Fill => "fill",
        Outcome::Confirm => "confirm",
        Outcome::None => "none",
    }
}

/// Expands the vectors' compact items into full body items.
fn items(v: &Value) -> Vec<Item> {
    let full: Vec<Value> = v
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
    Body::from_json(&serde_json::to_vec(&body).unwrap())
        .unwrap()
        .items
        .clone()
}

fn app(v: &Value) -> AppPage {
    let list = |k: &str| {
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect()
    };
    AppPage::new(
        v["package"].as_str().unwrap().to_owned(),
        list("signers"),
        list("history"),
        v["multiple_signers"].as_bool().unwrap(),
    )
    .expect("every vector app page passes the constructor")
}

fn offer(o: Offer) -> Value {
    match o {
        Offer::None => json!({"action": "none"}),
        Offer::Update { id } => json!({"action": "update", "id": id}),
        Offer::New(n) => json!({
            "action": "new",
            "name": n.name,
            "uris": n.uris.iter().map(|u| json!({"uri": u.uri, "match": u.match_value})).collect::<Vec<_>>(),
            "apps": n.apps.iter().map(|a| json!({"package": a.package, "cert_sha256": a.cert_sha256})).collect::<Vec<_>>(),
        }),
    }
}

fn mode(m: &str) -> vault_core::body::MatchMode {
    LoginUri {
        uri: String::new(),
        match_value: m.into(),
        extra: Default::default(),
    }
    .match_mode()
}

#[test]
fn autofill_vectors() {
    let v = load();
    let table = Table {
        suffixes: v["known_suffixes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect(),
        answers: v["suffix_answers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, a)| (k.clone(), a.as_str().unwrap().to_owned()))
            .collect(),
    };
    let s = |c: &Value, k: &str| c[k].as_str().unwrap().to_owned();
    let cases = v["cases"].as_array().unwrap();
    let mut ops: BTreeMap<String, usize> = BTreeMap::new();
    for c in cases {
        let name = s(c, "name");
        *ops.entry(s(c, "op")).or_default() += 1;
        let got = match c["op"].as_str().unwrap() {
            "prepare" => prepared(prepare_uri(&s(c, "uri"))),
            "page" => prepared(page_url(&s(c, "url"))),
            "registrable" => {
                let p = page_url(&s(c, "url")).unwrap();
                json!(registrable_domain(&p.host, &table).ok())
            }
            "match" => {
                let o = page_url(&s(c, "page")).map_or(Outcome::None, |page| {
                    match_uri(&page, &s(c, "uri"), mode(&s(c, "match")), &table)
                });
                json!(outcome(o))
            }
            "items" => {
                let its = items(&c["items"]);
                let out: Vec<Value> = candidates(&s(c, "page"), &its, &table)
                    .into_iter()
                    .map(|(i, o)| json!({"id": i.id, "outcome": outcome(o)}))
                    .collect();
                json!(out)
            }
            "frames" => {
                let frames: Vec<(u64, String)> = c["frames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| (f["id"].as_u64().unwrap(), s(f, "url")))
                    .collect();
                let refs: Vec<(u64, &str)> = frames.iter().map(|(i, u)| (*i, u.as_str())).collect();
                json!(frames_to_fill(&s(c, "top"), &refs))
            }
            "save" => {
                let its = items(&c["items"]);
                match save_offer(
                    &s(c, "page"),
                    &s(c, "username"),
                    &s(c, "password"),
                    &its,
                    &table,
                ) {
                    SaveOffer::None => json!({"action": "none"}),
                    SaveOffer::Update { id } => json!({"action": "update", "id": id}),
                    SaveOffer::New { name, uri } => json!({
                        "action": "new", "name": name, "uri": uri, "match": "base_domain",
                    }),
                }
            }
            "android_page" => prepared(android_web_page(&s(c, "scheme"), &s(c, "host"))),
            "android_match" => {
                let o =
                    android_web_page(&s(c, "scheme"), &s(c, "host")).map_or(Outcome::None, |p| {
                        let item = items(&json!([{
                            "id": "00000000-0000-4000-8000-000000000001", "type": "login",
                            "name": "n", "username": "u", "password": "p",
                            "uris": [{"uri": c["uri"], "match": c["match"]}],
                        }]));
                        item_outcome(&Page::AndroidWeb(p), &item[0], &table)
                    });
                json!(outcome(o))
            }
            "android_items" => {
                let its = items(&c["items"]);
                match android_web_page(&s(c, "scheme"), &s(c, "host")) {
                    None => json!([]),
                    Some(p) => json!(
                        page_candidates(&Page::AndroidWeb(p), &its, &table)
                            .into_iter()
                            .map(|(i, o)| json!({"id": i.id, "outcome": outcome(o)}))
                            .collect::<Vec<_>>()
                    ),
                }
            }
            "android_save" => {
                let its = items(&c["items"]);
                match android_web_page(&s(c, "scheme"), &s(c, "host")) {
                    None => json!({"action": "none"}),
                    Some(p) => offer(page_save_offer(
                        &Page::AndroidWeb(p),
                        &s(c, "username"),
                        &s(c, "password"),
                        &its,
                        &table,
                    )),
                }
            }
            "app_items" => {
                let its = items(&c["items"]);
                let a = app(&c["app"]);
                let page = Page::App(a.clone());
                json!(
                    page_candidates(&page, &its, &table)
                        .into_iter()
                        .map(|(i, o)| json!({
                            "id": i.id,
                            "outcome": outcome(o),
                            "kind": app_match(i, &a).unwrap().code(),
                        }))
                        .collect::<Vec<_>>()
                )
            }
            "app_bind" => {
                let its = items(&json!([c["item"]]));
                apps_after_fill(&its[0], &app(&c["app"])).map_or(Value::Null, |apps| {
                    json!(
                        apps.iter()
                            .map(|a| json!({"package": a.package, "cert_sha256": a.cert_sha256}))
                            .collect::<Vec<_>>()
                    )
                })
            }
            "app_save" => {
                let its = items(&c["items"]);
                offer(page_save_offer(
                    &Page::App(app(&c["app"])),
                    &s(c, "username"),
                    &s(c, "password"),
                    &its,
                    &table,
                ))
            }
            op => panic!("unknown op {op}"),
        };
        assert_eq!(got, c["result"], "{name}");
    }
    let minimums = [
        ("android_items", 3),
        ("android_match", 25),
        ("android_page", 10),
        ("android_save", 5),
        ("app_bind", 5),
        ("app_items", 3),
        ("app_save", 5),
        ("frames", 3),
        ("items", 5),
        ("match", 100),
        ("page", 8),
        ("prepare", 40),
        ("registrable", 15),
        ("save", 10),
    ];
    assert_eq!(
        ops.keys().map(String::as_str).collect::<Vec<_>>(),
        minimums.iter().map(|(op, _)| *op).collect::<Vec<_>>(),
        "the set of ops"
    );
    for (op, least) in minimums {
        assert!(
            ops[op] >= least,
            "{op}: {} cases, want at least {least}",
            ops[op]
        );
    }
}

/// A host passes its lookup as a closure; an answer that is not trailing labels is refused.
#[test]
fn a_closure_supplies_the_known_suffix() {
    use vault_client::autofill::{BadSuffixAnswer, known_suffix};
    let psl = |host: &str| match host {
        "a.example.com" => Some("com".to_owned()),
        "b.example.com" => Some("le.com".to_owned()),
        _ => None,
    };
    assert_eq!(
        known_suffix("a.example.com", &psl),
        Ok(Some("com".to_owned()))
    );
    assert_eq!(known_suffix("b.example.com", &psl), Err(BadSuffixAnswer));
    assert_eq!(known_suffix("c.example.com", &psl), Ok(None));
    let page = page_url("https://a.example.com/").unwrap();
    assert_eq!(
        registrable_domain(&page.host, &psl),
        Ok("example.com".to_owned())
    );
}

/// The app page constructor refuses what Android cannot report: a digest that is not 64
/// lowercase hex characters, or a history that does not fit the signers.
#[test]
fn app_page_constructor() {
    use vault_client::autofill::BadAppPage;
    let (a, b) = ("aa".repeat(32), "bb".repeat(32));
    let page = |signers: &[&String], history: &[&String], multiple| {
        AppPage::new(
            "com.bank".into(),
            signers.iter().map(|d| (*d).clone()).collect(),
            history.iter().map(|d| (*d).clone()).collect(),
            multiple,
        )
    };
    assert!(page(&[&a], &[&b, &a], false).is_ok());
    assert!(page(&[&a], &[&a], false).is_ok());
    assert!(
        page(&[], &[], false).is_ok(),
        "signing information not read"
    );
    assert!(page(&[&a, &b], &[], true).is_ok());
    assert!(
        page(&[&a], &[], true).is_ok(),
        "one signer flagged as several"
    );
    assert_eq!(
        page(&[&a], &[], false),
        Err(BadAppPage::History),
        "one signer, no history"
    );
    assert_eq!(
        page(&[&a], &[&a, &b], false),
        Err(BadAppPage::History),
        "history ends elsewhere"
    );
    assert_eq!(
        page(&[], &[&a], false),
        Err(BadAppPage::History),
        "history without a signer"
    );
    assert_eq!(page(&[&a, &b], &[], false), Err(BadAppPage::Signers));
    assert_eq!(page(&[&a, &b], &[&a], true), Err(BadAppPage::History));
    let upper = a.to_uppercase();
    assert_eq!(page(&[&upper], &[&upper], false), Err(BadAppPage::Digest));
    let short = "aa".repeat(31);
    assert_eq!(page(&[&short], &[&short], false), Err(BadAppPage::Digest));
    assert_eq!(
        page(&[&a], &[&b, &upper, &a], false),
        Err(BadAppPage::Digest),
        "in the history"
    );
    assert_eq!(
        AppPage::new(String::new(), vec![a.clone()], vec![a.clone()], false),
        Err(BadAppPage::Package)
    );
}

/// An upper-case `cert_sha256` never reaches matching: the body rules refuse it, so a body that
/// holds one does not open.
#[test]
fn an_upper_case_cert_sha256_is_refused_by_the_body_rules() {
    let item = json!([{
        "id": "00000000-0000-4000-8000-000000000001", "type": "login", "name": "n",
        "username": "u", "password": "p", "uris": [],
        "apps": [{"package": "com.bank", "cert_sha256": "AA".repeat(32)}],
    }]);
    let full = json!({"v": 1, "horizon": 0, "tombstones": [], "items": [{
        "id": item[0]["id"], "type": "login", "name": "n", "folder": "", "favourite": false,
        "notes": "", "fields": [], "password_history": [], "created": 0, "modified": 0,
        "modified_by": "00".repeat(16),
        "login": {"username": "u", "password": "p", "uris": [], "apps": item[0]["apps"],
            "totp": null, "passkeys": []},
    }]});
    assert!(Body::from_json(&serde_json::to_vec(&full).unwrap()).is_err());
}
