//! Checks `spec/vectors/autofill.json` against `vault_client::autofill`.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use vault_client::autofill::{
    Outcome, Prepared, SaveOffer, candidates, frames_to_fill, match_uri, page_url, prepare_uri,
    registrable_domain, save_offer,
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
                    "apps": [], "totp": null, "passkeys": [],
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
            op => panic!("unknown op {op}"),
        };
        assert_eq!(got, c["result"], "{name}");
    }
    let minimums = [
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
