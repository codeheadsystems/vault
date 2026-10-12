//! The export mapping and the round trip through import and export.

mod common;

use common::*;
use serde_json::{Value as J, json};
use vault_core::body::{Body, CustomField, ItemFields, Login, LoginUri, TYPE_LOGIN, TYPE_NOTE};
use vault_core::edit::{add_item, update_item};
use vault_core::json::Map;
use vault_interop::{Export, export_bitwarden, parse};

fn export(body: &Body) -> (J, String) {
    let out = export_bitwarden(body, &mut TestRng(9)).unwrap();
    let text = String::from_utf8(out.json.to_vec()).unwrap();
    (serde_json::from_str(&text).unwrap(), text)
}

fn folder_names(doc: &J) -> std::collections::BTreeMap<String, String> {
    doc["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_str().unwrap().to_owned(),
                f["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// An item with `revisionDate` removed and `folderId` replaced by the folder's name.
fn comparable(item: &J, folders: &std::collections::BTreeMap<String, String>) -> J {
    let mut item = item.clone();
    let m = item.as_object_mut().unwrap();
    m.remove("revisionDate");
    let folder = m["folderId"].as_str().map(|id| folders[id].clone());
    m.insert("folderId".into(), json!(folder));
    item
}

#[test]
fn round_trip_has_only_the_documented_differences() {
    let original: J = serde_json::from_slice(&fixture("full.json")).unwrap();
    let body = imported(&fixture("full.json"));
    let (exported, text) = export(&body);
    assert!(text.starts_with("{\n  \"encrypted\": false,\n  \"folders\": ["));
    assert!(matches!(parse(text.as_bytes()), Ok(Export::Plain(_))));

    let (of, ef) = (folder_names(&original), folder_names(&exported));
    assert_eq!(
        ef.values().collect::<Vec<_>>(),
        ["Work", "Work/AWS"],
        "one folder per path, with new IDs"
    );
    assert!(ef.keys().all(|id| !of.contains_key(id)));

    let mut expected: Vec<J> = original["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["deletedDate"].is_null())
        .map(|i| comparable(i, &of))
        .collect();
    let empty_history = |i: &mut J| {
        if i["passwordHistory"].is_null() {
            i["passwordHistory"] = json!([]);
        }
    };
    for i in &mut expected {
        empty_history(i);
        if i.get("fields").is_none() {
            i["fields"] = json!([]);
        }
    }
    // The login: a normalised history, with dates before 1970 or missing as 0; a null boolean
    // field value as "false"; a null URI match as 0 (domain).
    expected[0]["passwordHistory"] = json!([
        {"lastUsedDate": "2024-03-10T12:30:45.678Z", "password": "old-2"},
        {"lastUsedDate": "1970-01-01T00:00:00.000Z", "password": "moon"},
        {"lastUsedDate": "1970-01-01T00:00:00.000Z", "password": "undated"}
    ]);
    expected[0]["fields"][3]["value"] = json!("false");
    expected[0]["login"]["uris"][0]["match"] = json!(0);
    // The note: a null name as "Untitled".
    expected[1]["name"] = json!("Untitled");

    let got: Vec<J> = exported["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| comparable(i, &ef))
        .collect();
    assert_eq!(got.len(), expected.len());
    for e in &expected {
        let g = got.iter().find(|g| g["id"] == e["id"]).unwrap();
        assert_eq!(g, e);
    }
    // The card's keys keep the file's order.
    assert!(text.contains(
        "\"card\": {\n        \"cardholderName\": \"Jane Doe\",\n        \"expMonth\": \"4\","
    ));
}

#[test]
fn repeated_round_trip_is_stable() {
    let body = imported(&fixture("full.json"));
    let (_, first) = export(&body);
    let again = imported(first.as_bytes());
    for (a, b) in body.items.iter().zip(&again.items) {
        let (mut a, mut b) = (content(a), content(b));
        for x in [&mut a, &mut b] {
            x["origin"]["bitwarden"]["item"]
                .as_object_mut()
                .unwrap()
                .remove("revisionDate");
        }
        assert_eq!(a, b);
    }
}

fn field(name: &str, value: &str, hidden: bool) -> CustomField {
    CustomField {
        name: name.into(),
        value: value.into(),
        hidden,
        extra: Map::new(),
    }
}

fn fields(name: &str) -> ItemFields {
    ItemFields {
        name: name.into(),
        folder: String::new(),
        favourite: false,
        notes: String::new(),
        fields: Vec::new(),
        password_history: Vec::new(),
        created: 1_000,
        login: None,
        origin: None,
        extra: Map::new(),
    }
}

#[test]
fn items_made_in_the_vault() {
    let mut body = Body::default();
    let mut rng = TestRng(1);
    let mut f = fields("Mail");
    f.folder = "Personal".into();
    f.fields = vec![field("pin", "1234", true), field("flag", "true", false)];
    f.login = Some(Login {
        username: String::new(),
        password: "pw".into(),
        uris: vec![LoginUri {
            uri: "https://mail.example".into(),
            match_value: "something-new".into(),
            extra: Map::new(),
        }],
        apps: Vec::new(),
        totp: None,
        passkeys: Vec::new(),
        extra: Map::new(),
    });
    let login_id = add_item(&mut body, &mut rng, TYPE_LOGIN, f, 2_000, &DEV).unwrap();
    let note_id = add_item(&mut body, &mut rng, TYPE_NOTE, fields("Memo"), 3_000, &DEV).unwrap();
    let unknown = format!(
        r#"{{"id":"00000000-0000-4000-8000-0000000000aa","type":"card","modified":1,"modified_by":"{}"}}"#,
        "a".repeat(32)
    );
    let mut v = vault_core::json::parse(body.to_json().as_slice()).unwrap();
    if let vault_core::json::Value::Object(m) = &mut v
        && let Some(vault_core::json::Value::Array(items)) = m.get_mut("items")
    {
        items.push(vault_core::json::parse(unknown.as_bytes()).unwrap());
    }
    let body = Body::from_value(v).unwrap();

    let out = export_bitwarden(&body, &mut TestRng(9)).unwrap();
    assert_eq!((out.items, out.skipped), (2, 1));
    let (doc, _) = export(&body);
    let folder_id = doc["folders"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(doc["folders"][0]["name"], "Personal");
    let items = doc["items"].as_array().unwrap();
    assert_eq!(
        items[0],
        json!({
            "passwordHistory": [],
            "revisionDate": "1970-01-01T00:00:02.000Z",
            "creationDate": "1970-01-01T00:00:02.000Z",
            "id": login_id,
            "organizationId": null,
            "folderId": folder_id,
            "type": 1,
            "reprompt": 0,
            "name": "Mail",
            "notes": null,
            "favorite": false,
            "fields": [
                {"name": "pin", "value": "1234", "type": 1, "linkedId": null},
                {"name": "flag", "value": "true", "type": 0, "linkedId": null}
            ],
            "login": {
                "fido2Credentials": [],
                "uris": [{"match": 5, "uri": "https://mail.example"}],
                "username": null,
                "password": "pw",
                "totp": null
            },
            "collectionIds": null
        })
    );
    assert_eq!(items[1]["id"], json!(note_id));
    assert_eq!(items[1]["type"], 2);
    assert_eq!(items[1]["secureNote"], json!({"type": 0}));
    assert!(items[1].get("login").is_none());
    assert_eq!(items[1]["folderId"], J::Null);
}

#[test]
fn edits_after_import_decide_the_export() {
    let mut body = imported(&fixture("full.json"));
    let login = by_origin(&body, "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0001");
    let id = login.id.clone();
    let mut f = login.fields().unwrap().clone();
    // A boolean field whose value is no longer "true" or "false" is text; a regex URI whose match
    // changed is no longer a regex.
    f.fields[2].value = "maybe".into();
    f.login.as_mut().unwrap().uris[5].match_value = "host".into();
    update_item(&mut body, &id, f, NOW + 1, &DEV).unwrap();
    let (doc, _) = export(&body);
    let item = doc["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0001")
        .unwrap();
    assert_eq!(item["fields"][2]["type"], 0);
    assert_eq!(item["fields"][3]["type"], 2, "\"false\" is still boolean");
    assert_eq!(item["login"]["uris"][5]["match"], 1);
    assert_eq!(item["revisionDate"], "2025-10-09T08:53:20.001Z");
}

#[test]
fn a_card_note_without_its_fields_writes_nulls() {
    let mut body = imported(&fixture("full.json"));
    let card = by_origin(&body, "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0003");
    let id = card.id.clone();
    let mut f = card.fields().unwrap().clone();
    f.fields.retain(|c| c.name == "number" || c.name == "PIN");
    update_item(&mut body, &id, f, NOW + 1, &DEV).unwrap();
    let (doc, _) = export(&body);
    let item = doc["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0003")
        .unwrap();
    assert_eq!(
        item["card"],
        json!({
            "number": "4242424242424242",
            "cardholderName": null,
            "brand": null,
            "expMonth": null,
            "expYear": null,
            "code": null
        })
    );
    assert_eq!(item["fields"].as_array().unwrap().len(), 1);
    assert_eq!(item["fields"][0]["name"], "PIN");
}

#[test]
fn typed_objects_come_back_with_their_keys() {
    let text = serde_json::to_vec(&json!({"encrypted": false, "items": [{
        "id": "k", "type": 5, "name": "key",
        "sshKey": {"privateKey": "priv", "publicKey": "pub", "fingerprint": "SHA256:x"}
    }, {
        "id": "v", "type": 12, "name": "car",
        "vehicle": {"plate": "AB12", "seats": 5, "electric": true, "owners": ["a"], "vin": null}
    }]}))
    .unwrap();
    let (doc, _) = export(&imported(&text));
    assert_eq!(
        doc["items"][0]["sshKey"],
        json!({"privateKey": "priv", "publicKey": "pub", "fingerprint": "SHA256:x"})
    );
    assert_eq!(doc["items"][0]["fields"], json!([]));
    let car = &doc["items"][1];
    assert_eq!(car["type"], 12);
    assert!(car.get("secureNote").is_none());
    assert_eq!(
        car["vehicle"],
        json!({"plate": "AB12", "seats": "5", "electric": true, "owners": ["a"], "vin": null}),
        "numbers come back as strings"
    );
}

#[test]
fn export_always_reparses_whatever_origin_holds() {
    use vault_core::json::Value as V;
    let mut body = Body::default();
    let mut rng = TestRng(4);
    for (object, keys) in [
        ("name", vec!["a"]),
        ("reprompt", vec!["a"]),
        ("vehicle", vec!["a", "a", "fields"]),
    ] {
        let mut f = fields("x");
        f.fields = vec![field("a", "1", false), field("fields", "2", false)];
        let mut bw = Map::new();
        bw.insert("type".into(), V::Number(12));
        bw.insert("object".into(), V::String(object.into()));
        bw.insert(
            "object_keys".into(),
            V::Array(keys.iter().map(|k| V::String((*k).into())).collect()),
        );
        let mut item = Map::new();
        item.insert("name".into(), V::String("from origin".into()));
        item.insert("vehicle".into(), V::Bool(true));
        bw.insert("item".into(), V::Object(item));
        f.origin = Some(Map::from([("bitwarden".to_owned(), V::Object(bw))]));
        add_item(&mut body, &mut rng, TYPE_NOTE, f, 1, &DEV).unwrap();
    }
    let (doc, text) = export(&body);
    assert!(matches!(parse(text.as_bytes()), Ok(Export::Plain(_))));
    let items = doc["items"].as_array().unwrap();
    for i in &items[..2] {
        assert_eq!(
            i["type"], 2,
            "a key the mapping writes is never the typed object"
        );
        assert_eq!(i["name"], "x");
    }
    assert_eq!(items[2]["type"], 12);
    assert_eq!(items[2]["vehicle"], json!({"a": "1", "fields": "2"}));
    assert_eq!(items[2]["fields"], json!([]));
}
