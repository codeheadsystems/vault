//! The import mapping, repeated imports, the folder prefix, sanitising, and the file checks.

mod common;

use common::*;
use serde_json::json;
use vault_core::body::{AndroidApp, Body, TYPE_LOGIN, TYPE_NOTE};
use vault_core::json::Map;
use vault_interop::{Error, Export, MAX_EXPORT_SIZE, SkipReason, parse};

const LOGIN: &str = "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0001";
const NOTE: &str = "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0002";
const CARD: &str = "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0003";
const IDENTITY: &str = "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0004";
const SSH_KEY: &str = "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0005";

fn full() -> (Body, vault_interop::ImportReport) {
    let mut body = Body::default();
    let report = import_at(&mut body, &plain(&fixture("full.json")), "", NOW);
    (body, report)
}

#[test]
fn report_counts_and_skips() {
    let (body, r) = full();
    assert_eq!((r.added, r.updated, r.unchanged), (6, 0, 0));
    let skipped: Vec<(&str, SkipReason)> = r
        .skipped
        .iter()
        .map(|s| (s.name.as_str(), s.reason))
        .collect();
    assert_eq!(skipped, [("Old forum", SkipReason::Deleted)]);
    assert_eq!(r.collections, 1);
    assert_eq!(r.deleted_in_source, 0);
    assert_eq!(body.items.len(), 6);
    for item in &body.items {
        assert_eq!(item.modified, NOW, "imports are local edits");
        assert_eq!(item.modified_by, "d1".repeat(16));
        assert_eq!(item.review, None);
    }
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn login_mapping() {
    let (body, _) = full();
    let item = by_origin(&body, LOGIN);
    assert_eq!(item.item_type, TYPE_LOGIN);
    assert_eq!(
        content(item),
        json!({
            "type": "login",
            "name": "AWS console",
            "folder": "Work/AWS",
            "favourite": true,
            "notes": "Root account.\nUse the hardware key.",
            "fields": [
                {"name": "Account ID", "value": "123456789012", "hidden": false},
                {"name": "Recovery code", "value": "abcd-efgh", "hidden": true},
                {"name": "MFA enabled", "value": "true", "hidden": false},
                {"name": "Shared", "value": "false", "hidden": false}
            ],
            "password_history": [
                {"password": "old-2", "retired": 1_710_073_845_678u64},
                {"password": "moon", "retired": 0},
                {"password": "undated", "retired": 0}
            ],
            "created": 1_710_428_966_535u64,
            "login": {
                "username": "root@example.com",
                "password": "correct-password",
                "uris": [
                    {"uri": "https://console.aws.amazon.com", "match": "base_domain"},
                    {"uri": "https://aws.amazon.com", "match": "base_domain"},
                    {"uri": "https://signin.aws.amazon.com", "match": "host"},
                    {"uri": "https://console.aws.amazon.com/iam", "match": "starts_with"},
                    {"uri": "https://console.aws.amazon.com/billing/home", "match": "exact"},
                    {"uri": "^https://[a-z0-9-]+\\.signin\\.aws\\.amazon\\.com/", "match": "never"},
                    {"uri": "https://example.invalid", "match": "never"}
                ],
                "apps": [],
                "totp": "otpauth://totp/AWS:root?secret=KRSXG5CTMVRXEZLU&issuer=AWS",
                "passkeys": [{
                    "credentialId": "b64:AAECAwQFBgcICQ",
                    "keyType": "public-key",
                    "keyAlgorithm": "ECDSA",
                    "keyCurve": "P-256",
                    "keyValue": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
                    "rpId": "aws.amazon.com",
                    "userHandle": "dXNlcg",
                    "userName": "root",
                    "counter": "0",
                    "rpName": "AWS",
                    "userDisplayName": "Root",
                    "discoverable": "true",
                    "creationDate": "2024-03-14T15:09:26.535Z"
                }]
            },
            "origin": {"bitwarden": {
                "id": LOGIN,
                "type": 1,
                "item": {
                    "revisionDate": "2024-03-15T08:00:00.250Z",
                    "deletedDate": null,
                    "organizationId": null,
                    "reprompt": 1,
                    "collectionIds": null
                },
                "login": {
                    "passwordRevisionDate": "2024-03-10T12:30:45.678Z",
                    "autofillOnPageLoad": null
                },
                "boolean_fields": ["MFA enabled", "Shared"],
                "linked_fields": [
                    {"name": "Login name", "value": null, "type": 3, "linkedId": 100}
                ],
                "regex_uris": ["^https://[a-z0-9-]+\\.signin\\.aws\\.amazon\\.com/"]
            }}
        })
    );
}

#[test]
fn note_card_identity_and_ssh_key_mapping() {
    let (body, _) = full();
    let note = by_origin(&body, NOTE);
    assert_eq!(note.item_type, TYPE_NOTE);
    assert_eq!(
        content(note),
        json!({
            "type": "note",
            "name": "Untitled",
            "folder": "",
            "favourite": false,
            "notes": "Wi-Fi: guest / hunter2",
            "fields": [],
            "password_history": [],
            "created": 1_706_778_000_000u64,
            "origin": {"bitwarden": {
                "id": NOTE,
                "type": 2,
                "item": {
                    "revisionDate": "2024-02-01T09:00:00.000Z",
                    "deletedDate": null,
                    "organizationId": null,
                    "reprompt": 0,
                    "secureNote": {"type": 0},
                    "collectionIds": null
                }
            }}
        })
    );

    let card = by_origin(&body, CARD);
    assert_eq!(card.item_type, TYPE_NOTE);
    let c = content(card);
    assert_eq!(c["folder"], "Work");
    assert_eq!(c["notes"], "");
    assert_eq!(
        c["fields"],
        json!([
            {"name": "cardholderName", "value": "Jane Doe", "hidden": false},
            {"name": "expMonth", "value": "4", "hidden": false},
            {"name": "expYear", "value": "2030", "hidden": false},
            {"name": "code", "value": "123", "hidden": true},
            {"name": "brand", "value": "Visa", "hidden": false},
            {"name": "number", "value": "4242424242424242", "hidden": true},
            {"name": "PIN", "value": "1234", "hidden": true}
        ]),
        "card keys in the file's order, then the custom fields"
    );
    assert_eq!(c["origin"]["bitwarden"]["type"], 3);
    assert!(c["origin"]["bitwarden"]["item"].get("card").is_none());

    let identity = content(by_origin(&body, IDENTITY));
    let fields: Vec<(&str, bool)> = identity["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap(), f["hidden"].as_bool().unwrap()))
        .collect();
    assert_eq!(
        fields,
        [
            ("title", false),
            ("firstName", false),
            ("lastName", false),
            ("address1", false),
            ("city", false),
            ("postalCode", false),
            ("country", false),
            ("email", false),
            ("ssn", true),
            ("username", false),
            ("passportNumber", true)
        ],
        "null values are skipped"
    );
    assert_eq!(identity["origin"]["bitwarden"]["type"], 4);

    let ssh = content(by_origin(&body, SSH_KEY));
    assert_eq!(ssh["fields"][0]["name"], "privateKey");
    assert_eq!(ssh["fields"][0]["hidden"], true);
    assert_eq!(ssh["fields"][1]["name"], "publicKey");
    assert_eq!(ssh["fields"][2]["name"], "keyFingerprint");
    assert_eq!(ssh["fields"][2]["hidden"], false);
    assert_eq!(ssh["origin"]["bitwarden"]["type"], 5);
}

#[test]
fn organisation_items_keep_their_ownership() {
    let text = serde_json::to_vec(&json!({
        "encrypted": false,
        "collections": [
            {"id": "c-1", "organizationId": "org-1", "name": "Team", "externalId": null}
        ],
        "items": [{
            "id": "org-item",
            "organizationId": "org-1",
            "collectionIds": ["c-1"],
            "folderId": null,
            "type": 1,
            "reprompt": 0,
            "name": "Shared login",
            "notes": null,
            "favorite": false,
            "key": "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "login": {"uris": [{"uri": "team.example"}], "username": null, "password": null, "totp": ""}
        }]
    }))
    .unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&text), "", NOW);
    assert_eq!((r.added, r.collections), (1, 1));
    let c = content(&body.items[0]);
    assert_eq!(c["login"]["username"], "");
    assert_eq!(
        c["login"]["totp"],
        serde_json::Value::Null,
        "an empty TOTP is none"
    );
    assert_eq!(
        c["login"]["uris"],
        json!([{"uri": "team.example", "match": "base_domain"}])
    );
    let kept = &c["origin"]["bitwarden"]["item"];
    assert_eq!(kept["organizationId"], "org-1");
    assert_eq!(kept["collectionIds"], json!(["c-1"]));
    assert!(kept["key"].is_string());
}

#[test]
fn newer_typed_items_become_notes() {
    // Written as text, as serde_json would sort the keys of each typed object.
    let text = br#"{"encrypted": false, "items": [
        {"id": "bank", "type": 6, "name": "Bank", "bankAccount": {
            "bankName": "First Bank", "accountNumber": "12345678", "routingNumber": "021000021",
            "pin": "4321", "iban": "GB00TEST", "swiftCode": null}},
        {"id": "licence", "type": 7, "name": "Licence", "driversLicense": {
            "firstName": "Jane", "licenseNumber": "D123"}},
        {"id": "passport", "type": 8, "name": "Passport", "passport": {
            "surname": "Doe", "passportNumber": "X1", "nationalIdentificationNumber": "N1"}},
        {"id": "future", "type": 12, "name": "Future", "secureNote": null, "login": null,
         "vehicle": {"plate": "AB12 CDE", "seats": 5, "electric": true, "owners": ["a"],
                     "vin": null}}
    ]}"#;
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(text), "", NOW);
    assert_eq!((r.added, r.skipped.len()), (4, 0));
    let hidden = |id: &str| -> Vec<(String, bool)> {
        content(by_origin(&body, id))["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["name"].as_str().unwrap().to_owned(),
                    f["hidden"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let names = |v: &[(&str, bool)]| -> Vec<(String, bool)> {
        v.iter().map(|(n, h)| ((*n).to_owned(), *h)).collect()
    };
    assert_eq!(
        hidden("bank"),
        names(&[
            ("bankName", false),
            ("accountNumber", true),
            ("routingNumber", true),
            ("pin", true),
            ("iban", true)
        ])
    );
    assert_eq!(
        hidden("licence"),
        names(&[("firstName", false), ("licenseNumber", true)])
    );
    assert_eq!(
        hidden("passport"),
        names(&[
            ("surname", false),
            ("passportNumber", true),
            ("nationalIdentificationNumber", true)
        ])
    );
    let future = content(by_origin(&body, "future"));
    assert_eq!(future["type"], "note");
    assert_eq!(
        future["fields"],
        json!([
            {"name": "plate", "value": "AB12 CDE", "hidden": false},
            {"name": "seats", "value": "5", "hidden": false}
        ])
    );
    let bw = &future["origin"]["bitwarden"];
    assert_eq!(bw["type"], 12);
    assert_eq!(bw["object"], "vehicle");
    assert_eq!(
        bw["object_keys"],
        json!(["plate", "seats", "electric", "owners", "vin"])
    );
    assert_eq!(
        bw["object_values"],
        json!({"electric": true, "owners": ["a"]})
    );
    assert!(bw["item"].get("vehicle").is_none());
}

#[test]
fn an_item_without_a_recognisable_typed_object_is_skipped() {
    let text = serde_json::to_vec(&json!({"encrypted": false, "items": [
        {"id": "a", "type": 12, "name": "None"},
        {"id": "b", "type": 12, "name": "Two", "x": {}, "y": {}}
    ]}))
    .unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&text), "", NOW);
    assert_eq!(r.added, 0);
    let skipped: Vec<(&str, SkipReason)> = r
        .skipped
        .iter()
        .map(|s| (s.name.as_str(), s.reason))
        .collect();
    assert_eq!(
        skipped,
        [
            ("None", SkipReason::UnsupportedType),
            ("Two", SkipReason::UnsupportedType)
        ]
    );
}

#[test]
fn repeated_import_is_unchanged() {
    let export = plain(&fixture("full.json"));
    let mut body = Body::default();
    import_at(&mut body, &export, "", NOW);
    let before = body.clone();
    let r = import_at(&mut body, &export, "", NOW + 1000);
    assert_eq!((r.added, r.updated, r.unchanged), (0, 0, 6));
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.deleted_in_source, 0);
    assert!(body == before, "an unchanged item is not stamped");
}

/// Replaces `from`, which occurs once, in `text`.
fn edit(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from}");
    text.replace(from, to)
}

/// The fixture with its login's password and name changed and its card in the trash. The text is
/// edited in place, as a JSON round trip would reorder the card's keys.
fn changed_export() -> Vec<u8> {
    let text = String::from_utf8(fixture("full.json")).unwrap();
    let text = edit(
        &text,
        r#""password": "correct-password""#,
        r#""password": "new-password""#,
    );
    let text = edit(&text, r#""name": "AWS console""#, r#""name": "AWS root""#);
    let text = edit(
        &text,
        r#""deletedDate": null,
      "id": "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0003"#,
        r#""deletedDate": "2024-03-01T00:00:00.000Z",
      "id": "5f0e2a61-1c4b-4e7a-9d0c-7a3e2b1c0003"#,
    );
    text.into_bytes()
}

#[test]
fn repeated_import_updates_changed_items() {
    let mut body = imported(&fixture("full.json"));
    let id = by_origin(&body, LOGIN).id.clone();
    // Values the mapping does not set survive the update.
    let later = NOW + 5000;
    let r = import_at(&mut body, &plain(&changed_export()), "", later);
    assert_eq!((r.added, r.updated, r.unchanged), (0, 1, 4));
    assert_eq!(r.skipped.len(), 2);
    assert_eq!(r.deleted_in_source, 1, "the card is in the trash");
    assert!(
        body.items.iter().any(|i| origin_id(i) == Some(CARD)),
        "and stays"
    );
    let item = by_origin(&body, LOGIN);
    assert_eq!(item.id, id, "updated in place");
    assert_eq!(item.modified, later);
    let c = content(item);
    assert_eq!(c["name"], "AWS root");
    assert_eq!(c["login"]["password"], "new-password");
    assert_eq!(
        c["password_history"][0],
        json!({"password": "correct-password", "retired": later}),
        "the old password moves into the history"
    );
    assert_eq!(c["password_history"].as_array().unwrap().len(), 4);
    for other in [NOTE, IDENTITY, SSH_KEY] {
        assert_eq!(
            by_origin(&body, other).modified,
            NOW,
            "{other} is unchanged"
        );
    }
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn a_skipped_item_is_not_deleted_in_source() {
    let mut body = imported(&fixture("full.json"));
    let text = String::from_utf8(fixture("full.json")).unwrap();
    let text = edit(&text, r#""favorite": true,"#, r#""favorite": "yes","#);
    let r = import_at(&mut body, &plain(text.as_bytes()), "", NOW + 1);
    assert_eq!(r.skipped.len(), 2);
    assert_eq!(r.skipped[0].name, "AWS console");
    assert_eq!(r.skipped[0].reason, SkipReason::Malformed);
    assert_eq!(r.deleted_in_source, 0);
}

#[test]
fn update_keeps_what_the_mapping_does_not_set() {
    let mut body = imported(&fixture("full.json"));
    let pos = body
        .items
        .iter()
        .position(|i| origin_id(i) == Some(LOGIN))
        .unwrap();
    let mut f = body.items[pos].fields().unwrap().clone();
    f.login.as_mut().unwrap().apps.push(AndroidApp {
        package: "com.amazon.aws".into(),
        cert_sha256: "ab".repeat(32),
        extra: Map::new(),
    });
    f.extra
        .insert("future".into(), vault_core::json::Value::Bool(true));
    let mut other = Map::new();
    other.insert("x".into(), vault_core::json::Value::Number(1));
    f.origin
        .as_mut()
        .unwrap()
        .insert("onepassword".into(), vault_core::json::Value::Object(other));
    let id = body.items[pos].id.clone();
    vault_core::edit::update_item(&mut body, &id, f, NOW + 1, &DEV).unwrap();

    import_at(&mut body, &plain(&changed_export()), "", NOW + 2);
    let c = content(by_origin(&body, LOGIN));
    assert_eq!(c["login"]["password"], "new-password");
    assert_eq!(c["login"]["apps"][0]["package"], "com.amazon.aws");
    assert_eq!(c["future"], true);
    assert_eq!(c["origin"]["onepassword"]["x"], 1);
    assert_eq!(c["origin"]["bitwarden"]["id"], LOGIN);
}

#[test]
fn update_to_another_type_keeps_the_password() {
    let mut body = imported(&fixture("full.json"));
    let text = String::from_utf8(fixture("full.json")).unwrap();
    let text = edit(
        &text,
        r#""type": 1,
      "reprompt": 1"#,
        r#""type": 2,
      "reprompt": 1"#,
    );
    let r = import_at(&mut body, &plain(text.as_bytes()), "", NOW + 9);
    assert_eq!(r.updated, 1);
    let item = by_origin(&body, LOGIN);
    assert_eq!(item.item_type, TYPE_NOTE);
    let c = content(item);
    assert!(c.get("login").is_none());
    assert!(
        c["origin"]["bitwarden"]["item"]["login"].is_object(),
        "kept as a leftover"
    );
    assert_eq!(
        c["password_history"][0],
        json!({"password": "correct-password", "retired": NOW + 9})
    );
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn folder_prefix() {
    for prefix in ["Bitwarden", "/Bitwarden/"] {
        let mut body = Body::default();
        import_at(&mut body, &plain(&fixture("full.json")), prefix, NOW);
        let folder = |id| by_origin(&body, id).fields().unwrap().folder.clone();
        assert_eq!(folder(LOGIN), "Bitwarden/Work/AWS");
        assert_eq!(folder(CARD), "Bitwarden/Work");
        assert_eq!(folder(NOTE), "Bitwarden");
    }
}

fn one_item(item: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"encrypted": false, "folders": [], "items": [item]})).unwrap()
}

#[test]
fn sanitising() {
    // serde_json keeps number source text only through a string, so the file is written by hand.
    let text = r#"{"encrypted":false,"items":[{"id":"a","type":2,"name":"n",
        "creationDate":"1960-01-01T00:00:00.000Z","reprompt":0,
        "odd":[-1,1.5,1e3,-0,9007199254740992,9007199254740991,0]}]}"#;
    let body = imported(text.as_bytes());
    let c = content(&body.items[0]);
    assert_eq!(c["created"], 0, "a date before 1970 is 0");
    assert_eq!(
        c["origin"]["bitwarden"]["item"]["odd"],
        json!([
            "-1",
            "1.5",
            "1e3",
            "-0",
            "9007199254740992",
            9_007_199_254_740_991u64,
            0
        ])
    );
    assert_eq!(c["origin"]["bitwarden"]["item"]["reprompt"], 0);
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn items_that_break_a_body_rule_are_skipped() {
    let mut deep = json!("x");
    for _ in 0..30 {
        deep = json!([deep]);
    }
    let shallow = {
        let mut d = json!("x");
        for _ in 0..20 {
            d = json!([d]);
        }
        d
    };
    let text = serde_json::to_vec(&json!({"encrypted": false, "items": [
        {"id": "a", "type": 2, "name": "Too deep", "nested": deep},
        {"id": "b", "type": 2, "name": "Deep enough", "nested": shallow}
    ]}))
    .unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&text), "", NOW);
    assert_eq!(r.added, 1);
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.skipped[0].name, "Too deep");
    assert_eq!(r.skipped[0].reason, SkipReason::BodyRules);
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn passkeys_are_sanitised_too() {
    let body = imported(&one_item(json!({
        "id": "a", "type": 1, "name": "n",
        "login": {"fido2Credentials": [{"counter": -3, "n": 2}]}
    })));
    let c = content(&body.items[0]);
    assert_eq!(c["login"]["passkeys"], json!([{"counter": "-3", "n": 2}]));
}

#[test]
fn history_is_normalised() {
    let history: Vec<serde_json::Value> = (0..14)
        .map(|n| {
            json!({"password": format!("p{n:02}"), "lastUsedDate": format!("2024-01-{:02}T00:00:00Z", n + 1)})
        })
        .chain([
            json!({"password": "current", "lastUsedDate": "2025-01-01T00:00:00Z"}),
            json!({"password": "", "lastUsedDate": "2025-01-01T00:00:00Z"}),
            json!({"password": "p13", "lastUsedDate": "2023-01-01T00:00:00Z"}),
        ])
        .collect();
    let body = imported(&one_item(json!({
        "id": "a", "type": 1, "name": "n",
        "login": {"password": "current"},
        "passwordHistory": history
    })));
    let c = content(&body.items[0]);
    let h: Vec<&str> = c["password_history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["password"].as_str().unwrap())
        .collect();
    assert_eq!(
        h,
        [
            "p13", "p12", "p11", "p10", "p09", "p08", "p07", "p06", "p05", "p04"
        ]
    );
}

#[test]
fn malformed_items_are_skipped_and_named() {
    let text = serde_json::to_vec(&json!({"encrypted": false, "items": [
        {"id": "a", "type": 1, "name": "Bad login", "login": "x"},
        {"id": "b", "type": 1, "name": "Good"}
    ]}))
    .unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&text), "", NOW);
    assert_eq!(r.added, 1);
    assert_eq!(r.skipped[0].name, "Bad login");
    assert_eq!(r.skipped[0].reason, SkipReason::Malformed);
    assert_eq!(r.skipped[0].reason.code(), "malformed");
}

#[test]
fn file_refusals() {
    let err = |b: &[u8]| parse(b).err();
    assert_eq!(
        err(br#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.x|y|z", "folders": [], "items": []}"#),
        Some(Error::AccountRestricted)
    );
    assert_eq!(
        err(b"{\"encrypted\":true,\"items\":[]}"),
        Some(Error::AccountRestricted)
    );
    for not_export in [
        &b"[]"[..],
        b"{\"encrypted\":false}",
        b"{\"items\":{}}",
        b"{\"items\":[],\"folders\":1}",
        b"{\"encrypted\":\"no\",\"items\":[]}",
        b"{\"encrypted\":true,\"passwordProtected\":true,\"kdfType\":0,\"kdfIterations\":5000}",
    ] {
        assert_eq!(err(not_export), Some(Error::NotAnExport));
    }
    assert_eq!(err(b"{\"items\":[],}"), Some(Error::Json));
    assert_eq!(err(b"{\"items\":[],\"items\":[]}"), Some(Error::Json));
    assert!(matches!(parse(b"{\"items\":[]}"), Ok(Export::Plain(_))));
}

#[test]
fn size_cap() {
    let mut big = vec![b' '; MAX_EXPORT_SIZE + 1];
    big[0] = b'x';
    assert_eq!(parse(&big).err(), Some(Error::TooLarge));
    let mut fits = vec![b' '; MAX_EXPORT_SIZE];
    fits[..12].copy_from_slice(b"{\"items\":[]}");
    assert!(parse(&fits).is_ok());
}

#[test]
fn errors_have_codes() {
    assert_eq!(Error::WrongPassword.code(), "bitwarden.wrong_password");
    assert_eq!(
        Error::Core(vault_core::Error::Rng).code(),
        vault_core::Error::Rng.code()
    );
}

#[test]
fn a_failed_import_leaves_the_body_alone() {
    struct Failing;
    impl vault_core::rng::Rng for Failing {
        fn fill(&mut self, _: &mut [u8]) -> vault_core::Result<()> {
            Err(vault_core::Error::Rng)
        }
    }
    let mut body = imported(&fixture("full.json"));
    let before = body.clone();
    let res = vault_interop::import(
        &mut body,
        &plain(&changed_export()),
        &vault_interop::ImportOptions::default(),
        NOW + 1,
        &DEV,
        &mut Failing,
    );
    assert!(res.is_ok(), "no new item, so no draw");
    let mut body = before.clone();
    let res = vault_interop::import(
        &mut body,
        &plain(&one_item(json!({"id": "new", "type": 2, "name": "n"}))),
        &vault_interop::ImportOptions::default(),
        NOW + 1,
        &DEV,
        &mut Failing,
    );
    assert_eq!(res.err(), Some(Error::Core(vault_core::Error::Rng)));
    assert!(body == before);
}

#[test]
fn many_tiny_values_are_refused_by_count() {
    // About 512 Ki values in 1 MiB, over the limit of one value per 4 bytes. The same size
    // spent on fewer, longer values parses, so the refusal is the count, not the size.
    let n = 1 << 19;
    let zeros = format!("{{\"items\":[{}0]}}", "0,".repeat(n - 1));
    assert_eq!(parse(zeros.as_bytes()).err(), Some(Error::Json));
    let empties = format!("{{\"items\":[{}[]]}}", "[],".repeat(n - 1));
    assert_eq!(parse(empties.as_bytes()).err(), Some(Error::Json));
    let words = format!("{{\"items\":[{}\"x\"]}}", "\"abcdefg\",".repeat(n / 4 - 1));
    assert!(words.len() >= zeros.len() - 16);
    assert!(parse(words.as_bytes()).is_ok());
}

#[test]
fn lone_surrogates_import_as_replacement_characters() {
    let body = imported(
        br#"{"items":[{"id":"a","type":1,"name":"x\ud800y","login":{"password":"\udc00"}}]}"#,
    );
    let c = content(&body.items[0]);
    assert_eq!(c["name"], "x\u{fffd}y");
    assert_eq!(c["login"]["password"], "\u{fffd}");
}

#[test]
fn keys_the_mapping_owns_are_never_a_typed_object() {
    let text = serde_json::to_vec(&json!({"encrypted": false, "items": [
        {"id": "a", "type": 12, "name": "One", "reprompt": {"x": 1}, "revisionDate": {},
         "collectionIds": {}, "vehicle": {"plate": "P"}},
        {"id": "b", "type": 12, "name": "None", "reprompt": {"x": 1}, "deletedDate": null,
         "organizationId": {}, "creationDate": {}}
    ]}))
    .unwrap();
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&text), "", NOW);
    assert_eq!(r.added, 1);
    assert_eq!(r.skipped[0].name, "None");
    assert_eq!(r.skipped[0].reason, SkipReason::UnsupportedType);
    let c = content(&body.items[0]);
    assert_eq!(c["origin"]["bitwarden"]["object"], "vehicle");
    let out = vault_interop::export_bitwarden(&body, &mut TestRng(1)).unwrap();
    let again = imported(&out.json);
    assert_eq!(content(&again.items[0])["fields"], c["fields"]);
}

#[test]
fn reimport_overwrites_vault_edits_to_mapped_fields() {
    let export = plain(&fixture("full.json"));
    let mut body = imported(&fixture("full.json"));
    let id = by_origin(&body, LOGIN).id.clone();
    let mut f = by_origin(&body, LOGIN).fields().unwrap().clone();
    f.name = "Renamed in the vault".into();
    f.login.as_mut().unwrap().password = "changed-in-vault".into();
    vault_core::edit::update_item(&mut body, &id, f, NOW + 1, &DEV).unwrap();

    let r = import_at(&mut body, &export, "", NOW + 2);
    assert_eq!((r.added, r.updated), (0, 1));
    let c = content(by_origin(&body, LOGIN));
    assert_eq!(c["name"], "AWS console", "the export's name wins");
    assert_eq!(c["login"]["password"], "correct-password");
    let history: Vec<&str> = c["password_history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["password"].as_str().unwrap())
        .collect();
    assert_eq!(
        history[0], "changed-in-vault",
        "only the password reaches the history"
    );
    assert!(!history.contains(&"Renamed in the vault"));
}

#[test]
fn reimport_adds_an_item_deleted_in_the_vault_again() {
    let export = plain(&fixture("full.json"));
    let mut body = imported(&fixture("full.json"));
    let id = by_origin(&body, LOGIN).id.clone();
    vault_core::edit::delete_item(&mut body, &id, NOW + 1, &DEV).unwrap();
    let r = import_at(&mut body, &export, "", NOW + 2);
    assert_eq!((r.added, r.unchanged), (1, 5));
    let again = by_origin(&body, LOGIN);
    assert_ne!(again.id, id, "a new item; the tombstone carries no origin");
    assert!(body.tombstones.iter().any(|t| t.id == id));
    assert!(body.to_checked_json().is_ok());
}

#[test]
fn duplicate_bitwarden_ids_pair_with_vault_items_in_order() {
    let two = |a: &str, b: &str| {
        serde_json::to_vec(&json!({"encrypted": false, "items": [
            {"id": "dup", "type": 2, "name": a},
            {"id": "dup", "type": 2, "name": b}
        ]}))
        .unwrap()
    };
    let mut body = Body::default();
    let r = import_at(&mut body, &plain(&two("first", "second")), "", NOW);
    assert_eq!(r.added, 2, "both are added");
    let r = import_at(&mut body, &plain(&two("first", "second")), "", NOW + 1);
    assert_eq!(
        (r.added, r.updated, r.unchanged),
        (0, 0, 2),
        "each pairs with its own"
    );
    let r = import_at(&mut body, &plain(&two("first", "changed")), "", NOW + 2);
    assert_eq!((r.added, r.updated, r.unchanged), (0, 1, 1));
    let names: Vec<String> = body
        .items
        .iter()
        .map(|i| i.fields().unwrap().name.clone())
        .collect();
    assert_eq!(names, ["first", "changed"]);
    let r = import_at(&mut body, &plain(&two("first", "second")), "", NOW + 3);
    assert_eq!(r.updated, 1);
    let three = serde_json::to_vec(&json!({"encrypted": false, "items": [
        {"id": "dup", "type": 2, "name": "first"},
        {"id": "dup", "type": 2, "name": "second"},
        {"id": "dup", "type": 2, "name": "third"}
    ]}))
    .unwrap();
    let r = import_at(&mut body, &plain(&three), "", NOW + 4);
    assert_eq!((r.added, r.unchanged), (1, 2), "an extra entry is added");
}
