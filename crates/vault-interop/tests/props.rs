//! Properties: the export of any imported body imports to the same items, and a repeated import
//! of the same export changes nothing.

mod common;

use common::*;
use proptest::prelude::*;
use serde_json::{Value as J, json};
use vault_core::body::Body;
use vault_interop::export_bitwarden;

const DATES: [&str; 3] = [
    "2024-03-14T15:09:26.535Z",
    "1969-07-20T20:17:40.000Z",
    "2001-09-09T01:46:40.000Z",
];
/// The typed objects of types 3 to 9; 9 stands for a type added after this client.
const TYPED: [(&str, &[&str]); 7] = [
    (
        "card",
        &[
            "cardholderName",
            "brand",
            "number",
            "expMonth",
            "expYear",
            "code",
        ],
    ),
    (
        "identity",
        &[
            "title",
            "firstName",
            "lastName",
            "city",
            "ssn",
            "passportNumber",
        ],
    ),
    ("sshKey", &["privateKey", "publicKey", "keyFingerprint"]),
    (
        "bankAccount",
        &["bankName", "accountNumber", "routingNumber", "pin", "iban"],
    ),
    (
        "driversLicense",
        &["firstName", "licenseNumber", "issuingState"],
    ),
    (
        "passport",
        &["surname", "passportNumber", "nationalIdentificationNumber"],
    ),
    ("vehicle", &["plate", "vin", "colour"]),
];

fn text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 /é\"\\\\\n]{0,8}"
}

fn opt_text() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(text())
}

fn date() -> impl Strategy<Value = J> {
    prop_oneof![
        Just(J::Null),
        (0..DATES.len()).prop_map(|i| json!(DATES[i]))
    ]
}

fn odd_value() -> impl Strategy<Value = J> {
    prop_oneof![
        Just(json!(-1)),
        Just(json!(1.5)),
        Just(json!(7)),
        Just(json!(null)),
        text().prop_map(J::String),
        Just(json!({"nested": [1, -2, {"x": true}]})),
    ]
}

/// One Bitwarden item with index `n`. Field names and URIs carry the index of their entry, so
/// none repeats within an item.
fn item(n: usize) -> impl Strategy<Value = J> {
    let fields = proptest::collection::vec((0u64..5, opt_text(), any::<bool>()), 0..4);
    let uris = proptest::collection::vec(proptest::option::of(0u64..7), 0..4);
    let history = proptest::collection::vec((text(), date()), 0..13);
    let type_values = proptest::collection::vec(opt_text(), 7);
    let order = Just(()).prop_perturb(|_, mut r| {
        let mut o: Vec<usize> = (0..7).collect();
        for i in (1..o.len()).rev() {
            o.swap(i, r.random_range(0..=i));
        }
        o
    });
    (
        (1u64..=9, opt_text(), opt_text(), any::<bool>(), 0usize..3, date()),
        (fields, uris, history, type_values, order),
        (opt_text(), opt_text(), opt_text(), odd_value(), any::<bool>()),
    )
        .prop_map(move |(head, lists, rest)| {
            let (t, name, notes, favourite, folder, created) = head;
            let (fields, uris, history, type_values, order) = lists;
            let (username, password, totp, odd, linked) = rest;
            let folder = ["", "f1", "f2"][folder];
            let mut fs: Vec<J> = fields
                .iter()
                .enumerate()
                .map(|(i, (ft, v, _))| {
                    let ft = if *ft == 4 { 7 } else { *ft };
                    json!({"name": format!("field {i}"), "value": v, "type": ft, "linkedId": null})
                })
                .filter(|f| f["type"] != 3)
                .collect();
            if linked {
                fs.push(json!({"name": "linked", "value": null, "type": 3, "linkedId": 101}));
            }
            let mut item = json!({
                "passwordHistory": history.iter().map(|(p, d)| json!({"password": p, "lastUsedDate": d})).collect::<Vec<_>>(),
                "revisionDate": "2024-02-01T00:00:00.000Z",
                "creationDate": created,
                "deletedDate": null,
                "id": format!("bw-{n}"),
                "organizationId": null,
                "folderId": if folder.is_empty() { J::Null } else { json!(folder) },
                "type": t,
                "reprompt": u64::from(favourite),
                "name": name,
                "notes": notes,
                "favorite": favourite,
                "fields": fs,
                "collectionIds": null,
                "odd": [odd.clone()]
            });
            match t {
                1 => {
                    item["login"] = json!({
                        "fido2Credentials": [{"counter": -1, "rpId": "example.com", "n": 3}],
                        "uris": uris.iter().enumerate().map(|(i, m)| json!({"match": m, "uri": format!("https://{i}.example")})).collect::<Vec<_>>(),
                        "username": username,
                        "password": password,
                        "totp": totp,
                        "passwordRevisionDate": null
                    });
                }
                2 => item["secureNote"] = json!({"type": 0}),
                _ => {
                    let (key, keys) = TYPED[(t - 3) as usize];
                    let mut obj: serde_json::Map<String, J> = order
                        .iter()
                        .filter(|&&i| i < keys.len())
                        .map(|&i| (keys[i].to_owned(), json!(type_values[i])))
                        .collect();
                    obj.insert("other".into(), odd);
                    item[key] = J::Object(obj);
                }
            }
            item
        })
}

fn export_doc() -> impl Strategy<Value = Vec<u8>> {
    (0usize..6)
        .prop_flat_map(|n| (0..n).map(item).collect::<Vec<_>>())
        .prop_map(|items| {
            serde_json::to_vec(&json!({
                "encrypted": false,
                "folders": [{"id": "f1", "name": "A"}, {"id": "f2", "name": "A/B"}],
                "items": items
            }))
            .unwrap()
        })
}

/// The items keyed by their Bitwarden ID, without what an export legitimately changes: the vault
/// item ID, the import stamp, and the `revisionDate` kept from the source.
fn items_by_origin(body: &Body) -> Vec<(String, J)> {
    let mut out: Vec<(String, J)> = body
        .items
        .iter()
        .map(|i| {
            let mut c = content(i);
            c["origin"]["bitwarden"]["item"]
                .as_object_mut()
                .unwrap()
                .remove("revisionDate");
            (origin_id(i).unwrap().to_owned(), c)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn export_of_an_imported_body_imports_to_the_same_items(doc in export_doc()) {
        let first = imported(&doc);
        prop_assert!(first.to_checked_json().is_ok());
        let out = export_bitwarden(&first, &mut TestRng(3)).unwrap();
        prop_assert_eq!(out.items, first.items.len());
        let mut second = Body::default();
        let r = import_at(&mut second, &plain(&out.json), "", NOW + 1);
        prop_assert!(r.skipped.is_empty());
        prop_assert_eq!(items_by_origin(&first), items_by_origin(&second));
    }

    #[test]
    fn a_repeated_import_changes_nothing(doc in export_doc()) {
        let export = plain(&doc);
        let mut body = Body::default();
        let r1 = import_at(&mut body, &export, "", NOW);
        let before = body.clone();
        let r2 = import_at(&mut body, &export, "", NOW + 1);
        prop_assert_eq!((r2.added, r2.updated, r2.unchanged), (0, 0, r1.added));
        prop_assert!(body == before);
    }
}
