//! The export to a plain Bitwarden JSON file, reversing the import mapping. Keys are written in
//! the order Bitwarden writes them, followed by the keys kept in `origin`.

use crate::error::Result;
use crate::import::bitwarden_origin;
use crate::mapping::{BW_LOGIN, BW_NOTE, ITEM_KEYS, match_to_bitwarden};
use crate::source::{Json, to_pretty};
use crate::time::format_ms;
use std::collections::BTreeMap;
use vault_core::body::{Body, CustomField, Item, ItemFields, TYPE_LOGIN, new_item_id};
use vault_core::json::{Map, Value};
use vault_core::rng::Rng;
use zeroize::Zeroizing;

/// A Bitwarden export of a body.
pub struct BitwardenExport {
    /// The export file: JSON indented by two spaces, as Bitwarden writes it.
    pub json: Zeroizing<Vec<u8>>,
    /// Items written.
    pub items: usize,
    /// Items of a `type` this client does not know, which are not written.
    pub skipped: usize,
}

/// Exports the logins and notes of `body` as a plain Bitwarden JSON export, as described in
/// `docs/bitwarden.md`. Each distinct folder draws 16 bytes from `rng` for its ID, in the byte
/// order of the folder paths.
pub fn export_bitwarden(body: &Body, rng: &mut dyn Rng) -> Result<BitwardenExport> {
    let mut folder_ids: BTreeMap<&str, String> = BTreeMap::new();
    for f in body.items.iter().filter_map(Item::fields) {
        if !f.folder.is_empty() {
            folder_ids.insert(&f.folder, String::new());
        }
    }
    for id in folder_ids.values_mut() {
        *id = new_item_id(rng)?;
    }
    let folders = folder_ids
        .iter()
        .map(|(name, id)| obj(vec![("id", s(id)), ("name", s(name))]))
        .collect();
    let mut items = Vec::new();
    let mut skipped = 0;
    for item in &body.items {
        match item.fields() {
            Some(f) => items.push(export_item(item, f, &folder_ids)),
            None => skipped += 1,
        }
    }
    let count = items.len();
    let root = obj(vec![
        ("encrypted", Json::Bool(false)),
        ("folders", Json::Array(folders)),
        ("items", Json::Array(items)),
    ]);
    Ok(BitwardenExport {
        json: to_pretty(&root),
        items: count,
        skipped,
    })
}

fn s(v: &str) -> Json {
    Json::String(v.to_owned())
}

/// A string, or null when it is empty.
fn s_or_null(v: &str) -> Json {
    if v.is_empty() { Json::Null } else { s(v) }
}

fn num(n: u64) -> Json {
    Json::Number(n.to_string())
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// Appends each key of the kept object `from` that `into` does not hold yet.
fn fill_from(into: &mut Vec<(String, Json)>, from: Option<&Value>) {
    if let Some(Value::Object(m)) = from {
        for (k, v) in m {
            if !into.iter().any(|(x, _)| x == k) {
                into.push((k.clone(), v.into()));
            }
        }
    }
}

fn string_list(origin: Option<&Map>, key: &str) -> Vec<String> {
    match origin.and_then(|o| o.get(key)) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                Value::String(x) => Some(x.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The typed object of a note imported from a typed item, with its recorded keys in their
/// recorded order: the first custom field named after a key gives its value, and that field is
/// removed from `custom`; otherwise the value kept in `object_values`, or null.
fn type_object(keys: &[String], values: Option<&Map>, custom: &mut Vec<&CustomField>) -> Json {
    let mut o = Vec::new();
    for k in keys {
        if o.iter().any(|(x, _)| x == k) {
            continue;
        }
        let v = match custom.iter().position(|f| f.name == *k) {
            Some(p) => Json::String(custom.remove(p).value.clone()),
            None => values.and_then(|v| v.get(k)).map_or(Json::Null, Json::from),
        };
        o.push((k.clone(), v));
    }
    Json::Object(o)
}

fn export_item(item: &Item, f: &ItemFields, folder_ids: &BTreeMap<&str, String>) -> Json {
    let origin = bitwarden_origin(f);
    let kept = |k: &str| origin.and_then(|o| o.get(k));
    let is_login = item.item_type == TYPE_LOGIN;
    // A note imported from a typed item: its Bitwarden `type` and the key of its typed object.
    // `origin` may come from another client, so a key the mapping writes itself is never taken
    // as the typed object's.
    let typed = match (kept("type"), kept("object")) {
        (Some(t), Some(Value::String(k)))
            if !is_login
                && !matches!(t, Value::Number(BW_LOGIN | BW_NOTE))
                && !ITEM_KEYS.contains(&k.as_str()) =>
        {
            Some((t, k.as_str()))
        }
        _ => None,
    };
    let id = match kept("id") {
        Some(Value::String(bw)) => bw.clone(),
        _ => item.id.clone(),
    };
    let item_kept = match kept("item") {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    // Without a kept value, these take the values of an item made in Bitwarden.
    let kept_or =
        |k: &str, default: Json| item_kept.and_then(|m| m.get(k)).map_or(default, Json::from);

    let history = f
        .password_history
        .iter()
        .map(|h| {
            obj(vec![
                ("lastUsedDate", s(&format_ms(h.retired))),
                ("password", s(&h.password)),
            ])
        })
        .collect();

    let mut custom: Vec<&CustomField> = f.fields.iter().collect();
    let type_obj = typed.map(|(_, k)| {
        let keys = string_list(origin, "object_keys");
        let values = match kept("object_values") {
            Some(Value::Object(v)) => Some(v),
            _ => None,
        };
        (k, type_object(&keys, values, &mut custom))
    });
    let boolean = string_list(origin, "boolean_fields");
    let mut fields: Vec<Json> = custom
        .iter()
        .map(|c| {
            let t = if boolean.contains(&c.name) && (c.value == "true" || c.value == "false") {
                2
            } else if c.hidden {
                1
            } else {
                0
            };
            obj(vec![
                ("name", s(&c.name)),
                ("value", s(&c.value)),
                ("type", num(t)),
                ("linkedId", Json::Null),
            ])
        })
        .collect();
    if let Some(Value::Array(linked)) = kept("linked_fields") {
        fields.extend(linked.iter().map(Json::from));
    }

    let mut m: Vec<(String, Json)> = Vec::new();
    let mut put = |k: &str, v: Json| m.push((k.to_owned(), v));
    put("passwordHistory", Json::Array(history));
    put("revisionDate", s(&format_ms(item.modified)));
    put("creationDate", s(&format_ms(f.created)));
    put("id", Json::String(id));
    put("organizationId", kept_or("organizationId", Json::Null));
    put(
        "folderId",
        folder_ids
            .get(f.folder.as_str())
            .map_or(Json::Null, |id| s(id)),
    );
    put(
        "type",
        match typed {
            Some((t, _)) => t.into(),
            None if is_login => num(BW_LOGIN),
            None => num(BW_NOTE),
        },
    );
    put("reprompt", kept_or("reprompt", num(0)));
    put("name", s(&f.name));
    put("notes", s_or_null(&f.notes));
    put("favorite", Json::Bool(f.favourite));
    put("fields", Json::Array(fields));
    if let Some((k, o)) = type_obj {
        put(k, o);
    } else if !is_login {
        put("secureNote", obj(vec![("type", num(0))]));
    }
    if let Some(l) = item.login() {
        let regex = string_list(origin, "regex_uris");
        let uris = l
            .uris
            .iter()
            .map(|u| {
                let r = regex.contains(&u.uri);
                obj(vec![
                    ("match", num(match_to_bitwarden(&u.match_value, r))),
                    ("uri", s(&u.uri)),
                ])
            })
            .collect();
        let mut lm = vec![
            (
                "fido2Credentials".to_owned(),
                Json::Array(l.passkeys.iter().map(Json::from).collect()),
            ),
            ("uris".to_owned(), Json::Array(uris)),
            ("username".to_owned(), s_or_null(&l.username)),
            ("password".to_owned(), s_or_null(&l.password)),
            (
                "totp".to_owned(),
                s_or_null(l.totp.as_deref().unwrap_or("")),
            ),
        ];
        fill_from(&mut lm, kept("login"));
        put("login", Json::Object(lm));
    }
    put("collectionIds", kept_or("collectionIds", Json::Null));
    fill_from(&mut m, kept("item"));
    Json::Object(m)
}
