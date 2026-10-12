//! The import: each Bitwarden item mapped to a login or a note with `origin.bitwarden`, added as
//! a local edit, or applied to the item an earlier import created from it.

use crate::error::Result;
use crate::file::PlainExport;
use crate::mapping::{
    BW_LOGIN, BW_NOTE, HIDDEN_KEYS, ITEM_KEYS, MATCH_REGEX, match_to_vault, object_key,
};
use crate::source::Json;
use crate::time::parse_ms;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use vault_core::body::{
    Body, CustomField, HistoryEntry, Item, ItemData, ItemFields, Login, LoginUri, TYPE_LOGIN,
    TYPE_NOTE,
};
use vault_core::edit::{import_item, update_item};
use vault_core::json::{Map, Value};
use vault_core::rng::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The name an item gets when its Bitwarden `name` is empty or null.
pub const UNTITLED: &str = "Untitled";

/// Options of an import.
#[derive(Clone, Default)]
pub struct ImportOptions {
    /// A folder path the imported folders go under, such as `"Bitwarden"`; `""` for none.
    /// Slashes at either end are ignored. Items without a folder go into the prefix itself.
    pub folder: String,
}

/// What an import did.
#[derive(Default)]
pub struct ImportReport {
    /// Items added.
    pub added: usize,
    /// Existing items, from an earlier import, updated because a mapped value differs.
    pub updated: usize,
    /// Existing items, from an earlier import, whose mapped values are all equal.
    pub unchanged: usize,
    /// Items not imported, in export order.
    pub skipped: Vec<Skipped>,
    /// Entries in the export's `collections`, which are not imported.
    pub collections: usize,
    /// Vault items from an earlier import whose Bitwarden item is absent from the export or in
    /// its trash. They are left in the vault.
    pub deleted_in_source: usize,
}

/// An item the import skipped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Skipped {
    /// The item's name, or [`UNTITLED`].
    pub name: String,
    /// Why it was skipped.
    #[zeroize(skip)]
    pub reason: SkipReason,
}

/// Why an item was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// It has a non-null `deletedDate`: it is in Bitwarden's trash.
    Deleted,
    /// Its `type` is neither 1 nor 2 and it carries no recognisable typed object: its `type`
    /// names none, and not exactly one other key holds an object.
    UnsupportedType,
    /// A key the mapping reads has a value of the wrong JSON type.
    Malformed,
    /// After sanitising, the item still breaks a body JSON rule, such as the nesting limit.
    BodyRules,
}

impl SkipReason {
    /// A stable name for the reason.
    pub fn code(self) -> &'static str {
        match self {
            SkipReason::Deleted => "deleted",
            SkipReason::UnsupportedType => "unsupported_type",
            SkipReason::Malformed => "malformed",
            SkipReason::BodyRules => "body_rules",
        }
    }
}

/// An item mapped to the body schema.
struct Mapped {
    item_type: &'static str,
    fields: ItemFields,
    bw_id: Option<String>,
    /// Whether `created` came from `creationDate`, rather than from the import time.
    created_known: bool,
}

type Skip = core::result::Result<Mapped, SkipReason>;

/// Imports `export` into `body` at time `now` as device `device_id`, as described in
/// `docs/bitwarden.md`. Every new item draws 16 bytes from `rng` for its ID. Either every change
/// is applied or, on an error, `body` is left as it was.
pub fn import(
    body: &mut Body,
    export: &PlainExport,
    options: &ImportOptions,
    now: u64,
    device_id: &[u8; 16],
    rng: &mut dyn Rng,
) -> Result<ImportReport> {
    let mut work = body.clone();
    let mut report = ImportReport {
        collections: export.collections(),
        ..ImportReport::default()
    };
    let folders = folder_names(export.folders());
    let prefix = options.folder.trim_matches('/');
    // The vault items from each Bitwarden ID, in vault order. The n-th export entry with an ID
    // updates the n-th of them, so duplicate IDs pair up rather than overwrite one item.
    let mut existing: BTreeMap<String, VecDeque<String>> = BTreeMap::new();
    for item in &body.items {
        if let Some(bw) = item.fields().and_then(bitwarden_id) {
            existing
                .entry(bw.to_owned())
                .or_default()
                .push_back(item.id.clone());
        }
    }
    let mut seen = BTreeSet::new();
    for source in export.items() {
        let mapped = match map_item(source, &folders, prefix, now) {
            Ok(m) => m,
            Err(reason) => {
                // An item skipped for any reason but the trash is still in the source.
                if let Some(bw) = source.get("id").and_then(Json::as_str)
                    && reason != SkipReason::Deleted
                {
                    seen.insert(bw.to_owned());
                }
                report.skipped.push(Skipped {
                    name: display_name(source),
                    reason,
                });
                continue;
            }
        };
        if let Some(bw) = &mapped.bw_id {
            seen.insert(bw.clone());
        }
        let paired = mapped
            .bw_id
            .as_ref()
            .and_then(|b| existing.get_mut(b))
            .and_then(VecDeque::pop_front);
        match paired {
            Some(id) => match apply_update(&mut work, &id, mapped, now, device_id)? {
                Applied::Updated => report.updated += 1,
                Applied::Unchanged => report.unchanged += 1,
                Applied::Skipped(s) => report.skipped.push(s),
            },
            None => {
                if !obeys_body_rules(mapped.item_type, &mapped.fields) {
                    report.skipped.push(Skipped {
                        name: mapped.fields.name.clone(),
                        reason: SkipReason::BodyRules,
                    });
                    continue;
                }
                import_item(
                    &mut work,
                    rng,
                    mapped.item_type,
                    mapped.fields,
                    now,
                    device_id,
                )?;
                report.added += 1;
            }
        }
    }
    report.deleted_in_source = body
        .items
        .iter()
        .filter_map(|i| i.fields().and_then(bitwarden_id))
        .filter(|bw| !seen.contains(*bw))
        .count();
    *body = work;
    Ok(report)
}

/// `origin.bitwarden`, when the item carries it as an object.
pub(crate) fn bitwarden_origin(f: &ItemFields) -> Option<&Map> {
    match f.origin.as_ref()?.get("bitwarden")? {
        Value::Object(b) => Some(b),
        _ => None,
    }
}

fn bitwarden_id(f: &ItemFields) -> Option<&str> {
    match bitwarden_origin(f)?.get("id")? {
        Value::String(s) => Some(s),
        _ => None,
    }
}

fn display_name(source: &Json) -> String {
    match source.get("name").and_then(Json::as_str) {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => UNTITLED.to_owned(),
    }
}

/// Folder IDs to names. A folder without a string `id` or `name` is left out.
fn folder_names(folders: &[Json]) -> BTreeMap<&str, &str> {
    folders
        .iter()
        .filter_map(|f| Some((f.get("id")?.as_str()?, f.get("name")?.as_str()?)))
        .collect()
}

/// A string, null, or absent value; another type is malformed.
fn opt_str<'a>(obj: &'a Json, key: &str) -> core::result::Result<Option<&'a str>, SkipReason> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s)),
        Some(_) => Err(SkipReason::Malformed),
    }
}

/// An array, null, or absent value (as empty); another type is malformed.
fn opt_array<'a>(obj: &'a Json, key: &str) -> core::result::Result<&'a [Json], SkipReason> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(&[]),
        Some(Json::Array(a)) => Ok(a),
        Some(_) => Err(SkipReason::Malformed),
    }
}

/// The keys of `obj` other than `used`, sanitised.
fn leftovers(obj: &Json, used: &[&str]) -> Map {
    obj.as_object()
        .unwrap_or(&[])
        .iter()
        .filter(|(k, _)| !used.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.to_value()))
        .collect()
}

fn field(name: &str, value: &str, hidden: bool) -> CustomField {
    CustomField {
        name: name.to_owned(),
        value: value.to_owned(),
        hidden,
        extra: Map::new(),
    }
}

fn strings(v: Vec<String>) -> Value {
    Value::Array(v.into_iter().map(Value::String).collect())
}

/// The key of the typed object an item of a `type` other than login and secure note carries: the
/// key its known `type` names, or else the one key, other than those the mapping reads or writes
/// itself, whose value is an object. `None` when no key or several keys qualify.
fn typed_object_key(src: &Json, bw_type: Option<u64>) -> Option<&str> {
    if let Some(k) = bw_type.and_then(object_key) {
        return Some(k);
    }
    let mut candidates = src
        .as_object()?
        .iter()
        .filter(|(k, v)| matches!(v, Json::Object(_)) && !ITEM_KEYS.contains(&k.as_str()));
    match (candidates.next(), candidates.next()) {
        (Some((k, _)), None) => Some(k),
        _ => None,
    }
}

/// Maps one Bitwarden item, or says why it is skipped.
fn map_item(src: &Json, folders: &BTreeMap<&str, &str>, prefix: &str, now: u64) -> Skip {
    if src.as_object().is_none() {
        return Err(SkipReason::Malformed);
    }
    if src.get("deletedDate").is_some_and(|d| !d.is_null()) {
        return Err(SkipReason::Deleted);
    }
    let type_value = match src.get("type") {
        Some(t @ Json::Number(_)) => t,
        _ => return Err(SkipReason::Malformed),
    };
    let bw_type = type_value.as_u64();
    let type_key = match bw_type {
        Some(BW_LOGIN | BW_NOTE) => None,
        t => Some(typed_object_key(src, t).ok_or(SkipReason::UnsupportedType)?),
    };
    let mut used = vec![
        "id",
        "type",
        "name",
        "notes",
        "favorite",
        "folderId",
        "creationDate",
        "fields",
        "passwordHistory",
    ];
    used.extend(type_key);
    if bw_type == Some(BW_LOGIN) {
        used.push("login");
    }

    let name = match opt_str(src, "name")? {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => UNTITLED.to_owned(),
    };
    let notes = opt_str(src, "notes")?.unwrap_or("").to_owned();
    let favourite = match src.get("favorite") {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(_) => return Err(SkipReason::Malformed),
    };
    // A `folderId` that names no folder in the export is no folder.
    let folder = opt_str(src, "folderId")?
        .and_then(|id| folders.get(id).copied())
        .unwrap_or("");
    let folder = match (prefix, folder) {
        ("", f) => f.to_owned(),
        (p, "") => p.to_owned(),
        (p, f) => format!("{p}/{f}"),
    };
    // A `creationDate` that is not an RFC 3339 time counts as absent.
    let creation = src
        .get("creationDate")
        .and_then(Json::as_str)
        .and_then(parse_ms);

    let mut origin = Map::new();
    let mut fields = Vec::new();
    if let Some(key) = type_key {
        let mut keys = Vec::new();
        let mut values = Map::new();
        match src.get(key) {
            None | Some(Json::Null) => {}
            Some(Json::Object(m)) => {
                for (k, v) in m {
                    keys.push(k.clone());
                    match v {
                        Json::Null => {}
                        Json::String(s) | Json::Number(s) => {
                            fields.push(field(k, s, HIDDEN_KEYS.contains(&k.as_str())));
                        }
                        _ => {
                            values.insert(k.clone(), v.to_value());
                        }
                    }
                }
            }
            Some(_) => return Err(SkipReason::Malformed),
        }
        origin.insert("object".into(), Value::String(key.to_owned()));
        origin.insert("object_keys".into(), strings(keys));
        if !values.is_empty() {
            origin.insert("object_values".into(), Value::Object(values));
        }
    }
    let mut boolean_fields = Vec::new();
    let mut linked_fields = Vec::new();
    for f in opt_array(src, "fields")? {
        if f.as_object().is_none() {
            return Err(SkipReason::Malformed);
        }
        let ftype = match f.get("type") {
            None | Some(Json::Null) => Some(0),
            Some(t @ Json::Number(_)) => t.as_u64(),
            Some(_) => return Err(SkipReason::Malformed),
        };
        let fname = opt_str(f, "name")?.unwrap_or("");
        let value = opt_str(f, "value")?.unwrap_or("");
        match ftype {
            Some(1) => fields.push(field(fname, value, true)),
            Some(2) => {
                let b = if value == "true" { "true" } else { "false" };
                fields.push(field(fname, b, false));
                boolean_fields.push(fname.to_owned());
            }
            Some(3) => linked_fields.push(f.to_value()),
            // A later type is text, so its value stays visible and editable.
            _ => fields.push(field(fname, value, false)),
        }
    }

    let mut history = Vec::new();
    for h in opt_array(src, "passwordHistory")? {
        if h.as_object().is_none() {
            return Err(SkipReason::Malformed);
        }
        // An entry without a readable `lastUsedDate` is retired at 0, so a repeated import gives
        // the same history rather than one dated at each import.
        let retired = h
            .get("lastUsedDate")
            .and_then(Json::as_str)
            .and_then(parse_ms)
            .unwrap_or(0);
        history.push(HistoryEntry {
            password: opt_str(h, "password")?.unwrap_or("").to_owned(),
            retired,
            extra: Map::new(),
        });
    }

    let mut regex_uris = Vec::new();
    let login = if bw_type == Some(BW_LOGIN) {
        let empty = Json::Object(Vec::new());
        let l = match src.get("login") {
            None | Some(Json::Null) => &empty,
            Some(l @ Json::Object(_)) => l,
            Some(_) => return Err(SkipReason::Malformed),
        };
        let mut uris = Vec::new();
        for u in opt_array(l, "uris")? {
            if u.as_object().is_none() {
                return Err(SkipReason::Malformed);
            }
            // An entry without a URI has nothing to fill and is dropped.
            let Some(uri) = opt_str(u, "uri")? else {
                continue;
            };
            let m = match u.get("match") {
                None | Some(Json::Null) => None,
                Some(m @ Json::Number(_)) => Some(m.as_u64().unwrap_or(u64::MAX)),
                Some(_) => return Err(SkipReason::Malformed),
            };
            if m == Some(MATCH_REGEX) {
                regex_uris.push(uri.to_owned());
            }
            uris.push(LoginUri {
                uri: uri.to_owned(),
                match_value: match_to_vault(m).to_owned(),
                extra: Map::new(),
            });
        }
        let passkeys = opt_array(l, "fido2Credentials")?
            .iter()
            .map(Json::to_value)
            .collect();
        let rest = leftovers(
            l,
            &["username", "password", "uris", "totp", "fido2Credentials"],
        );
        if !rest.is_empty() {
            origin.insert("login".into(), Value::Object(rest));
        }
        Some(Login {
            username: opt_str(l, "username")?.unwrap_or("").to_owned(),
            password: opt_str(l, "password")?.unwrap_or("").to_owned(),
            uris,
            apps: Vec::new(),
            totp: opt_str(l, "totp")?
                .filter(|t| !t.is_empty())
                .map(str::to_owned),
            passkeys,
            extra: Map::new(),
        })
    } else {
        None
    };

    let bw_id = opt_str(src, "id")?.map(str::to_owned);
    if let Some(id) = &bw_id {
        origin.insert("id".into(), Value::String(id.clone()));
    }
    origin.insert("type".into(), type_value.to_value());
    let rest = leftovers(src, &used);
    if !rest.is_empty() {
        origin.insert("item".into(), Value::Object(rest));
    }
    if !boolean_fields.is_empty() {
        origin.insert("boolean_fields".into(), strings(boolean_fields));
    }
    if !linked_fields.is_empty() {
        origin.insert("linked_fields".into(), Value::Array(linked_fields));
    }
    if !regex_uris.is_empty() {
        origin.insert("regex_uris".into(), strings(regex_uris));
    }

    let mut fields = ItemFields {
        name,
        folder,
        favourite,
        notes,
        fields,
        password_history: history,
        created: creation.unwrap_or(now),
        login,
        origin: Some(Map::from([("bitwarden".to_owned(), Value::Object(origin))])),
        extra: Map::new(),
    };
    fields.normalise_history();
    Ok(Mapped {
        item_type: if bw_type == Some(BW_LOGIN) {
            TYPE_LOGIN
        } else {
            TYPE_NOTE
        },
        fields,
        bw_id,
        created_known: creation.is_some(),
    })
}

/// Whether an item with these fields passes every body rule, checked by the body encoder on a
/// body holding only that item.
fn obeys_body_rules(item_type: &str, fields: &ItemFields) -> bool {
    let mut probe = Body::default();
    probe.items.push(Item {
        id: "00000000-0000-4000-8000-000000000000".into(),
        item_type: item_type.into(),
        modified: 0,
        modified_by: "0".repeat(32),
        review: None,
        data: ItemData::Known(Box::new(fields.clone())),
    });
    probe.to_checked_json().is_ok()
}

enum Applied {
    Updated,
    Unchanged,
    Skipped(Skipped),
}

/// The fields of `old` with the mapped values of `m` in place of its own. What the mapping does
/// not set is kept: Android app bindings, unknown fields, and other sources in `origin`. The
/// histories are joined and normalised; a missing `creationDate` keeps the existing `created`.
fn merged(old: &ItemFields, m: &Mapped) -> ItemFields {
    let new = &m.fields;
    let mut f = old.clone();
    f.name.clone_from(&new.name);
    f.folder.clone_from(&new.folder);
    f.favourite = new.favourite;
    f.notes.clone_from(&new.notes);
    f.fields.clone_from(&new.fields);
    if m.created_known {
        f.created = new.created;
    }
    f.login = match (&new.login, &old.login) {
        (Some(n), Some(o)) => {
            let mut l = o.clone();
            l.username.clone_from(&n.username);
            l.password.clone_from(&n.password);
            l.uris.clone_from(&n.uris);
            l.totp.clone_from(&n.totp);
            l.passkeys.clone_from(&n.passkeys);
            Some(l)
        }
        (n, _) => n.clone(),
    };
    f.password_history
        .extend(new.password_history.iter().cloned());
    f.normalise_history();
    let mut origin = old.origin.clone().unwrap_or_default();
    if let Some(bw) = new.origin.as_ref().and_then(|o| o.get("bitwarden")) {
        origin.insert("bitwarden".into(), bw.clone());
    }
    f.origin = Some(origin);
    f
}

/// Applies a mapped item to the existing item `id` as a local edit when a mapped value differs.
fn apply_update(
    body: &mut Body,
    id: &str,
    m: Mapped,
    now: u64,
    device_id: &[u8; 16],
) -> Result<Applied> {
    let Some(item) = body.items.iter_mut().find(|i| i.id == id) else {
        return Ok(Applied::Unchanged);
    };
    let Some(old) = item.fields() else {
        return Ok(Applied::Unchanged);
    };
    let mut f = merged(old, &m);
    if item.item_type == m.item_type && f == *old {
        return Ok(Applied::Unchanged);
    }
    // A login that becomes a note keeps its password in the history, as a password change would.
    if let Some(l) = old.login.as_ref().filter(|_| m.item_type != TYPE_LOGIN) {
        f.password_history.push(HistoryEntry {
            password: l.password.clone(),
            retired: now,
            extra: Map::new(),
        });
        f.normalise_history();
    }
    if !obeys_body_rules(m.item_type, &f) {
        return Ok(Applied::Skipped(Skipped {
            name: m.fields.name.clone(),
            reason: SkipReason::BodyRules,
        }));
    }
    item.item_type = m.item_type.to_owned();
    update_item(body, id, f, now, device_id)?;
    Ok(Applied::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse;

    fn map(j: &str) -> Skip {
        let src = parse(j.as_bytes()).unwrap();
        map_item(&src, &BTreeMap::new(), "", 77)
    }

    #[test]
    fn skip_reasons() {
        for (j, r) in [
            (r#"[]"#, SkipReason::Malformed),
            (
                r#"{"type":1,"deletedDate":"2024-01-01T00:00:00Z"}"#,
                SkipReason::Deleted,
            ),
            (r#"{"type":9}"#, SkipReason::UnsupportedType),
            (
                r#"{"type":0,"login":{},"secureNote":{}}"#,
                SkipReason::UnsupportedType,
            ),
            (r#"{"type":1.5,"a":{},"b":{}}"#, SkipReason::UnsupportedType),
            (r#"{"type":"1"}"#, SkipReason::Malformed),
            (r#"{}"#, SkipReason::Malformed),
            (r#"{"type":1,"name":5}"#, SkipReason::Malformed),
            (r#"{"type":1,"favorite":"yes"}"#, SkipReason::Malformed),
            (r#"{"type":1,"login":[]}"#, SkipReason::Malformed),
            (
                r#"{"type":1,"login":{"uris":[{"uri":"a","match":"1"}]}}"#,
                SkipReason::Malformed,
            ),
            (r#"{"type":3,"card":"x"}"#, SkipReason::Malformed),
            (r#"{"type":2,"fields":[1]}"#, SkipReason::Malformed),
            (r#"{"type":2,"passwordHistory":{}}"#, SkipReason::Malformed),
        ] {
            assert_eq!(map(j).err(), Some(r), "{j}");
        }
    }

    #[test]
    fn defaults() {
        let m = map(r#"{"type":1,"name":"","deletedDate":null}"#).unwrap();
        let f = &m.fields;
        assert_eq!(f.name, UNTITLED);
        assert_eq!(f.created, 77);
        assert!(!m.created_known);
        assert!(m.bw_id.is_none());
        let l = f.login.as_ref().unwrap();
        assert_eq!((l.username.as_str(), l.password.as_str()), ("", ""));
        assert!(l.totp.is_none());
        let origin = bitwarden_origin(f).unwrap();
        assert!(origin.get("item").is_some(), "a null deletedDate is kept");
        assert!(origin.get("login").is_none());
    }
}
