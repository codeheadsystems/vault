//! The body schema: typed items, tombstones, and the body, converted from and to [`Value`] under
//! the required-key rules. Every type keeps the keys it does not define in an `extra` map, so
//! unknown fields survive every read, edit, merge, and write.
//!
//! None of these types has `Debug`, because they hold passwords, and each zeroizes its strings and
//! the keys of its `extra` map when dropped.

use crate::error::{Error, InputKind, IntegrityKind as K, Result, integrity};
use crate::json::{self, Map, Value, wipe_keys};
use crate::rng::{Rng, draw};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

/// The body schema version this client implements and writes.
pub const BODY_VERSION: u64 = 1;
/// The `type` of a login item.
pub const TYPE_LOGIN: &str = "login";
/// The `type` of a secure note.
pub const TYPE_NOTE: &str = "note";
/// The `review` value a merge sets on an item whose `modified` it clamped.
pub const REVIEW_CLAMPED: &str = "clamped";
/// The most `password_history` entries an item keeps.
pub const MAX_PASSWORD_HISTORY: usize = 10;

/// The decrypted body.
#[derive(Clone, PartialEq, Eq)]
pub struct Body {
    /// Body schema version.
    pub v: u64,
    /// The purge horizon, in ms.
    pub horizon: u64,
    /// Items, with unique `id` values.
    pub items: Vec<Item>,
    /// Tombstones, with `id` values unique and absent from `items`.
    pub tombstones: Vec<Tombstone>,
    /// Unknown top-level fields.
    pub extra: Map,
}

/// An item. The fields every item has, whatever its `type`, are here; the rest is in `data`.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    /// A lowercase hyphenated UUID.
    pub id: String,
    /// `"login"`, `"note"`, or a type this client does not know.
    pub item_type: String,
    /// Time of the last change, in ms.
    pub modified: u64,
    /// Device ID of the last change, 32 lowercase hex characters.
    pub modified_by: String,
    /// Present only when a merge flagged a login or a note. An item of unknown `type` keeps its
    /// `review` key, if any, in [`ItemData::Unknown`], and this is `None`.
    pub review: Option<String>,
    /// The rest of the item.
    pub data: ItemData,
}

/// The fields of an item beyond the common ones.
#[derive(Clone, PartialEq, Eq)]
pub enum ItemData {
    /// A login or a note.
    Known(Box<ItemFields>),
    /// An item of a `type` this client does not know: every other key, kept whole.
    Unknown(Map),
}

/// The fields of a login or a note.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemFields {
    /// Display name, not empty.
    pub name: String,
    /// Folder path such as `"Work/AWS"`; `""` for none.
    pub folder: String,
    /// Whether the item is a favourite.
    pub favourite: bool,
    /// Notes.
    pub notes: String,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Retired passwords, at most 10; written in history order after every edit and merge.
    pub password_history: Vec<HistoryEntry>,
    /// Creation time, in ms.
    pub created: u64,
    /// Present on a login item, and `None` on a note, whose `login` key is an unknown field.
    pub login: Option<Login>,
    /// Present only on imported items: data from the source that has no key in the schema, one
    /// object per source such as `bitwarden`. Its contents are never checked and are kept
    /// verbatim.
    pub origin: Option<Map>,
    /// Unknown fields.
    pub extra: Map,
}

/// A custom field.
#[derive(Clone, PartialEq, Eq)]
pub struct CustomField {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Whether the value is hidden.
    pub hidden: bool,
    /// Unknown fields.
    pub extra: Map,
}

/// A retired password.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The password.
    pub password: String,
    /// When it was retired, in ms.
    pub retired: u64,
    /// Unknown fields.
    pub extra: Map,
}

/// The login part of a login item.
#[derive(Clone, PartialEq, Eq)]
pub struct Login {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// URIs with match modes.
    pub uris: Vec<LoginUri>,
    /// Android app bindings.
    pub apps: Vec<AndroidApp>,
    /// An `otpauth://` URI or a base32 secret.
    pub totp: Option<String>,
    /// Passkey objects, kept verbatim.
    pub passkeys: Vec<Value>,
    /// Unknown fields.
    pub extra: Map,
}

/// A login URI.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginUri {
    /// The URI.
    pub uri: String,
    /// The match mode as stored; see [`LoginUri::match_mode`].
    pub match_value: String,
    /// Unknown fields.
    pub extra: Map,
}

/// How a login URI matches a page when filling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// `"base_domain"`.
    BaseDomain,
    /// `"host"`.
    Host,
    /// `"exact"`.
    Exact,
    /// `"starts_with"`.
    StartsWith,
    /// `"never"`, and every unknown value.
    Never,
}

/// An Android app binding.
#[derive(Clone, PartialEq, Eq)]
pub struct AndroidApp {
    /// The package name.
    pub package: String,
    /// The signing certificate's SHA-256, 64 lowercase hex characters.
    pub cert_sha256: String,
    /// Unknown fields.
    pub extra: Map,
}

/// A deletion record.
#[derive(Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The deleted item's `id`.
    pub id: String,
    /// Time of the deletion, in ms.
    pub modified: u64,
    /// Device ID of the deletion.
    pub modified_by: String,
    /// Unknown fields.
    pub extra: Map,
}

/// Zeroizes the listed string fields and the keys of the listed maps on drop. Nested values,
/// vectors of typed entries, and boxed fields zeroize themselves.
macro_rules! wipe_on_drop {
    ($t:ty, [$($s:ident),*], [$($m:ident),*]) => {
        impl Drop for $t {
            fn drop(&mut self) {
                $(self.$s.zeroize();)*
                $(wipe_keys(&mut self.$m);)*
            }
        }
    };
}

wipe_on_drop!(Body, [], [extra]);
wipe_on_drop!(Item, [id, item_type, modified_by, review], []);
impl Drop for ItemFields {
    fn drop(&mut self) {
        self.name.zeroize();
        self.folder.zeroize();
        self.notes.zeroize();
        if let Some(o) = &mut self.origin {
            wipe_keys(o);
        }
        wipe_keys(&mut self.extra);
    }
}
wipe_on_drop!(CustomField, [name, value], [extra]);
wipe_on_drop!(HistoryEntry, [password], [extra]);
wipe_on_drop!(Login, [username, password, totp], [extra]);
wipe_on_drop!(LoginUri, [uri, match_value], [extra]);
wipe_on_drop!(AndroidApp, [package, cert_sha256], [extra]);
wipe_on_drop!(Tombstone, [id, modified_by], [extra]);

impl Drop for ItemData {
    fn drop(&mut self) {
        if let ItemData::Unknown(m) = self {
            wipe_keys(m);
        }
    }
}

impl ItemFields {
    /// Normalises `password_history` against this item's current `login.password`.
    pub fn normalise_history(&mut self) {
        let current = self.login.as_ref().map(|l| l.password.as_str());
        normalise_history(&mut self.password_history, current);
    }
}

impl LoginUri {
    /// The mode used when filling: an unknown `match` value is treated as `"never"`.
    pub fn match_mode(&self) -> MatchMode {
        match self.match_value.as_str() {
            "base_domain" => MatchMode::BaseDomain,
            "host" => MatchMode::Host,
            "exact" => MatchMode::Exact,
            "starts_with" => MatchMode::StartsWith,
            _ => MatchMode::Never,
        }
    }
}

impl Item {
    /// The login or note fields, or `None` for an item of unknown `type`.
    pub fn fields(&self) -> Option<&ItemFields> {
        match &self.data {
            ItemData::Known(f) => Some(f),
            ItemData::Unknown(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn fields_mut(&mut self) -> Option<&mut ItemFields> {
        match &mut self.data {
            ItemData::Known(f) => Some(f),
            ItemData::Unknown(_) => None,
        }
    }

    /// Sets `review = "clamped"`. On an item of unknown `type` the key lives in its map.
    pub(crate) fn flag_clamped(&mut self) {
        match &mut self.data {
            ItemData::Known(_) => self.review = Some(REVIEW_CLAMPED.to_owned()),
            ItemData::Unknown(m) => {
                m.insert("review".into(), Value::String(REVIEW_CLAMPED.into()));
            }
        }
    }

    /// Removes `review`, wherever the item keeps it.
    pub(crate) fn clear_review(&mut self) {
        self.review = None;
        if let ItemData::Unknown(m) = &mut self.data {
            m.remove("review");
        }
    }

    /// The login part when the item is a login item.
    pub fn login(&self) -> Option<&Login> {
        if self.item_type != TYPE_LOGIN {
            return None;
        }
        self.fields().and_then(|f| f.login.as_ref())
    }
}

impl Default for Body {
    /// The body `vault init` writes: `v = 1`, `horizon = 0`, and nothing else.
    fn default() -> Self {
        Body {
            v: BODY_VERSION,
            horizon: 0,
            items: Vec::new(),
            tombstones: Vec::new(),
            extra: Map::new(),
        }
    }
}

/// History order: `retired` newest first, then `password` as bytes in ascending order.
pub fn sort_history(h: &mut [HistoryEntry]) {
    h.sort_by(|a, b| {
        b.retired
            .cmp(&a.retired)
            .then_with(|| a.password.as_bytes().cmp(b.password.as_bytes()))
    });
}

/// Normalises a history: removes entries with an empty `password` and entries equal to
/// `current`, the item's current `login.password` (`None` for an item without one), deduplicates by
/// `password` keeping the newest `retired` (the earlier entry on equal `retired`), sorts in
/// history order, and keeps the first 10.
pub fn normalise_history(h: &mut Vec<HistoryEntry>, current: Option<&str>) {
    let mut keep: Vec<HistoryEntry> = Vec::with_capacity(h.len());
    for e in h.drain(..) {
        if e.password.is_empty() || current == Some(e.password.as_str()) {
            continue;
        }
        match keep.iter_mut().find(|k| k.password == e.password) {
            Some(k) if e.retired > k.retired => *k = e,
            Some(_) => {}
            None => keep.push(e),
        }
    }
    sort_history(&mut keep);
    keep.truncate(MAX_PASSWORD_HISTORY);
    *h = keep;
}

/// Whether `s` is a UUID in lowercase hyphenated form.
pub fn is_item_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// A new random version 4 UUID in lowercase hyphenated form. Draws 16 bytes.
pub fn new_item_id(rng: &mut dyn Rng) -> Result<String> {
    let mut b: [u8; 16] = draw(rng)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// The text form of a device ID or vault ID: 32 lowercase hex characters.
pub fn id_text(id: &[u8; 16]) -> String {
    hex::encode(id)
}

pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

// Decoding helpers. Each takes a defined key out of the object, so what remains is the unknown
// fields.

fn take(m: &mut Map, k: &str) -> Result<Value> {
    m.remove(k).ok_or(Error::Integrity(K::MissingKey))
}

fn take_str(m: &mut Map, k: &str) -> Result<String> {
    take(m, k)?
        .take_string()
        .ok_or(Error::Integrity(K::WrongType))
}

fn take_opt_str(m: &mut Map, k: &str) -> Result<Option<String>> {
    match m.remove(k) {
        None => Ok(None),
        Some(mut v) => v
            .take_string()
            .map(Some)
            .ok_or(Error::Integrity(K::WrongType)),
    }
}

fn take_u64(m: &mut Map, k: &str) -> Result<u64> {
    match take(m, k)? {
        Value::Number(n) => Ok(n),
        _ => integrity(K::WrongType),
    }
}

fn take_bool(m: &mut Map, k: &str) -> Result<bool> {
    match take(m, k)? {
        Value::Bool(b) => Ok(b),
        _ => integrity(K::WrongType),
    }
}

fn take_array(m: &mut Map, k: &str) -> Result<Vec<Value>> {
    take(m, k)?
        .take_array()
        .ok_or(Error::Integrity(K::WrongType))
}

fn object(mut v: Value) -> Result<Map> {
    v.take_object().ok_or(Error::Integrity(K::WrongType))
}

fn objects<T>(a: Vec<Value>, f: impl Fn(Map) -> Result<T>) -> Result<Vec<T>> {
    a.into_iter().map(|v| f(object(v)?)).collect()
}

fn check(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { integrity(K::BadValue) }
}

fn take_device_id(m: &mut Map, k: &str) -> Result<String> {
    let s = take_str(m, k)?;
    check(is_lower_hex(&s, 32))?;
    Ok(s)
}

impl Body {
    /// Parses and checks a body: the JSON rules, then the schema rules.
    pub fn from_json(bytes: &[u8]) -> Result<Body> {
        Body::from_value(json::parse(bytes)?)
    }

    /// Converts a parsed value, checking the required-key rules, the stated bounds, and the
    /// uniqueness of `id` values.
    pub fn from_value(v: Value) -> Result<Body> {
        let mut m = object(v)?;
        let v = take_u64(&mut m, "v")?;
        check(v >= 1)?;
        let horizon = take_u64(&mut m, "horizon")?;
        let items = objects(take_array(&mut m, "items")?, item_from_map)?;
        let tombstones = objects(take_array(&mut m, "tombstones")?, tombstone_from_map)?;
        let mut ids = BTreeSet::new();
        for id in items
            .iter()
            .map(|i| &i.id)
            .chain(tombstones.iter().map(|t| &t.id))
        {
            if !ids.insert(id.as_str()) {
                return integrity(K::DuplicateId);
            }
        }
        Ok(Body {
            v,
            horizon,
            items,
            tombstones,
            extra: m,
        })
    }

    /// The body as a JSON value.
    pub fn to_value(&self) -> Value {
        let mut m = self.extra.clone();
        m.insert("v".into(), Value::Number(self.v));
        m.insert("horizon".into(), Value::Number(self.horizon));
        m.insert(
            "items".into(),
            Value::Array(self.items.iter().map(Item::to_value).collect()),
        );
        m.insert(
            "tombstones".into(),
            Value::Array(self.tombstones.iter().map(Tombstone::to_value).collect()),
        );
        Value::Object(m)
    }

    /// The body as compact JSON with keys in byte order. Nothing is checked; see
    /// [`Body::to_checked_json`].
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        json::to_vec(&self.to_value())
    }

    /// The body as JSON, after checking that it reads back under every body rule, so a client
    /// never writes a body that no client can open. Refuses a body whose `v` is greater than
    /// [`BODY_VERSION`].
    pub fn to_checked_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.v > BODY_VERSION {
            return Err(Error::ReadOnlyBody);
        }
        let out = self.to_json();
        match Body::from_json(&out) {
            Ok(back) if back == *self => Ok(out),
            _ => Err(Error::InvalidInput(InputKind::Body)),
        }
    }

    /// Whether this client may write the body: its `v` is at most [`BODY_VERSION`].
    pub fn writable(&self) -> bool {
        self.v <= BODY_VERSION
    }

    /// The item with `id`.
    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }
}

fn item_from_map(mut m: Map) -> Result<Item> {
    let id = take_str(&mut m, "id")?;
    check(is_item_id(&id))?;
    let item_type = take_str(&mut m, "type")?;
    let modified = take_u64(&mut m, "modified")?;
    let modified_by = take_device_id(&mut m, "modified_by")?;
    // An item of unknown `type` is checked for these four keys only; every other key on it,
    // `review` included, stays in its map unchecked.
    let known = item_type == TYPE_LOGIN || item_type == TYPE_NOTE;
    let review = if known {
        take_opt_str(&mut m, "review")?
    } else {
        None
    };
    let data = if known {
        ItemData::Known(Box::new(fields_from_map(m, item_type == TYPE_LOGIN)?))
    } else {
        ItemData::Unknown(m)
    };
    Ok(Item {
        id,
        item_type,
        modified,
        modified_by,
        review,
        data,
    })
}

fn fields_from_map(mut m: Map, is_login: bool) -> Result<ItemFields> {
    let name = take_str(&mut m, "name")?;
    check(!name.is_empty())?;
    let folder = take_str(&mut m, "folder")?;
    let favourite = take_bool(&mut m, "favourite")?;
    let notes = take_str(&mut m, "notes")?;
    let fields = objects(take_array(&mut m, "fields")?, |mut f| {
        Ok(CustomField {
            name: take_str(&mut f, "name")?,
            value: take_str(&mut f, "value")?,
            hidden: take_bool(&mut f, "hidden")?,
            extra: f,
        })
    })?;
    let password_history = objects(take_array(&mut m, "password_history")?, |mut h| {
        Ok(HistoryEntry {
            password: take_str(&mut h, "password")?,
            retired: take_u64(&mut h, "retired")?,
            extra: h,
        })
    })?;
    // A decoder accepts duplicate passwords and any order; only the count is bounded.
    check(password_history.len() <= MAX_PASSWORD_HISTORY)?;
    let created = take_u64(&mut m, "created")?;
    // `login` is required on login items. On any other type it is an unknown field and stays in
    // `extra`.
    let login = if is_login {
        Some(login_from_map(object(take(&mut m, "login")?)?)?)
    } else {
        None
    };
    // `origin` is optional and must be an object; its contents are kept without checks.
    let origin = m.remove("origin").map(object).transpose()?;
    Ok(ItemFields {
        name,
        folder,
        favourite,
        notes,
        fields,
        password_history,
        created,
        login,
        origin,
        extra: m,
    })
}

fn login_from_map(mut m: Map) -> Result<Login> {
    let username = take_str(&mut m, "username")?;
    let password = take_str(&mut m, "password")?;
    let uris = objects(take_array(&mut m, "uris")?, |mut u| {
        Ok(LoginUri {
            uri: take_str(&mut u, "uri")?,
            match_value: take_str(&mut u, "match")?,
            extra: u,
        })
    })?;
    let apps = objects(take_array(&mut m, "apps")?, |mut a| {
        let package = take_str(&mut a, "package")?;
        let cert_sha256 = take_str(&mut a, "cert_sha256")?;
        check(is_lower_hex(&cert_sha256, 64))?;
        Ok(AndroidApp {
            package,
            cert_sha256,
            extra: a,
        })
    })?;
    let mut totp = take(&mut m, "totp")?;
    let totp = match totp {
        Value::Null => None,
        _ => Some(totp.take_string().ok_or(Error::Integrity(K::WrongType))?),
    };
    let passkeys = take_array(&mut m, "passkeys")?;
    Ok(Login {
        username,
        password,
        uris,
        apps,
        totp,
        passkeys,
        extra: m,
    })
}

fn tombstone_from_map(mut m: Map) -> Result<Tombstone> {
    let id = take_str(&mut m, "id")?;
    check(is_item_id(&id))?;
    Ok(Tombstone {
        id,
        modified: take_u64(&mut m, "modified")?,
        modified_by: take_device_id(&mut m, "modified_by")?,
        extra: m,
    })
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

impl Item {
    /// The item as a JSON value.
    pub fn to_value(&self) -> Value {
        let mut m = match &self.data {
            ItemData::Known(f) => f.to_map(),
            ItemData::Unknown(m) => m.clone(),
        };
        m.insert("id".into(), s(&self.id));
        m.insert("type".into(), s(&self.item_type));
        m.insert("modified".into(), Value::Number(self.modified));
        m.insert("modified_by".into(), s(&self.modified_by));
        if let Some(r) = &self.review {
            m.insert("review".into(), s(r));
        }
        Value::Object(m)
    }
}

impl ItemFields {
    fn to_map(&self) -> Map {
        let mut m = self.extra.clone();
        m.insert("name".into(), s(&self.name));
        m.insert("folder".into(), s(&self.folder));
        m.insert("favourite".into(), Value::Bool(self.favourite));
        m.insert("notes".into(), s(&self.notes));
        let fields = self.fields.iter().map(|f| {
            let mut x = f.extra.clone();
            x.insert("name".into(), s(&f.name));
            x.insert("value".into(), s(&f.value));
            x.insert("hidden".into(), Value::Bool(f.hidden));
            Value::Object(x)
        });
        m.insert("fields".into(), Value::Array(fields.collect()));
        m.insert(
            "password_history".into(),
            Value::Array(
                self.password_history
                    .iter()
                    .map(HistoryEntry::to_value)
                    .collect(),
            ),
        );
        m.insert("created".into(), Value::Number(self.created));
        if let Some(l) = &self.login {
            m.insert("login".into(), l.to_value());
        }
        if let Some(o) = &self.origin {
            m.insert("origin".into(), Value::Object(o.clone()));
        }
        m
    }
}

impl HistoryEntry {
    fn to_value(&self) -> Value {
        let mut x = self.extra.clone();
        x.insert("password".into(), s(&self.password));
        x.insert("retired".into(), Value::Number(self.retired));
        Value::Object(x)
    }
}

impl Login {
    fn to_value(&self) -> Value {
        let mut m = self.extra.clone();
        m.insert("username".into(), s(&self.username));
        m.insert("password".into(), s(&self.password));
        let uris = self.uris.iter().map(|u| {
            let mut x = u.extra.clone();
            x.insert("uri".into(), s(&u.uri));
            x.insert("match".into(), s(&u.match_value));
            Value::Object(x)
        });
        m.insert("uris".into(), Value::Array(uris.collect()));
        let apps = self.apps.iter().map(|a| {
            let mut x = a.extra.clone();
            x.insert("package".into(), s(&a.package));
            x.insert("cert_sha256".into(), s(&a.cert_sha256));
            Value::Object(x)
        });
        m.insert("apps".into(), Value::Array(apps.collect()));
        m.insert("totp".into(), self.totp.as_deref().map_or(Value::Null, s));
        m.insert("passkeys".into(), Value::Array(self.passkeys.clone()));
        Value::Object(m)
    }
}

impl Tombstone {
    /// The tombstone as a JSON value.
    pub fn to_value(&self) -> Value {
        let mut m = self.extra.clone();
        m.insert("id".into(), s(&self.id));
        m.insert("modified".into(), Value::Number(self.modified));
        m.insert("modified_by".into(), s(&self.modified_by));
        Value::Object(m)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const ID1: &str = "00000000-0000-4000-8000-000000000001";
    pub(crate) const DEV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    pub(crate) fn login_json(id: &str, modified: u64, by: &str, password: &str) -> String {
        format!(
            r#"{{"id":"{id}","type":"login","name":"n","folder":"","favourite":false,"notes":"",
            "fields":[],"password_history":[],"created":0,"modified":{modified},
            "modified_by":"{by}","login":{{"username":"u","password":"{password}","uris":[],
            "apps":[],"totp":null,"passkeys":[]}}}}"#
        )
    }

    fn body_with(items: &[String]) -> String {
        format!(
            r#"{{"v":1,"horizon":0,"items":[{}],"tombstones":[]}}"#,
            items.join(",")
        )
    }

    fn err(s: &str) -> Option<K> {
        match Body::from_json(s.as_bytes()) {
            Err(Error::Integrity(k)) => Some(k),
            Err(_) => panic!("not an integrity error"),
            Ok(_) => None,
        }
    }

    /// Replaces the first occurrence of `from` in a valid login body.
    fn mutated(from: &str, to: &str) -> Option<K> {
        let b = body_with(&[login_json(ID1, 5, DEV_A, "pw")]);
        assert!(b.contains(from), "{from}");
        err(&b.replacen(from, to, 1))
    }

    #[test]
    fn empty_body() {
        let b = Body::from_json(br#"{"v":1,"horizon":0,"items":[],"tombstones":[]}"#).unwrap();
        assert!(b == Body::default());
        assert_eq!(
            String::from_utf8(b.to_json().to_vec()).unwrap(),
            r#"{"horizon":0,"items":[],"tombstones":[],"v":1}"#
        );
    }

    #[test]
    fn login_round_trip_keeps_unknown_fields_at_every_level() {
        let item = login_json(ID1, 5, DEV_A, "pw")
            .replace(r#""name":"n""#, r#""name":"n","x1":{"deep":[1]}"#)
            .replace(r#""username":"u""#, r#""username":"u","x2":true"#)
            .replace(
                r#""uris":[]"#,
                r#""uris":[{"uri":"https://a","match":"weird","x3":1}]"#,
            )
            .replace(
                r#""fields":[]"#,
                r#""fields":[{"name":"f","value":"v","hidden":true,"x4":null}]"#,
            )
            .replace(
                r#""password_history":[]"#,
                r#""password_history":[{"password":"old","retired":3,"x5":"y"}]"#,
            )
            .replace(r#""passkeys":[]"#, r#""passkeys":[{"anything":[{}]}]"#);
        let body = format!(
            r#"{{"v":1,"horizon":7,"items":[{item}],"tombstones":[{{"id":"{}","modified":1,"modified_by":"{DEV_A}","x6":2}}],"top":{{"a":1}}}}"#,
            "00000000-0000-4000-8000-000000000002"
        );
        let b = Body::from_json(body.as_bytes()).unwrap();
        let again = Body::from_json(&b.to_json()).unwrap();
        assert!(again == b);
        assert!(json::parse(&b.to_json()).unwrap() == json::parse(body.as_bytes()).unwrap());
        let login = b.items[0].login().unwrap();
        assert_eq!(login.uris[0].match_mode(), MatchMode::Never);
        assert!(login.extra.contains_key("x2"));
        assert!(b.extra.contains_key("top"));
        assert!(b.tombstones[0].extra.contains_key("x6"));
        assert!(b.to_checked_json().is_ok());
    }

    #[test]
    fn match_modes() {
        let u = |m: &str| LoginUri {
            uri: String::new(),
            match_value: m.into(),
            extra: Map::new(),
        };
        assert_eq!(u("base_domain").match_mode(), MatchMode::BaseDomain);
        assert_eq!(u("host").match_mode(), MatchMode::Host);
        assert_eq!(u("exact").match_mode(), MatchMode::Exact);
        assert_eq!(u("starts_with").match_mode(), MatchMode::StartsWith);
        assert_eq!(u("never").match_mode(), MatchMode::Never);
        assert_eq!(u("Host").match_mode(), MatchMode::Never);
    }

    #[test]
    fn note_without_login_and_unknown_type() {
        let note = login_json(ID1, 5, DEV_A, "pw").replace(r#""type":"login""#, r#""type":"note""#);
        let note = note[..note.find(r#","login""#).unwrap()].to_owned() + "}";
        let unknown = format!(
            r#"{{"id":"00000000-0000-4000-8000-000000000003","type":"card","modified":9,"modified_by":"{DEV_A}","number":[1,2],"name":5}}"#
        );
        let b = Body::from_json(body_with(&[note, unknown]).as_bytes()).unwrap();
        assert!(b.items[0].fields().unwrap().login.is_none());
        assert!(b.items[0].login().is_none());
        assert!(b.items[1].fields().is_none());
        match &b.items[1].data {
            ItemData::Unknown(m) => assert!(m.contains_key("number") && m.contains_key("name")),
            ItemData::Known(_) => panic!("card is not a known type"),
        }
        let back = String::from_utf8(b.to_json().to_vec()).unwrap();
        assert!(back.contains(r#""number":[1,2]"#));
    }

    #[test]
    fn unknown_type_needs_only_four_keys() {
        let unknown =
            format!(r#"{{"id":"{ID1}","type":"x","modified":9,"modified_by":"{DEV_A}"}}"#);
        assert_eq!(err(&body_with(std::slice::from_ref(&unknown))), None);
        for key in [r#""modified":9,"#, r#""type":"x","#] {
            assert_eq!(
                err(&body_with(&[unknown.replace(key, "")])),
                Some(K::MissingKey)
            );
        }
        assert_eq!(
            err(&body_with(&[
                unknown.replace(r#""modified":9"#, r#""modified":"9""#)
            ])),
            Some(K::WrongType)
        );
        assert_eq!(
            err(&body_with(&[unknown.replace(DEV_A, "x")])),
            Some(K::BadValue)
        );
        // Every other key is kept unchecked, including keys the schema defines for known types.
        let loose = unknown.replace(
            r#""type":"x""#,
            r#""type":"x","review":1,"name":"","login":7,"password_history":"no","created":"x""#,
        );
        let b = Body::from_json(body_with(&[loose]).as_bytes()).unwrap();
        assert!(b.items[0].review.is_none());
        let ItemData::Unknown(m) = &b.items[0].data else {
            panic!("unknown type")
        };
        for k in ["review", "name", "login", "password_history", "created"] {
            assert!(m.contains_key(k), "{k}");
        }
        assert!(Body::from_json(&b.to_json()).unwrap() == b);
        assert!(b.to_checked_json().is_ok());
    }

    #[test]
    fn origin_is_an_object_kept_verbatim() {
        let origin = r#""origin":{"bitwarden":{"id":"x","fields":[{"type":3,"n":null}],"z":{}}}"#;
        let item = login_json(ID1, 5, DEV_A, "pw")
            .replace(r#""name":"n""#, &format!(r#""name":"n",{origin}"#));
        let b = Body::from_json(body_with(std::slice::from_ref(&item)).as_bytes()).unwrap();
        let f = b.items[0].fields().unwrap();
        assert!(f.origin.as_ref().unwrap().contains_key("bitwarden"));
        assert!(!f.extra.contains_key("origin"));
        let back = json::parse(&b.to_json()).unwrap();
        let Value::Object(top) = &back else { panic!() };
        let Value::Array(items) = &top["items"] else {
            panic!()
        };
        let Value::Object(it) = &items[0] else {
            panic!()
        };
        let want = json::parse(format!("{{{origin}}}").as_bytes()).unwrap();
        let Value::Object(want) = &want else { panic!() };
        assert!(it["origin"] == want["origin"], "kept verbatim");
        assert!(b.to_checked_json().is_ok());
        // On a note too.
        let note = item.replace(r#""type":"login""#, r#""type":"note""#);
        assert!(
            Body::from_json(body_with(&[note]).as_bytes())
                .unwrap()
                .items[0]
                .fields()
                .unwrap()
                .origin
                .is_some()
        );
        // Absent is fine, and stays absent.
        let plain =
            Body::from_json(body_with(&[login_json(ID1, 5, DEV_A, "pw")]).as_bytes()).unwrap();
        assert!(plain.items[0].fields().unwrap().origin.is_none());
        assert!(
            !String::from_utf8(plain.to_json().to_vec())
                .unwrap()
                .contains("origin")
        );
    }

    #[test]
    fn origin_that_is_not_an_object_is_an_integrity_error() {
        for bad in [r#""x""#, "[]", "null", "1", "true"] {
            let item = login_json(ID1, 5, DEV_A, "pw")
                .replace(r#""name":"n""#, &format!(r#""name":"n","origin":{bad}"#));
            assert_eq!(
                err(&body_with(std::slice::from_ref(&item))),
                Some(K::WrongType),
                "{bad}"
            );
            let note = item.replace(r#""type":"login""#, r#""type":"note""#);
            assert_eq!(
                err(&body_with(&[note])),
                Some(K::WrongType),
                "{bad} on a note"
            );
        }
        // An item of unknown type keeps any `origin`, unchecked.
        let card = format!(
            r#"{{"id":"{ID1}","type":"card","modified":1,"modified_by":"{DEV_A}","origin":"x"}}"#
        );
        assert_eq!(err(&body_with(&[card])), None);
    }

    #[test]
    fn a_body_with_a_bad_origin_is_never_written() {
        let mut b =
            Body::from_json(body_with(&[login_json(ID1, 5, DEV_A, "pw")]).as_bytes()).unwrap();
        b.items[0]
            .fields_mut()
            .unwrap()
            .extra
            .insert("origin".into(), Value::String("x".into()));
        assert_eq!(
            b.to_checked_json().err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
    }

    #[test]
    fn login_on_a_note_is_an_unknown_field() {
        let note = login_json(ID1, 5, DEV_A, "pw").replace(r#""type":"login""#, r#""type":"note""#);
        let b = Body::from_json(body_with(std::slice::from_ref(&note)).as_bytes()).unwrap();
        let f = b.items[0].fields().unwrap();
        assert!(f.login.is_none());
        assert!(f.extra.contains_key("login"));
        assert!(b.items[0].login().is_none());
        // Kept unchecked: a malformed `login` on a note still reads.
        let odd = note
            .replace(r#""login":{"#, r#""login":{"bad":1,"#)
            .replace(r#""username":"u","#, "");
        assert!(Body::from_json(body_with(&[odd]).as_bytes()).is_ok());
        assert!(b.to_checked_json().is_ok());
    }

    #[test]
    fn required_keys_and_types() {
        assert_eq!(mutated(r#""name":"n","#, ""), Some(K::MissingKey));
        assert_eq!(
            mutated(r#""login":{"#, r#""login_":{"#),
            Some(K::MissingKey)
        );
        assert_eq!(mutated(r#""totp":null,"#, ""), Some(K::MissingKey));
        assert_eq!(
            mutated(r#""passkeys":[]"#, r#""passkeys":{}"#),
            Some(K::WrongType)
        );
        assert_eq!(
            mutated(r#""favourite":false"#, r#""favourite":0"#),
            Some(K::WrongType)
        );
        assert_eq!(mutated(r#""totp":null"#, r#""totp":"JBSWY3DP""#), None);
        assert_eq!(mutated(r#""totp":null"#, r#""totp":1"#), Some(K::WrongType));
        assert_eq!(
            mutated(r#""created":0"#, r#""created":"0""#),
            Some(K::WrongType)
        );
        assert_eq!(
            mutated(r#""fields":[]"#, r#""fields":[1]"#),
            Some(K::WrongType)
        );
        assert_eq!(
            mutated(r#""fields":[]"#, r#""fields":[{"name":"a","value":"b"}]"#),
            Some(K::MissingKey)
        );
        assert_eq!(
            err(r#"{"v":1,"horizon":0,"items":[]}"#),
            Some(K::MissingKey)
        );
        assert_eq!(err(r#"[]"#), Some(K::WrongType));
    }

    #[test]
    fn stated_bounds() {
        assert_eq!(mutated(r#""name":"n""#, r#""name":"""#), Some(K::BadValue));
        let upper = ID1.replace('a', "A").replace("4000", "4ABC");
        assert_eq!(mutated(ID1, &upper), Some(K::BadValue), "upper-case UUID");
        assert_eq!(mutated(ID1, "not-a-uuid"), Some(K::BadValue));
        assert_eq!(mutated(DEV_A, &DEV_A.to_uppercase()), Some(K::BadValue));
        assert_eq!(mutated(DEV_A, &DEV_A[..31]), Some(K::BadValue));
        assert_eq!(
            mutated(
                r#""apps":[]"#,
                &format!(
                    r#""apps":[{{"package":"p","cert_sha256":"{}"}}]"#,
                    "AB".repeat(32)
                )
            ),
            Some(K::BadValue)
        );
        assert_eq!(
            mutated(
                r#""apps":[]"#,
                &format!(
                    r#""apps":[{{"package":"p","cert_sha256":"{}"}}]"#,
                    "ab".repeat(32)
                )
            ),
            None
        );
        let hist = |entries: &[(&str, u64)]| {
            let e: Vec<String> = entries
                .iter()
                .map(|(p, r)| format!(r#"{{"password":"{p}","retired":{r}}}"#))
                .collect();
            mutated(
                r#""password_history":[]"#,
                &format!(r#""password_history":[{}]"#, e.join(",")),
            )
        };
        assert_eq!(hist(&[("b", 2), ("a", 1)]), None);
        assert_eq!(hist(&[("a", 2), ("b", 2)]), None);
        assert_eq!(hist(&[("a", 2), ("a", 2)]), None, "duplicates are accepted");
        assert_eq!(hist(&[("a", 1), ("b", 2)]), None, "any order is accepted");
        assert_eq!(hist(&[("b", 2), ("a", 2)]), None);
        assert_eq!(hist(&[("", 2)]), None, "an empty password is accepted");
        let ten: Vec<(&str, u64)> = (0..10).map(|i| ("p", 20 - i)).collect();
        assert_eq!(hist(&ten), None);
        let eleven: Vec<(&str, u64)> = (0..11).map(|i| ("p", 20 - i)).collect();
        assert_eq!(hist(&eleven), Some(K::BadValue));
        assert_eq!(
            err(r#"{"v":0,"horizon":0,"items":[],"tombstones":[]}"#),
            Some(K::BadValue)
        );
    }

    #[test]
    fn duplicate_ids() {
        let a = login_json(ID1, 5, DEV_A, "pw");
        assert_eq!(
            err(&body_with(&[a.clone(), a.clone()])),
            Some(K::DuplicateId)
        );
        let tomb = format!(r#"{{"id":"{ID1}","modified":1,"modified_by":"{DEV_A}"}}"#);
        let both = format!(r#"{{"v":1,"horizon":0,"items":[{a}],"tombstones":[{tomb}]}}"#);
        assert_eq!(err(&both), Some(K::DuplicateId));
        let two = format!(r#"{{"v":1,"horizon":0,"items":[],"tombstones":[{tomb},{tomb}]}}"#);
        assert_eq!(err(&two), Some(K::DuplicateId));
    }

    #[test]
    fn newer_version_reads_but_does_not_write() {
        let b = Body::from_json(br#"{"v":2,"horizon":0,"items":[],"tombstones":[]}"#).unwrap();
        assert!(!b.writable());
        assert_eq!(b.to_checked_json().err(), Some(Error::ReadOnlyBody));
    }

    #[test]
    fn checked_json_refuses_bodies_that_break_the_rules() {
        let mut b =
            Body::from_json(body_with(&[login_json(ID1, 5, DEV_A, "pw")]).as_bytes()).unwrap();
        b.items[0].modified = 1 << 53;
        assert_eq!(
            b.to_checked_json().err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
        b.items[0].modified = 5;
        b.items.push(b.items[0].clone());
        assert_eq!(
            b.to_checked_json().err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
        b.items.pop();
        b.items[0].fields_mut().unwrap().name.clear();
        assert_eq!(
            b.to_checked_json().err(),
            Some(Error::InvalidInput(InputKind::Body))
        );
    }

    #[test]
    fn item_ids() {
        let mut rng = crate::rng::BufferRng::new(&[&[0xff; 16]]);
        let id = new_item_id(&mut rng).unwrap();
        assert_eq!(id, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert!(is_item_id(&id));
        assert!(!is_item_id("ffffffff-ffff-4fff-bfff-fffffffffff"));
        assert!(!is_item_id("ffffffffffff-4fff-bfff-ffffffffffff-"));
        assert_eq!(id_text(&[0xab; 16]), "ab".repeat(16));
    }

    #[test]
    fn history_sort() {
        let e = |p: &str, r: u64| HistoryEntry {
            password: p.into(),
            retired: r,
            extra: Map::new(),
        };
        let mut h = vec![e("b", 1), e("a", 1), e("z", 9), e("\u{e9}", 1)];
        sort_history(&mut h);
        let order: Vec<&str> = h.iter().map(|x| x.password.as_str()).collect();
        assert_eq!(order, ["z", "a", "b", "\u{e9}"]);
    }

    #[test]
    fn normalising() {
        let e = |p: &str, r: u64, x: u64| {
            let mut extra = Map::new();
            extra.insert("x".into(), Value::Number(x));
            HistoryEntry {
                password: p.into(),
                retired: r,
                extra,
            }
        };
        let mut h = vec![
            e("a", 1, 0),
            e("", 9, 0),
            e("a", 3, 1),
            e("b", 3, 0),
            e("b", 3, 1),
        ];
        normalise_history(&mut h, None);
        let got: Vec<(&str, u64, bool)> = h
            .iter()
            .map(|x| {
                (
                    x.password.as_str(),
                    x.retired,
                    x.extra["x"] == Value::Number(1),
                )
            })
            .collect();
        assert_eq!(
            got,
            [("a", 3, true), ("b", 3, false)],
            "first entry kept on a tie"
        );
        let mut many: Vec<HistoryEntry> = (0..15).map(|i| e(&format!("p{i:02}"), 7, 0)).collect();
        normalise_history(&mut many, None);
        // The current password is removed too.
        let mut with_current = vec![e("cur", 5, 0), e("old", 4, 0)];
        normalise_history(&mut with_current, Some("cur"));
        assert_eq!(with_current.len(), 1);
        assert_eq!(with_current[0].password, "old");
        assert_eq!(many.len(), 10);
        assert_eq!(many[0].password, "p00");
        assert_eq!(many[9].password, "p09");
    }
}
