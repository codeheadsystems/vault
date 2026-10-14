//! An unlocked vault for JavaScript: `vault_client::session::Session` behind JSON and camelCase
//! conversions.

use crate::WebRng;
use crate::autofill::{KnownSuffix, outcome};
use crate::convert::{
    array, client_err, core_err, get, get_str, set, state, state_text, to_js, usage,
};
use crate::procedure::Procedure;
use js_sys::Uint8Array;
use serde_json::json;
use vault_client::ClientState;
use vault_client::autofill::SaveOffer;
use vault_client::restore::{RestoreSummary, Revision};
use vault_client::session::{self, NewItem};
use vault_core::body::{Body, Item, ItemFields, LoginUri};
use vault_core::json::Map;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::{Error, InputKind};
use wasm_bindgen::prelude::*;

/// An unlocked vault. `lock` zeroes the vault key and the body; the extension then drops the
/// instance.
#[wasm_bindgen]
pub struct Session {
    inner: session::Session,
}

/// Parses one item from its body-schema JSON object.
fn parse_item(v: &JsValue) -> Result<Item, JsValue> {
    let text = js_sys::JSON::stringify(v)
        .map_err(|_| usage("the item is not JSON"))?
        .as_string()
        .unwrap_or_default();
    let body = format!(r#"{{"v":1,"horizon":0,"items":[{text}],"tombstones":[]}}"#);
    let mut b = Body::from_json(body.as_bytes()).map_err(core_err)?;
    b.items.pop().ok_or_else(|| usage("no item"))
}

fn fields(item: &Item) -> Result<&ItemFields, JsValue> {
    item.fields()
        .ok_or_else(|| core_err(Error::InvalidInput(InputKind::UnsupportedItem)))
}

fn summary_js(s: &RestoreSummary) -> serde_json::Value {
    json!({"added": s.added, "changed": s.changed, "removed": s.removed})
}

/// `v` with `state` set to the state to write, or `null`.
fn with_state(v: serde_json::Value, state: Option<ClientState>) -> JsValue {
    let o = to_js(&v);
    let s = state.map_or(JsValue::NULL, |s| state_text(&s).into());
    set(&o, "state", &s);
    o
}

fn revision(p: &Procedure) -> Result<&Revision, JsValue> {
    p.inner()
        .revision()
        .ok_or_else(|| usage("not a finished fetchRevision procedure"))
}

fn device(v: &JsValue) -> Result<[u8; 16], JsValue> {
    Ok(*array::<16>(v, "deviceId")?)
}

#[wasm_bindgen]
impl Session {
    /// Unlocks the local file with the secret key and the master password. Pulling first is the
    /// `unlock` procedure; this opens only the local file.
    pub fn unlock(
        state_text_in: &str,
        secret_key: &JsValue,
        password: &str,
    ) -> Result<Session, JsValue> {
        let sk = SecretKey::from_bytes(*array::<16>(secret_key, "secretKey")?);
        let inner =
            session::Session::unlock(state(state_text_in)?, &sk, password).map_err(client_err)?;
        Ok(Session { inner })
    }

    /// Reopens the local file with a vault key from `storage.session`.
    pub fn reopen(state_text_in: &str, vault_key: &JsValue) -> Result<Session, JsValue> {
        let vk = VaultKey::from_bytes(*array::<32>(vault_key, "vaultKey")?);
        let inner = session::Session::reopen(state(state_text_in)?, vk).map_err(client_err)?;
        Ok(Session { inner })
    }

    /// The vault key, for `storage.session` only. The caller zeroes the array when done.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Result<Uint8Array, JsValue> {
        let k = self.inner.vault_key().map_err(client_err)?;
        Ok(Uint8Array::from(&k.expose()[..]))
    }

    /// Takes a state another context committed. A file the vault key does not open throws, and
    /// the caller locks.
    pub fn reload(&mut self, state_text_in: &str) -> Result<(), JsValue> {
        self.inner.reload(state(state_text_in)?).map_err(client_err)
    }

    /// Zeroes the vault key and the body. Every later call throws `sync.locked`.
    pub fn lock(&mut self) {
        self.inner.lock();
    }

    /// Whether the body has a `v` greater than this client writes: it opens read-only, and
    /// every edit throws `read_only_body`.
    #[wasm_bindgen(js_name = readOnly)]
    pub fn read_only(&self) -> Result<bool, JsValue> {
        self.inner.read_only().map_err(client_err)
    }

    /// List entries without secrets, in listing order, optionally only those in `filter.folder`
    /// (and below) and matching `filter.text`.
    pub fn list(&self, filter: JsValue) -> Result<JsValue, JsValue> {
        let (folder, text) = if filter.is_undefined() || filter.is_null() {
            (None, None)
        } else {
            (get_str(&filter, "folder")?, get_str(&filter, "text")?)
        };
        let entries = self
            .inner
            .list(folder.as_deref(), text.as_deref())
            .map_err(client_err)?;
        let out: Vec<serde_json::Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "type": e.item_type,
                    "name": e.name,
                    "folder": e.folder,
                    "username": e.username,
                    "uris": e.uris,
                    "favourite": e.favourite,
                    "review": e.review,
                    "supported": e.supported,
                    "modified": e.modified,
                })
            })
            .collect();
        Ok(to_js(&json!(out)))
    }

    /// Every folder path in use, with the folders above it, sorted.
    pub fn folders(&self) -> Result<Vec<String>, JsValue> {
        self.inner.folders().map_err(client_err)
    }

    /// One item as the body schema defines it, secrets included.
    pub fn item(&self, id: &str) -> Result<JsValue, JsValue> {
        let v = self.inner.item(id).map_err(client_err)?.to_value();
        let text = vault_core::json::to_vec(&v);
        js_sys::JSON::parse(std::str::from_utf8(&text).expect("JSON is UTF-8"))
    }

    /// The username and password of a login, for one fill or copy.
    pub fn credential(&self, id: &str) -> Result<JsValue, JsValue> {
        let c = self.inner.credential(id).map_err(client_err)?;
        let o: JsValue = js_sys::Object::new().into();
        set(&o, "username", &c.username.as_str().into());
        set(&o, "password", &c.password.as_str().into());
        Ok(o)
    }

    /// Adds a login or a note: `{ id, state }`, `state` being the state to write.
    pub fn add(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        item: &JsValue,
    ) -> Result<JsValue, JsValue> {
        let s = |k: &str| get_str(item, k).map(Option::unwrap_or_default);
        let uris = match get(item, "uris") {
            v if v.is_undefined() || v.is_null() => Vec::new(),
            v => crate::convert::js_array(v, "uris")?
                .iter()
                .map(|u| {
                    Ok(LoginUri {
                        uri: get_str(&u, "uri")?.unwrap_or_default(),
                        match_value: get_str(&u, "match")?.unwrap_or_else(|| "base_domain".into()),
                        extra: Map::new(),
                    })
                })
                .collect::<Result<_, JsValue>>()?,
        };
        let new = NewItem {
            item_type: s("type")?,
            name: s("name")?,
            folder: s("folder")?,
            favourite: get(item, "favourite").as_bool().unwrap_or(false),
            notes: s("notes")?,
            username: s("username")?,
            password: s("password")?,
            uris,
        };
        let (id, next) = self
            .inner
            .add(
                &state(state_text_in)?,
                &device(device_id)?,
                now as u64,
                &mut WebRng,
                new,
            )
            .map_err(client_err)?;
        Ok(with_state(json!({"id": id}), next))
    }

    /// Applies the keys the user changed from `base` to `edited` onto the current item: `{ state }`.
    pub fn update(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        id: &str,
        base: &JsValue,
        edited: &JsValue,
    ) -> Result<JsValue, JsValue> {
        let (base, edited) = (parse_item(base)?, parse_item(edited)?);
        let next = self
            .inner
            .update(
                &state(state_text_in)?,
                &device(device_id)?,
                now as u64,
                &mut WebRng,
                id,
                fields(&base)?,
                fields(&edited)?,
            )
            .map_err(client_err)?;
        Ok(with_state(json!({}), next))
    }

    /// Deletes an item: `{ state }`.
    pub fn remove(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        id: &str,
    ) -> Result<JsValue, JsValue> {
        let next = self
            .inner
            .remove(
                &state(state_text_in)?,
                &device(device_id)?,
                now as u64,
                &mut WebRng,
                id,
            )
            .map_err(client_err)?;
        Ok(with_state(json!({}), next))
    }

    /// The hosts whose known suffix `candidates` and `saveOffer` look up for `pageUrl`: the page
    /// host and every domain of a login URI.
    #[wasm_bindgen(js_name = suffixHosts)]
    pub fn suffix_hosts(&self, page_url: &str) -> Result<Vec<String>, JsValue> {
        self.inner.suffix_hosts(page_url).map_err(client_err)
    }

    /// The fill candidates for `pageUrl`, in candidate order: `[{ id, name, username, outcome }]`.
    pub fn candidates(&self, page_url: &str, known_suffix: JsValue) -> Result<JsValue, JsValue> {
        let ks = KnownSuffix::from_js(known_suffix)?;
        let out: Vec<serde_json::Value> = self
            .inner
            .candidates(page_url, &ks)
            .map_err(client_err)?
            .into_iter()
            .map(|c| {
                json!({
                    "id": c.id, "name": c.name, "username": c.username,
                    "outcome": outcome(c.outcome),
                })
            })
            .collect();
        Ok(to_js(&json!(out)))
    }

    /// The save offer for a form submitted on `pageUrl`.
    #[wasm_bindgen(js_name = saveOffer)]
    pub fn save_offer(
        &self,
        page_url: &str,
        username: &str,
        password: &str,
        known_suffix: JsValue,
    ) -> Result<JsValue, JsValue> {
        let ks = KnownSuffix::from_js(known_suffix)?;
        let offer = self
            .inner
            .save_offer(page_url, username, password, &ks)
            .map_err(client_err)?;
        Ok(to_js(&match offer {
            SaveOffer::None => json!({"action": "none"}),
            SaveOffer::Update { id } => json!({"action": "update", "id": id}),
            SaveOffer::New { name, uri } => {
                json!({"action": "new", "name": name, "uri": uri, "match": "base_domain"})
            }
        }))
    }

    /// What restoring from a fetched revision would change: `{ added, changed, removed }`.
    #[wasm_bindgen(js_name = restorePreview)]
    pub fn restore_preview(
        &self,
        revision_in: &Procedure,
        item_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let s = self
            .inner
            .restore_preview(revision(revision_in)?, item_id.as_deref())
            .map_err(client_err)?;
        Ok(to_js(&summary_js(&s)))
    }

    /// Restores the whole vault, or one item, from a fetched revision as a local edit:
    /// `{ state, added, changed, removed }`.
    pub fn restore(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        revision_in: &Procedure,
        item_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let (next, s) = self
            .inner
            .restore(
                &state(state_text_in)?,
                &device(device_id)?,
                now as u64,
                &mut WebRng,
                revision(revision_in)?,
                item_id.as_deref(),
            )
            .map_err(client_err)?;
        let mut v = summary_js(&s);
        v["state"] = json!(state_text(&next));
        Ok(to_js(&v))
    }
}
