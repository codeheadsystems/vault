//! An unlocked vault: the local state, the vault key, and the body, held in WASM memory.

use crate::WebRng;
use crate::autofill::{KnownSuffix, outcome};
use crate::convert::{array, client_err, core_err, get_str, set, state, state_text, to_js, usage};
use crate::procedure::Procedure;
use js_sys::Uint8Array;
use serde_json::json;
use vault_client::autofill::{self, SaveOffer, UrlHost};
use vault_client::edit::{EditError, local_edit};
use vault_client::restore::{RestoreScope, restore, restore_preview};
use vault_client::{ClientError, ClientState, items};
use vault_core::body::{Body, Item, ItemFields, Login, LoginUri, TYPE_LOGIN, TYPE_NOTE};
use vault_core::edit::{add_item, delete_item, update_item};
use vault_core::file::{open_file, unlock};
use vault_core::json::Map;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::{Error, InputKind};
use wasm_bindgen::prelude::*;

/// An unlocked vault. `lock` zeroes the vault key and the body; the extension then drops the
/// instance.
#[wasm_bindgen]
pub struct Session {
    state: ClientState,
    vault_key: Option<VaultKey>,
    body: Option<Body>,
}

fn locked() -> JsValue {
    client_err(ClientError::Locked)
}

fn not_found() -> JsValue {
    core_err(Error::InvalidInput(InputKind::NotFound))
}

fn edit_err(e: EditError<Error>) -> JsValue {
    match e {
        EditError::Client(e) => client_err(e),
        EditError::Edit(e) => core_err(e),
    }
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

impl Session {
    fn opened(state: ClientState, vault_key: VaultKey, body: Body) -> Session {
        Session {
            state,
            vault_key: Some(vault_key),
            body: Some(body),
        }
    }

    fn key(&self) -> Result<&VaultKey, JsValue> {
        self.vault_key.as_ref().ok_or_else(locked)
    }

    fn body(&self) -> Result<&Body, JsValue> {
        self.body.as_ref().ok_or_else(locked)
    }

    fn item_ref(&self, id: &str) -> Result<&Item, JsValue> {
        self.body()?.item(id).ok_or_else(not_found)
    }

    /// Runs a local edit on `state_text` and takes its result into the session.
    fn edit<R>(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        f: impl FnOnce(&mut Body, u64, &[u8; 16]) -> Result<R, Error>,
    ) -> Result<(R, JsValue), JsValue> {
        let current = state(state_text_in)?;
        let device = array::<16>(device_id, "deviceId")?;
        let vk = self.key()?.clone_secret();
        let (r, next) =
            local_edit(&current, &vk, &device, now as u64, &mut WebRng, f).map_err(edit_err)?;
        let written = match next {
            Some(s) => {
                let text = state_text(&s);
                self.take(s)?;
                JsValue::from_str(&text)
            }
            None => {
                self.take(current)?;
                JsValue::NULL
            }
        };
        Ok((r, written))
    }

    /// Makes `state` the session's state, opening its file with the session's vault key.
    fn take(&mut self, state: ClientState) -> Result<(), JsValue> {
        let (_, body) = open_file(&state.file, self.key()?).map_err(core_err)?;
        self.state = state;
        self.body = Some(body);
        Ok(())
    }
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
        let s = state(state_text_in)?;
        let sk = SecretKey::from_bytes(*array::<16>(secret_key, "secretKey")?);
        let u = unlock(&s.file, password, &sk).map_err(core_err)?;
        Ok(Session::opened(s, u.vault_key, u.body))
    }

    /// Reopens the local file with a vault key from `storage.session`.
    pub fn reopen(state_text_in: &str, vault_key: &JsValue) -> Result<Session, JsValue> {
        let s = state(state_text_in)?;
        let vk = VaultKey::from_bytes(*array::<32>(vault_key, "vaultKey")?);
        let (_, body) = open_file(&s.file, &vk).map_err(core_err)?;
        Ok(Session::opened(s, vk, body))
    }

    /// The vault key, for `storage.session` only. The caller zeroes the array when done.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Result<Uint8Array, JsValue> {
        Ok(Uint8Array::from(&self.key()?.expose()[..]))
    }

    /// Takes a state another context committed. A file the vault key does not open throws, and
    /// the caller locks.
    pub fn reload(&mut self, state_text_in: &str) -> Result<(), JsValue> {
        self.take(state(state_text_in)?)
    }

    /// Zeroes the vault key and the body. Every later call throws `sync.locked`.
    pub fn lock(&mut self) {
        self.vault_key = None;
        self.body = None;
        self.state.dropped.clear();
    }

    /// Whether the body has a `v` greater than this client writes: it opens read-only, and
    /// every edit throws `read_only_body`.
    #[wasm_bindgen(js_name = readOnly)]
    pub fn read_only(&self) -> Result<bool, JsValue> {
        Ok(!self.body()?.writable())
    }

    /// List entries without secrets, in listing order, optionally only those in `filter.folder`
    /// (and below) and matching `filter.text`.
    pub fn list(&self, filter: JsValue) -> Result<JsValue, JsValue> {
        let (folder, text) = if filter.is_undefined() || filter.is_null() {
            (None, None)
        } else {
            (get_str(&filter, "folder")?, get_str(&filter, "text")?)
        };
        let found = items::sorted(
            self.body()?
                .items
                .iter()
                .filter(|i| folder.as_deref().is_none_or(|f| items::in_folder(i, f)))
                .filter(|i| text.as_deref().is_none_or(|t| items::matches_text(i, t)))
                .collect(),
        );
        let out: Vec<serde_json::Value> = found
            .into_iter()
            .map(|i| {
                let f = i.fields();
                let login = i.login();
                json!({
                    "id": i.id,
                    "type": i.item_type,
                    "name": f.map_or("", |f| f.name.as_str()),
                    "folder": f.map_or("", |f| f.folder.as_str()),
                    "username": login.map_or("", |l| l.username.as_str()),
                    "uris": login.map_or(Vec::new(), |l| l.uris.iter().map(|u| u.uri.clone()).collect()),
                    "favourite": f.is_some_and(|f| f.favourite),
                    "review": i.review.is_some(),
                    "supported": f.is_some(),
                    "modified": i.modified,
                })
            })
            .collect();
        Ok(to_js(&json!(out)))
    }

    /// Every folder path in use, with the folders above it, sorted.
    pub fn folders(&self) -> Result<Vec<String>, JsValue> {
        let mut out = std::collections::BTreeSet::new();
        for f in self.body()?.items.iter().filter_map(Item::fields) {
            let mut path = f.folder.as_str();
            while !path.is_empty() {
                out.insert(path.to_owned());
                path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// One item as the body schema defines it, secrets included.
    pub fn item(&self, id: &str) -> Result<JsValue, JsValue> {
        let v = self.item_ref(id)?.to_value();
        let text = vault_core::json::to_vec(&v);
        js_sys::JSON::parse(std::str::from_utf8(&text).expect("JSON is UTF-8"))
    }

    /// The username and password of a login, for one fill or copy.
    pub fn credential(&self, id: &str) -> Result<JsValue, JsValue> {
        let login = self
            .item_ref(id)?
            .login()
            .ok_or_else(|| core_err(Error::InvalidInput(InputKind::UnsupportedItem)))?;
        let o: JsValue = js_sys::Object::new().into();
        set(&o, "username", &login.username.as_str().into());
        set(&o, "password", &login.password.as_str().into());
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
        let item_type = get_str(item, "type")?.unwrap_or_default();
        let s = |k: &str| get_str(item, k).map(Option::unwrap_or_default);
        let uris = match crate::convert::get(item, "uris") {
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
        let login = match item_type.as_str() {
            TYPE_LOGIN => Some(Login {
                username: s("username")?,
                password: s("password")?,
                uris,
                apps: Vec::new(),
                totp: None,
                passkeys: Vec::new(),
                extra: Map::new(),
            }),
            TYPE_NOTE => None,
            _ => return Err(core_err(Error::InvalidInput(InputKind::UnsupportedItem))),
        };
        let fields = ItemFields {
            name: s("name")?,
            folder: s("folder")?,
            favourite: crate::convert::get(item, "favourite")
                .as_bool()
                .unwrap_or(false),
            notes: s("notes")?,
            fields: Vec::new(),
            password_history: Vec::new(),
            created: 0,
            login,
            origin: None,
            extra: Map::new(),
        };
        let (id, written) = self.edit(state_text_in, device_id, now, |body, now, dev| {
            add_item(body, &mut WebRng, &item_type, fields, now, dev)
        })?;
        Ok(to_js_with_state(json!({"id": id}), written))
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
        let base = parse_item(base)?;
        let edited = parse_item(edited)?;
        let (base, edited) = (fields(&base)?.clone(), fields(&edited)?.clone());
        let id = id.to_owned();
        let ((), written) = self.edit(state_text_in, device_id, now, |body, now, dev| {
            let current = body
                .item(&id)
                .ok_or(Error::InvalidInput(InputKind::NotFound))?
                .fields()
                .ok_or(Error::InvalidInput(InputKind::UnsupportedItem))?;
            let merged = items::apply_changes(&base, &edited, current);
            if merged != *current {
                update_item(body, &id, merged, now, dev)?;
            }
            Ok(())
        })?;
        Ok(to_js_with_state(json!({}), written))
    }

    /// Deletes an item: `{ state }`.
    pub fn remove(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        id: &str,
    ) -> Result<JsValue, JsValue> {
        let ((), written) = self.edit(state_text_in, device_id, now, |body, now, dev| {
            delete_item(body, id, now, dev)
        })?;
        Ok(to_js_with_state(json!({}), written))
    }

    /// The hosts whose known suffix `candidates` and `saveOffer` look up for `pageUrl`: the page
    /// host and every domain of a login URI.
    #[wasm_bindgen(js_name = suffixHosts)]
    pub fn suffix_hosts(&self, page_url: &str) -> Result<Vec<String>, JsValue> {
        let mut out = std::collections::BTreeSet::new();
        let mut add = |p: Option<autofill::Prepared>| {
            if let Some(autofill::Prepared {
                host: UrlHost::Domain(d),
                ..
            }) = p
            {
                out.insert(d);
            }
        };
        add(autofill::page_url(page_url));
        for l in self.body()?.items.iter().filter_map(Item::login) {
            for u in &l.uris {
                add(autofill::prepare_uri(&u.uri));
            }
        }
        Ok(out.into_iter().collect())
    }

    /// The fill candidates for `pageUrl`, in candidate order: `[{ id, name, username, outcome }]`.
    pub fn candidates(&self, page_url: &str, known_suffix: JsValue) -> Result<JsValue, JsValue> {
        let ks = KnownSuffix::from_js(known_suffix)?;
        let out: Vec<serde_json::Value> = autofill::candidates(page_url, &self.body()?.items, &ks)
            .into_iter()
            .map(|(i, o)| {
                json!({
                    "id": i.id,
                    "name": i.fields().map_or("", |f| f.name.as_str()),
                    "username": i.login().map_or("", |l| l.username.as_str()),
                    "outcome": outcome(o),
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
        let offer = autofill::save_offer(page_url, username, password, &self.body()?.items, &ks);
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
        revision: &Procedure,
        item_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let rev = revision.revision()?;
        let scope = item_id
            .as_deref()
            .map_or(RestoreScope::All, RestoreScope::Item);
        let s = restore_preview(self.body()?, rev, scope).map_err(client_err)?;
        Ok(to_js(
            &json!({"added": s.added, "changed": s.changed, "removed": s.removed}),
        ))
    }

    /// Restores the whole vault, or one item, from a fetched revision as a local edit:
    /// `{ state, added, changed, removed }`.
    pub fn restore(
        &mut self,
        state_text_in: &str,
        device_id: &JsValue,
        now: f64,
        revision: &Procedure,
        item_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let current = state(state_text_in)?;
        let device = array::<16>(device_id, "deviceId")?;
        let rev = revision.revision()?;
        let scope = item_id
            .as_deref()
            .map_or(RestoreScope::All, RestoreScope::Item);
        let vk = self.key()?.clone_secret();
        let (next, s) = restore(&current, &vk, rev, scope, &device, now as u64, &mut WebRng)
            .map_err(client_err)?;
        let text = state_text(&next);
        self.take(next)?;
        Ok(to_js(&json!({
            "state": text, "added": s.added, "changed": s.changed, "removed": s.removed,
        })))
    }
}

/// `v` with `state` set to the state to write, or `null`.
fn to_js_with_state(v: serde_json::Value, state: JsValue) -> JsValue {
    let o = to_js(&v);
    set(&o, "state", &state);
    o
}
