//! The `vault-client` procedures for JavaScript: `vault_client::session::Procedure` behind JSON
//! and camelCase conversions, and a commit through a JavaScript host that queues IndexedDB writes
//! in one transaction.

use crate::WebRng;
use crate::convert::{
    byte_vec, bytes, client_err, get, get_array, get_str, js_err, set, state, state_text, to_js,
    usage,
};
use js_sys::{Function, Uint8Array};
use serde_json::{Value, json};
use vault_client::commit::{Applied, ApplyError, CommitHost};
use vault_client::passwd::{PasswdChange, PasswdOptions};
use vault_client::session::{self, Event, Report};
use vault_client::sync::{Mode, SyncOutcome, SyncReport};
use vault_client::{
    Answer, ClientError, ClientState, Confirmation, Input, Keys, Precondition, Prompt, Purpose,
    Request, Response, SavedKey, SecretKeyStore,
};
use vault_core::credentials::PendingKeyOutcome;
use vault_core::kdf::KdfParams;
use vault_core::secret::{SecretKey, VaultKey};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn pending_outcome(p: Option<PendingKeyOutcome>) -> Value {
    match p {
        Some(PendingKeyOutcome::Landed) => json!("landed"),
        Some(PendingKeyOutcome::NotLanded) => json!("not_landed"),
        None => Value::Null,
    }
}

fn sync_json(r: &SyncReport) -> Value {
    json!({
        "outcome": match r.outcome {
            SyncOutcome::UpToDate => "up_to_date",
            SyncOutcome::Adopted => "adopted",
            SyncOutcome::Pushed => "pushed",
        },
        "generation": r.generation,
        "expired": r.expired,
        "credentialsChanged": r.credentials_changed,
        "pendingSecretKey": pending_outcome(r.pending_secret_key),
    })
}

fn error_json(e: ClientError) -> Value {
    json!({"code": e.code(), "message": e.to_string()})
}

fn report_json(r: &Report) -> Value {
    match r {
        Report::Sync(r) => sync_json(r),
        Report::Unlock(r) => json!({"sync": match &r.sync {
            Ok(s) => sync_json(s),
            Err(e) => json!({"error": error_json(*e)}),
        }}),
        Report::Recover(r) => json!({
            "generation": r.generation,
            "revision": r.revision,
            "expired": r.expired,
            "credentialsChanged": r.credentials_changed,
            "pendingSecretKey": pending_outcome(r.pending_secret_key),
        }),
        Report::Passwd(r) => json!({
            "generation": r.generation,
            "retiredRevision": r.retired_revision,
            "expired": r.expired,
        }),
        Report::Setup | Report::RepairToken => json!({}),
        Report::Revision(r) => json!({"id": r.id, "generation": r.generation}),
    }
}

/// The keys a procedure starts with: `{ vaultKey?, secretKey?, pendingSecretKey? }`.
fn keys(v: &JsValue) -> Result<Keys, JsValue> {
    if v.is_undefined() || v.is_null() {
        return Ok(Keys::default());
    }
    Ok(Keys {
        vault_key: get_array::<32>(v, "vaultKey")?.map(|k| VaultKey::from_bytes(*k)),
        secret_key: get_array::<16>(v, "secretKey")?.map(|k| SecretKey::from_bytes(*k)),
        pending_secret_key: get_array::<16>(v, "pendingSecretKey")?
            .map(|k| SecretKey::from_bytes(*k)),
    })
}

/// A running `vault-client` procedure.
#[wasm_bindgen]
pub struct Procedure {
    inner: session::Procedure,
}

impl Procedure {
    pub(crate) fn inner(&self) -> &session::Procedure {
        &self.inner
    }
}

fn present(event: Event<'_>) -> JsValue {
    match event {
        Event::Request(r) => request_js(&r),
        Event::Prompt(p) => to_js(&json!({"type": "prompt", "prompt": prompt_json(p)})),
        Event::Save(s) => {
            let (slot, key) = match &s.secret_key {
                SavedKey::Current(k) => ("current", k),
                SavedKey::Pending(k) => ("pending", k),
            };
            let o = to_js(&json!({
                "type": "save",
                "state": state_text(&s.state),
                "slot": slot,
                "vaultId": hex::encode(s.state.vault_id),
            }));
            let kit = vault_core::secret_key_text::encode(key);
            set(&o, "kit", &kit.as_str().into());
            o
        }
        Event::Done(f) => to_js(&match &f.result {
            Ok(r) => json!({"type": "done", "ok": true, "result": report_json(r)}),
            Err(e) => json!({"type": "done", "ok": false, "error": error_json(*e)}),
        }),
    }
}

fn request_js(r: &Request) -> JsValue {
    let (method, path) = match r {
        Request::GetVault => ("GET", "/v1/vault".to_owned()),
        Request::PutVault { .. } => ("PUT", "/v1/vault".to_owned()),
        Request::ListRevisions => ("GET", "/v1/revisions".to_owned()),
        Request::GetRevision(id) => ("GET", format!("/v1/revisions/{id}")),
    };
    let o = to_js(&json!({"type": "request", "method": method, "path": path}));
    if let Request::PutVault { condition, file } = r {
        match condition {
            Precondition::IfMatch(e) => set(&o, "ifMatch", &e.as_str().into()),
            Precondition::IfNoneMatch => set(&o, "ifNoneMatch", &"*".into()),
        }
        set(&o, "body", &bytes(file));
    }
    o
}

fn purpose(p: Purpose) -> &'static str {
    match p {
        Purpose::Unlock => "unlock",
        Purpose::CredentialsChanged => "credentials_changed",
        Purpose::PendingSecretKey => "pending_secret_key",
        Purpose::Recovery => "recovery",
        Purpose::Revision => "revision",
    }
}

fn prompt_json(p: Prompt) -> Value {
    match p {
        Prompt::MasterPassword { purpose: p, failed } => {
            json!({"kind": "master_password", "purpose": purpose(p), "failed": failed})
        }
        Prompt::MasterPasswordAndSecretKey { purpose: p } => {
            json!({"kind": "master_password_and_secret_key", "purpose": purpose(p)})
        }
        Prompt::OldMasterPassword { failed } => {
            json!({"kind": "old_master_password", "failed": failed})
        }
        Prompt::NewMasterPassword { rejected } => {
            json!({"kind": "new_master_password", "rejected": rejected.map(|e| e.code())})
        }
        Prompt::SecretKey => json!({"kind": "secret_key"}),
        Prompt::KitVaultId => json!({"kind": "kit_vault_id"}),
        Prompt::Confirm(c) => json!({
            "kind": "confirm",
            "confirmation": match c {
                Confirmation::DiscardLocalChanges => "discard_local_changes",
                Confirmation::NoCredentialChange => "no_credential_change",
            },
            "description": c.description(),
        }),
    }
}

fn secret_string(s: String) -> vault_core::secret::SecretString {
    Zeroizing::new(s)
}

fn input(v: &JsValue) -> Result<Input, JsValue> {
    match get_str(v, "type")?.as_deref() {
        Some("response") => {
            let status = get(v, "status")
                .as_f64()
                .filter(|s| s.fract() == 0.0 && (0.0..1000.0).contains(s))
                .ok_or_else(|| usage("status is not an HTTP status"))?
                as u16;
            let body = match get(v, "body") {
                b if b.is_undefined() || b.is_null() => Vec::new(),
                b => byte_vec(&b, "body")?,
            };
            let date = get(v, "date").as_f64().map(|d| d as u64);
            Ok(Input::Response(Response { status, body, date }))
        }
        Some("unreachable") => Ok(Input::Unreachable),
        Some("saved") => Ok(Input::Saved),
        Some("answer") => Ok(Input::Answer(answer(v)?)),
        _ => Err(usage("unknown input type")),
    }
}

fn answer(v: &JsValue) -> Result<Answer, JsValue> {
    if get(v, "declined").as_bool() == Some(true) {
        return Ok(Answer::Declined);
    }
    if let Some(c) = get(v, "confirmed").as_bool() {
        return Ok(Answer::Confirmed(c));
    }
    if js_sys::Reflect::has(v, &"vaultId".into()).unwrap_or(false) {
        let id = get_array::<16>(v, "vaultId")?.map(|a| *a);
        return Ok(Answer::VaultId(id));
    }
    let password = get_str(v, "password")?.map(secret_string);
    let secret_key = get_array::<16>(v, "secretKey")?.map(|k| SecretKey::from_bytes(*k));
    match (password, secret_key) {
        (Some(p), Some(k)) => Ok(Answer::PasswordAndSecretKey(p, k)),
        (Some(p), None) => Ok(Answer::Password(p)),
        (None, Some(k)) => Ok(Answer::SecretKey(k)),
        (None, None) => Err(usage("the answer is empty")),
    }
}

/// A JavaScript `CommitHost`: each method only queues IndexedDB requests, so none reads a slot.
/// The pending key a commit promotes comes from the procedure.
struct JsHost<'a> {
    host: &'a JsValue,
}

impl JsHost<'_> {
    fn call(&self, name: &str, args: &[JsValue]) -> Result<(), JsValue> {
        let f: Function = get(self.host, name)
            .dyn_into()
            .map_err(|_| usage(&format!("the host has no {name} method")))?;
        let a = js_sys::Array::new();
        for x in args {
            a.push(x);
        }
        f.apply(self.host, &a).map(|_| ())
    }

    fn store(&self, method: &str, vault_id: &[u8; 16], key: &SecretKey) -> Result<(), JsValue> {
        let k = Uint8Array::from(&key.expose()[..]);
        let r = self.call(method, &[hex::encode(vault_id).into(), k.clone().into()]);
        k.fill(0, 0, k.length());
        r
    }
}

impl CommitHost for JsHost<'_> {
    type Error = JsValue;

    fn store_current(
        &mut self,
        _: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), JsValue> {
        self.store("storeCurrent", vault_id, key)
    }

    fn store_pending(
        &mut self,
        _: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), JsValue> {
        self.store("storePending", vault_id, key)
    }

    fn copy_pending_to_current(&mut self, _: SecretKeyStore, _: &[u8; 16]) -> Result<(), JsValue> {
        Err(js_err(
            "usage",
            "no pending secret key was given to the procedure",
        ))
    }

    fn delete_pending(&mut self, _: SecretKeyStore, vault_id: &[u8; 16]) -> Result<(), JsValue> {
        self.call("deletePending", &[hex::encode(vault_id).into()])
    }

    fn write_state(&mut self, state: &ClientState) -> Result<(), JsValue> {
        self.call("writeState", &[state_text(state).into()])
    }
}

fn apply_err(e: ApplyError<JsValue>) -> JsValue {
    match e {
        ApplyError::Client(e) => client_err(e),
        ApplyError::Host(e) => e,
    }
}

fn applied_js(a: Option<Applied<JsValue>>, superseded: bool) -> JsValue {
    match a {
        None => to_js(&json!({
            "written": false, "superseded": superseded, "mergedLocalChanges": false,
            "expired": [], "pendingLeft": false,
        })),
        Some(a) => to_js(&json!({
            "written": a.commit.state.is_some(),
            "superseded": false,
            "mergedLocalChanges": a.commit.merged_local_changes,
            "expired": a.commit.expired,
            "pendingLeft": a.pending_left.is_some(),
        })),
    }
}

#[wasm_bindgen]
impl Procedure {
    /// Sync, in mode `"background"`, `"interactive"`, or `"interactive-ask-again"`.
    pub fn sync(state_text_in: &str, keys_in: &JsValue, mode: &str) -> Result<Procedure, JsValue> {
        let mode = match mode {
            "background" => Mode::Background,
            "interactive" => Mode::Interactive { ask_again: false },
            "interactive-ask-again" => Mode::Interactive { ask_again: true },
            _ => return Err(usage("unknown sync mode")),
        };
        let inner = session::Procedure::sync(state(state_text_in)?, keys(keys_in)?, mode, WebRng);
        Ok(Procedure { inner })
    }

    /// An unlock with a typed master password, which pulls first.
    pub fn unlock(state_text_in: &str, keys_in: &JsValue) -> Result<Procedure, JsValue> {
        let inner = session::Procedure::unlock(state(state_text_in)?, keys(keys_in)?, WebRng);
        Ok(Procedure { inner })
    }

    /// `vault sync --recover`.
    pub fn recover(state_text_in: &str, keys_in: &JsValue) -> Result<Procedure, JsValue> {
        let inner = session::Procedure::recover(state(state_text_in)?, keys(keys_in)?, WebRng);
        Ok(Procedure { inner })
    }

    /// A credential change: `"new-password"`, `"rekey"`, `"new-secret-key"`, or
    /// `"new-secret-key-and-password"`, with the KDF memory in MiB (64 by default).
    pub fn passwd(
        state_text_in: &str,
        keys_in: &JsValue,
        change: &str,
        kdf_memory_mib: Option<u32>,
    ) -> Result<Procedure, JsValue> {
        let change = match change {
            "new-password" => PasswdChange::NewPassword,
            "rekey" => PasswdChange::Rekey,
            "new-secret-key" => PasswdChange::NewSecretKey {
                new_password: false,
            },
            "new-secret-key-and-password" => PasswdChange::NewSecretKey { new_password: true },
            _ => return Err(usage("unknown credential change")),
        };
        let kdf = KdfParams::with_memory_mib(kdf_memory_mib.unwrap_or(64))
            .map_err(crate::convert::core_err)?;
        let options = PasswdOptions {
            change,
            kdf,
            test_kdf: false,
        };
        let inner =
            session::Procedure::passwd(state(state_text_in)?, keys(keys_in)?, options, WebRng);
        Ok(Procedure { inner })
    }

    /// Adds this browser to an existing vault. The extension's IndexedDB plays the secret key
    /// file, so the state records the `file` store.
    pub fn setup() -> Procedure {
        Procedure {
            inner: session::Procedure::setup(SecretKeyStore::File, WebRng),
        }
    }

    /// Checks a new server token against the stored `vault_id`.
    #[wasm_bindgen(js_name = repairToken)]
    pub fn repair_token(state_text_in: &str) -> Result<Procedure, JsValue> {
        let inner = session::Procedure::repair_token(state(state_text_in)?, WebRng);
        Ok(Procedure { inner })
    }

    /// Fetches and opens revision `id` for a restore.
    #[wasm_bindgen(js_name = fetchRevision)]
    pub fn fetch_revision(
        state_text_in: &str,
        keys_in: &JsValue,
        id: f64,
    ) -> Result<Procedure, JsValue> {
        let inner = session::Procedure::fetch_revision(
            state(state_text_in)?,
            keys(keys_in)?,
            id as u64,
            WebRng,
        );
        Ok(Procedure { inner })
    }

    /// Runs the procedure up to its first step.
    pub fn start(&mut self, now: f64) -> JsValue {
        present(self.inner.start(now as u64))
    }

    /// Feeds the input for the previous step and runs up to the next.
    pub fn step(&mut self, input_in: &JsValue, now: f64) -> Result<JsValue, JsValue> {
        let i = input(input_in)?;
        Ok(present(self.inner.step(i, now as u64)))
    }

    /// After a `save` step: stores the secret key in its slot, runs the commit rule, and writes
    /// the state, through `host` inside one IndexedDB transaction.
    #[wasm_bindgen(js_name = applySave)]
    pub fn apply_save(
        &self,
        started: &str,
        on_disk: &str,
        now: f64,
        host: &JsValue,
    ) -> Result<(), JsValue> {
        let (started, on_disk) = (state(started)?, state(on_disk)?);
        self.inner
            .apply_save(
                &started,
                &on_disk,
                now as u64,
                &mut WebRng,
                &mut JsHost { host },
            )
            .map(|_| ())
            .map_err(apply_err)
    }

    /// After `done`: commits the procedure's end and its secret key change through `host` inside
    /// one IndexedDB transaction, in the order `vault_client::commit::apply` gives.
    ///
    /// `setup` has no earlier state: pass `null` for `started` and `onDisk`, and the secret key
    /// and the new state are written as they are. A stored state with a `null` start throws,
    /// because a browser that holds a vault repairs its token with `repairToken` instead.
    pub fn apply(
        &self,
        started: Option<String>,
        on_disk: Option<String>,
        background: bool,
        now: f64,
        host: &JsValue,
    ) -> Result<JsValue, JsValue> {
        if self.inner.finished().is_none() {
            return Err(usage("the procedure has not finished"));
        }
        let (started, on_disk) = match (started, on_disk) {
            (Some(s), Some(d)) => (Some(state(&s)?), Some(state(&d)?)),
            (None, None) => (None, None),
            (None, Some(_)) => return Err(usage("a state is stored; run repairToken, not setup")),
            (Some(_), None) => return Err(usage("onDisk is missing")),
        };
        let first = started.is_none();
        let a = self
            .inner
            .apply(
                started.as_ref(),
                on_disk.as_ref(),
                background,
                now as u64,
                &mut WebRng,
                &mut JsHost { host },
            )
            .map_err(apply_err)?;
        Ok(applied_js(a, !first))
    }

    /// After `done`: the vault key for the committed state, for `storage.session` and
    /// `Session.reopen`, or `null`. The caller zeroes the array when done.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> JsValue {
        self.inner
            .vault_key()
            .map_or(JsValue::NULL, |k| bytes(k.expose()))
    }
}
