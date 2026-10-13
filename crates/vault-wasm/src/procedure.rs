//! The `vault-client` machines, stepped from JavaScript, and the commit through a JavaScript
//! host that queues IndexedDB writes in one transaction.

use crate::WebRng;
use crate::convert::{
    byte_vec, bytes, client_err, get, get_array, get_str, js_err, set, state, state_text, to_js,
    usage,
};
use js_sys::{Function, Uint8Array};
use serde_json::{Value, json};
use vault_client::commit::{ApplyError, CommitHost, apply};
use vault_client::passwd::{PasswdChange, PasswdOptions, PasswdReport, passwd};
use vault_client::recover::{RecoverReport, recover};
use vault_client::restore::{Revision, fetch_revision};
use vault_client::setup::{repair_token, setup};
use vault_client::sync::{Mode, SyncOutcome, SyncReport, sync};
use vault_client::unlock::{UnlockReport, unlock};
use vault_client::{
    Answer, ClientError, ClientState, Confirmation, Finished, Input, Keys, Machine, Precondition,
    Prompt, Purpose, Request, Response, Save, SavedKey, SecretKeyChange, SecretKeyStore, Step,
};
use vault_core::credentials::PendingKeyOutcome;
use vault_core::kdf::KdfParams;
use vault_core::secret::{SecretKey, VaultKey};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// A finished procedure's result, as JSON for JavaScript and, after `fetchRevision`, the
/// revision.
struct Out {
    json: Value,
    revision: Option<Revision>,
}

/// A machine whose result type is erased to [`Out`].
trait AnyMachine {
    fn start(&mut self, now: u64) -> Step<Out>;
    fn step(&mut self, input: Input, now: u64) -> Step<Out>;
}

struct Typed<T> {
    machine: Machine<T>,
    out: fn(T) -> Out,
}

impl<T: 'static> AnyMachine for Typed<T> {
    fn start(&mut self, now: u64) -> Step<Out> {
        erase(self.machine.start(now), self.out)
    }

    fn step(&mut self, input: Input, now: u64) -> Step<Out> {
        erase(self.machine.step(input, now), self.out)
    }
}

fn erase<T>(step: Step<T>, out: fn(T) -> Out) -> Step<Out> {
    match step {
        Step::Request(r) => Step::Request(r),
        Step::Prompt(p) => Step::Prompt(p),
        Step::Save(s) => Step::Save(s),
        Step::Done(f) => Step::Done(Finished {
            result: f.result.map(out),
            state: f.state,
            vault_key: f.vault_key,
            started_vault_key: f.started_vault_key,
            secret_key: f.secret_key,
        }),
    }
}

fn typed<T: 'static>(machine: Machine<T>, out: fn(T) -> Out) -> Box<dyn AnyMachine> {
    Box::new(Typed { machine, out })
}

fn json_out(json: Value) -> Out {
    Out {
        json,
        revision: None,
    }
}

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

fn sync_out(r: SyncReport) -> Out {
    json_out(sync_json(&r))
}

fn unlock_out(r: UnlockReport) -> Out {
    json_out(json!({"sync": match &r.sync {
        Ok(s) => sync_json(s),
        Err(e) => json!({"error": error_json(*e)}),
    }}))
}

fn recover_out(r: RecoverReport) -> Out {
    json_out(json!({
        "generation": r.generation,
        "revision": r.revision,
        "expired": r.expired,
        "credentialsChanged": r.credentials_changed,
        "pendingSecretKey": pending_outcome(r.pending_secret_key),
    }))
}

fn passwd_out(r: PasswdReport) -> Out {
    json_out(json!({
        "generation": r.generation,
        "retiredRevision": r.retired_revision,
        "expired": r.expired,
    }))
}

fn unit_out((): ()) -> Out {
    json_out(json!({}))
}

fn revision_out(r: Revision) -> Out {
    Out {
        json: json!({"id": r.id, "generation": r.generation}),
        revision: Some(r),
    }
}

/// The keys a procedure starts with: `{ vaultKey?, secretKey?, pendingSecretKey? }`.
fn keys(v: &JsValue) -> Result<(Keys, Option<SecretKey>), JsValue> {
    if v.is_undefined() || v.is_null() {
        return Ok((Keys::default(), None));
    }
    let vault_key = get_array::<32>(v, "vaultKey")?.map(|k| VaultKey::from_bytes(*k));
    let secret_key = get_array::<16>(v, "secretKey")?.map(|k| SecretKey::from_bytes(*k));
    let pending = get_array::<16>(v, "pendingSecretKey")?.map(|k| SecretKey::from_bytes(*k));
    let kept = pending.as_ref().map(SecretKey::clone_secret);
    Ok((
        Keys {
            vault_key,
            secret_key,
            pending_secret_key: pending,
        },
        kept,
    ))
}

/// A running `vault-client` procedure.
#[wasm_bindgen]
pub struct Procedure {
    machine: Box<dyn AnyMachine>,
    /// The pending secret key, from the keys or a save, for a commit that promotes it.
    pending: Option<SecretKey>,
    save: Option<Save>,
    finished: Option<Finished<Out>>,
}

impl Procedure {
    fn new(machine: Box<dyn AnyMachine>, pending: Option<SecretKey>) -> Procedure {
        Procedure {
            machine,
            pending,
            save: None,
            finished: None,
        }
    }

    /// The revision a finished `fetchRevision` holds.
    pub(crate) fn revision(&self) -> Result<&Revision, JsValue> {
        self.finished
            .as_ref()
            .and_then(|f| f.result.as_ref().ok())
            .and_then(|o| o.revision.as_ref())
            .ok_or_else(|| usage("not a finished fetchRevision procedure"))
    }

    fn present(&mut self, step: Step<Out>) -> JsValue {
        match step {
            Step::Request(r) => request_js(&r),
            Step::Prompt(p) => to_js(&json!({"type": "prompt", "prompt": prompt_json(p)})),
            Step::Save(s) => {
                let (slot, key) = match &s.secret_key {
                    SavedKey::Current(k) => ("current", k),
                    SavedKey::Pending(k) => ("pending", k),
                };
                if let SavedKey::Pending(k) = &s.secret_key {
                    self.pending = Some(k.clone_secret());
                }
                let o = to_js(&json!({
                    "type": "save",
                    "state": state_text(&s.state),
                    "slot": slot,
                    "vaultId": hex::encode(s.state.vault_id),
                }));
                let kit = vault_core::secret_key_text::encode(key);
                set(&o, "kit", &kit.as_str().into());
                self.save = Some(s);
                o
            }
            Step::Done(f) => {
                let o = match &f.result {
                    Ok(out) => json!({"type": "done", "ok": true, "result": out.json}),
                    Err(e) => json!({"type": "done", "ok": false, "error": error_json(*e)}),
                };
                self.finished = Some(f);
                to_js(&o)
            }
        }
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

/// A JavaScript `CommitHost`: each method only queues IndexedDB requests.
struct JsHost<'a> {
    host: &'a JsValue,
    pending: Option<&'a SecretKey>,
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

    fn copy_pending_to_current(
        &mut self,
        _: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), JsValue> {
        let p = self
            .pending
            .ok_or_else(|| js_err("usage", "no pending secret key was given to the procedure"))?;
        self.store("storeCurrent", vault_id, p)
    }

    fn delete_pending(&mut self, _: SecretKeyStore, vault_id: &[u8; 16]) -> Result<(), JsValue> {
        self.call("deletePending", &[hex::encode(vault_id).into()])
    }

    fn write_state(&mut self, state: &ClientState) -> Result<(), JsValue> {
        self.call("writeState", &[state_text(state).into()])
    }
}

fn state_arg(text: &str) -> Result<ClientState, JsValue> {
    state(text)
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
        let (k, pending) = keys(keys_in)?;
        Ok(Procedure::new(
            typed(sync(state_arg(state_text_in)?, k, mode, WebRng), sync_out),
            pending,
        ))
    }

    /// An unlock with a typed master password, which pulls first.
    pub fn unlock(state_text_in: &str, keys_in: &JsValue) -> Result<Procedure, JsValue> {
        let (k, pending) = keys(keys_in)?;
        Ok(Procedure::new(
            typed(unlock(state_arg(state_text_in)?, k, WebRng), unlock_out),
            pending,
        ))
    }

    /// `vault sync --recover`.
    pub fn recover(state_text_in: &str, keys_in: &JsValue) -> Result<Procedure, JsValue> {
        let (k, pending) = keys(keys_in)?;
        Ok(Procedure::new(
            typed(recover(state_arg(state_text_in)?, k, WebRng), recover_out),
            pending,
        ))
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
        let (k, pending) = keys(keys_in)?;
        Ok(Procedure::new(
            typed(
                passwd(state_arg(state_text_in)?, k, options, WebRng),
                passwd_out,
            ),
            pending,
        ))
    }

    /// Adds this browser to an existing vault. The extension's IndexedDB plays the secret key
    /// file, so the state records the `file` store.
    pub fn setup() -> Procedure {
        Procedure::new(typed(setup(SecretKeyStore::File, WebRng), unit_out), None)
    }

    /// Checks a new server token against the stored `vault_id`.
    #[wasm_bindgen(js_name = repairToken)]
    pub fn repair_token(state_text_in: &str) -> Result<Procedure, JsValue> {
        Ok(Procedure::new(
            typed(repair_token(state_arg(state_text_in)?, WebRng), unit_out),
            None,
        ))
    }

    /// Fetches and opens revision `id` for a restore.
    #[wasm_bindgen(js_name = fetchRevision)]
    pub fn fetch_revision(
        state_text_in: &str,
        keys_in: &JsValue,
        id: f64,
    ) -> Result<Procedure, JsValue> {
        let (k, pending) = keys(keys_in)?;
        Ok(Procedure::new(
            typed(
                fetch_revision(state_arg(state_text_in)?, k, id as u64, WebRng),
                revision_out,
            ),
            pending,
        ))
    }

    /// Runs the procedure up to its first step.
    pub fn start(&mut self, now: f64) -> JsValue {
        let s = self.machine.start(now as u64);
        self.present(s)
    }

    /// Feeds the input for the previous step and runs up to the next.
    pub fn step(&mut self, input_in: &JsValue, now: f64) -> Result<JsValue, JsValue> {
        let i = input(input_in)?;
        let s = self.machine.step(i, now as u64);
        Ok(self.present(s))
    }

    /// After a `save` step: stores the secret key in its slot, then commits the state, through
    /// `host` inside one IndexedDB transaction.
    #[wasm_bindgen(js_name = applySave)]
    pub fn apply_save(
        &self,
        started: &str,
        on_disk: &str,
        now: f64,
        host: &JsValue,
    ) -> Result<(), JsValue> {
        let save = self
            .save
            .as_ref()
            .ok_or_else(|| usage("no save step to apply"))?;
        let (started, on_disk) = (state_arg(started)?, state_arg(on_disk)?);
        let c = save
            .commit(&started, &on_disk, now as u64, &mut WebRng)
            .map_err(client_err)?;
        let h = JsHost {
            host,
            pending: None,
        };
        let id = save.state.vault_id;
        match &save.secret_key {
            SavedKey::Current(k) => h.store("storeCurrent", &id, k)?,
            SavedKey::Pending(k) => h.store("storePending", &id, k)?,
        }
        if let Some(s) = &c.state {
            h.call("writeState", &[state_text(s).into()])?;
        }
        Ok(())
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
        let finished = self
            .finished
            .as_ref()
            .ok_or_else(|| usage("the procedure has not finished"))?;
        let (started, on_disk) = match (started, on_disk) {
            (Some(s), Some(d)) => (state_arg(&s)?, state_arg(&d)?),
            (None, None) => return self.apply_first(host),
            (None, Some(_)) => return Err(usage("a state is stored; run repairToken, not setup")),
            (Some(_), None) => return Err(usage("onDisk is missing")),
        };
        let mut h = JsHost {
            host,
            pending: self.pending.as_ref(),
        };
        match apply(
            finished,
            &started,
            &on_disk,
            background,
            now as u64,
            &mut WebRng,
            &mut h,
        ) {
            Ok(None) => Ok(to_js(&json!({
                "written": false, "superseded": true, "mergedLocalChanges": false,
                "expired": [], "pendingLeft": false,
            }))),
            Ok(Some(a)) => Ok(to_js(&json!({
                "written": a.commit.state.is_some(),
                "superseded": false,
                "mergedLocalChanges": a.commit.merged_local_changes,
                "expired": a.commit.expired,
                "pendingLeft": a.pending_left.is_some(),
            }))),
            Err(ApplyError::Client(e)) => Err(client_err(e)),
            Err(ApplyError::Host(e)) => Err(e),
        }
    }

    /// Writes the first state of this browser, after `setup`: the secret key, then the state.
    fn apply_first(&self, host: &JsValue) -> Result<JsValue, JsValue> {
        let finished = self.finished.as_ref().expect("checked by apply");
        let Some(state) = &finished.state else {
            return Ok(to_js(&json!({
                "written": false, "superseded": false, "mergedLocalChanges": false,
                "expired": [], "pendingLeft": false,
            })));
        };
        let h = JsHost {
            host,
            pending: None,
        };
        if let Some(SecretKeyChange::Replace(k)) = &finished.secret_key {
            h.store("storeCurrent", &state.vault_id, k)?;
        }
        h.call("writeState", &[state_text(state).into()])?;
        Ok(to_js(&json!({
            "written": true, "superseded": false, "mergedLocalChanges": false,
            "expired": [], "pendingLeft": false,
        })))
    }

    /// After `done`: the vault key for the committed state, for `storage.session` and
    /// `Session.reopen`, or `null`. The caller zeroes the array when done.
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> JsValue {
        match self.finished.as_ref().and_then(|f| f.vault_key.as_ref()) {
            Some(k) => bytes(k.expose()),
            None => JsValue::NULL,
        }
    }
}
