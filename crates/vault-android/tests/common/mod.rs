//! An in-memory `Host` with settable clocks, a minimal server, and a procedure driver.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use vault_android::{Answer, Host, Input, KeySlot, Procedure, Request, Step, Vault, VaultError};
use vault_client::{ClientState, SecretKeyStore};
use vault_core::kdf::FLOOR;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::sync::SyncState;

/// A time after the build time, in ms.
pub const T0: u64 = 1_800_000_000_000;
pub const PW: &str = "correct horse battery staple";

/// The app's files and clocks in memory.
#[derive(Default)]
pub struct MemHost {
    pub state: Mutex<Option<Vec<u8>>>,
    pub current: Mutex<Option<Vec<u8>>>,
    pub pending: Mutex<Option<Vec<u8>>>,
    pub device: Mutex<Option<Vec<u8>>>,
    pub wrap_deletes: AtomicU32,
    pub device_writes: AtomicU32,
    pub now: AtomicU64,
    pub elapsed: AtomicU64,
    /// Makes `write_state` fail with `host.io`.
    pub fail_writes: AtomicBool,
    /// Makes `read_state` panic.
    pub panic_reads: AtomicBool,
}

impl MemHost {
    pub fn new() -> Arc<MemHost> {
        let h = MemHost::default();
        h.now.store(T0, Ordering::SeqCst);
        h.elapsed.store(1_000, Ordering::SeqCst);
        Arc::new(h)
    }

    pub fn state(&self) -> ClientState {
        ClientState::from_json(self.state.lock().unwrap().as_ref().expect("a state")).unwrap()
    }

    pub fn set_state(&self, s: &ClientState) {
        *self.state.lock().unwrap() = Some(s.to_json());
    }

    pub fn advance(&self, ms: u64) {
        self.elapsed.fetch_add(ms, Ordering::SeqCst);
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    fn slot(&self, slot: KeySlot) -> &Mutex<Option<Vec<u8>>> {
        match slot {
            KeySlot::Current => &self.current,
            KeySlot::Pending => &self.pending,
        }
    }
}

impl Host for MemHost {
    fn read_state(&self) -> Result<Option<Vec<u8>>, VaultError> {
        assert!(
            !self.panic_reads.load(Ordering::SeqCst),
            "read_state panics"
        );
        Ok(self.state.lock().unwrap().clone())
    }

    fn write_state(&self, state: Vec<u8>) -> Result<(), VaultError> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(VaultError::Failed {
                code: "host.io".into(),
                detail: "disk full".into(),
            });
        }
        *self.state.lock().unwrap() = Some(state);
        Ok(())
    }

    fn read_key(&self, slot: KeySlot) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.slot(slot).lock().unwrap().clone())
    }

    fn write_key(&self, slot: KeySlot, key: Vec<u8>) -> Result<(), VaultError> {
        *self.slot(slot).lock().unwrap() = Some(key);
        Ok(())
    }

    fn delete_key(&self, slot: KeySlot) -> Result<(), VaultError> {
        *self.slot(slot).lock().unwrap() = None;
        Ok(())
    }

    fn delete_biometric_wrap(&self) -> Result<(), VaultError> {
        self.wrap_deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn read_device_id(&self) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.device.lock().unwrap().clone())
    }

    fn write_device_id(&self, id: Vec<u8>) -> Result<(), VaultError> {
        self.device_writes.fetch_add(1, Ordering::SeqCst);
        *self.device.lock().unwrap() = Some(id);
        Ok(())
    }

    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn elapsed_realtime_ms(&self) -> u64 {
        self.elapsed.load(Ordering::SeqCst)
    }
}

/// A new vault at the floor KDF parameters, not yet pushed: its state, secret key, and vault
/// key.
pub struct NewVault {
    pub state: ClientState,
    pub secret_key: SecretKey,
    pub vault_key: VaultKey,
}

pub fn new_vault(seed: u8) -> NewVault {
    let v = vault_core::credentials::create_vault(&mut Counter(seed), PW, FLOOR, false).unwrap();
    NewVault {
        state: ClientState::new(
            SyncState {
                vault_id: v.state.vault_id,
                accepted: None,
                wrap_nonce: v.state.wrap_nonce,
                retired_wrap_nonces: Vec::new(),
            },
            v.file,
            SecretKeyStore::File,
        ),
        secret_key: v.secret_key,
        vault_key: v.vault_key,
    }
}

/// A host holding `v`'s state and secret key, and a vault over it.
pub fn vault_with(v: &NewVault) -> (Arc<MemHost>, Arc<Vault>) {
    let host = MemHost::new();
    host.set_state(&v.state);
    *host.current.lock().unwrap() = Some(v.secret_key.expose().to_vec());
    let vault = Vault::new(host.clone());
    (host, vault)
}

/// Opens the session with the vault key, as a biometric unlock does.
pub fn reopen(host: &MemHost, vault: &Vault, vk: &VaultKey) {
    let wrap = host.state().wrap_nonce.to_vec();
    vault.reopen(vk.expose().to_vec(), wrap).unwrap();
}

/// The spec's server API over a list of stored files.
#[derive(Default)]
pub struct Server {
    pub files: Vec<Vec<u8>>,
}

impl Server {
    pub fn handle(&mut self, r: &Request) -> Input {
        let ok = |body: Vec<u8>| Input::Response {
            status: 200,
            body,
            date: None,
        };
        let status = |status: u16| Input::Response {
            status,
            body: Vec::new(),
            date: None,
        };
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/v1/vault") => match self.files.last() {
                Some(f) => ok(f.clone()),
                None => status(404),
            },
            ("PUT", "/v1/vault") => {
                let current = self.files.last().map(|f| vault_core::sync::etag(f));
                let pass = match (&r.if_match, &r.if_none_match, &current) {
                    (Some(e), None, Some(c)) => e == c,
                    (None, Some(_), None) => true,
                    _ => false,
                };
                if !pass {
                    return status(412);
                }
                self.files.push(r.body.clone().unwrap());
                status(200)
            }
            ("GET", "/v1/revisions") => {
                let list: Vec<String> = self
                    .files
                    .iter()
                    .enumerate()
                    .rev()
                    .map(|(i, f)| {
                        format!(
                            r#"{{"id":{},"etag":"{}","size":{},"created":"2026-10-12T15:04:05Z","token":"phone"}}"#,
                            i + 1,
                            vault_core::sync::etag(f).replace('"', "\\\""),
                            f.len()
                        )
                    })
                    .collect();
                ok(format!(r#"{{"revisions":[{}]}}"#, list.join(",")).into_bytes())
            }
            ("GET", p) => match p
                .strip_prefix("/v1/revisions/")
                .and_then(|id| id.parse::<usize>().ok())
                .and_then(|id| self.files.get(id - 1))
            {
                Some(f) => ok(f.clone()),
                None => status(404),
            },
            _ => status(400),
        }
    }
}

/// Runs a procedure to its end, answering requests from `server` (or unreachable without one)
/// and prompts from `answers`, applying each save as it comes. Returns the last step.
pub fn run(p: &Procedure, mut server: Option<&mut Server>, mut answers: Vec<Answer>) -> Step {
    let mut step = p.start().unwrap();
    loop {
        let input = match &step {
            Step::Request { request } => match server.as_deref_mut() {
                Some(s) => s.handle(request),
                None => Input::Unreachable,
            },
            Step::Prompt { prompt } => {
                assert!(!answers.is_empty(), "unexpected prompt {prompt:?}");
                Input::Answer {
                    answer: answers.remove(0),
                }
            }
            Step::Save { .. } => {
                p.apply_save().unwrap();
                Input::Saved
            }
            Step::Done { .. } | Step::Failed { .. } => return step,
        };
        step = p.step(input).unwrap();
    }
}

pub fn password(pw: &str) -> Answer {
    Answer::Password {
        password: pw.into(),
    }
}

pub fn code<T>(r: Result<T, VaultError>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code().to_owned(),
    }
}

/// Deterministic bytes, so a test vault needs no randomness.
pub struct Counter(pub u8);

impl vault_core::rng::Rng for Counter {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}
