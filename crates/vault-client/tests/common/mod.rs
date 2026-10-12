//! Test support: an in-memory server with the spec's Server API semantics, a driver that runs a
//! machine against it with scripted answers, and vault fixtures that open without Argon2id.

#![allow(dead_code)]

use std::collections::VecDeque;
use vault_client::commit::Commit;
use vault_client::sync::{Mode, SyncReport, sync};
use vault_client::{
    Answer, ClientState, Finished, Input, Keys, Machine, Precondition, Prompt, Request, Response,
    Save, SavedKey, SecretKeyChange, SecretKeyStore, Step,
};
use vault_core::body::{Body, ItemFields, Login, TYPE_LOGIN};
use vault_core::file::{open_file, seal_file, seal_file_with_rng};
use vault_core::header::Header;
use vault_core::kdf::FLOOR;
use vault_core::rng::Rng;
use vault_core::secret::{Kek, SecretKey, VaultKey};
use vault_core::sync::{SyncState, etag};

/// A time after the build time, in ms.
pub const T0: u64 = 1_800_000_000_000;

pub const TOKEN: &str = "phone";

/// One stored revision.
#[derive(Clone)]
pub struct Rev {
    pub id: u64,
    pub file: Vec<u8>,
    pub token: String,
}

/// A request with what the server answered.
pub type Hook = Box<dyn FnMut(&mut Server, &Request) -> Option<Option<Response>>>;

/// The spec's Server API over an in-memory list of revisions. Every revision is retained.
pub struct Server {
    pub revisions: Vec<Rev>,
    pub next_id: u64,
    pub tokens: Vec<String>,
    /// The `Date` header of every response.
    pub date: Option<u64>,
    /// Runs before each request; `Some(answer)` replaces the server's own handling, and
    /// `Some(None)` makes the request fail in transport.
    pub hook: Option<Hook>,
    /// Every request handled, in order.
    pub log: Vec<Request>,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            revisions: Vec::new(),
            next_id: 1,
            tokens: vec![TOKEN.into(), "laptop".into(), "thief".into()],
            date: Some(T0),
            hook: None,
            log: Vec::new(),
        }
    }
}

impl Server {
    pub fn current(&self) -> Option<&Rev> {
        self.revisions.last()
    }

    pub fn current_file(&self) -> Vec<u8> {
        self.current().expect("a vault").file.clone()
    }

    /// Stores a file as the current revision, as a `PUT` that passed its precondition does.
    pub fn store(&mut self, file: Vec<u8>, token: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.revisions.push(Rev {
            id,
            file,
            token: token.into(),
        });
        id
    }

    pub fn response(&self, status: u16, body: Vec<u8>) -> Response {
        Response {
            status,
            body,
            date: self.date,
        }
    }

    pub fn handle(&mut self, token: &str, req: &Request) -> Option<Response> {
        self.log.push(req.clone());
        if let Some(mut hook) = self.hook.take() {
            let r = hook(self, req);
            self.hook = Some(hook);
            if let Some(answer) = r {
                return answer;
            }
        }
        if !self.tokens.iter().any(|t| t == token) {
            return Some(self.response(401, Vec::new()));
        }
        Some(match req {
            Request::GetVault => match self.current() {
                Some(r) => self.response(200, r.file.clone()),
                None => self.response(404, Vec::new()),
            },
            Request::PutVault { condition, file } => {
                let shaped = file.starts_with(b"VAULT")
                    && file.len() >= 4269
                    && (file.len() - 173) % 4096 == 0;
                if !shaped {
                    return Some(self.response(400, Vec::new()));
                }
                let ok = match (condition, self.current()) {
                    (Precondition::IfMatch(e), Some(cur)) => *e == etag(&cur.file),
                    (Precondition::IfMatch(_), None) => false,
                    (Precondition::IfNoneMatch, cur) => cur.is_none(),
                };
                if !ok {
                    return Some(self.response(412, Vec::new()));
                }
                self.store(file.clone(), token);
                self.response(200, Vec::new())
            }
            Request::ListRevisions => {
                let items: Vec<String> = self
                    .revisions
                    .iter()
                    .rev()
                    .map(|r| {
                        format!(
                            r#"{{"id":{},"etag":{},"size":{},"created":"2026-10-12T15:04:05Z","token":"{}","extra":[1]}}"#,
                            r.id,
                            serde_quote(&etag(&r.file)),
                            r.file.len(),
                            r.token
                        )
                    })
                    .collect();
                self.response(
                    200,
                    format!(r#"{{"revisions":[{}]}}"#, items.join(",")).into_bytes(),
                )
            }
            Request::GetRevision(id) => match self.revisions.iter().find(|r| r.id == *id) {
                Some(r) => self.response(200, r.file.clone()),
                None => self.response(404, Vec::new()),
            },
        })
    }
}

fn serde_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\\\""))
}

/// Deterministic bytes from a seed (splitmix64).
pub struct TestRng(pub u64);

impl Rng for TestRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *b = (z ^ (z >> 31)) as u8;
        }
        Ok(())
    }
}

/// Serves queued bytes, then panics, so a miscounted draw fails loudly.
pub struct Fixed(pub VecDeque<u8>);

impl Fixed {
    pub fn new(draws: &[Vec<u8>]) -> Fixed {
        Fixed(draws.iter().flatten().copied().collect())
    }
}

impl Rng for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            *b = self.0.pop_front().expect("no more scripted random bytes");
        }
        Ok(())
    }
}

/// What a run of a machine produced.
pub struct Run<T> {
    pub finished: Finished<T>,
    pub prompts: Vec<Prompt>,
    pub saves: Vec<Save>,
    pub requests: Vec<Request>,
}

impl<T> Run<T> {
    pub fn ok(&self) -> &T {
        match &self.finished.result {
            Ok(t) => t,
            Err(e) => panic!("procedure failed: {e:?} ({e})"),
        }
    }

    pub fn err(&self) -> vault_client::ClientError {
        match &self.finished.result {
            Ok(_) => panic!("procedure succeeded"),
            Err(e) => *e,
        }
    }

    pub fn state(&self) -> &ClientState {
        self.finished.state.as_ref().expect("a state to commit")
    }

    pub fn puts(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| matches!(r, Request::PutVault { .. }))
            .count()
    }
}

/// Runs `machine` against `server` with `token`, answering prompts from `answers` in order. A
/// prompt with no answer left panics. Saves are acknowledged and kept.
pub fn drive<T: 'static>(
    machine: Machine<T>,
    server: &mut Server,
    token: &str,
    now: u64,
    answers: Vec<Answer>,
) -> Run<T> {
    drive_with(machine, server, token, now, answers, &mut |_| {})
}

/// [`drive`], calling `on_save` for each save before acknowledging it.
pub fn drive_with<T: 'static>(
    mut machine: Machine<T>,
    server: &mut Server,
    token: &str,
    now: u64,
    answers: Vec<Answer>,
    on_save: &mut dyn FnMut(&Save),
) -> Run<T> {
    let mut answers: VecDeque<Answer> = answers.into();
    let (mut prompts, mut saves, mut requests) = (Vec::new(), Vec::new(), Vec::new());
    let mut step = machine.start(now);
    loop {
        step = match step {
            Step::Request(r) => {
                requests.push(r.clone());
                let input = match server.handle(token, &r) {
                    Some(resp) => Input::Response(resp),
                    None => Input::Unreachable,
                };
                machine.step(input, now)
            }
            Step::Prompt(p) => {
                prompts.push(p);
                let a = answers
                    .pop_front()
                    .unwrap_or_else(|| panic!("no answer scripted for {p:?}"));
                machine.step(Input::Answer(a), now)
            }
            Step::Save(s) => {
                on_save(&s);
                saves.push(s);
                machine.step(Input::Saved, now)
            }
            Step::Done(finished) => {
                assert!(
                    answers.is_empty(),
                    "{} scripted answers left unused",
                    answers.len()
                );
                return Run {
                    finished,
                    prompts,
                    saves,
                    requests,
                };
            }
        }
    }
}

pub fn pw(s: &str) -> Answer {
    Answer::Password(zeroize::Zeroizing::new(s.to_owned()))
}

/// A vault whose wrap opens under a fixed KEK, so tests that hold the vault key never run
/// Argon2id.
pub struct Fixture {
    pub vault_id: [u8; 16],
    pub header: Header,
    pub vk: [u8; 32],
}

impl Fixture {
    pub fn new(seed: u8) -> Fixture {
        Fixture::with_wrap(seed, [seed; 16], [seed.wrapping_add(1); 24], [seed; 32])
    }

    pub fn with_wrap(seed: u8, vault_id: [u8; 16], wrap: [u8; 24], vk: [u8; 32]) -> Fixture {
        let header = Header::wrap(
            false,
            vault_id,
            1,
            FLOOR,
            [seed; 16],
            wrap,
            &Kek::from_bytes([seed.wrapping_add(2); 32]),
            &VaultKey::from_bytes(vk),
        );
        Fixture {
            vault_id,
            header,
            vk,
        }
    }

    pub fn key(&self) -> VaultKey {
        VaultKey::from_bytes(self.vk)
    }

    pub fn file(&self, generation: u64, body: &Body, nonce: u8) -> Vec<u8> {
        seal_file(
            &self.header.with_generation(generation),
            &self.key(),
            &[nonce; 24],
            body,
        )
        .unwrap()
    }

    /// The state of a client whose local file is `file`, with nothing accepted yet.
    pub fn state(&self, file: Vec<u8>) -> ClientState {
        ClientState::new(
            SyncState {
                vault_id: self.vault_id,
                accepted: None,
                wrap_nonce: self.header.wrap_nonce,
                retired_wrap_nonces: Vec::new(),
            },
            file,
            SecretKeyStore::Keyring,
        )
    }
}

pub fn login(name: &str, password: &str) -> ItemFields {
    ItemFields {
        name: name.into(),
        folder: String::new(),
        favourite: false,
        notes: String::new(),
        fields: Vec::new(),
        password_history: Vec::new(),
        created: 0,
        login: Some(Login {
            username: "u".into(),
            password: password.into(),
            uris: Vec::new(),
            apps: Vec::new(),
            totp: None,
            passkeys: Vec::new(),
            extra: Default::default(),
        }),
        origin: None,
        extra: Default::default(),
    }
}

/// A client: its state on disk, its cached vault key, and its device ID.
pub struct Client {
    pub state: ClientState,
    pub vk: Option<VaultKey>,
    pub sk: Option<SecretKey>,
    pub pending: Option<SecretKey>,
    pub device: [u8; 16],
    pub token: String,
    pub rng: u64,
}

impl Client {
    pub fn new(state: ClientState, vk: VaultKey, device: u8) -> Client {
        Client {
            state,
            vk: Some(vk),
            sk: None,
            pending: None,
            device: [device; 16],
            token: TOKEN.into(),
            rng: device as u64 * 1000,
        }
    }

    pub fn keys(&self) -> Keys {
        Keys {
            vault_key: self.vk.as_ref().map(VaultKey::clone_secret),
            secret_key: self.sk.as_ref().map(SecretKey::clone_secret),
            pending_secret_key: self.pending.as_ref().map(SecretKey::clone_secret),
        }
    }

    pub fn rng(&mut self) -> TestRng {
        self.rng += 1;
        TestRng(self.rng)
    }

    pub fn body(&self) -> Body {
        open_file(&self.state.file, self.vk.as_ref().expect("unlocked"))
            .unwrap()
            .1
    }

    /// A local edit: changes the body and re-seals it under the local header.
    pub fn edit(&mut self, f: impl FnOnce(&mut Body, &mut TestRng, &[u8; 16])) {
        let vk = self.vk.as_ref().expect("unlocked").clone_secret();
        let (header, mut body) = open_file(&self.state.file, &vk).unwrap();
        let mut rng = self.rng();
        f(&mut body, &mut rng, &self.device);
        self.state.file = seal_file_with_rng(&mut rng, &header, &vk, &body).unwrap();
    }

    /// Commits a finished procedure that started from `started`, as the CLI does under its
    /// lock, and applies its key changes.
    pub fn commit<T>(&mut self, started: &ClientState, finished: &Finished<T>, now: u64) -> Commit {
        self.commit_as(started, finished, false, now)
    }

    /// [`Client::commit`] for a background or an interactive caller.
    pub fn commit_as<T>(
        &mut self,
        started: &ClientState,
        finished: &Finished<T>,
        background: bool,
        now: u64,
    ) -> Commit {
        let mut rng = self.rng();
        let c = finished
            .commit(started, &self.state, background, now, &mut rng)
            .expect("commit");
        if let Some(s) = &c.state {
            self.state = s.clone();
        }
        if let Some(vk) = &finished.vault_key {
            self.vk = Some(vk.clone_secret());
        }
        match &finished.secret_key {
            Some(SecretKeyChange::Replace(sk)) => self.sk = Some(sk.clone_secret()),
            Some(SecretKeyChange::PromotePending) => self.sk = self.pending.take(),
            Some(SecretKeyChange::DiscardPending) => self.pending = None,
            Some(SecretKeyChange::ReplaceAndDiscardPending(sk)) => {
                self.sk = Some(sk.clone_secret());
                self.pending = None;
            }
            None => {}
        }
        c
    }

    /// Runs a procedure to the end, committing its saves and its end as the CLI does.
    pub fn run<T: 'static>(
        &mut self,
        make: impl FnOnce(ClientState, Keys, TestRng) -> Machine<T>,
        server: &mut Server,
        now: u64,
        answers: Vec<Answer>,
    ) -> Run<T> {
        let mut started = self.state.clone();
        let m = make(started.clone(), self.keys(), self.rng());
        let token = self.token.clone();
        let mut rng = self.rng();
        let run = drive_with(m, server, &token, now, answers, &mut |s: &Save| {
            let c = s
                .commit(&started, &self.state, now, &mut rng)
                .expect("save");
            if let Some(st) = c.state {
                self.state = st;
            }
            match &s.secret_key {
                SavedKey::Current(k) => self.sk = Some(k.clone_secret()),
                SavedKey::Pending(k) => self.pending = Some(k.clone_secret()),
            }
            started = s.state.clone();
        });
        self.commit(&started, &run.finished, now);
        run
    }

    /// Runs a sync to the end and commits it.
    pub fn sync(
        &mut self,
        server: &mut Server,
        mode: Mode,
        now: u64,
        answers: Vec<Answer>,
    ) -> Run<SyncReport> {
        let started = self.state.clone();
        let m = sync(started.clone(), self.keys(), mode, self.rng());
        let token = self.token.clone();
        let run = drive(m, server, &token, now, answers);
        self.commit_as(&started, &run.finished, mode == Mode::Background, now);
        run
    }
}

pub fn background() -> Mode {
    Mode::Background
}

pub fn interactive() -> Mode {
    Mode::Interactive { ask_again: false }
}

pub fn add_login(
    body: &mut Body,
    rng: &mut TestRng,
    device: &[u8; 16],
    name: &str,
    pw: &str,
    now: u64,
) -> String {
    vault_core::edit::add_item(body, rng, TYPE_LOGIN, login(name, pw), now, device).unwrap()
}

/// The cases of a file in `spec/vectors/`.
pub fn cases(name: &str) -> Vec<serde_json::Value> {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["cases"].as_array().unwrap().clone()
}

pub fn case<'a>(cases: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    cases
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

pub fn hex_of(c: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(
        c[k].as_str()
            .unwrap_or_else(|| panic!("{k} in {}", c["name"])),
    )
    .unwrap()
}

pub fn arr<const N: usize>(c: &serde_json::Value, k: &str) -> [u8; N] {
    hex_of(c, k).try_into().unwrap()
}

/// A client state from a vector's `state`, with `file` as the local file.
pub fn vector_state(v: &serde_json::Value, file: Vec<u8>) -> ClientState {
    let accepted = (!v["accepted"].is_null()).then(|| vault_core::sync::Accepted {
        generation: v["accepted"]["generation"].as_u64().unwrap(),
        file_hash: arr(&v["accepted"], "file_hash"),
    });
    let mut s = ClientState::new(
        SyncState {
            vault_id: arr(v, "vault_id"),
            accepted,
            wrap_nonce: arr(v, "wrap_nonce"),
            retired_wrap_nonces: Vec::new(),
        },
        file,
        SecretKeyStore::Keyring,
    );
    for n in v["retired_wrap_nonces"].as_array().unwrap() {
        s.retired.push(vault_client::Retired {
            nonce: hex::decode(n.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            revision: Some(0),
        });
    }
    s
}
