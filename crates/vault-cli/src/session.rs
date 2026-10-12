//! What every client command shares: the command context, the driver loop for the vault-client
//! machines, the commit rule under the lock, opening the vault (from the agent or with a typed
//! master password), saving a local edit, and syncing after it.

use crate::error::{CliError, Exit, Result};
use crate::http::Transport;
use crate::output::Out;
use crate::paths::Paths;
use crate::settings::Settings;
use crate::store::{self, ServerConfig};
use crate::sys::{agent, prompt, secrets};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vault_client::commit::Commit;
use vault_client::sync::{self, Mode, SyncOutcome, SyncReport};
use vault_client::{
    Answer, ClientError, ClientState, Finished, Input, Keys, Machine, Prompt, Purpose, Request,
    Response, Save, SecretKeyChange, SecretKeyStore, Step, StopReason,
};
use vault_core::body::Body;
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::file::{open_file, seal_file_with_rng};
use vault_core::secret::{SecretKey, SecretString, VaultKey};
use vault_core::{Error, InputKind};

/// The unlock's limit on its first pull.
pub const UNLOCK_PULL_LIMIT: Duration = Duration::from_secs(5);
/// The limit on the sync after a write when no agent runs.
pub const WRITE_SYNC_LIMIT: Duration = Duration::from_secs(10);
/// How many times a prompt for a typed value is repeated after a typo.
const ATTEMPTS: u32 = 3;

/// The operating system CSPRNG.
pub struct OsRng;

impl vault_core::rng::Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        getrandom::getrandom(dest).map_err(|_| Error::Rng)
    }
}

/// The clock in ms.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The context of one client command.
pub struct Ctx {
    /// The directories.
    pub paths: Paths,
    /// `config.toml`.
    pub settings: Settings,
    /// Output streams and `--json`.
    pub out: Out,
    /// `--offline`.
    pub offline: bool,
    /// The number of items flagged for review, once a command opened the vault.
    pub review: std::cell::Cell<Option<usize>>,
}

impl Ctx {
    /// Whether this command uses the agent.
    pub fn use_agent(&self) -> bool {
        self.settings.use_agent(&self.paths)
    }

    /// A transport to the server in `server.json`, or `None` with `--offline` or without a
    /// server.
    pub fn transport(&self) -> Result<Option<Transport>> {
        if self.offline {
            return Ok(None);
        }
        match store::read_server(&self.paths)? {
            None => Ok(None),
            Some(s) => transport(&s).map(Some),
        }
    }

    /// A transport to the server, failing with `--offline` or without a server.
    pub fn require_transport(&self) -> Result<Transport> {
        if self.offline {
            return Err(CliError::usage(
                "this command needs the server; drop --offline",
            ));
        }
        transport(&store::require_server(&self.paths)?)
    }
}

/// A transport for `server`.
pub fn transport(server: &ServerConfig) -> Result<Transport> {
    Transport::new(server).map_err(|_| {
        CliError::other(
            "input.server_url",
            "the server URL is not https, or http to localhost, 127.0.0.1, or [::1]",
        )
    })
}

/// Converts a procedure's error, adding the transport's reason to `server.unreachable`, and the
/// repair to an integrity error, which stops sync.
pub fn client_error(e: ClientError, transport: Option<&Transport>) -> CliError {
    match (e, transport.and_then(|t| t.last_error.as_deref())) {
        (ClientError::Unreachable, Some(why)) => CliError::new(
            Exit::Server,
            e.code(),
            format!("the server is unreachable: {why}"),
        ),
        (ClientError::Core(Error::Integrity(k)), _) => CliError::new(
            Exit::Integrity,
            k.code(),
            format!("{e}; sync is stopped until `vault sync --recover`"),
        ),
        _ => e.into(),
    }
}

/// Runs a machine to its end. `send` answers requests (`None` for a transport failure),
/// `prompt` answers prompts, and `save` carries out a save. An error from `prompt` or `save`
/// drops the machine and is returned.
pub fn drive<T: 'static>(
    mut machine: Machine<T>,
    send: &mut dyn FnMut(&Request) -> Option<Response>,
    prompt: &mut dyn FnMut(Prompt) -> Result<Answer>,
    save: &mut dyn FnMut(Save) -> Result<()>,
) -> Result<Finished<T>> {
    let mut step = machine.start(now_ms());
    loop {
        step = match step {
            Step::Request(r) => {
                let input = match send(&r) {
                    Some(resp) => Input::Response(resp),
                    None => Input::Unreachable,
                };
                machine.step(input, now_ms())
            }
            Step::Prompt(p) => {
                let a = prompt(p)?;
                machine.step(Input::Answer(a), now_ms())
            }
            Step::Save(s) => {
                save(s)?;
                machine.step(Input::Saved, now_ms())
            }
            Step::Done(f) => return Ok(f),
        };
    }
}

/// A sender over an optional transport; without one every request is unreachable.
pub fn sender(t: &mut Option<Transport>) -> impl FnMut(&Request) -> Option<Response> + '_ {
    move |r| t.as_mut().and_then(|t| t.send(r))
}

/// A save handler for procedures that never save.
pub fn no_save(_: Save) -> Result<()> {
    Err(ClientError::UnexpectedInput.into())
}

/// Answers the prompts of a background procedure: it never asks.
pub fn decline(_: Prompt) -> Result<Answer> {
    Ok(Answer::Declined)
}

/// Commits the end of a procedure that started from `started` under the lock, and applies its
/// secret key change. A `background` commit records items its merge drops in `dropped`; an
/// interactive caller shows [`Commit::expired`] instead.
///
/// When another sync committed first, nothing is written and the caller reports the
/// procedure's own result; `out`, when given, warns that this run's outcome was not saved.
pub fn commit<T>(
    paths: &Paths,
    started: &ClientState,
    f: &Finished<T>,
    background: bool,
    out: Option<&Out>,
) -> Result<Commit> {
    let lock = store::lock(paths)?;
    let on_disk = store::require_state(paths)?;
    let c = match f.commit(started, &on_disk, background, now_ms(), &mut OsRng) {
        Err(ClientError::Superseded) => {
            if let (Some(out), true) = (out, f.result.is_ok()) {
                out.warn("another sync finished first; it already holds the vault's state");
            }
            return Ok(Commit {
                state: None,
                merged_local_changes: false,
                expired: Vec::new(),
            });
        }
        r => r?,
    };
    let target = c.state.as_ref().unwrap_or(&on_disk);
    let (kind, id) = (target.secret_key_store, target.vault_id);
    // A new or promoted key goes in before the state that needs it; a discarded one after.
    let discard = match &f.secret_key {
        None => false,
        Some(SecretKeyChange::Replace(sk)) => {
            secrets::store(paths, kind, &id, secrets::Slot::Current, sk)?;
            false
        }
        Some(SecretKeyChange::ReplaceAndDiscardPending(sk)) => {
            secrets::store(paths, kind, &id, secrets::Slot::Current, sk)?;
            true
        }
        Some(SecretKeyChange::PromotePending) => {
            secrets::promote_pending(paths, kind, &id)?;
            false
        }
        Some(SecretKeyChange::DiscardPending) => true,
    };
    if let Some(s) = &c.state {
        store::write_state(paths, &lock, s)?;
    }
    if discard {
        secrets::remove(paths, kind, &id, secrets::Slot::Pending)?;
    }
    Ok(c)
}

/// The secret keys stored for `state`.
pub fn load_keys(paths: &Paths, state: &ClientState) -> Result<Keys> {
    let current = secrets::load(
        paths,
        state.secret_key_store,
        &state.vault_id,
        secrets::Slot::Current,
    )?;
    let pending = if state.pending_secret_key {
        secrets::load(
            paths,
            state.secret_key_store,
            &state.vault_id,
            secrets::Slot::Pending,
        )?
    } else {
        None
    };
    Ok(Keys {
        vault_key: None,
        secret_key: current,
        pending_secret_key: pending,
    })
}

/// Reads and decodes a secret key text form, asking again after a typo.
pub fn read_secret_key(label: &str) -> Result<Option<SecretKey>> {
    for _ in 0..ATTEMPTS {
        let text = prompt::hidden_line(label)?;
        if text.trim().is_empty() {
            return Ok(None);
        }
        match vault_core::secret_key_text::decode(&text) {
            Ok(sk) => return Ok(Some(sk)),
            Err(Error::SecretKeyTypo) => {
                prompt::say("The secret key has a typo; check it against the emergency kit.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::SecretKeyTypo.into())
}

/// Reads a new master password, twice on a terminal, until both entries match.
pub fn read_new_password(label: &str) -> Result<SecretString> {
    loop {
        let pw = prompt::password(label)?;
        if prompt::password_from_fd() {
            return Ok(pw);
        }
        let again = prompt::password("Repeat the new master password: ")?;
        if *pw == *again {
            return Ok(pw);
        }
        prompt::say("The two entries differ.");
    }
}

/// Why a new master password was refused.
fn rejection(e: &vault_core::Error) -> &'static str {
    match e {
        Error::InvalidInput(InputKind::PasswordTooShort) => {
            "The master password needs at least 12 characters."
        }
        Error::InvalidInput(InputKind::PasswordTooLong) => {
            "The master password may have at most 4,096 bytes."
        }
        Error::InvalidInput(InputKind::PasswordUnassigned) => {
            "The master password contains a character unassigned in this client's Unicode tables."
        }
        _ => "The master password was refused.",
    }
}

/// Answers a procedure's prompt on the terminal, or from `--password-fd` and standard input.
pub fn ask(p: Prompt) -> Result<Answer> {
    Ok(match p {
        Prompt::MasterPassword { purpose, failed } => {
            if failed > 0 {
                prompt::say("Wrong master password.");
            }
            let label = match purpose {
                Purpose::Unlock | Purpose::PendingSecretKey => "Master password: ",
                Purpose::CredentialsChanged => {
                    if failed == 0 {
                        prompt::say("The credentials changed on another device.");
                    }
                    "Current master password: "
                }
                Purpose::Recovery => {
                    if failed == 0 {
                        prompt::say("The server holds revisions under other credentials.");
                    }
                    "Master password for those revisions: "
                }
                Purpose::Revision => "Master password of that revision: ",
            };
            Answer::Password(prompt::password(label)?)
        }
        Prompt::MasterPasswordAndSecretKey { purpose } => {
            let _ = purpose;
            prompt::say(
                "The stored secret key does not open it. Enter the master password and the \
                 secret key from the newer emergency kit.",
            );
            let pw = prompt::password("Master password: ")?;
            match read_secret_key("Secret key (empty to give up): ")? {
                Some(sk) => Answer::PasswordAndSecretKey(pw, sk),
                None => Answer::Declined,
            }
        }
        Prompt::OldMasterPassword { failed } => {
            if failed > 0 {
                prompt::say("Wrong master password.");
            }
            prompt::say("Local changes were made under the old credentials.");
            let pw = prompt::password("Old master password (empty if unknown): ")?;
            if pw.is_empty() {
                Answer::Declined
            } else {
                Answer::Password(pw)
            }
        }
        Prompt::NewMasterPassword { rejected } => {
            if let Some(e) = rejected {
                prompt::say(rejection(&e));
            }
            Answer::Password(read_new_password("New master password: ")?)
        }
        Prompt::SecretKey => match read_secret_key("Secret key: ")? {
            Some(sk) => Answer::SecretKey(sk),
            None => Answer::Declined,
        },
        Prompt::KitVaultId => {
            for _ in 0..ATTEMPTS {
                let text = prompt::line("Vault ID from the emergency kit (empty to skip): ")?;
                let text = text.trim().to_ascii_lowercase();
                if text.is_empty() {
                    return Ok(Answer::VaultId(None));
                }
                let mut id = [0u8; 16];
                if text.len() == 32 && hex::decode_to_slice(&text, &mut id).is_ok() {
                    return Ok(Answer::VaultId(Some(id)));
                }
                prompt::say("A vault ID is 32 hex characters.");
            }
            return Err(CliError::usage("no valid vault ID given"));
        }
        Prompt::Confirm(c) => {
            prompt::say(c.description());
            Answer::Confirmed(prompt::confirm("Continue?")?)
        }
    })
}

/// The open vault of a command.
pub struct Session {
    /// The state read when the vault was opened.
    pub state: ClientState,
    /// The vault key of the local file.
    pub vault_key: VaultKey,
    /// The local body.
    pub body: Body,
    /// Whether an agent holds the key, so a write asks it to sync.
    pub agent: bool,
}

/// Opens the local vault: with the agent's key when an agent runs, and otherwise with a typed
/// master password, after a pull (see [`unlock`]). Starts the agent after a typed unlock when
/// agents are in use.
pub fn open(ctx: &Ctx) -> Result<Session> {
    let state = store::require_state(&ctx.paths)?;
    take_dropped(ctx)?;
    if ctx.use_agent()
        && let Some((id, vk)) = agent_key_or_none(ctx)
    {
        if id == state.vault_id
            && let Ok((_, body)) = open_file(&state.file, &vk)
        {
            ctx.review.set(Some(review_count(&body)));
            return Ok(Session {
                state,
                vault_key: vk,
                body,
                agent: true,
            });
        }
        // The key no longer opens the local file: end the agent and ask.
        let _ = agent::lock(&ctx.paths);
    }
    let vk = unlock(ctx, &state)?;
    let state = store::require_state(&ctx.paths)?;
    let (_, body) = open_file(&state.file, &vk)?;
    ctx.review.set(Some(review_count(&body)));
    let mut agent = false;
    if ctx.use_agent() {
        match agent::start(&ctx.paths, &ctx.settings, &state.vault_id, &vk) {
            Ok(()) => agent = true,
            Err(e) => ctx.out.warn(&format!("the agent did not start: {e}")),
        }
    }
    Ok(Session {
        state,
        vault_key: vk,
        body,
        agent,
    })
}

/// The running agent's vault ID and key. An agent that refuses, such as one that is ending
/// after `vault lock`, counts as none, so the command asks for the master password instead.
fn agent_key_or_none(ctx: &Ctx) -> Option<([u8; 16], VaultKey)> {
    match agent::get_key(&ctx.paths) {
        Ok(k) => k,
        Err(e) if e.code() == "agent.refused" => None,
        Err(e) => {
            ctx.out
                .warn(&format!("{e}; asking for the master password instead"));
            None
        }
    }
}

/// An unlock with a typed master password. Online, it pulls first with a 5 s limit and syncs
/// (vault-client `unlock`); offline, or when the server does not answer, it opens the local file.
pub fn unlock(ctx: &Ctx, state: &ClientState) -> Result<VaultKey> {
    let keys = load_keys(&ctx.paths, state)?;
    let Some(sk) = keys.secret_key.as_ref().map(SecretKey::clone_secret) else {
        return Err(missing_secret_key());
    };
    let mut transport = ctx.transport()?;
    if transport.is_none() {
        for failed in 0..ATTEMPTS {
            if failed > 0 {
                prompt::say("Wrong master password.");
            }
            let pw = prompt::password("Master password: ")?;
            match vault_core::file::unlock(&state.file, &pw, &sk) {
                Ok(u) => return Ok(u.vault_key),
                Err(Error::WrongCredentials) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        return Err(Error::WrongCredentials.into());
    }
    if let Some(t) = transport.as_mut() {
        t.set_deadline(Some(Instant::now() + UNLOCK_PULL_LIMIT));
    }
    let machine = vault_client::unlock::unlock(state.clone(), keys, OsRng);
    let mut first = true;
    let mut send = |r: &Request| {
        let t = transport.as_mut()?;
        let resp = t.send(r);
        if first {
            first = false;
            t.set_deadline(None);
        }
        resp
    };
    let f = drive(machine, &mut send, &mut ask, &mut no_save)?;
    let c = commit(&ctx.paths, state, &f, false, Some(&ctx.out))?;
    report_expired(ctx, &c.expired);
    let vault_key = f.vault_key;
    match f.result {
        Ok(report) => {
            match report.sync {
                Ok(r) => report_sync_extras(ctx, &r),
                Err(ClientError::Unreachable) => ctx.out.warn(&format!(
                    "{}; using the local file",
                    client_error(ClientError::Unreachable, transport.as_ref())
                )),
                Err(e) => ctx.out.warn(&format!("sync failed: {}", CliError::from(e))),
            }
            vault_key.ok_or_else(|| ClientError::Locked.into())
        }
        Err(e) => Err(client_error(e, transport.as_ref())),
    }
}

/// The error for a secret key missing from its store.
pub fn missing_secret_key() -> CliError {
    CliError::new(
        Exit::Auth,
        "auth.no_secret_key",
        "the secret key is missing from its store; run `vault setup` again",
    )
}

/// Prints what a sync settled besides its outcome: a credential change taken over and a pending
/// secret key.
pub fn report_sync_extras(ctx: &Ctx, r: &SyncReport) {
    report_expired(ctx, &r.expired);
    if r.credentials_changed {
        ctx.out
            .err("Took over the credential change made on another device.");
    }
    report_pending(ctx, r.pending_secret_key);
}

/// Reports how a pending secret key was settled.
pub fn report_pending(ctx: &Ctx, p: Option<vault_core::credentials::PendingKeyOutcome>) {
    use vault_core::credentials::PendingKeyOutcome as P;
    match p {
        Some(P::Landed) => ctx.out.err("The new secret key is now in use."),
        Some(P::NotLanded) => ctx.out.warn(
            "the earlier `vault passwd --new-secret-key` did not reach the server; the \
             emergency kit it printed is void; run it again",
        ),
        None => {}
    }
}

/// Lists items a merge dropped because they predate the purge horizon.
pub fn report_expired(ctx: &Ctx, names: &[String]) {
    if !names.is_empty() {
        ctx.out.warn(&format!(
            "dropped local items older than the server's purge horizon: {}",
            names.join(", ")
        ));
    }
}

/// Prints and clears the items a background sync dropped, as the first interactive command
/// after it does.
fn take_dropped(ctx: &Ctx) -> Result<()> {
    let Some(state) = store::read_state(&ctx.paths)? else {
        return Ok(());
    };
    if state.dropped.is_empty() {
        return Ok(());
    }
    let lock = store::lock(&ctx.paths)?;
    let mut s = store::require_state(&ctx.paths)?;
    report_expired(ctx, &s.dropped);
    s.dropped.clear();
    store::write_state(&ctx.paths, &lock, &s)
}

/// Applies a local edit to the vault under the lock: reads the state, opens its file with the
/// session's key, runs `edit` on the body with the time and the device ID, seals the result
/// under the same header, and writes it. Returns `edit`'s value, and whether the body changed.
pub fn write<R>(
    ctx: &Ctx,
    session: &Session,
    edit: impl FnOnce(&mut Body, u64, &[u8; 16]) -> Result<R>,
) -> Result<(R, bool)> {
    let now = now_ms();
    check_clock(now, BUILD_TIME_MS, None)?;
    let device_id = store::read_device_id(&ctx.paths)?;
    let lock = store::lock(&ctx.paths)?;
    let mut state = store::require_state(&ctx.paths)?;
    let (header, mut body) = open_file(&state.file, &session.vault_key)?;
    let before = body.clone();
    let r = edit(&mut body, now, &device_id)?;
    if body == before {
        return Ok((r, false));
    }
    state.file = seal_file_with_rng(&mut OsRng, &header, &session.vault_key, &body)?;
    store::write_state(&ctx.paths, &lock, &state)?;
    Ok((r, true))
}

/// After a write: asks the agent to sync, or without an agent syncs with a 10 s limit. Returns
/// whether the change reached the server. A failed sync prints a warning; the change stays local.
pub fn sync_after_write(ctx: &Ctx, session: &Session) -> bool {
    if ctx.offline || !ctx.settings.sync_auto {
        return false;
    }
    if session.agent {
        match agent::request_sync(&ctx.paths) {
            Ok(true) => return false,
            Ok(false) => {}
            Err(e) => ctx
                .out
                .warn(&format!("the agent did not take the sync: {e}")),
        }
    }
    match quiet_sync(
        &ctx.paths,
        &session.vault_key,
        Some(Instant::now() + WRITE_SYNC_LIMIT),
        &|| false,
    ) {
        Ok(_) => true,
        Err(e) => {
            ctx.out.warn(&format!(
                "the change is saved on this device; sync failed: {e}"
            ));
            false
        }
    }
}

/// A sync that never prompts, with the vault key: the agent's sync, and the sync after a write.
/// Anything that needs a prompt records `stopped`; dropped items are recorded in `dropped`.
///
/// `cancelled` is checked before each request; once it returns true the sync stops at once,
/// commits nothing, and fails with `sync.cancelled`.
pub fn quiet_sync(
    paths: &Paths,
    vault_key: &VaultKey,
    deadline: Option<Instant>,
    cancelled: &dyn Fn() -> bool,
) -> Result<SyncReport> {
    let state = store::require_state(paths)?;
    let server = store::read_server(paths)?
        .ok_or_else(|| CliError::other("state.no_server", "no server is configured"))?;
    let mut t = Some(transport(&server)?);
    if let Some(t) = t.as_mut() {
        t.set_deadline(deadline);
    }
    let keys = Keys {
        vault_key: Some(vault_key.clone_secret()),
        ..Keys::default()
    };
    let machine = sync::sync(state.clone(), keys, Mode::Background, OsRng);
    let mut send = |r: &Request| {
        if cancelled() {
            return None;
        }
        t.as_mut().and_then(|t| t.send(r))
    };
    let f = drive(machine, &mut send, &mut decline, &mut no_save)?;
    if cancelled() {
        return Err(CliError::other("sync.cancelled", "the agent is ending"));
    }
    commit(paths, &state, &f, true, None)?;
    f.result.map_err(|e| client_error(e, t.as_ref()))
}

/// The sync the agent runs every `sync.interval` and after a command reports a write. It never
/// prompts, resolves its paths from the environment, and commits under the lock. It blocks: it
/// runs requests on a runtime of its own, so the caller runs it outside any async runtime.
/// `Err(None)` means the key does not open the local file, or belongs to another vault, so the
/// agent ends.
pub fn background_sync(
    vault_id: &[u8; 16],
    vault_key: &VaultKey,
) -> std::result::Result<(), Option<CliError>> {
    let paths = Paths::from_env().map_err(Some)?;
    if !paths.check_data().map_err(Some)? {
        return Err(None);
    }
    let state = store::read_state(&paths).map_err(Some)?.ok_or(None)?;
    if state.vault_id != *vault_id || open_file(&state.file, vault_key).is_err() {
        return Err(None);
    }
    quiet_sync(&paths, vault_key, None, &crate::agent::sync_cancelled)
        .map(|_| ())
        .map_err(Some)
}

/// The outcome word of a sync, as the JSON output spells it.
pub fn outcome_name(o: SyncOutcome) -> &'static str {
    match o {
        SyncOutcome::UpToDate => "up_to_date",
        SyncOutcome::Adopted => "adopted",
        SyncOutcome::Pushed => "pushed",
    }
}

/// The repair for a stopped sync.
pub fn repair_hint(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Integrity => "vault sync --recover",
        StopReason::Token => "vault setup",
        StopReason::Credentials => "vault sync",
    }
}

/// Prints at most one status line on a terminal's standard error after a command's output, in
/// order of priority: dropped items, sync stopped, unpushed changes older than an hour, and
/// items flagged for review (known once the command opened the vault).
pub fn status_line(ctx: &Ctx) {
    if !ctx.out.stderr_tty {
        return;
    }
    let Ok(Some(state)) = store::read_state(&ctx.paths) else {
        return;
    };
    let line = if !state.dropped.is_empty() {
        Some(format!(
            "Dropped items older than the purge horizon: {}",
            state.dropped.join(", ")
        ))
    } else if let Some(s) = &state.stopped {
        Some(format!(
            "Sync is stopped ({}); run `{}`.",
            s.code,
            repair_hint(s.reason)
        ))
    } else if state.unpushed()
        && state
            .last_sync
            .is_none_or(|t| now_ms().saturating_sub(t) > 3_600_000)
    {
        Some("Changes on this device have not reached the server for over an hour.".to_owned())
    } else {
        ctx.review
            .get()
            .filter(|&n| n > 0)
            .map(|n| format!("{n} item(s) flagged for review; see `vault ls --review`."))
    };
    if let Some(l) = line {
        ctx.out.err(&l);
    }
}

/// Items a merge flagged.
pub fn review_count(body: &Body) -> usize {
    body.items.iter().filter(|i| i.review.is_some()).count()
}

/// The secret key store `vault init` and `vault setup` choose, with a warning for the file.
pub fn choose_store(ctx: &Ctx) -> SecretKeyStore {
    let s = secrets::choose_store(ctx.settings.keyring);
    if s == SecretKeyStore::File {
        ctx.out.warn(&format!(
            "the secret key is stored in {}, readable only by this user",
            ctx.paths.secret_key().display()
        ));
    }
    s
}

/// Turns an error a procedure returned into the command's error, with the transport's reason.
pub fn finish<T>(r: std::result::Result<T, ClientError>, t: Option<&Transport>) -> Result<T> {
    r.map_err(|e| client_error(e, t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_client::SecretKeyStore;
    use vault_core::sync::Accepted;

    fn state(generation: u64) -> ClientState {
        ClientState {
            vault_id: [1; 16],
            accepted: Some(Accepted {
                generation,
                file_hash: [2; 32],
            }),
            wrap_nonce: [3; 24],
            retired: Vec::new(),
            refused: Vec::new(),
            secret_key_store: SecretKeyStore::File,
            pending_secret_key: false,
            stopped: None,
            dropped: Vec::new(),
            last_sync: None,
            file: b"VAULT".to_vec(),
        }
    }

    #[test]
    fn a_superseded_commit_writes_nothing_and_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            data: dir.path().to_owned(),
            config: dir.path().join("config.toml"),
            runtime: None,
        };
        // Another sync committed generation 3 while this one ran from generation 2.
        let on_disk = state(3);
        {
            let lock = store::lock(&paths).unwrap();
            store::write_state(&paths, &lock, &on_disk).unwrap();
        }
        for result in [Ok(()), Err(ClientError::Unreachable)] {
            let f = Finished {
                result,
                state: Some(state(4)),
                vault_key: None,
                started_vault_key: None,
                secret_key: None,
            };
            let c = commit(&paths, &state(2), &f, true, None).unwrap();
            assert!(c.state.is_none());
            assert!(store::require_state(&paths).unwrap() == on_disk);
        }
    }
}
