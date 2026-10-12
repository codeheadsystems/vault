//! The agent: a detached process that holds the vault ID and vault key between commands, answers
//! the requests of `docs/cli.md` on `$XDG_RUNTIME_DIR/vault/agent.sock`, and syncs in the
//! background.
//!
//! A command starts it as `vault agent` with [`start`], which passes the key and the settings
//! through the agent's standard input. The agent ends after `agent.idle` without a `key`
//! request, `agent.max` after it started, on a `lock` request, on `SIGTERM`, `SIGINT`, or
//! `SIGHUP`, when its socket is removed or replaced, or when a background sync reports that the
//! key does not open the local file.
//!
//! Threads, no async runtime: an acceptor that checks each connection's peer and answers its one
//! request on a thread of its own, and the main thread, which runs the timers and the background
//! sync.

mod client;
pub mod proto;
pub mod sock;

pub use client::{get_key, lock, request_sync, start, status};
pub use proto::{AgentStatus, ErrorBody};

use crate::harden::LockedBuf;
use proto::{ErrorResponse, KeyResponse, Request};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use vault_core::secret::VaultKey;
use zeroize::Zeroizing;

/// The agent's timers and sync settings, from `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSettings {
    /// `agent.idle`.
    pub idle: Duration,
    /// `agent.max`.
    pub max: Duration,
    /// `sync.interval`.
    pub sync_interval: Duration,
    /// `sync.auto`.
    pub sync_auto: bool,
}

/// What a background sync reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResult {
    /// The sync ran: up to date, adopted, or pushed, or it set `stopped` in `local.json`.
    Done,
    /// The sync failed, such as an unreachable server; the agent reports it in `status` and
    /// tries again at the next interval.
    Failed {
        /// A stable code, as in the JSON output.
        code: String,
        /// A message without key material.
        message: String,
    },
    /// The key does not open the local file; the agent zeroes it and ends.
    KeyRejected,
}

/// The background sync: given the vault ID and key, sync without prompting.
pub type SyncFn = Box<dyn Fn(&[u8; 16], &VaultKey) -> SyncResult + Send + Sync>;

/// The delay between a `sync` request and the sync.
pub const SYNC_DELAY: Duration = Duration::from_secs(2);
/// How often the agent checks its timers, signals, and socket.
const TICK: Duration = Duration::from_millis(200);
/// How long a command waits for a new agent to report that it listens.
const START_WAIT: Duration = Duration::from_secs(5);
/// The most connections served at once.
const MAX_CONNS: usize = 16;
/// The stack size of the agent's threads.
const STACK: usize = 256 * 1024;

/// An agent failure. Messages never contain key material.
#[derive(Debug)]
pub enum AgentError {
    /// `$XDG_RUNTIME_DIR` is not set.
    NoRuntimeDir,
    /// The agent directory or socket fails its checks.
    Unsafe(sock::Unsafe),
    /// The process at the other end of the socket is another user's.
    WrongPeer,
    /// The agent answered with an error.
    Agent(ErrorBody),
    /// A message did not parse or broke the protocol.
    Protocol(&'static str),
    /// The agent could not be started.
    Start(String),
    /// The socket or a pipe failed.
    Io(std::io::Error),
}

impl AgentError {
    /// The exit code: always 1.
    pub fn exit_code(&self) -> u8 {
        1
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::NoRuntimeDir => f.write_str("the agent needs $XDG_RUNTIME_DIR"),
            AgentError::Unsafe(u) => write!(f, "the agent directory {u}"),
            AgentError::WrongPeer => f.write_str("the agent socket belongs to another user"),
            AgentError::Agent(e) => write!(f, "the agent refused: {}", e.message),
            AgentError::Protocol(what) => write!(f, "the agent connection failed: {what}"),
            AgentError::Start(why) => write!(f, "cannot start the agent: {why}"),
            AgentError::Io(e) => write!(f, "the agent connection failed: {e}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<proto::FrameError> for AgentError {
    fn from(e: proto::FrameError) -> Self {
        match e {
            proto::FrameError::TooLarge => AgentError::Protocol("a message is too large"),
            proto::FrameError::Io(e) => AgentError::Io(e),
        }
    }
}

/// A clock in ms.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// `CLOCK_BOOTTIME` in ms, for the timers: it counts suspended time, so a laptop that sleeps past
/// `agent.idle` ends the agent when it wakes, and setting the wall clock moves no timer.
pub fn boot_ms() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u64::try_from(t.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1000)
        .saturating_add(u64::try_from(t.tv_nsec / 1_000_000).unwrap_or(0))
}

/// The wall clock in ms since the Unix epoch, for the times `status` reports.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

std::thread_local! {
    /// The ending flag of the agent whose background sync runs on this thread.
    static CANCEL: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

/// Whether the agent whose background sync runs on this thread is ending. The [`SyncFn`] checks
/// it between requests and returns at once when it is set, so that its copies of the key and the
/// decrypted body go within one request's time after a `lock`. Outside a background sync it is
/// `false`.
pub fn sync_cancelled() -> bool {
    CANCEL.with(|c| {
        c.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
    })
}

/// A vault key in a locked page.
fn locked_key(bytes: &[u8]) -> Result<LockedBuf, AgentError> {
    let mut b = LockedBuf::new(32).map_err(AgentError::Io)?;
    b.copy_from_slice(bytes);
    Ok(b)
}

/// What the timers call for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    /// The agent ends.
    End,
    /// A background sync.
    Sync,
    /// Nothing yet.
    Wait,
}

/// Times are [`boot_ms`] unless named `_wall`.
struct State {
    /// The vault key in a locked page; `None` once the agent is ending.
    key: Option<LockedBuf>,
    unlocked_at: u64,
    unlocked_at_wall: u64,
    last_request: u64,
    last_attempt: u64,
    sync_requested: Option<u64>,
    last_sync_wall: Option<u64>,
    last_error: Option<ErrorBody>,
}

/// The agent's state and request handling, without sockets or processes.
struct Daemon {
    vault_id: [u8; 16],
    settings: AgentSettings,
    clock: Clock,
    wall: Clock,
    state: Mutex<State>,
    ending: Arc<AtomicBool>,
}

impl Daemon {
    fn new(
        vault_id: [u8; 16],
        key: LockedBuf,
        settings: AgentSettings,
        clock: Clock,
        wall: Clock,
    ) -> Daemon {
        let now = clock();
        let now_wall = wall();
        Daemon {
            vault_id,
            settings,
            clock,
            wall,
            state: Mutex::new(State {
                key: Some(key),
                unlocked_at: now,
                unlocked_at_wall: now_wall,
                last_request: now,
                last_attempt: now,
                sync_requested: None,
                last_sync_wall: None,
                last_error: None,
            }),
            ending: Arc::new(AtomicBool::new(false)),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

    /// Zeroes the key and marks the agent as ending.
    fn end(&self) {
        self.ending.store(true, Ordering::SeqCst);
        self.state().key = None;
    }

    /// When the agent ends without a further `key` request.
    fn locks_at(&self, s: &State) -> u64 {
        let idle = s.last_request.saturating_add(ms(self.settings.idle));
        let max = s.unlocked_at.saturating_add(ms(self.settings.max));
        idle.min(max)
    }

    fn due(&self, now: u64) -> Due {
        let s = self.state();
        if self.ending() || s.key.is_none() || now >= self.locks_at(&s) {
            return Due::End;
        }
        if !self.settings.sync_auto {
            return Due::Wait;
        }
        let requested = s.sync_requested.is_some_and(|t| now >= t);
        let periodic = now
            >= s.last_attempt
                .saturating_add(ms(self.settings.sync_interval));
        if requested || periodic {
            Due::Sync
        } else {
            Due::Wait
        }
    }

    /// Runs one background sync with a copy of the key, and records its outcome. The sync
    /// sees [`sync_cancelled`] once the agent starts ending.
    fn sync(&self, sync: &SyncFn) {
        let key = {
            let mut s = self.state();
            let Some(locked) = &s.key else { return };
            let mut bytes = Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(locked);
            s.last_attempt = (self.clock)();
            s.sync_requested = None;
            VaultKey::from_bytes(*bytes)
        };
        CANCEL.with(|c| *c.borrow_mut() = Some(Arc::clone(&self.ending)));
        let result = sync(&self.vault_id, &key);
        CANCEL.with(|c| *c.borrow_mut() = None);
        drop(key);
        if self.ending() {
            return;
        }
        match result {
            SyncResult::Done => {
                let now_wall = (self.wall)();
                let mut s = self.state();
                s.last_sync_wall = Some(now_wall);
                s.last_error = None;
            }
            SyncResult::Failed { code, message } => {
                self.state().last_error = Some(ErrorBody { code, message });
            }
            SyncResult::KeyRejected => self.end(),
        }
    }

    /// Answers one request.
    fn handle(&self, frame: &[u8]) -> Zeroizing<Vec<u8>> {
        let error = |code: &str, message: &str| ErrorResponse {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        };
        let encoded = match serde_json::from_slice::<Request>(frame) {
            Err(_) => proto::encode(&error("agent.bad_request", "malformed request")),
            Ok(r) if r.v != proto::VERSION => proto::encode(&error(
                "agent.version",
                "the agent speaks another protocol version",
            )),
            Ok(r) => match r.op.as_str() {
                "key" => match self.key_response() {
                    Some(k) => proto::encode(&k),
                    None => proto::encode(&error("agent.locked", "the agent is ending")),
                },
                "sync" => {
                    if self.settings.sync_auto {
                        let due = (self.clock)().saturating_add(ms(SYNC_DELAY));
                        let mut s = self.state();
                        s.sync_requested = Some(s.sync_requested.map_or(due, |t| t.min(due)));
                    }
                    proto::encode(&serde_json::json!({}))
                }
                "status" if self.ending() => {
                    proto::encode(&error("agent.locked", "the agent is ending"))
                }
                "status" => proto::encode(&self.status()),
                "lock" => {
                    self.end();
                    proto::encode(&serde_json::json!({}))
                }
                _ => proto::encode(&error("agent.bad_request", "unknown op")),
            },
        };
        encoded.unwrap_or_else(|_| Zeroizing::new(Vec::new()))
    }

    fn key_response(&self) -> Option<KeyResponse> {
        let now = (self.clock)();
        let mut s = self.state();
        if self.ending() {
            return None;
        }
        let key = s.key.as_ref()?;
        let mut hex_key = Zeroizing::new(String::with_capacity(64));
        for b in key.iter() {
            hex_key.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            hex_key.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
        }
        s.last_request = now;
        Some(KeyResponse {
            vault_id: hex::encode(self.vault_id),
            vault_key: hex_key,
        })
    }

    /// The status in wall clock times: the lock time is now plus what remains on the timers.
    fn status(&self) -> AgentStatus {
        let now = (self.clock)();
        let now_wall = (self.wall)();
        let s = self.state();
        AgentStatus {
            unlocked_at: s.unlocked_at_wall,
            locks_at: now_wall.saturating_add(self.locks_at(&s).saturating_sub(now)),
            last_sync: s.last_sync_wall,
            last_error: s.last_error.clone(),
        }
    }
}

/// A bound socket, the lock file that makes this agent the only one, and the socket's identity.
struct Listener {
    listener: UnixListener,
    path: PathBuf,
    id: Option<(u64, u64, i64, i64)>,
    lock: std::fs::File,
}

impl Listener {
    /// Takes the agent lock in `dir` and binds the socket with mode `0600`. `Ok(None)` means
    /// another agent holds the lock.
    fn bind(dir: &Path) -> Result<Option<Listener>, AgentError> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        sock::ensure_dir(dir, sock::uid()).map_err(AgentError::Unsafe)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(dir.join(sock::LOCK_NAME))
            .map_err(AgentError::Io)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(e)) => return Err(AgentError::Io(e)),
        }
        let path = dir.join(sock::SOCKET_NAME);
        // Holding the lock, a socket left at the path is an ended agent's.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AgentError::Io(e)),
        }
        let listener = UnixListener::bind(&path).map_err(AgentError::Io)?;
        // The directory is 0700, so nobody else reaches the socket before its mode is set.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(AgentError::Io)?;
        Ok(Some(Listener {
            id: sock::identity(&path),
            listener,
            path,
            lock,
        }))
    }

    /// Whether the socket at the path is still this one.
    fn present(&self) -> bool {
        sock::identity(&self.path) == self.id
    }

    /// Removes the socket if it is still this one, and releases the lock so that a new agent
    /// can start while this one winds down.
    fn remove(&self) {
        if self.present() {
            let _ = std::fs::remove_file(&self.path);
        }
        let _ = self.lock.unlock();
    }
}

/// Serves `daemon` on `listener` until it ends: the acceptor runs on its own thread, and the
/// timers and background sync on this one. `uid` is the only user allowed to connect;
/// `signalled` ends the agent when set.
fn serve(
    daemon: Arc<Daemon>,
    listener: Listener,
    uid: u32,
    sync: &SyncFn,
    signalled: &AtomicBool,
) -> Result<(), AgentError> {
    let listener = Arc::new(listener);
    let acceptor = {
        let daemon = Arc::clone(&daemon);
        let listener = Arc::clone(&listener);
        std::thread::Builder::new()
            .name("vault-agent-accept".into())
            .stack_size(STACK)
            .spawn(move || accept_loop(&daemon, &listener, uid))
            .map_err(AgentError::Io)?
    };
    loop {
        if signalled.load(Ordering::SeqCst) || !listener.present() {
            daemon.end();
        }
        match daemon.due((daemon.clock)()) {
            Due::End => break,
            Due::Sync => daemon.sync(sync),
            Due::Wait => std::thread::sleep(TICK),
        }
    }
    daemon.end();
    let _ = acceptor.join();
    listener.remove();
    Ok(())
}

fn accept_loop(daemon: &Arc<Daemon>, listener: &Arc<Listener>, uid: u32) {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let conns = Arc::new(AtomicUsize::new(0));
    let tick = Timespec {
        tv_sec: 0,
        tv_nsec: i64::try_from(TICK.as_nanos()).unwrap_or(200_000_000),
    };
    while !daemon.ending() {
        let mut fds = [PollFd::new(&listener.listener, PollFlags::IN)];
        match poll(&mut fds, Some(&tick)) {
            Ok(0) | Err(_) => continue,
            Ok(_) => {}
        }
        let Ok((stream, _)) = listener.listener.accept() else {
            // Such as too many open files: do not spin.
            std::thread::sleep(TICK);
            continue;
        };
        // Another user's connection is closed without a word.
        if sock::peer_uid(&stream) != Some(uid) {
            continue;
        }
        if conns.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            conns.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let d = Arc::clone(daemon);
        let l = Arc::clone(listener);
        let c = Arc::clone(&conns);
        let spawned = std::thread::Builder::new()
            .name("vault-agent-conn".into())
            .stack_size(STACK)
            .spawn(move || {
                serve_conn(&d, &l, stream);
                c.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            conns.fetch_sub(1, Ordering::SeqCst);
        }
    }
    // Commands stop finding this agent at once, even while a sync finishes.
    listener.remove();
}

/// Answers one connection. Once the agent is ending, a connection is closed unanswered; the
/// request that ends it removes the socket before its response is written, so a command that
/// connects afterwards finds no agent.
fn serve_conn(daemon: &Daemon, listener: &Listener, mut s: UnixStream) {
    let _ = s.set_read_timeout(Some(proto::IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(proto::IO_TIMEOUT));
    let Ok(frame) = proto::read_frame(&mut s) else {
        return;
    };
    if daemon.ending() {
        return;
    }
    let response = daemon.handle(&frame);
    drop(frame);
    if daemon.ending() {
        listener.remove();
    }
    let _ = proto::write_frame(&mut s, &response);
}

/// The `vault agent` subcommand: reads the start message from standard input, hardens the
/// process, leaves the command's session, binds the socket, writes `R` to standard output when it
/// listens (`B` when another agent holds the lock, or `E` and a message when it fails), and
/// serves until it ends.
pub fn run_daemon(sync: SyncFn) -> Result<(), AgentError> {
    let mut started = false;
    let result = daemon_main(sync, &mut started);
    if let Err(e) = &result
        && !started
    {
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "E{e}").and_then(|()| out.flush());
    }
    result
}

fn daemon_main(sync: SyncFn, started: &mut bool) -> Result<(), AgentError> {
    crate::harden::harden_process();
    let _ = rustix::process::setsid();
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    let signalled = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(sig, Arc::clone(&signalled)).map_err(AgentError::Io)?;
    }
    crate::harden::lock_memory();
    // Read straight from descriptor 0 into a locked page, past the buffer of `std::io::Stdin`.
    let mut message = LockedBuf::new(proto::START_LEN).map_err(AgentError::Io)?;
    crate::prompt::RawStdin
        .read_exact(&mut message)
        .map_err(|_| AgentError::Protocol("no start message"))?;
    let start = proto::decode_start(&message).ok_or(AgentError::Protocol("bad start message"))?;
    drop(message);
    let dir = sock::agent_dir().ok_or(AgentError::NoRuntimeDir)?;
    let mut out = std::io::stdout().lock();
    let Some(listener) = Listener::bind(&dir)? else {
        *started = true;
        let _ = out.write_all(b"B").and_then(|()| out.flush());
        return Ok(());
    };
    let daemon = Arc::new(Daemon::new(
        start.vault_id,
        start.key,
        start.settings,
        Box::new(boot_ms),
        Box::new(now_ms),
    ));
    *started = true;
    out.write_all(b"R")
        .and_then(|()| out.flush())
        .map_err(AgentError::Io)?;
    drop(out);
    serve(daemon, listener, sock::uid(), &sync, &signalled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn settings() -> AgentSettings {
        AgentSettings {
            idle: Duration::from_secs(60),
            max: Duration::from_secs(600),
            sync_interval: Duration::from_secs(30),
            sync_auto: true,
        }
    }

    /// A daemon on a clock the test moves.
    fn daemon(settings: AgentSettings) -> (Arc<Daemon>, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let c = Arc::clone(&t);
        let w = Arc::clone(&t);
        let d = Daemon::new(
            [0xab; 16],
            locked_key(&[0x5a; 32]).unwrap(),
            settings,
            Box::new(move || c.load(Ordering::SeqCst)),
            Box::new(move || w.load(Ordering::SeqCst)),
        );
        (Arc::new(d), t)
    }

    fn request(d: &Daemon, op: &str) -> serde_json::Value {
        let body = serde_json::to_vec(&serde_json::json!({"v": 1, "op": op})).unwrap();
        let f = d.handle(&body);
        serde_json::from_slice(&f[4..]).unwrap()
    }

    #[test]
    fn key_requests_return_the_key_and_reset_the_idle_timer() {
        let mut s = settings();
        s.sync_auto = false;
        let (d, t) = daemon(s);
        let r = request(&d, "key");
        assert_eq!(r["vault_id"], "ab".repeat(16));
        assert_eq!(r["vault_key"], "5a".repeat(32));
        t.fetch_add(59_000, Ordering::SeqCst);
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::Wait);
        request(&d, "key");
        t.fetch_add(59_000, Ordering::SeqCst);
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::Wait);
        // Status and sync requests do not count as activity.
        request(&d, "status");
        request(&d, "sync");
        t.fetch_add(1_000, Ordering::SeqCst);
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::End);
    }

    #[test]
    fn the_maximum_lifetime_ends_an_active_agent() {
        let mut s = settings();
        s.sync_auto = false;
        let (d, t) = daemon(s);
        let start = t.load(Ordering::SeqCst);
        for _ in 0..20 {
            t.fetch_add(30_000, Ordering::SeqCst);
            request(&d, "key");
            let now = t.load(Ordering::SeqCst);
            let expect = if now >= start + 600_000 {
                Due::End
            } else {
                Due::Wait
            };
            assert_eq!(d.due(now), expect, "at {}", now - start);
        }
        let st = request(&d, "status");
        assert_eq!(st["unlocked_at"], start);
        assert_eq!(st["locks_at"], start + 600_000);
    }

    #[test]
    fn status_reports_the_lock_time_and_syncs() {
        let (d, t) = daemon(settings());
        let start = t.load(Ordering::SeqCst);
        let st: AgentStatus = serde_json::from_value(request(&d, "status")).unwrap();
        assert_eq!(
            st,
            AgentStatus {
                unlocked_at: start,
                locks_at: start + 60_000,
                last_sync: None,
                last_error: None,
            }
        );
        let fail: SyncFn = Box::new(|_, _| SyncResult::Failed {
            code: "server.unreachable".into(),
            message: "no answer".into(),
        });
        t.fetch_add(5_000, Ordering::SeqCst);
        d.sync(&fail);
        let st: AgentStatus = serde_json::from_value(request(&d, "status")).unwrap();
        assert_eq!(st.last_error.unwrap().code, "server.unreachable");
        let ok: SyncFn = Box::new(|_, _| SyncResult::Done);
        t.fetch_add(5_000, Ordering::SeqCst);
        d.sync(&ok);
        let st: AgentStatus = serde_json::from_value(request(&d, "status")).unwrap();
        assert_eq!(st.last_sync, Some(start + 10_000));
        assert_eq!(st.last_error, None);
    }

    #[test]
    fn syncs_run_every_interval_and_2_s_after_a_request() {
        let (d, t) = daemon(settings());
        let now = || t.load(Ordering::SeqCst);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let sync: SyncFn = Box::new(move |id, key| {
            assert_eq!(id, &[0xab; 16]);
            assert_eq!(key.expose(), &[0x5a; 32]);
            c.fetch_add(1, Ordering::SeqCst);
            SyncResult::Done
        });
        t.fetch_add(29_999, Ordering::SeqCst);
        assert_eq!(d.due(now()), Due::Wait);
        t.fetch_add(1, Ordering::SeqCst);
        assert_eq!(d.due(now()), Due::Sync);
        d.sync(&sync);
        assert_eq!(d.due(now()), Due::Wait);
        request(&d, "key");

        request(&d, "sync");
        t.fetch_add(1_000, Ordering::SeqCst);
        // A second request does not postpone the first.
        request(&d, "sync");
        t.fetch_add(999, Ordering::SeqCst);
        assert_eq!(d.due(now()), Due::Wait);
        t.fetch_add(1, Ordering::SeqCst);
        assert_eq!(d.due(now()), Due::Sync);
        d.sync(&sync);
        assert_eq!(d.due(now()), Due::Wait);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_lock_cancels_a_running_sync() {
        let (d, _) = daemon(settings());
        assert!(!sync_cancelled());
        let d2 = Arc::clone(&d);
        let locker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            request(&d2, "lock");
        });
        let saw = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&saw);
        let sync: SyncFn = Box::new(move |_, _| {
            // A sync that checks between its requests.
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(10) {
                if sync_cancelled() {
                    s.store(true, Ordering::SeqCst);
                    return SyncResult::Failed {
                        code: "sync.cancelled".into(),
                        message: "the agent is ending".into(),
                    };
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            SyncResult::Done
        });
        let start = std::time::Instant::now();
        d.sync(&sync);
        locker.join().unwrap();
        assert!(saw.load(Ordering::SeqCst));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!sync_cancelled());
        assert!(d.state().key.is_none());
    }

    #[test]
    fn status_times_follow_the_wall_clock() {
        let t = Arc::new(AtomicU64::new(5_000));
        let c = Arc::clone(&t);
        let d = Daemon::new(
            [1; 16],
            locked_key(&[2; 32]).unwrap(),
            settings(),
            Box::new(move || c.load(Ordering::SeqCst)),
            Box::new(|| 1_700_000_000_000),
        );
        t.fetch_add(10_000, Ordering::SeqCst);
        let st = d.status();
        assert_eq!(st.unlocked_at, 1_700_000_000_000);
        // 60 s idle from the start, 10 s of which have passed on the timer clock.
        assert_eq!(st.locks_at, 1_700_000_000_000 + 50_000);
    }

    #[test]
    fn the_boot_clock_moves() {
        let a = boot_ms();
        std::thread::sleep(Duration::from_millis(20));
        assert!(boot_ms() >= a + 20);
    }

    #[test]
    fn without_sync_auto_nothing_syncs() {
        let mut s = settings();
        s.sync_auto = false;
        let (d, t) = daemon(s);
        request(&d, "sync");
        t.fetch_add(40_000, Ordering::SeqCst);
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::Wait);
    }

    #[test]
    fn a_rejected_key_or_lock_ends_the_agent() {
        let (d, t) = daemon(settings());
        let reject: SyncFn = Box::new(|_, _| SyncResult::KeyRejected);
        d.sync(&reject);
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::End);
        assert_eq!(request(&d, "key")["error"]["code"], "agent.locked");

        let (d, t) = daemon(settings());
        assert_eq!(request(&d, "lock"), serde_json::json!({}));
        assert_eq!(request(&d, "status")["error"]["code"], "agent.locked");
        assert!(d.state().key.is_none());
        assert_eq!(d.due(t.load(Ordering::SeqCst)), Due::End);
    }

    #[test]
    fn bad_requests_get_error_responses() {
        let (d, _) = daemon(settings());
        let r = |body: &[u8]| -> serde_json::Value {
            serde_json::from_slice(&d.handle(body)[4..]).unwrap()
        };
        assert_eq!(r(b"not json")["error"]["code"], "agent.bad_request");
        assert_eq!(
            r(br#"{"v": 2, "op": "key"}"#)["error"]["code"],
            "agent.version"
        );
        assert_eq!(
            r(br#"{"v": 1, "op": "dump"}"#)["error"]["code"],
            "agent.bad_request"
        );
        assert_eq!(r(br#"{"op": "key"}"#)["error"]["code"], "agent.bad_request");
    }

    /// An agent served in this process on a socket in a temporary directory.
    fn served(
        s: AgentSettings,
        uid: u32,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Arc<Daemon>,
        std::thread::JoinHandle<()>,
    ) {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("vault");
        let listener = Listener::bind(&dir).unwrap().unwrap();
        let (d, _) = daemon(s);
        let d2 = Arc::clone(&d);
        let h = std::thread::spawn(move || {
            let sync: SyncFn = Box::new(|_, _| SyncResult::Done);
            serve(d2, listener, uid, &sync, &AtomicBool::new(false)).unwrap();
        });
        (t, dir.join(sock::SOCKET_NAME), d, h)
    }

    #[test]
    fn a_served_agent_answers_and_ends_on_lock() {
        let (_t, path, _d, h) = served(settings(), sock::uid());
        let (id, key) = client::get_key_at(&path).unwrap().unwrap();
        assert_eq!(id, [0xab; 16]);
        assert_eq!(key.expose(), &[0x5a; 32]);
        assert!(client::request_sync_at(&path).unwrap());
        assert!(client::status_at(&path).unwrap().is_some());
        // A second agent finds the lock taken.
        assert!(Listener::bind(path.parent().unwrap()).unwrap().is_none());
        assert!(client::lock_at(&path).unwrap());
        // The socket is gone as soon as the lock is answered.
        assert!(!path.exists());
        assert!(client::status_at(&path).unwrap().is_none());
        assert!(client::get_key_at(&path).unwrap().is_none());
        h.join().unwrap();
        assert!(!path.exists());
        assert!(client::get_key_at(&path).unwrap().is_none());
        // The lock is free again.
        assert!(Listener::bind(path.parent().unwrap()).unwrap().is_some());
    }

    #[test]
    fn other_users_are_refused() {
        // The agent expects another user ID, so this process counts as a stranger.
        let (_t, path, d, h) = served(settings(), sock::uid() + 1);
        // The connection is closed unanswered, so no key arrives.
        assert!(!matches!(client::get_key_at(&path), Ok(Some(_))));
        d.end();
        h.join().unwrap();
    }

    #[test]
    fn removing_the_socket_ends_the_agent() {
        let (_t, path, d, h) = served(settings(), sock::uid());
        std::fs::remove_file(&path).unwrap();
        h.join().unwrap();
        assert!(d.state().key.is_none());
    }

    #[test]
    fn a_replaced_socket_is_left_alone() {
        let (_t, path, _d, h) = served(settings(), sock::uid());
        std::fs::remove_file(&path).unwrap();
        let _other = UnixListener::bind(&path).unwrap();
        h.join().unwrap();
        assert!(
            path.exists(),
            "the agent removed a socket that is not its own"
        );
    }
}
