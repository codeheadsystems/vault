//! The agent as its own process: `vault agent` started with a key on its standard input, asked
//! for the key over its socket, and ended by its idle timer, `SIGTERM`, or a `lock` request.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VAULT_ID: [u8; 16] = [0x11; 16];
const VAULT_KEY: [u8; 32] = [0x42; 32];

/// A running agent in its own runtime directory.
struct Agent {
    child: Child,
    runtime: tempfile::TempDir,
    _data: tempfile::TempDir,
}

impl Agent {
    fn socket(&self) -> PathBuf {
        self.runtime.path().join("vault/agent.sock")
    }

    /// Whether the process has exited, waiting up to `limit`.
    fn exits_within(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The start message: vault ID, key, idle, max, and sync interval in ms, and `sync.auto`.
fn start_message(idle_ms: u64, max_ms: u64) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&VAULT_ID);
    m.extend_from_slice(&VAULT_KEY);
    for v in [idle_ms, max_ms, 3_600_000] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m.push(0);
    m
}

/// Starts `vault agent` in `runtime` and returns it with the byte it reported.
fn spawn_in(runtime: tempfile::TempDir, idle_ms: u64, max_ms: u64) -> (Agent, u8) {
    let data = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("agent")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_CONFIG_HOME", data.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&start_message(idle_ms, max_ms)).unwrap();
    drop(stdin);
    let mut ready = [0u8; 1];
    child.stdout.take().unwrap().read_exact(&mut ready).unwrap();
    (
        Agent {
            child,
            runtime,
            _data: data,
        },
        ready[0],
    )
}

fn spawn(idle_ms: u64, max_ms: u64) -> Agent {
    let (agent, ready) = spawn_in(tempfile::tempdir().unwrap(), idle_ms, max_ms);
    assert_eq!(ready, b'R');
    agent
}

/// Sends one request and returns the response.
fn request(socket: &Path, op: &str) -> serde_json::Value {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({"v": 1, "op": op})).unwrap();
    s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn the_agent_hands_out_the_key_and_ends_when_idle() {
    let mut agent = spawn(1_500, 60_000);
    let socket = agent.socket();
    assert_eq!(mode(socket.parent().unwrap()), 0o700);
    assert_eq!(mode(&socket), 0o600);

    let r = request(&socket, "key");
    assert_eq!(r["vault_id"], hex(&VAULT_ID));
    assert_eq!(r["vault_key"], hex(&VAULT_KEY));

    // Key requests keep it alive past its idle time.
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(request(&socket, "key")["vault_key"], hex(&VAULT_KEY));
    }
    let status = request(&socket, "status");
    let unlocked_at = status["unlocked_at"].as_u64().unwrap();
    let locks_at = status["locks_at"].as_u64().unwrap();
    assert!(locks_at > unlocked_at + 1_500);
    assert_eq!(status["last_sync"], serde_json::Value::Null);

    // Without requests, it ends and removes its socket.
    assert!(agent.exits_within(Duration::from_secs(4)));
    assert!(!socket.exists());
}

#[test]
fn the_agent_ends_at_its_maximum_lifetime() {
    let mut agent = spawn(60_000, 1_500);
    let socket = agent.socket();
    for _ in 0..2 {
        std::thread::sleep(Duration::from_millis(500));
        request(&socket, "key");
    }
    assert!(agent.exits_within(Duration::from_secs(3)));
    assert!(!socket.exists());
}

#[test]
fn lock_sigterm_and_socket_removal_end_the_agent() {
    let mut agent = spawn(60_000, 60_000);
    assert_eq!(request(&agent.socket(), "lock"), serde_json::json!({}));
    assert!(agent.exits_within(Duration::from_secs(3)));
    assert!(!agent.socket().exists());

    let mut agent = spawn(60_000, 60_000);
    let pid = rustix::process::Pid::from_raw(agent.child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(agent.exits_within(Duration::from_secs(3)));
    assert!(!agent.socket().exists());

    let mut agent = spawn(60_000, 60_000);
    std::fs::remove_file(agent.socket()).unwrap();
    assert!(agent.exits_within(Duration::from_secs(3)));
}

#[test]
fn a_second_agent_defers_to_the_first() {
    let first = spawn(60_000, 60_000);
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("agent")
        .env("XDG_RUNTIME_DIR", first.runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&start_message(60_000, 60_000))
        .unwrap();
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    assert_eq!(out, b"B");
    assert!(child.wait().unwrap().success());
    assert_eq!(request(&first.socket(), "key")["vault_id"], hex(&VAULT_ID));
}

#[test]
fn an_unsafe_runtime_directory_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let runtime = tempfile::tempdir().unwrap();
    let dir = runtime.path().join("vault");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("agent")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&start_message(60_000, 60_000))
        .unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(out.starts_with('E'), "{out:?}");
    assert!(out.contains("mode is not 0700"), "{out:?}");
    assert!(!child.wait().unwrap().success());
    assert!(!dir.join("agent.sock").exists());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
