//! The command side of the agent: requests over the socket, after checking the directory, the
//! socket, and the agent's user, and starting a new agent with a key.

use super::proto::{self, AgentStatus, ErrorResponse, KeyResponse, Request};
use super::{AgentError, AgentSettings, START_WAIT, sock};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use vault_core::secret::VaultKey;
use zeroize::Zeroizing;

fn socket_path() -> Result<PathBuf, AgentError> {
    sock::agent_dir()
        .map(|d| d.join(sock::SOCKET_NAME))
        .ok_or(AgentError::NoRuntimeDir)
}

/// Sends `op` to the agent at `path` and returns the response's JSON. `Ok(None)` means no agent
/// runs: no directory, no socket, or nobody listening on it.
fn call(path: &Path, op: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AgentError> {
    let uid = sock::uid();
    let dir = path.parent().unwrap_or(Path::new("/"));
    if !sock::check_dir(dir, uid).map_err(AgentError::Unsafe)? {
        return Ok(None);
    }
    if !sock::check_socket(path, uid).map_err(AgentError::Unsafe)? {
        return Ok(None);
    }
    let mut s = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(AgentError::Io(e)),
    };
    if sock::peer_uid(&s) != Some(uid) {
        return Err(AgentError::WrongPeer);
    }
    s.set_read_timeout(Some(proto::IO_TIMEOUT))
        .and_then(|()| s.set_write_timeout(Some(proto::IO_TIMEOUT)))
        .map_err(AgentError::Io)?;
    let request = proto::encode(&Request {
        v: proto::VERSION,
        op: op.into(),
    })?;
    proto::write_frame(&mut s, &request)?;
    let response = match proto::read_frame(&mut s) {
        Ok(r) => r,
        // An ending agent closes connections unanswered.
        Err(proto::FrameError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    if let Ok(e) = serde_json::from_slice::<ErrorResponse>(&response) {
        return Err(AgentError::Agent(e.error));
    }
    Ok(Some(response))
}

/// Asks the running agent for the vault ID and vault key; `None` when no agent runs.
pub fn get_key() -> Result<Option<([u8; 16], VaultKey)>, AgentError> {
    get_key_at(&socket_path()?)
}

pub(super) fn get_key_at(path: &Path) -> Result<Option<([u8; 16], VaultKey)>, AgentError> {
    let Some(response) = call(path, "key")? else {
        return Ok(None);
    };
    let bad = || AgentError::Protocol("a malformed key response");
    let r: KeyResponse = serde_json::from_slice(&response).map_err(|_| bad())?;
    let mut vault_id = [0u8; 16];
    hex::decode_to_slice(&r.vault_id, &mut vault_id).map_err(|_| bad())?;
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(r.vault_key.as_bytes(), &mut *key).map_err(|_| bad())?;
    Ok(Some((vault_id, VaultKey::from_bytes(*key))))
}

/// Asks the running agent to sync in 2 s; `false` when no agent runs.
pub fn request_sync() -> Result<bool, AgentError> {
    request_sync_at(&socket_path()?)
}

pub(super) fn request_sync_at(path: &Path) -> Result<bool, AgentError> {
    Ok(call(path, "sync")?.is_some())
}

/// The running agent's status; `None` when no agent runs.
pub fn status() -> Result<Option<AgentStatus>, AgentError> {
    status_at(&socket_path()?)
}

pub(super) fn status_at(path: &Path) -> Result<Option<AgentStatus>, AgentError> {
    let Some(response) = call(path, "status")? else {
        return Ok(None);
    };
    serde_json::from_slice(&response)
        .map(Some)
        .map_err(|_| AgentError::Protocol("a malformed status response"))
}

/// Ends the running agent; `false` when no agent runs. Without `$XDG_RUNTIME_DIR` no agent can
/// run, so that is `false` too.
pub fn lock() -> Result<bool, AgentError> {
    match socket_path() {
        Ok(p) => lock_at(&p),
        Err(AgentError::NoRuntimeDir) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) fn lock_at(path: &Path) -> Result<bool, AgentError> {
    Ok(call(path, "lock")?.is_some())
}

/// Starts `vault agent` as a detached process holding `key`, and waits until it listens. The key
/// and settings travel through the agent's standard input, never its arguments or environment.
/// When another agent already runs, the new one exits and this returns `Ok` as well.
pub fn start(
    vault_id: &[u8; 16],
    key: &VaultKey,
    settings: &AgentSettings,
) -> Result<(), AgentError> {
    if sock::agent_dir().is_none() {
        return Err(AgentError::NoRuntimeDir);
    }
    let exe = std::env::current_exe()
        .map_err(|e| AgentError::Start(format!("cannot find the vault executable: {e}")))?;
    crate::harden::close_on_exec_all();
    let mut child = Command::new(exe)
        .arg("agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir("/")
        // Fewer malloc arenas keep the agent's locked memory small.
        .env("MALLOC_ARENA_MAX", "2")
        .spawn()
        .map_err(|e| AgentError::Start(e.to_string()))?;
    let message = proto::encode_start(vault_id, key, settings);
    let sent = child
        .stdin
        .take()
        .ok_or_else(|| AgentError::Start("no pipe to the agent".into()))
        .and_then(|mut stdin| stdin.write_all(&message).map_err(AgentError::Io));
    drop(message);
    if let Err(e) = sent {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let Some(mut out) = child.stdout.take() else {
        return Err(AgentError::Start("no pipe from the agent".into()));
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        let first = out.read(&mut b).ok().filter(|&n| n == 1).map(|_| b[0]);
        // A failing agent writes `E` and its message, then exits.
        let mut message = String::new();
        if first == Some(b'E') {
            let _ = out.take(1024).read_to_string(&mut message);
        }
        let _ = tx.send((first, message));
    });
    match rx.recv_timeout(START_WAIT) {
        Ok((Some(b'R'), _)) => Ok(()),
        Ok((Some(b'B'), _)) => {
            let _ = child.wait();
            Ok(())
        }
        Ok((Some(b'E'), message)) => {
            let _ = child.wait();
            Err(AgentError::Start(message))
        }
        Ok(_) => {
            let status = child.wait().map_err(AgentError::Io)?;
            Err(AgentError::Start(format!("the agent exited with {status}")))
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(AgentError::Start("the agent did not start in time".into()))
        }
    }
}
