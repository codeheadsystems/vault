//! The files in the data directory: the `lock` every writer holds, `local.json` with the
//! vault-client commit rule, `server.json`, and `device-id`. Every file is written with mode
//! `0600` through a temporary file, `fsync`, a rename, and an `fsync` of the directory.

use crate::error::{CliError, Result};
use crate::paths::Paths;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use vault_client::ClientState;
use vault_core::json::{self, Map, Value};
use vault_core::secret::Token;
use zeroize::Zeroizing;

/// The advisory lock on `lock`, held while reading for a write and while committing. Released
/// on drop.
pub struct Lock {
    _file: File,
}

/// Takes the lock, waiting for another command or the agent to release it.
pub fn lock(paths: &Paths) -> Result<Lock> {
    let path = paths.lock();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|e| CliError::io(path.display(), e))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| CliError::io(path.display(), e.into()))?;
    Ok(Lock { _file: file })
}

/// Writes `bytes` to `path` atomically with mode `0600`: a temporary file next to it, `fsync`,
/// a rename over `path`, and an `fsync` of the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("a file in the data directory");
    let mut tmp_name = path.file_name().expect("a file name").to_owned();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    let run = || -> io::Result<()> {
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    };
    run().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        CliError::io(path.display(), e)
    })
}

/// Reads a file of the data directory, or `None` when it does not exist.
fn read_optional(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(Zeroizing::new(b))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::io(path.display(), e)),
    }
}

/// Reads `local.json`, or `None` when this device has no vault.
pub fn read_state(paths: &Paths) -> Result<Option<ClientState>> {
    match read_optional(&paths.local_json())? {
        None => Ok(None),
        Some(b) => ClientState::from_json(&b).map(Some).map_err(|e| {
            CliError::other(e.code(), format!("{}: {e}", paths.local_json().display()))
        }),
    }
}

/// Reads `local.json` and fails when this device has no vault.
pub fn require_state(paths: &Paths) -> Result<ClientState> {
    read_state(paths)?.ok_or_else(no_vault)
}

/// The error for a device without a vault.
pub fn no_vault() -> CliError {
    CliError::other(
        "state.no_vault",
        "this device has no vault; run `vault init` or `vault setup`",
    )
}

/// Writes `local.json`. The caller holds the lock.
pub fn write_state(paths: &Paths, _lock: &Lock, state: &ClientState) -> Result<()> {
    write_atomic(&paths.local_json(), &state.to_json())
}

/// The server connection settings in `server.json`.
pub struct ServerConfig {
    /// The server URL, as the WHATWG URL parser serialises it.
    pub url: String,
    /// The token.
    pub token: Token,
    /// The certificate pin.
    pub fp: Option<[u8; 32]>,
}

impl ServerConfig {
    /// From parsed setup text.
    pub fn from_setup(s: vault_core::setup::SetupText) -> ServerConfig {
        ServerConfig {
            url: s.url,
            token: s.token,
            fp: s.fp,
        }
    }
}

/// Reads `server.json`, or `None` when it does not exist.
pub fn read_server(paths: &Paths) -> Result<Option<ServerConfig>> {
    let path = paths.server_json();
    let Some(bytes) = read_optional(&path)? else {
        return Ok(None);
    };
    let bad = || CliError::other("state.invalid", format!("{} is malformed", path.display()));
    let mut m = json::parse(&bytes)
        .ok()
        .and_then(|mut v| v.take_object())
        .ok_or_else(bad)?;
    let mut string = |k: &str| m.remove(k).and_then(|mut v| v.take_string());
    let url = string("url").ok_or_else(bad)?;
    let token = Zeroizing::new(string("token").ok_or_else(bad)?);
    let fp = match string("fp") {
        Some(f) => Some(vault_core::setup::parse_fingerprint(&f).map_err(|_| bad())?),
        None => None,
    };
    let url = vault_core::setup::check_server_url(&url)
        .map_err(|_| bad())?
        .url;
    Ok(Some(ServerConfig {
        url,
        token: vault_core::token::decode(&token).map_err(|_| bad())?,
        fp,
    }))
}

/// Reads `server.json` and fails when it does not exist.
pub fn require_server(paths: &Paths) -> Result<ServerConfig> {
    read_server(paths)?.ok_or_else(|| {
        CliError::other(
            "state.no_server",
            "no server is configured; run `vault setup` with setup text",
        )
    })
}

/// Writes `server.json`.
pub fn write_server(paths: &Paths, s: &ServerConfig) -> Result<()> {
    let mut m = Map::new();
    m.insert("v".into(), Value::Number(1));
    m.insert("url".into(), Value::String(s.url.clone()));
    m.insert(
        "token".into(),
        Value::String(vault_core::token::encode(&s.token).to_string()),
    );
    m.insert(
        "fp".into(),
        s.fp.map_or(Value::Null, |f| Value::String(hex::encode(f))),
    );
    write_atomic(&paths.server_json(), &json::to_vec(&Value::Object(m)))
}

/// Reads `device-id`.
pub fn read_device_id(paths: &Paths) -> Result<[u8; 16]> {
    let path = paths.device_id();
    let bytes = read_optional(&path)?.ok_or_else(no_vault)?;
    let text = std::str::from_utf8(&bytes).unwrap_or_default().trim_end();
    let mut id = [0u8; 16];
    if text.len() != 32
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        || hex::decode_to_slice(text, &mut id).is_err()
    {
        return Err(CliError::other(
            "state.invalid",
            format!("{} is not 32 lowercase hex characters", path.display()),
        ));
    }
    Ok(id)
}

/// Generates and writes a new `device-id`.
pub fn create_device_id(paths: &Paths) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)
        .map_err(|e| CliError::other("rng", format!("the random number generator failed: {e}")))?;
    write_atomic(
        &paths.device_id(),
        format!("{}\n", hex::encode(id)).as_bytes(),
    )?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn atomic_write_replaces_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!dir.path().join("f.json.tmp").exists());
    }

    #[test]
    fn server_json_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            data: dir.path().to_owned(),
            config: dir.path().join("config.toml"),
            runtime: None,
        };
        assert!(read_server(&paths).unwrap().is_none());
        let s = ServerConfig {
            url: "https://nas.lan:8443/".into(),
            token: Token::from_bytes([7; 20]),
            fp: Some([9; 32]),
        };
        write_server(&paths, &s).unwrap();
        let back = read_server(&paths).unwrap().unwrap();
        assert_eq!(back.url, s.url);
        assert_eq!(back.token.expose(), s.token.expose());
        assert_eq!(back.fp, s.fp);
    }

    #[test]
    fn device_id_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            data: dir.path().to_owned(),
            config: dir.path().join("config.toml"),
            runtime: None,
        };
        let id = create_device_id(&paths).unwrap();
        assert_eq!(read_device_id(&paths).unwrap(), id);
        fs::write(paths.device_id(), "ABC").unwrap();
        assert!(read_device_id(&paths).is_err());
    }
}
