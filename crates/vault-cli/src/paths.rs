//! Where the client keeps its files: the data directory, `config.toml`, and the runtime
//! directory, resolved from the XDG variables, and the ownership and mode checks on them.

use crate::error::{CliError, Result};
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The client's directories.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `$XDG_DATA_HOME/vault`.
    pub data: PathBuf,
    /// `$XDG_CONFIG_HOME/vault/config.toml`.
    pub config: PathBuf,
    /// `$XDG_RUNTIME_DIR/vault`, or `None` without `$XDG_RUNTIME_DIR`.
    pub runtime: Option<PathBuf>,
}

/// An XDG variable when it holds an absolute path; the specification says to ignore a relative
/// one.
fn xdg(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home() -> Result<PathBuf> {
    xdg("HOME").ok_or_else(|| {
        CliError::other(
            "config.no_home",
            "neither $XDG_DATA_HOME nor $HOME is set to an absolute path",
        )
    })
}

impl Paths {
    /// Resolves the directories from the environment. Nothing is created or checked.
    pub fn from_env() -> Result<Paths> {
        let data = match xdg("XDG_DATA_HOME") {
            Some(d) => d,
            None => home()?.join(".local/share"),
        }
        .join("vault");
        let config = match xdg("XDG_CONFIG_HOME") {
            Some(d) => d,
            None => home()?.join(".config"),
        }
        .join("vault/config.toml");
        let runtime = xdg("XDG_RUNTIME_DIR").map(|d| d.join("vault"));
        Ok(Paths {
            data,
            config,
            runtime,
        })
    }

    /// `local.json`.
    pub fn local_json(&self) -> PathBuf {
        self.data.join("local.json")
    }

    /// `server.json`.
    pub fn server_json(&self) -> PathBuf {
        self.data.join("server.json")
    }

    /// `device-id`.
    pub fn device_id(&self) -> PathBuf {
        self.data.join("device-id")
    }

    /// `secret-key`, used only with the file store.
    pub fn secret_key(&self) -> PathBuf {
        self.data.join("secret-key")
    }

    /// `lock`.
    pub fn lock(&self) -> PathBuf {
        self.data.join("lock")
    }

    /// Creates the data directory with mode `0700` when it is missing, and checks it.
    pub fn ensure_data(&self) -> Result<()> {
        ensure_private_dir(&self.data)
    }

    /// Checks the data directory when it exists. Returns whether it exists.
    pub fn check_data(&self) -> Result<bool> {
        match fs::symlink_metadata(&self.data) {
            Ok(_) => check_private_dir(&self.data).map(|()| true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(CliError::io(self.data.display(), e)),
        }
    }
}

/// Creates `dir` with mode `0700` when it is missing (its parents with the default mode), then
/// checks it with [`check_private_dir`].
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(|e| CliError::io(parent.display(), e))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(CliError::io(dir.display(), e)),
    }
    check_private_dir(dir)
}

/// Refuses a directory that is a symbolic link, that another user owns, or that the group or
/// others can access.
pub fn check_private_dir(dir: &Path) -> Result<()> {
    let m = fs::symlink_metadata(dir).map_err(|e| CliError::io(dir.display(), e))?;
    let refuse = |why: &str| {
        Err(CliError::other(
            "config.directory",
            format!("refusing {}: {why}", dir.display()),
        ))
    };
    if m.file_type().is_symlink() {
        return refuse("it is a symbolic link");
    }
    if !m.is_dir() {
        return refuse("it is not a directory");
    }
    if m.uid() != rustix::process::geteuid().as_raw() {
        return refuse("another user owns it");
    }
    if m.permissions().mode() & 0o077 != 0 {
        return refuse("the group or others can access it; run chmod 700 on it");
    }
    Ok(())
}
