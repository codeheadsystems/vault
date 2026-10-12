//! The data directory: its paths, the ownership and mode checks, `O_NOFOLLOW` opens, atomic
//! writes, and the two locks.

use crate::error::{Context, Error, Result};
use rustix::fs::{FlockOperation, OFlags, flock};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// `serve.toml`.
pub(crate) const CONFIG: &str = "serve.toml";
/// `tokens.json`.
pub(crate) const TOKENS: &str = "tokens.json";
/// `server.lock`, held by the running server.
pub(crate) const SERVER_LOCK: &str = "server.lock";
/// `lock`, held by every writer.
pub(crate) const WRITE_LOCK: &str = "lock";
/// `revisions/`.
pub(crate) const REVISIONS: &str = "revisions";
/// `tls/`.
pub(crate) const TLS: &str = "tls";
/// The suffix of every temporary file.
pub(crate) const TMP_SUFFIX: &str = ".tmp";

/// A data directory, named by its path.
#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Names a data directory. Nothing is checked until a command uses it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DataDir { root: root.into() }
    }

    /// The default data directory: `$VAULT_SERVE_DATA`, then `$XDG_DATA_HOME/vault-serve`, then
    /// `~/.local/share/vault-serve`. An empty or relative `$XDG_DATA_HOME` is ignored, as the XDG
    /// base directory specification requires.
    pub fn default_path() -> Result<PathBuf> {
        if let Some(d) = std::env::var_os("VAULT_SERVE_DATA").filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(d));
        }
        if let Some(d) = xdg_data_home() {
            return Ok(d.join("vault-serve"));
        }
        crate::error::invalid("no data directory: set --data, $VAULT_SERVE_DATA, or $HOME")
    }

    /// The directory's path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of an entry, relative to the directory.
    pub(crate) fn path(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.root.join(rel)
    }

    /// `revisions/`.
    pub(crate) fn revisions(&self) -> PathBuf {
        self.root.join(REVISIONS)
    }

    /// Checks the directory, `revisions/`, `tls/`, and every entry in them: each is owned by the
    /// effective user, is neither group- nor other-accessible, and is not a symbolic link.
    pub fn check(&self) -> Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        let meta = match fs::symlink_metadata(&self.root) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return crate::error::invalid(format!(
                    "{} does not exist; run vault serve init",
                    self.root.display()
                ));
            }
            r => r.context(|| format!("reading {}", self.root.display()))?,
        };
        check_entry(&self.root, &meta, uid)?;
        if !meta.is_dir() {
            return crate::error::invalid(format!("{} is not a directory", self.root.display()));
        }
        self.check_children(&self.root, uid, true)
    }

    fn check_children(&self, dir: &Path, uid: u32, top: bool) -> Result<()> {
        let entries = fs::read_dir(dir).context(|| format!("reading {}", dir.display()))?;
        for entry in entries {
            let entry = entry.context(|| format!("reading {}", dir.display()))?;
            let path = entry.path();
            // A running server creates and removes temporary files while a command checks.
            let meta = match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                r => r.context(|| format!("reading {}", path.display()))?,
            };
            check_entry(&path, &meta, uid)?;
            if top && meta.is_dir() {
                self.check_children(&path, uid, false)?;
            }
        }
        Ok(())
    }

    /// Creates `name` as a directory with mode `0700`, or checks the existing one.
    pub(crate) fn create_dir(path: &Path) -> Result<()> {
        match DirBuilder::new().mode(0o700).create(path) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let meta =
                    fs::symlink_metadata(path).context(|| format!("reading {}", path.display()))?;
                check_entry(path, &meta, rustix::process::geteuid().as_raw())?;
                if meta.is_dir() {
                    Ok(())
                } else {
                    crate::error::invalid(format!("{} is not a directory", path.display()))
                }
            }
            r => r.context(|| format!("creating {}", path.display())),
        }
    }

    /// Takes the writer lock, waiting for another writer to finish.
    pub(crate) fn write_lock(&self) -> Result<WriteLock> {
        let path = self.path(WRITE_LOCK);
        let f = open_lock_file(&path)?;
        flock(&f, FlockOperation::LockExclusive)
            .map_err(io::Error::from)
            .context(|| format!("locking {}", path.display()))?;
        Ok(WriteLock(f))
    }

    /// Takes `server.lock` without waiting; [`Error::Locked`] when another server holds it.
    pub(crate) fn server_lock(&self) -> Result<File> {
        let path = self.path(SERVER_LOCK);
        let f = open_lock_file(&path)?;
        match flock(&f, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(f),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(Error::Locked),
            Err(e) => Err(io::Error::from(e)).context(|| format!("locking {}", path.display())),
        }
    }
}

/// The writer lock on `lock`. Dropping it closes the file, which releases the lock.
pub(crate) struct WriteLock(#[allow(dead_code, reason = "held for its lock")] File);

fn open_lock_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(path)
        .context(|| format!("opening {}", path.display()))
}

/// `$XDG_DATA_HOME`, or `~/.local/share` when it is unset, empty, or relative.
pub(crate) fn xdg_data_home() -> Option<PathBuf> {
    match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        Some(d) if d.is_absolute() => Some(d),
        _ => home().map(|h| h.join(".local/share")),
    }
}

/// `$HOME`, when it is set and absolute.
pub(crate) fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
}

fn check_entry(path: &Path, meta: &fs::Metadata, uid: u32) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(Error::Unsafe(format!(
            "{} is a symbolic link",
            path.display()
        )));
    }
    if meta.uid() != uid {
        return Err(Error::Unsafe(format!(
            "{} is owned by another user",
            path.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Unsafe(format!(
            "{} is accessible to the group or others (mode {:04o})",
            path.display(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

/// Checks an opened file in the data directory the way [`DataDir::check`] does.
pub(crate) fn check_open_file(path: &Path, f: &File) -> Result<()> {
    let meta = f
        .metadata()
        .context(|| format!("reading {}", path.display()))?;
    check_entry(path, &meta, rustix::process::geteuid().as_raw())
}

fn nofollow() -> i32 {
    OFlags::NOFOLLOW.bits() as i32
}

/// Opens a file in the data directory for reading, refusing a symbolic link.
pub(crate) fn open_read(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nofollow())
        .open(path)
}

/// Creates a new file with mode `0600`, refusing an existing file or a symbolic link.
pub(crate) fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(path)
}

/// Reads a whole file in the data directory, refusing a symbolic link.
pub(crate) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = open_read(path)?;
    let mut buf = Vec::new();
    io::Read::read_to_end(&mut f, &mut buf)?;
    Ok(buf)
}

/// Writes `bytes` to `path` through `path.tmp`, `fsync`, a rename, and an `fsync` of the
/// directory. A stale temporary file is replaced.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let ctx = || format!("writing {}", path.display());
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e).context(ctx),
        _ => {}
    }
    let mut f = create_new(&tmp).context(ctx)?;
    f.write_all(bytes).context(ctx)?;
    f.sync_all().context(ctx)?;
    drop(f);
    fs::rename(&tmp, path).context(ctx)?;
    fsync_dir(path.parent().unwrap_or(Path::new("."))).context(ctx)
}

/// `path` with [`TMP_SUFFIX`] appended.
pub(crate) fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(TMP_SUFFIX);
    PathBuf::from(s)
}

/// `fsync` of a directory, which makes the renames in it durable.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::DIRECTORY).bits() as i32)
        .open(dir)?
        .sync_all()
}

/// Removes temporary files left in the top of the data directory by a writer that crashed.
pub(crate) fn remove_stale_tmp(dir: &Path) -> Result<()> {
    let entries = fs::read_dir(dir).context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry.context(|| format!("reading {}", dir.display()))?;
        if entry.file_name().to_string_lossy().ends_with(TMP_SUFFIX) {
            let p = entry.path();
            fs::remove_file(&p).context(|| format!("removing {}", p.display()))?;
        }
    }
    Ok(())
}
