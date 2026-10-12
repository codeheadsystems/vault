//! The agent's socket: its path, the directory checks the agent and every command make, and the
//! peer check on every connection.

use std::fmt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// The socket's name in the agent directory.
pub const SOCKET_NAME: &str = "agent.sock";
/// The lock file that one agent at a time holds.
pub const LOCK_NAME: &str = "agent.lock";

/// Why the agent directory or socket is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsafe {
    /// The path refused.
    pub path: PathBuf,
    /// The reason.
    pub why: &'static str,
}

impl fmt::Display for Unsafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not safe to use: {}",
            self.path.display(),
            self.why
        )
    }
}

/// The agent directory, `$XDG_RUNTIME_DIR/vault`, when `$XDG_RUNTIME_DIR` is an absolute path.
pub fn agent_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join("vault"))
}

/// This process's user ID.
pub fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Checks with `lstat` that `dir` is a directory, not a symbolic link, owned by `uid`, with mode
/// `0700`. `Ok(false)` means it does not exist.
pub fn check_dir(dir: &Path, uid: u32) -> Result<bool, Unsafe> {
    let refuse = |why| Unsafe {
        path: dir.to_owned(),
        why,
    };
    let m = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(refuse("it cannot be read")),
    };
    if m.file_type().is_symlink() {
        return Err(refuse("it is a symbolic link"));
    }
    if !m.is_dir() {
        return Err(refuse("it is not a directory"));
    }
    if m.uid() != uid {
        return Err(refuse("another user owns it"));
    }
    if m.mode() & 0o7777 != 0o700 {
        return Err(refuse("its mode is not 0700"));
    }
    Ok(true)
}

/// Creates `dir` with mode `0700` when missing (its parent must exist), then checks it.
pub fn ensure_dir(dir: &Path, uid: u32) -> Result<(), Unsafe> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(Unsafe {
                path: dir.to_owned(),
                why: "it cannot be created",
            });
        }
    }
    match check_dir(dir, uid)? {
        true => Ok(()),
        false => Err(Unsafe {
            path: dir.to_owned(),
            why: "it disappeared",
        }),
    }
}

/// Checks with `lstat` that `path` is a socket owned by `uid`. `Ok(false)` means it does not
/// exist.
pub fn check_socket(path: &Path, uid: u32) -> Result<bool, Unsafe> {
    let refuse = |why| Unsafe {
        path: path.to_owned(),
        why,
    };
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(refuse("it cannot be read")),
    };
    if !m.file_type().is_socket() {
        return Err(refuse("it is not a socket"));
    }
    if m.uid() != uid {
        return Err(refuse("another user owns it"));
    }
    Ok(true)
}

/// The user ID of the process at the other end of a connection (`SO_PEERCRED`).
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(s)
        .ok()
        .map(|c| c.uid.as_raw())
}

/// The device, inode, and change time of a path, without following links, to notice a removed
/// or replaced socket; the change time tells a new socket that reuses the inode number.
pub fn identity(path: &Path) -> Option<(u64, u64, i64, i64)> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino(), m.ctime(), m.ctime_nsec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directory_checks() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("vault");
        assert_eq!(check_dir(&d, uid()), Ok(false));
        ensure_dir(&d, uid()).unwrap();
        assert_eq!(check_dir(&d, uid()), Ok(true));
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700);

        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            check_dir(&d, uid()).unwrap_err().why,
            "its mode is not 0700"
        );
        assert!(ensure_dir(&d, uid()).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            check_dir(&d, uid() + 1).unwrap_err().why,
            "another user owns it"
        );
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert_eq!(
            check_dir(&link, uid()).unwrap_err().why,
            "it is a symbolic link"
        );
        let f = t.path().join("file");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(
            check_dir(&f, uid()).unwrap_err().why,
            "it is not a directory"
        );
        assert!(ensure_dir(&t.path().join("missing/vault"), uid()).is_err());
    }

    #[test]
    fn socket_checks() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(SOCKET_NAME);
        assert_eq!(check_socket(&p, uid()), Ok(false));
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert_eq!(check_socket(&p, uid()), Ok(true));
        assert!(check_socket(&p, uid() + 1).is_err());
        let f = t.path().join("file");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(
            check_socket(&f, uid()).unwrap_err().why,
            "it is not a socket"
        );
        assert!(identity(&p).is_some());
        std::fs::remove_file(&p).unwrap();
        assert_eq!(identity(&p), None);
    }

    #[test]
    fn the_peer_is_this_user() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a), Some(uid()));
        assert_eq!(peer_uid(&b), Some(uid()));
    }
}
