//! Editor files for `vault edit` and `vault add -e`: the item text form in a new mode `0700`
//! directory under `$XDG_RUNTIME_DIR/vault/` on a `tmpfs`, edited with `$VISUAL`, `$EDITOR`, or
//! `vi`, and overwritten with zeros and removed with its directory on every path.

use crate::signals::{self, Deferral};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroizing;

/// The `statfs` magic number of `tmpfs`.
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The editor file's name.
pub const FILE_NAME: &str = "item.toml";

/// The largest edited file read back, in bytes.
pub const EDIT_MAX: u64 = 1024 * 1024;

/// Vi, Vim, and Neovim: no swap file (`-n`), no viminfo or ShaDa file (`-i NONE`), and no backup,
/// undo, or swap files or modelines, set before the user's `vimrc` and again after it.
const VIM_FLAGS: &str = "-n -i NONE \
    --cmd 'set nobackup nowritebackup noundofile noswapfile nomodeline' \
    -c 'set nobackup nowritebackup noundofile noswapfile nomodeline'";

/// Emacs: no backup files, auto-save, lock files, or file-local variables.
const EMACS_FLAGS: &str = "--eval '(setq make-backup-files nil auto-save-default nil \
    auto-save-list-file-prefix nil create-lockfiles nil enable-local-variables nil)'";

/// An editor file failure. Messages never contain the file's content.
#[derive(Debug)]
pub enum EditorError {
    /// `$XDG_RUNTIME_DIR` is not set, or not an absolute path.
    NoRuntimeDir,
    /// The editor directory is not on a `tmpfs`.
    NotTmpfs,
    /// `$XDG_RUNTIME_DIR/vault/` is not a directory of this user with mode `0700`.
    UnsafeDir(PathBuf, &'static str),
    /// The editor could not start, or exited with an error.
    EditorFailed(String),
    /// The edited file is larger than [`EDIT_MAX`], or not a regular file.
    BadFile,
    /// A termination signal arrived while the editor ran.
    Interrupted,
    /// Creating, reading, or removing the file failed.
    Io(std::io::Error),
}

impl EditorError {
    /// The exit code: always 1.
    pub fn exit_code(&self) -> u8 {
        1
    }
}

impl fmt::Display for EditorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditorError::NoRuntimeDir => {
                f.write_str("editing needs $XDG_RUNTIME_DIR, an absolute path on a tmpfs")
            }
            EditorError::NotTmpfs => f.write_str(
                "$XDG_RUNTIME_DIR is not on a tmpfs, so the editor file could reach the disk; \
                 nothing was written",
            ),
            EditorError::UnsafeDir(p, why) => {
                write!(f, "{} is not safe for the editor file: {why}", p.display())
            }
            EditorError::EditorFailed(why) => write!(f, "{why}; nothing was saved"),
            EditorError::BadFile => {
                f.write_str("the edited file is too large or not a regular file")
            }
            EditorError::Interrupted => f.write_str("interrupted; nothing was saved"),
            EditorError::Io(e) => write!(f, "cannot use the editor file: {e}"),
        }
    }
}

impl std::error::Error for EditorError {}

impl From<rustix::io::Errno> for EditorError {
    fn from(e: rustix::io::Errno) -> Self {
        EditorError::Io(e.into())
    }
}

impl From<std::io::Error> for EditorError {
    fn from(e: std::io::Error) -> Self {
        EditorError::Io(e)
    }
}

/// Edits `initial` in the user's editor and returns the saved bytes. The caller compares them
/// with `initial` to tell an unchanged file.
pub fn edit(initial: &[u8]) -> Result<Zeroizing<Vec<u8>>, EditorError> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(EditorError::NoRuntimeDir)?;
    let command = EditorCommand::from_env();
    edit_with(&runtime, initial, &mut |path, deferral| {
        command.run(path, deferral)
    })
}

/// Creates the file under `runtime`, runs `run` on its path, and reads it back. Termination
/// signals are deferred until the file is gone.
fn edit_with(
    runtime: &Path,
    initial: &[u8],
    run: &mut dyn FnMut(&Path, &Deferral) -> Result<(), EditorError>,
) -> Result<Zeroizing<Vec<u8>>, EditorError> {
    let deferral = signals::defer();
    let result = (|| {
        let file = EditorFile::create(runtime, initial)?;
        run(&file.path, &deferral)?;
        file.read()
    })();
    // The file is wiped and removed by now; a deferred signal is delivered here.
    drop(deferral);
    result
}

/// The editor file and its directory; dropping it overwrites every file in the directory with
/// zeros and removes them and the directory.
struct EditorFile {
    base: OwnedFd,
    dir: OwnedFd,
    dir_name: String,
    path: PathBuf,
}

impl EditorFile {
    fn create(runtime: &Path, content: &[u8]) -> Result<EditorFile, EditorError> {
        let base_path = runtime.join("vault");
        let base = open_private_dir(&base_path)?;
        remove_stale(&base, &base_path);
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random)
            .map_err(|_| EditorError::Io(std::io::Error::other("no random numbers")))?;
        let dir_name = format!("edit-{}-{}", std::process::id(), hex::encode(random));
        rustix::fs::mkdirat(&base, dir_name.as_str(), Mode::from_raw_mode(0o700))?;
        let dir = match rustix::fs::openat(
            &base,
            dir_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = rustix::fs::unlinkat(&base, dir_name.as_str(), AtFlags::REMOVEDIR);
                return Err(e.into());
            }
        };
        let file = EditorFile {
            path: base_path.join(&dir_name).join(FILE_NAME),
            base,
            dir,
            dir_name,
        };
        // From here on, dropping `file` cleans up.
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
        let fs_type = rustix::fs::fstatfs(&file.dir)?.f_type as u64;
        if fs_type != TMPFS_MAGIC {
            return Err(EditorError::NotTmpfs);
        }
        let fd = rustix::fs::openat(
            &file.dir,
            FILE_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let mut f = File::from(fd);
        f.write_all(content)?;
        Ok(file)
    }

    /// Reads the file back by name, because editors often replace the file rather than write
    /// it in place.
    fn read(&self) -> Result<Zeroizing<Vec<u8>>, EditorError> {
        let fd = rustix::fs::openat(
            &self.dir,
            FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP => EditorError::BadFile,
            e => e.into(),
        })?;
        let mut f = File::from(fd);
        let m = f.metadata()?;
        if !m.is_file() || m.len() > EDIT_MAX {
            return Err(EditorError::BadFile);
        }
        // Reserved up front, so the buffer does not reallocate and leave a copy behind.
        let mut out = Zeroizing::new(Vec::with_capacity(m.len() as usize + 1));
        Read::by_ref(&mut f)
            .take(EDIT_MAX + 1)
            .read_to_end(&mut out)?;
        if out.len() as u64 > EDIT_MAX {
            return Err(EditorError::BadFile);
        }
        Ok(out)
    }
}

impl Drop for EditorFile {
    fn drop(&mut self) {
        let base_path = self
            .path
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("/"));
        remove_edit_dir(&self.base, base_path, &self.dir_name);
    }
}

/// Overwrites every file in the edit directory `name` under `base` with zeros, and removes them
/// and the directory. A directory that is not this user's, or a symbolic link, is left alone.
fn remove_edit_dir(base: &OwnedFd, base_path: &Path, name: &str) {
    let Ok(dir) = rustix::fs::openat(
        base,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return;
    };
    if !rustix::fs::fstat(&dir).is_ok_and(|st| st.st_uid == rustix::process::getuid().as_raw()) {
        return;
    }
    let mut names = Vec::new();
    if let Ok(mut d) = rustix::fs::Dir::read_from(&dir) {
        while let Some(Ok(e)) = d.read() {
            let entry = e.file_name().to_owned();
            if entry.as_bytes() != b"." && entry.as_bytes() != b".." {
                names.push((entry, e.file_type()));
            }
        }
    }
    for (entry, kind) in names {
        if kind == FileType::Directory {
            let _ = std::fs::remove_dir_all(
                base_path.join(name).join(entry.to_string_lossy().as_ref()),
            );
            continue;
        }
        wipe(&dir, &entry);
        let _ = rustix::fs::unlinkat(&dir, entry.as_c_str(), AtFlags::empty());
    }
    let _ = rustix::fs::unlinkat(base, name, AtFlags::REMOVEDIR);
}

/// How old an edit directory of a live process must be before it counts as stale.
const STALE_AGE: Duration = Duration::from_secs(3600);

/// Wipes and removes the edit directories that a killed process left behind: those whose
/// creator (the process ID in the name `edit-<pid>-<random>`) no longer runs, and those older
/// than [`STALE_AGE`] whose creator is not a `vault` process, because its process ID was reused.
/// A long edit by a running `vault` is left alone.
fn remove_stale(base: &OwnedFd, base_path: &Path) {
    let Ok(entries) = std::fs::read_dir(base_path) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("edit-") else {
            continue;
        };
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_AGE);
        let creator = rest
            .split_once('-')
            .and_then(|(pid, _)| pid.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw);
        let stale = match creator {
            Some(pid) if pid.as_raw_nonzero().get() as u32 == std::process::id() => false,
            Some(pid) => match rustix::process::test_kill_process(pid) {
                Err(rustix::io::Errno::SRCH) => true,
                _ => old && !is_vault_process(pid),
            },
            // A name without a process ID: only its age tells.
            None => old,
        };
        if stale {
            remove_edit_dir(base, base_path, &name);
        }
    }
}

fn is_vault_process(pid: rustix::process::Pid) -> bool {
    std::fs::read_to_string(format!("/proc/{}/comm", pid.as_raw_nonzero()))
        .is_ok_and(|c| c.trim_end() == "vault")
}

/// Overwrites a regular file in `dir` with zeros and syncs it; anything else is left alone.
fn wipe(dir: &OwnedFd, name: &std::ffi::CStr) {
    let Ok(fd) = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) else {
        return;
    };
    let mut f = File::from(fd);
    let Ok(m) = f.metadata() else { return };
    if !m.is_file() {
        return;
    }
    let zeros = [0u8; 16 * 1024];
    let mut left = m.len();
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        if f.write_all(&zeros[..n]).is_err() {
            break;
        }
        left -= n as u64;
    }
    let _ = f.sync_all();
}

/// Creates `path` with mode `0700` if it is missing, checks with `lstat` that it is a directory
/// of this user with mode `0700`, and opens it without following links, checking that the
/// opened directory is the one `lstat` saw.
fn open_private_dir(path: &Path) -> Result<OwnedFd, EditorError> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let unsafe_dir = |why| EditorError::UnsafeDir(path.to_owned(), why);
    let m = std::fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() {
        return Err(unsafe_dir("it is a symbolic link"));
    }
    if !m.is_dir() {
        return Err(unsafe_dir("it is not a directory"));
    }
    if m.uid() != rustix::process::getuid().as_raw() {
        return Err(unsafe_dir("another user owns it"));
    }
    if m.mode() & 0o7777 != 0o700 {
        return Err(unsafe_dir("its mode is not 0700"));
    }
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let st = rustix::fs::fstat(&fd)?;
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    if st.st_dev as u64 != m.dev() || st.st_ino as u64 != m.ino() {
        return Err(unsafe_dir("it changed while it was checked"));
    }
    Ok(fd)
}

/// The editors that get flags turning off their side files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Vim,
    Emacs,
    Other,
}

/// The kind of the program an editor setting runs, skipping a leading `env` and `NAME=value`
/// words. Vim and Neovim (names starting `vim`, `nvim`, `gvim`, or `mvim`) get the Vim flags;
/// `vi`, `view`, and `ex` get them only when they resolve to one of those, because nvi and
/// BusyBox vi reject the flags.
fn kind(setting: &str) -> Kind {
    kind_with(setting, &resolve)
}

fn kind_with(setting: &str, resolve: &dyn Fn(&str) -> Option<PathBuf>) -> Kind {
    let program = setting
        .split_whitespace()
        .find(|w| *w != "env" && !w.contains('='))
        .unwrap_or_default();
    let base = program.rsplit('/').next().unwrap_or_default();
    let vim = |name: &str| {
        ["vim", "nvim", "gvim", "mvim"]
            .iter()
            .any(|p| name.starts_with(p))
    };
    if vim(base) {
        Kind::Vim
    } else if matches!(base, "vi" | "view" | "ex") {
        let target = resolve(program);
        let target = target
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if vim(target) { Kind::Vim } else { Kind::Other }
    } else if base.starts_with("emacs") && !base.starts_with("emacsclient") {
        Kind::Emacs
    } else {
        Kind::Other
    }
}

/// The file `program` runs, found in `$PATH` when it has no `/`, with every symbolic link
/// followed (such as `/usr/bin/vi` through `/etc/alternatives/vi` to `/usr/bin/vim.basic`).
fn resolve(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return std::fs::canonicalize(program).ok();
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
        .and_then(|p| std::fs::canonicalize(p).ok())
}

/// The editor: `$VISUAL`, then `$EDITOR`, then `vi`; an empty variable counts as unset.
struct EditorCommand {
    visual: Option<OsString>,
    editor: Option<OsString>,
}

impl EditorCommand {
    fn from_env() -> EditorCommand {
        EditorCommand {
            visual: std::env::var_os("VISUAL"),
            editor: std::env::var_os("EDITOR"),
        }
    }

    /// The `sh -c` script: the variable is expanded by the shell, so a setting may carry
    /// arguments, and the path is `"$1"`.
    fn script(&self) -> String {
        let set = |v: &Option<OsString>| v.as_ref().filter(|v| !v.is_empty()).cloned();
        let (program, setting) = match (set(&self.visual), set(&self.editor)) {
            (Some(v), _) => ("$VISUAL", v),
            (None, Some(e)) => ("$EDITOR", e),
            (None, None) => ("vi", OsString::from("vi")),
        };
        let flags = match kind(&setting.to_string_lossy()) {
            Kind::Vim => VIM_FLAGS,
            Kind::Emacs => EMACS_FLAGS,
            Kind::Other => "",
        };
        if flags.is_empty() {
            format!("{program} \"$1\"")
        } else {
            format!("{program} {flags} \"$1\"")
        }
    }

    /// Runs the editor on `path` and waits for it. `SIGINT` and `SIGQUIT`, which the terminal
    /// also sends to the editor, are ignored; `SIGTERM` or `SIGHUP` passes `SIGTERM` on to the
    /// editor and ends the edit.
    fn run(&self, path: &Path, deferral: &Deferral) -> Result<(), EditorError> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(self.script()).arg("sh").arg(path);
        for (name, value) in [("VISUAL", &self.visual), ("EDITOR", &self.editor)] {
            match value {
                Some(v) => cmd.env(name, v),
                None => cmd.env_remove(name),
            };
        }
        crate::harden::close_on_exec_all();
        let mut child = cmd
            .spawn()
            .map_err(|e| EditorError::EditorFailed(format!("cannot start the editor: {e}")))?;
        let mut terminated = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            match deferral.caught() {
                Some(signal_hook::consts::SIGINT | signal_hook::consts::SIGQUIT) => {
                    deferral.forget()
                }
                Some(_) if !terminated => {
                    terminated = true;
                    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                    }
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if terminated {
            return Err(EditorError::Interrupted);
        }
        if !status.success() {
            return Err(EditorError::EditorFailed(format!(
                "the editor exited with {status}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A runtime directory on a `tmpfs` (`/dev/shm`), or `None` where there is none.
    fn tmpfs_runtime() -> Option<tempfile::TempDir> {
        let t = tempfile::tempdir_in("/dev/shm").ok()?;
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
        let on_tmpfs = rustix::fs::statfs(t.path()).ok()?.f_type as u64 == TMPFS_MAGIC;
        on_tmpfs.then_some(t)
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// The entries of the `vault` directory, which is empty after every edit.
    fn leftovers(runtime: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(runtime.join("vault"))
            .map(|rd| rd.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_file_is_private_and_removed_after_an_edit() {
        let Some(rt) = tmpfs_runtime() else { return };
        let mut seen = None;
        let out = edit_with(rt.path(), b"name = \"old\"\n", &mut |path, _| {
            assert_eq!(path.file_name().unwrap(), FILE_NAME);
            assert_eq!(mode(path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
            assert_eq!(mode(&rt.path().join("vault")), 0o700);
            assert_eq!(std::fs::read(path).unwrap(), b"name = \"old\"\n");
            // Replace the file, as many editors do, and leave a swap file behind.
            std::fs::write(path.with_file_name(".item.toml.swp"), b"leftover").unwrap();
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, b"name = \"new\"\n").unwrap();
            seen = Some(path.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(out.as_slice(), b"name = \"new\"\n");
        let path = seen.unwrap();
        assert!(!path.parent().unwrap().exists());
        assert!(leftovers(rt.path()).is_empty());
    }

    #[test]
    fn stale_edit_directories_are_wiped() {
        let Some(rt) = tmpfs_runtime() else { return };
        let base = rt.path().join("vault");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let dead = gone.id();
        gone.wait().unwrap();
        let make = |name: &str, age: Duration| {
            let d = base.join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join(FILE_NAME), b"plaintext").unwrap();
            let t = std::time::SystemTime::now() - age;
            std::fs::File::open(&d)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(t))
                .unwrap();
            d
        };
        let hour = Duration::from_secs(7200);
        let dead_dir = make(&format!("edit-{dead}-aa"), Duration::ZERO);
        let old_unnamed = make("edit-bbbb", hour);
        let fresh_unnamed = make("edit-cccc", Duration::ZERO);
        // The test process is not named `vault`, so an old directory of it counts as reused.
        let parent = std::os::unix::process::parent_id();
        let old_other = make(&format!("edit-{parent}-dd"), hour);
        let fresh_other = make(&format!("edit-{parent}-ee"), Duration::ZERO);
        let unrelated = make("other", hour);
        edit_with(rt.path(), b"x", &mut |_, _| Ok(())).unwrap();
        assert!(!dead_dir.exists());
        assert!(!old_unnamed.exists());
        assert!(fresh_unnamed.exists());
        assert!(!old_other.exists());
        assert!(fresh_other.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn the_editor_inherits_no_extra_descriptors() {
        let Some(rt) = tmpfs_runtime() else { return };
        use nix::fcntl::{FcntlArg, fcntl};
        let f = std::fs::File::open("/dev/null").unwrap();
        let leaked = fcntl(std::os::fd::AsRawFd::as_raw_fd(&f), FcntlArg::F_DUPFD(300)).unwrap();
        let script_dir = tempfile::tempdir().unwrap();
        let script = script_dir.path().join("list-fds");
        std::fs::write(&script, "#!/bin/sh\nls /proc/$$/fd > \"$1\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cmd = EditorCommand {
            visual: Some(script.into_os_string()),
            editor: None,
        };
        let out = edit_with(rt.path(), b"", &mut |p, d| cmd.run(p, d)).unwrap();
        let listing = String::from_utf8_lossy(&out).into_owned();
        let _ = nix::unistd::close(leaked);
        assert!(!listing.is_empty());
        assert!(
            !listing.split_whitespace().any(|n| n == leaked.to_string()),
            "{listing:?}"
        );
    }

    #[test]
    fn a_failing_editor_still_removes_the_file() {
        let Some(rt) = tmpfs_runtime() else { return };
        let mut seen = None;
        let r = edit_with(rt.path(), b"secret", &mut |path, _| {
            seen = Some(path.to_owned());
            Err(EditorError::EditorFailed("boom".into()))
        });
        assert!(matches!(r, Err(EditorError::EditorFailed(_))));
        assert!(!seen.unwrap().exists());
        assert!(leftovers(rt.path()).is_empty());
    }

    #[test]
    fn a_link_or_oversized_file_is_refused_and_removed() {
        let Some(rt) = tmpfs_runtime() else { return };
        let outside = rt.path().join("outside");
        std::fs::write(&outside, b"other").unwrap();
        let r = edit_with(rt.path(), b"x", &mut |path, _| {
            std::fs::remove_file(path).unwrap();
            std::os::unix::fs::symlink(&outside, path).unwrap();
            Ok(())
        });
        assert!(matches!(r, Err(EditorError::BadFile)));
        assert_eq!(std::fs::read(&outside).unwrap(), b"other");
        assert!(leftovers(rt.path()).is_empty());

        let r = edit_with(rt.path(), b"x", &mut |path, _| {
            std::fs::write(path, vec![b'a'; EDIT_MAX as usize + 1]).unwrap();
            Ok(())
        });
        assert!(matches!(r, Err(EditorError::BadFile)));
        assert!(leftovers(rt.path()).is_empty());
    }

    #[test]
    fn a_disk_directory_is_refused() {
        let disk = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
        if rustix::fs::statfs(disk.path()).unwrap().f_type as u64 == TMPFS_MAGIC {
            return;
        }
        let mut ran = false;
        let r = edit_with(disk.path(), b"secret", &mut |_, _| {
            ran = true;
            Ok(())
        });
        assert!(matches!(r, Err(EditorError::NotTmpfs)));
        assert!(!ran);
        assert!(leftovers(disk.path()).is_empty());
    }

    #[test]
    fn unsafe_vault_directories_are_refused() {
        let Some(rt) = tmpfs_runtime() else { return };
        let base = rt.path().join("vault");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut run = |_: &Path, _: &Deferral| -> Result<(), EditorError> {
            panic!("the editor must not run")
        };
        assert!(matches!(
            edit_with(rt.path(), b"x", &mut run),
            Err(EditorError::UnsafeDir(_, "its mode is not 0700"))
        ));
        std::fs::remove_dir(&base).unwrap();
        let elsewhere = rt.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &base).unwrap();
        assert!(matches!(
            edit_with(rt.path(), b"x", &mut run),
            Err(EditorError::UnsafeDir(_, "it is a symbolic link"))
        ));
        std::fs::remove_file(&base).unwrap();
        std::fs::write(&base, b"").unwrap();
        assert!(matches!(
            edit_with(rt.path(), b"x", &mut run),
            Err(EditorError::UnsafeDir(_, "it is not a directory"))
        ));
    }

    #[test]
    fn a_missing_runtime_directory_fails() {
        let r = edit_with(Path::new("/nonexistent/runtime"), b"x", &mut |_, _| Ok(()));
        assert!(matches!(r, Err(EditorError::Io(_))));
    }

    #[test]
    fn editor_kinds() {
        for v in [
            "vim",
            "/usr/bin/nvim -p",
            "vim.basic",
            "gvim -f",
            "env TERM=xterm vim",
        ] {
            assert_eq!(kind(v), Kind::Vim, "{v}");
        }
        // vi, view, and ex count as Vim only when they resolve to it.
        let to = |target: &'static str| move |_: &str| Some(PathBuf::from(target));
        assert_eq!(kind_with("vi", &to("/usr/bin/vim.basic")), Kind::Vim);
        assert_eq!(kind_with("/usr/bin/view", &to("/usr/bin/nvim")), Kind::Vim);
        assert_eq!(kind_with("vi", &to("/usr/bin/busybox")), Kind::Other);
        assert_eq!(kind_with("vi", &to("/usr/bin/nvi")), Kind::Other);
        assert_eq!(kind_with("ex", &|_| None), Kind::Other);
        assert_eq!(kind("nvi"), Kind::Other);
        for v in ["emacs -nw", "/usr/bin/emacs", "emacs-nox"] {
            assert_eq!(kind(v), Kind::Emacs, "{v}");
        }
        for v in [
            "emacsclient -t",
            "nano",
            "code --wait",
            "env EDITOR=vim nano",
            "",
        ] {
            assert_eq!(kind(v), Kind::Other, "{v}");
        }
    }

    #[test]
    fn scripts() {
        let c = |visual: Option<&str>, editor: Option<&str>| EditorCommand {
            visual: visual.map(OsString::from),
            editor: editor.map(OsString::from),
        };
        assert_eq!(c(Some("nano"), Some("vim")).script(), "$VISUAL \"$1\"");
        assert_eq!(c(Some(""), Some("nano")).script(), "$EDITOR \"$1\"");
        assert_eq!(
            c(None, Some("nvim")).script(),
            format!("$EDITOR {VIM_FLAGS} \"$1\"")
        );
        let vi = if kind("vi") == Kind::Vim {
            format!("vi {VIM_FLAGS} \"$1\"")
        } else {
            "vi \"$1\"".to_owned()
        };
        assert_eq!(c(None, None).script(), vi);
        assert_eq!(
            c(Some("emacs -nw"), None).script(),
            format!("$VISUAL {EMACS_FLAGS} \"$1\"")
        );
    }

    #[test]
    fn a_real_editor_runs_through_the_shell() {
        let Some(rt) = tmpfs_runtime() else { return };
        // `sed -i` writes a new file and renames it over the old one, as many editors do; the
        // variable's words split into the program and its arguments.
        let cmd = EditorCommand {
            visual: None,
            editor: Some("sed -i s/old/new/".into()),
        };
        let out = edit_with(rt.path(), b"old value\n", &mut |p, d| cmd.run(p, d)).unwrap();
        assert_eq!(out.as_slice(), b"new value\n");
        assert!(leftovers(rt.path()).is_empty());

        let failing = EditorCommand {
            visual: Some("false".into()),
            editor: None,
        };
        let r = edit_with(rt.path(), b"x", &mut |p, d| failing.run(p, d));
        assert!(matches!(r, Err(EditorError::EditorFailed(_))));
        assert!(leftovers(rt.path()).is_empty());
    }
}
