//! Process hardening for the processes that hold secrets for longer than one command: the agent
//! and the clipboard helper. Neither function reports a failure to its caller, because each step
//! only narrows what another process of the same user can read, and the process works without it.

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// The smallest `RLIMIT_MEMLOCK` at which [`lock_memory`] locks: a background sync parses a vault
/// file of up to 16 MiB and holds several copies of it, and with future mappings locked, an
/// allocation past the limit fails and aborts the process.
pub const MEMLOCK_MIN: u64 = 256 * 1024 * 1024;

/// Turns off core files (`RLIMIT_CORE` 0) and makes the process not dumpable
/// (`PR_SET_DUMPABLE` 0), which also refuses `ptrace` and `/proc/<pid>/mem` to other processes of
/// the same user.
pub fn harden_process() {
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    let _ = setrlimit(Resource::Core, zero);
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
}

/// Locks all current and future memory of the process against swapping when the memory lock
/// limit allows, and reports whether it did. The soft limit is raised to the hard limit first.
/// Pages are locked as they are touched (`MCL_ONFAULT`), so reserved but unused stacks cost
/// nothing.
pub fn lock_memory() -> bool {
    let limit = getrlimit(Resource::Memlock);
    let raised = Rlimit {
        current: limit.maximum,
        maximum: limit.maximum,
    };
    let _ = setrlimit(Resource::Memlock, raised);
    if !limit_allows(getrlimit(Resource::Memlock).current) {
        return false;
    }
    use rustix::mm::MlockAllFlags as F;
    rustix::mm::mlockall(F::CURRENT | F::FUTURE | F::ONFAULT).is_ok()
}

/// Whether a memory lock limit (`None` for unlimited) is large enough to lock everything.
pub fn limit_allows(limit: Option<u64>) -> bool {
    limit.is_none_or(|l| l >= MEMLOCK_MIN)
}

/// A buffer for a secret in its own anonymous mapping: locked against swapping when the memory
/// lock limit allows, excluded from core dumps (`MADV_DONTDUMP`), and zeroed when dropped. It
/// is used where [`lock_memory`] cannot lock everything, and costs one page when it can.
pub struct LockedBuf {
    map: memmap2::MmapMut,
    len: usize,
}

impl LockedBuf {
    /// A zeroed buffer of `len` bytes.
    pub fn new(len: usize) -> std::io::Result<LockedBuf> {
        let map = memmap2::MmapMut::map_anon(len.max(1))?;
        let _ = map.lock();
        let _ = map.advise(memmap2::Advice::DontDump);
        Ok(LockedBuf { map, len })
    }
}

impl std::ops::Deref for LockedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.map[..self.len]
    }
}

impl std::ops::DerefMut for LockedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.map[..self.len]
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.map[..]);
    }
}

/// Marks file descriptor `fd` close-on-exec, so no child process inherits it.
pub fn set_cloexec(fd: i32) -> std::io::Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(std::io::Error::from)?;
    let flags = FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(std::io::Error::from)?;
    Ok(())
}

/// Marks every open file descriptor above 2 close-on-exec, so that the agent, the clipboard
/// helper, and the editor inherit only standard input, output, and error. Called before each
/// of those starts; descriptors the process opened itself are close-on-exec already, so this
/// catches those inherited from the parent, such as the `--password-fd` descriptor.
pub fn close_on_exec_all() {
    let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
        return;
    };
    for entry in dir.flatten() {
        if let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
            && fd > 2
        {
            let _ = set_cloexec(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_gate_needs_the_minimum_or_unlimited() {
        assert!(limit_allows(None));
        assert!(limit_allows(Some(MEMLOCK_MIN)));
        assert!(limit_allows(Some(u64::MAX)));
        assert!(!limit_allows(Some(MEMLOCK_MIN - 1)));
        assert!(!limit_allows(Some(8 * 1024 * 1024)));
        assert!(!limit_allows(Some(0)));
    }

    #[test]
    fn locked_buffers_hold_and_zero_their_bytes() {
        let mut b = LockedBuf::new(48).unwrap();
        assert_eq!(b.len(), 48);
        assert!(b.iter().all(|&x| x == 0));
        b.copy_from_slice(&[7; 48]);
        assert_eq!(&b[..], &[7; 48]);
        assert_eq!(LockedBuf::new(0).unwrap().len(), 0);
    }

    #[test]
    fn children_inherit_no_descriptor_above_2() {
        use nix::fcntl::{FcntlArg, fcntl};
        // A descriptor without close-on-exec, as a shell passes for --password-fd.
        let f = std::fs::File::open("/dev/null").unwrap();
        let leaked = fcntl(std::os::fd::AsRawFd::as_raw_fd(&f), FcntlArg::F_DUPFD(200)).unwrap();
        let listing = || {
            let out = std::process::Command::new("ls")
                .arg("/proc/self/fd")
                .output()
                .unwrap();
            String::from_utf8(out.stdout)
                .unwrap()
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert!(listing().contains(&leaked.to_string()));
        close_on_exec_all();
        let fds = listing();
        assert!(!fds.contains(&leaked.to_string()), "{fds:?}");
        let _ = nix::unistd::close(leaked);
    }

    #[test]
    fn a_hardened_child_is_not_dumpable() {
        // Hardening the test process itself would affect other tests, so a child checks it.
        if std::env::var_os("VAULT_HARDEN_CHILD").is_some() {
            harden_process();
            let d = rustix::process::dumpable_behavior().unwrap();
            assert_eq!(d, rustix::process::DumpableBehavior::NotDumpable);
            assert_eq!(getrlimit(Resource::Core).current, Some(0));
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "harden::tests::a_hardened_child_is_not_dumpable",
                "--nocapture",
            ])
            .env("VAULT_HARDEN_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
