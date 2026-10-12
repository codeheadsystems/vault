//! Deferred termination signals, for the stretches in which a command holds state it must undo
//! before it ends: a terminal without echo, or an editor file holding plaintext.
//!
//! The handlers are registered once per process. Outside a [`Deferral`], `SIGINT`, `SIGTERM`,
//! `SIGHUP`, and `SIGQUIT` keep their default action. Inside one, they are recorded instead; the
//! owner polls [`Deferral::caught`], cleans up, and drops the deferral, which delivers the
//! recorded signal with its default action.
//!
//! A deferral made with [`defer_with_stops`] also holds back the job control stops `SIGTSTP`,
//! `SIGTTIN`, and `SIGTTOU`: the owner polls [`Deferral::take_stop`], undoes its state, stops
//! with [`Deferral::stop_now`], and sets its state up again when the process continues.

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The signals a deferral holds back.
const SIGNALS: [i32; 4] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT];
/// The stop signals a deferral with stops holds back.
const STOPS: [i32; 3] = [SIGTSTP, SIGTTIN, SIGTTOU];

struct Handlers {
    /// When set, a signal takes its default action at once.
    armed: Arc<AtomicBool>,
    /// The last signal caught while disarmed, or 0.
    caught: Arc<AtomicUsize>,
    /// When set, a stop signal stops the process at once.
    stop_armed: Arc<AtomicBool>,
    /// Whether a stop signal arrived while disarmed.
    stopped: Arc<AtomicBool>,
    /// Serialises deferrals, so that two never disarm and re-arm over each other.
    owner: Mutex<()>,
}

fn handlers() -> &'static Handlers {
    static HANDLERS: OnceLock<Handlers> = OnceLock::new();
    HANDLERS.get_or_init(|| {
        let h = Handlers {
            armed: Arc::new(AtomicBool::new(true)),
            caught: Arc::new(AtomicUsize::new(0)),
            stop_armed: Arc::new(AtomicBool::new(true)),
            stopped: Arc::new(AtomicBool::new(false)),
            owner: Mutex::new(()),
        };
        for sig in SIGNALS {
            let _ = signal_hook::flag::register_usize(sig, Arc::clone(&h.caught), sig as usize);
            let _ = signal_hook::flag::register_conditional_default(sig, Arc::clone(&h.armed));
        }
        for sig in STOPS {
            let _ = signal_hook::flag::register(sig, Arc::clone(&h.stopped));
            let _ = signal_hook::flag::register_conditional_default(sig, Arc::clone(&h.stop_armed));
        }
        h
    })
}

/// Holds back termination signals, and with [`defer_with_stops`] stop signals, until dropped.
pub struct Deferral {
    stops: bool,
    _owner: std::sync::MutexGuard<'static, ()>,
}

/// Starts deferring termination signals.
pub fn defer() -> Deferral {
    start(false)
}

/// Starts deferring termination and stop signals.
pub fn defer_with_stops() -> Deferral {
    start(true)
}

fn start(stops: bool) -> Deferral {
    let h = handlers();
    let owner = h.owner.lock().unwrap_or_else(|p| p.into_inner());
    h.caught.store(0, Ordering::SeqCst);
    h.armed.store(false, Ordering::SeqCst);
    if stops {
        h.stopped.store(false, Ordering::SeqCst);
        h.stop_armed.store(false, Ordering::SeqCst);
    }
    Deferral {
        stops,
        _owner: owner,
    }
}

impl Deferral {
    /// The signal caught since the deferral began, if any.
    pub fn caught(&self) -> Option<i32> {
        match handlers().caught.load(Ordering::SeqCst) {
            0 => None,
            s => i32::try_from(s).ok(),
        }
    }

    /// Forgets a caught signal, for a signal the owner handles itself (the editor ignores
    /// `SIGINT`, which the terminal also sends to the editor).
    pub fn forget(&self) {
        handlers().caught.store(0, Ordering::SeqCst);
    }

    /// Whether a stop signal arrived since the last call; always `false` without stops.
    pub fn take_stop(&self) -> bool {
        self.stops && handlers().stopped.swap(false, Ordering::SeqCst)
    }

    /// Stops the process with `SIGSTOP`; returns when it continues.
    pub fn stop_now(&self) {
        let _ = signal_hook::low_level::raise(SIGSTOP);
    }
}

impl Drop for Deferral {
    fn drop(&mut self) {
        let h = handlers();
        if self.stops {
            h.stop_armed.store(true, Ordering::SeqCst);
            if h.stopped.swap(false, Ordering::SeqCst) {
                let _ = signal_hook::low_level::raise(SIGSTOP);
            }
        }
        h.armed.store(true, Ordering::SeqCst);
        if let Some(sig) = self.caught() {
            h.caught.store(0, Ordering::SeqCst);
            let _ = signal_hook::low_level::raise(sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_waits_for_the_end_of_the_deferral() {
        // Raising a terminating signal ends the process, so a child runs the check.
        if std::env::var_os("VAULT_SIGNALS_CHILD").is_some() {
            let d = defer();
            signal_hook::low_level::raise(SIGTERM).unwrap();
            assert_eq!(d.caught(), Some(SIGTERM));
            println!("survived");
            drop(d);
            println!("not reached");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "signals::tests::a_signal_waits_for_the_end_of_the_deferral",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("VAULT_SIGNALS_CHILD", "1")
            .output()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(out.status.signal(), Some(SIGTERM));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("survived"));
        assert!(!stdout.contains("not reached"));
    }

    #[test]
    fn a_forgotten_signal_is_not_delivered() {
        if std::env::var_os("VAULT_SIGNALS_CHILD").is_some() {
            let d = defer();
            signal_hook::low_level::raise(SIGINT).unwrap();
            assert_eq!(d.caught(), Some(SIGINT));
            d.forget();
            drop(d);
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "signals::tests::a_forgotten_signal_is_not_delivered",
            ])
            .env("VAULT_SIGNALS_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
