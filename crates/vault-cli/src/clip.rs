//! The clipboard: `show -c` and `gen -c` start a helper process (`vault clip`) that owns the
//! clipboard, offers the value with the `x-kde-passwordManagerHint` type set to `secret`, and
//! after `clipboard.clear_after` clears the clipboard if it still holds the value.
//!
//! The value reaches the helper through its standard input. X11 and Wayland compositors with the
//! data control protocol go through `arboard`; other Wayland compositors use the X11 clipboard
//! through XWayland.

use crate::harden::LockedBuf;
use std::fmt;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

/// The largest value copied, in bytes.
pub const VALUE_MAX: usize = 64 * 1024;
/// How long a command waits for the helper to take the clipboard.
const START_WAIT: Duration = Duration::from_secs(5);

/// A clipboard failure. Messages never contain the value.
#[derive(Debug)]
pub enum ClipError {
    /// Neither `$WAYLAND_DISPLAY` nor `$DISPLAY` is set.
    NoDisplay,
    /// The value is larger than [`VALUE_MAX`].
    TooLarge,
    /// The clipboard refused, or the helper reported a failure.
    Clipboard(String),
    /// Starting or talking to the helper failed.
    Io(std::io::Error),
}

impl ClipError {
    /// The exit code: always 1.
    pub fn exit_code(&self) -> u8 {
        1
    }
}

impl fmt::Display for ClipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipError::NoDisplay => {
                f.write_str("no clipboard: neither $WAYLAND_DISPLAY nor $DISPLAY is set")
            }
            ClipError::TooLarge => f.write_str("the value is too large for the clipboard"),
            ClipError::Clipboard(why) => write!(f, "the clipboard failed: {why}"),
            ClipError::Io(e) => write!(f, "cannot start the clipboard helper: {e}"),
        }
    }
}

impl std::error::Error for ClipError {}

/// Copies `value` to the clipboard through a new `vault clip` helper, and returns once the
/// helper owns the clipboard; the helper clears it after `clear_after`.
pub fn copy(value: &str, clear_after: Duration) -> Result<(), ClipError> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return Err(ClipError::NoDisplay);
    }
    let message = encode_request(value, clear_after)?;
    let exe = std::env::current_exe().map_err(ClipError::Io)?;
    crate::harden::close_on_exec_all();
    let mut child = Command::new(exe)
        .arg("clip")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn()
        .map_err(ClipError::Io)?;
    let sent = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(&message).map_err(ClipError::Io),
        None => Err(ClipError::Clipboard("no pipe to the helper".into())),
    };
    drop(message);
    if let Err(e) = sent {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let Some(mut out) = child.stdout.take() else {
        return Err(ClipError::Clipboard("no pipe from the helper".into()));
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        let first = out.read(&mut b).ok().filter(|&n| n == 1).map(|_| b[0]);
        let mut message = String::new();
        if first == Some(b'E') {
            let _ = out.take(1024).read_to_string(&mut message);
        }
        let _ = tx.send((first, message));
    });
    match rx.recv_timeout(START_WAIT) {
        Ok((Some(b'R'), _)) => Ok(()),
        Ok((Some(b'E'), message)) => {
            let _ = child.wait();
            Err(ClipError::Clipboard(message))
        }
        Ok(_) => {
            let status = child.wait().map_err(ClipError::Io)?;
            Err(ClipError::Clipboard(format!(
                "the helper exited with {status}"
            )))
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(ClipError::Clipboard(
                "the helper did not start in time".into(),
            ))
        }
    }
}

/// The helper's request: `clear_after` in ms as a big-endian `u64`, the value's length as a
/// big-endian `u32`, and the value.
fn encode_request(value: &str, clear_after: Duration) -> Result<Zeroizing<Vec<u8>>, ClipError> {
    if value.len() > VALUE_MAX {
        return Err(ClipError::TooLarge);
    }
    let mut m = Zeroizing::new(Vec::with_capacity(12 + value.len()));
    let ms = u64::try_from(clear_after.as_millis()).unwrap_or(u64::MAX);
    m.extend_from_slice(&ms.to_be_bytes());
    m.extend_from_slice(&(value.len() as u32).to_be_bytes());
    m.extend_from_slice(value.as_bytes());
    Ok(m)
}

/// Reads a request; the value goes into a locked page, and is checked to be UTF-8.
fn read_request(r: &mut impl Read) -> Result<(LockedBuf, Duration), ClipError> {
    let bad = || ClipError::Clipboard("a malformed request".into());
    let mut head = [0u8; 12];
    r.read_exact(&mut head).map_err(|_| bad())?;
    let mut ms = [0u8; 8];
    ms.copy_from_slice(&head[..8]);
    let mut len = [0u8; 4];
    len.copy_from_slice(&head[8..]);
    let len = u32::from_be_bytes(len) as usize;
    if len > VALUE_MAX {
        return Err(ClipError::TooLarge);
    }
    let mut value = LockedBuf::new(len).map_err(ClipError::Io)?;
    r.read_exact(&mut value).map_err(|_| bad())?;
    if std::str::from_utf8(&value).is_err() {
        return Err(bad());
    }
    Ok((value, Duration::from_millis(u64::from_be_bytes(ms))))
}

/// `CLOCK_BOOTTIME`, which counts suspended time and ignores changes to the wall clock.
fn boot_time() -> Duration {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(
        u64::try_from(t.tv_sec).unwrap_or(0),
        u32::try_from(t.tv_nsec).unwrap_or(0),
    )
}

/// The longest single sleep: sleeps do not advance while the system is suspended, so the
/// deadline is checked against [`boot_time`] at least this often.
const SLEEP_STEP: Duration = Duration::from_secs(1);

/// The clipboard as the helper uses it.
trait Clipboard {
    /// Offers `value`, with the password manager hint, and keeps offering it while the
    /// clipboard object lives or until another program takes the clipboard.
    fn offer(&mut self, value: &str) -> Result<(), ClipError>;
    /// The clipboard's current text, if any.
    fn read(&mut self) -> Option<Zeroizing<String>>;
    /// Empties the clipboard.
    fn clear(&mut self) -> Result<(), ClipError>;
}

/// What became of a copied value.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// It was still on the clipboard, and was cleared.
    Cleared,
    /// Something else replaced it, and was left alone.
    Replaced,
}

/// Offers `value`, reports readiness, waits until `clear_after` has passed on `clock`, and
/// clears the clipboard only if it still holds `value`.
fn hold(
    cb: &mut dyn Clipboard,
    value: &str,
    clear_after: Duration,
    ready: &mut dyn FnMut(),
    clock: &mut dyn FnMut() -> Duration,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Outcome, ClipError> {
    cb.offer(value)?;
    ready();
    let deadline = clock().saturating_add(clear_after);
    loop {
        let left = deadline.saturating_sub(clock());
        if left.is_zero() {
            break;
        }
        sleep(left.min(SLEEP_STEP));
    }
    match cb.read() {
        Some(current) if current.as_str() == value => {
            cb.clear()?;
            Ok(Outcome::Cleared)
        }
        _ => Ok(Outcome::Replaced),
    }
}

/// The system clipboard through `arboard`.
struct SystemClipboard(arboard::Clipboard);

impl Clipboard for SystemClipboard {
    fn offer(&mut self, value: &str) -> Result<(), ClipError> {
        use arboard::SetExtLinux;
        self.0
            .set()
            .exclude_from_history()
            .text(value)
            .map_err(|e| ClipError::Clipboard(e.to_string()))
    }

    fn read(&mut self) -> Option<Zeroizing<String>> {
        self.0.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), ClipError> {
        self.0
            .clear()
            .map_err(|e| ClipError::Clipboard(e.to_string()))
    }
}

/// The `vault clip` subcommand: hardens the process, leaves the command's session, reads the
/// request from standard input, takes the clipboard, writes `R` to standard output (or `E` and a
/// message when it fails), and holds the value until it is cleared or replaced.
pub fn run_helper() -> Result<(), ClipError> {
    crate::harden::harden_process();
    let _ = rustix::process::setsid();
    let mut out = std::io::stdout().lock();
    let mut ready = false;
    let result = (|| {
        crate::harden::lock_memory();
        // Read straight from descriptor 0 into a locked page, past the buffer of
        // `std::io::Stdin`. The clipboard library keeps copies of its own while it offers it.
        let (value, clear_after) = read_request(&mut crate::prompt::RawStdin)?;
        let text = std::str::from_utf8(&value)
            .map_err(|_| ClipError::Clipboard("a malformed request".into()))?;
        let cb = arboard::Clipboard::new().map_err(|e| ClipError::Clipboard(e.to_string()))?;
        let mut cb = SystemClipboard(cb);
        hold(
            &mut cb,
            text,
            clear_after,
            &mut || {
                ready = true;
                let _ = out.write_all(b"R").and_then(|()| out.flush());
            },
            &mut boot_time,
            &mut std::thread::sleep,
        )
    })();
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if !ready {
                let _ = write!(out, "E{e}").and_then(|()| out.flush());
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// A clipboard in memory.
    #[derive(Default)]
    struct Fake {
        content: Rc<RefCell<Option<String>>>,
        hinted: bool,
        cleared: bool,
    }

    impl Clipboard for Fake {
        fn offer(&mut self, value: &str) -> Result<(), ClipError> {
            *self.content.borrow_mut() = Some(value.to_owned());
            self.hinted = true;
            Ok(())
        }
        fn read(&mut self) -> Option<Zeroizing<String>> {
            self.content.borrow().clone().map(Zeroizing::new)
        }
        fn clear(&mut self) -> Result<(), ClipError> {
            *self.content.borrow_mut() = None;
            self.cleared = true;
            Ok(())
        }
    }

    /// A clock that only sleeps move, with `during` run on each sleep.
    fn run(
        cb: &mut Fake,
        clear_after: Duration,
        mut during: impl FnMut(Duration, &Cell<Duration>),
    ) -> (Outcome, Vec<Duration>) {
        let now = Rc::new(Cell::new(Duration::from_secs(1000)));
        let mut sleeps = Vec::new();
        let n = Rc::clone(&now);
        let r = hold(
            cb,
            "hunter2",
            clear_after,
            &mut || {},
            &mut move || n.get(),
            &mut |d| {
                sleeps.push(d);
                during(d, &now);
            },
        )
        .unwrap();
        (r, sleeps)
    }

    #[test]
    fn an_untouched_value_is_cleared_after_the_delay() {
        let mut cb = Fake::default();
        let total = Rc::new(Cell::new(Duration::ZERO));
        let t = Rc::clone(&total);
        let (r, sleeps) = run(&mut cb, Duration::from_millis(2500), |d, now| {
            now.set(now.get() + d);
            t.set(t.get() + d);
        });
        assert_eq!(r, Outcome::Cleared);
        assert!(cb.hinted && cb.cleared);
        assert_eq!(total.get(), Duration::from_millis(2500));
        // No single sleep is longer than the step, so a suspend is noticed soon after it.
        assert!(sleeps.iter().all(|d| *d <= SLEEP_STEP), "{sleeps:?}");
        assert_eq!(*cb.content.borrow(), None);
    }

    #[test]
    fn suspended_time_counts_toward_the_delay() {
        let mut cb = Fake::default();
        let mut calls = 0;
        let (r, sleeps) = run(&mut cb, Duration::from_secs(45), |d, now| {
            calls += 1;
            // The first sleep spans a suspend of an hour on the boot clock.
            let jump = if calls == 1 {
                Duration::from_secs(3600)
            } else {
                d
            };
            now.set(now.get() + jump);
        });
        assert_eq!(r, Outcome::Cleared);
        assert_eq!(sleeps.len(), 1);
    }

    #[test]
    fn a_short_sleep_still_waits_the_full_time() {
        let mut cb = Fake::default();
        let total = Rc::new(Cell::new(Duration::ZERO));
        let t = Rc::clone(&total);
        let mut first = true;
        run(&mut cb, Duration::from_millis(500), |d, now| {
            // The first sleep is cut short, as by a signal.
            let slept = if std::mem::take(&mut first) {
                Duration::from_millis(5)
            } else {
                d
            };
            now.set(now.get() + slept);
            t.set(t.get() + slept);
        });
        assert_eq!(total.get(), Duration::from_millis(500));
    }

    #[test]
    fn a_replaced_value_is_left_alone() {
        let mut cb = Fake::default();
        let content = Rc::clone(&cb.content);
        let (r, _) = run(&mut cb, Duration::from_millis(10), |d, now| {
            *content.borrow_mut() = Some("something else".into());
            now.set(now.get() + d);
        });
        assert_eq!(r, Outcome::Replaced);
        assert!(!cb.cleared);
        assert_eq!(cb.content.borrow().as_deref(), Some("something else"));

        let mut cb = Fake::default();
        let content = Rc::clone(&cb.content);
        let (r, _) = run(&mut cb, Duration::from_millis(10), |d, now| {
            *content.borrow_mut() = None;
            now.set(now.get() + d);
        });
        assert_eq!(r, Outcome::Replaced);
        assert!(!cb.cleared);
    }

    #[test]
    fn a_refused_offer_is_not_reported_ready() {
        struct Refuse;
        impl Clipboard for Refuse {
            fn offer(&mut self, _: &str) -> Result<(), ClipError> {
                Err(ClipError::Clipboard("no".into()))
            }
            fn read(&mut self) -> Option<Zeroizing<String>> {
                None
            }
            fn clear(&mut self) -> Result<(), ClipError> {
                Ok(())
            }
        }
        let mut readied = false;
        let r = hold(
            &mut Refuse,
            "x",
            Duration::ZERO,
            &mut || readied = true,
            &mut || Duration::ZERO,
            &mut |_| {},
        );
        assert!(r.is_err());
        assert!(!readied);
    }

    #[test]
    fn requests_round_trip_and_are_limited() {
        let m = encode_request("pässword", Duration::from_secs(45)).unwrap();
        let (v, d) = read_request(&mut &m[..]).unwrap();
        assert_eq!(std::str::from_utf8(&v).unwrap(), "pässword");
        assert_eq!(d, Duration::from_secs(45));
        assert!(matches!(
            encode_request(&"x".repeat(VALUE_MAX + 1), Duration::ZERO),
            Err(ClipError::TooLarge)
        ));
        let mut over = 0u64.to_be_bytes().to_vec();
        over.extend_from_slice(&(VALUE_MAX as u32 + 1).to_be_bytes());
        assert!(matches!(
            read_request(&mut &over[..]),
            Err(ClipError::TooLarge)
        ));
        assert!(read_request(&mut &m[..m.len() - 1]).is_err());
        let mut not_utf8 = 0u64.to_be_bytes().to_vec();
        not_utf8.extend_from_slice(&2u32.to_be_bytes());
        not_utf8.extend_from_slice(b"\xff\xfe");
        assert!(read_request(&mut &not_utf8[..]).is_err());
    }

    #[test]
    fn the_boot_clock_moves() {
        let a = boot_time();
        std::thread::sleep(Duration::from_millis(20));
        assert!(boot_time() >= a + Duration::from_millis(20));
    }

    /// Needs an X11 display or a Wayland compositor with the data control protocol, and changes
    /// the user's clipboard for a moment.
    #[test]
    #[ignore = "needs a display"]
    fn the_system_clipboard_holds_and_clears() {
        let mut cb = SystemClipboard(arboard::Clipboard::new().unwrap());
        let value = "vault clipboard test value";
        let r = hold(
            &mut cb,
            value,
            Duration::from_secs(1),
            &mut || {},
            &mut boot_time,
            &mut std::thread::sleep,
        )
        .unwrap();
        assert_eq!(r, Outcome::Cleared);
        assert_ne!(cb.read().as_deref().map(String::as_str), Some(value));
    }
}
