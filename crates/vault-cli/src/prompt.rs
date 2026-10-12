//! Prompts: passwords and other secrets read from the terminal without echo, or the master
//! password from the file descriptor `--password-fd` names; lines with echo; and confirmations.
//!
//! Prompts go to `/dev/tty`, never to standard output, so they stay out of a command's output.
//! While a secret is read, the terminal has echo off. A termination signal, such as the `SIGINT`
//! of Ctrl-C, ends the read and takes effect once the terminal state is restored.

use crate::signals;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

/// The longest input a prompt accepts, in bytes.
pub const INPUT_MAX: usize = 64 * 1024;

/// A prompt's failure.
#[derive(Debug)]
pub enum PromptError {
    /// No terminal is available to ask.
    NoTerminal,
    /// Ctrl-D at the prompt, or a termination signal.
    Interrupted,
    /// The password file descriptor ended before a line.
    EndOfInput,
    /// The input exceeds [`INPUT_MAX`].
    TooLong,
    /// The input is not valid UTF-8.
    NotUtf8,
    /// The password file descriptor cannot be used.
    BadFd(i32),
    /// Reading or writing the terminal failed.
    Io(std::io::Error),
}

impl PromptError {
    /// The exit code of `docs/cli.md`: 4 when there is no terminal to ask, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            PromptError::NoTerminal => 4,
            _ => 1,
        }
    }
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PromptError::NoTerminal => {
                f.write_str("no terminal to ask for input; use --password-fd for the password")
            }
            PromptError::Interrupted => f.write_str("interrupted"),
            PromptError::EndOfInput => {
                f.write_str("the password file descriptor has no more lines")
            }
            PromptError::TooLong => f.write_str("the input is too long"),
            PromptError::NotUtf8 => f.write_str("the input is not valid UTF-8"),
            PromptError::BadFd(n) => write!(f, "cannot read the password from file descriptor {n}"),
            PromptError::Io(e) => write!(f, "cannot use the terminal: {e}"),
        }
    }
}

impl std::error::Error for PromptError {}

/// Reads prompts from the terminal and the password from `--password-fd`.
pub struct Prompter {
    fd: Option<FdSource>,
    tty_path: PathBuf,
    tty: Option<File>,
    tried: bool,
}

/// The `--password-fd` descriptor, opened again through `/proc/self/fd`.
struct FdSource {
    number: i32,
    file: Option<File>,
}

impl Prompter {
    /// A prompter that reads the master password from `password_fd` when given, and everything
    /// else from `/dev/tty`. The terminal is opened when first needed.
    pub fn new(password_fd: Option<i32>) -> Prompter {
        Prompter::with_tty(password_fd, PathBuf::from("/dev/tty"))
    }

    fn with_tty(password_fd: Option<i32>, tty_path: PathBuf) -> Prompter {
        // No child process (the agent, the clipboard helper, or the editor) inherits the
        // password descriptor.
        if let Some(n) = password_fd.filter(|&n| n > 2) {
            let _ = crate::harden::set_cloexec(n);
        }
        Prompter {
            fd: password_fd.map(|number| FdSource { number, file: None }),
            tty_path,
            tty: None,
            tried: false,
        }
    }

    /// Reads the master password: the next line of `--password-fd` when given, otherwise a line
    /// from the terminal without echo.
    pub fn password(&mut self, prompt: &str) -> Result<Zeroizing<String>, PromptError> {
        match &mut self.fd {
            Some(src) => src.next_line(),
            None => self.read_tty(prompt, false),
        }
    }

    /// Reads a line from the terminal without echo, such as the setup text or the secret key.
    pub fn hidden(&mut self, prompt: &str) -> Result<Zeroizing<String>, PromptError> {
        self.read_tty(prompt, false)
    }

    /// Reads a line from the terminal with echo.
    pub fn line(&mut self, prompt: &str) -> Result<String, PromptError> {
        Ok(self.read_tty(prompt, true)?.as_str().to_owned())
    }

    /// Asks a yes or no question; `y` and `yes`, in any case, are yes.
    pub fn confirm(&mut self, question: &str) -> Result<bool, PromptError> {
        let answer = self.line(&format!("{question} [y/N] "))?;
        Ok(is_yes(&answer))
    }

    /// Writes `text` to the terminal, or to standard error when there is none.
    pub fn say(&mut self, text: &str) {
        match self.tty() {
            Some(t) => {
                let _ = t.write_all(text.as_bytes());
                let _ = t.flush();
            }
            None => {
                let _ = std::io::stderr().write_all(text.as_bytes());
            }
        }
    }

    fn tty(&mut self) -> Option<&mut File> {
        if !self.tried {
            self.tried = true;
            self.tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.tty_path)
                .ok();
        }
        self.tty.as_mut()
    }

    /// Reads one line from the terminal. Without echo, type-ahead is discarded on entry, and the
    /// saved state is restored on every exit path, including a termination signal and a job
    /// control stop, after which echo is turned off again and the prompt repeated.
    fn read_tty(&mut self, prompt: &str, echo: bool) -> Result<Zeroizing<String>, PromptError> {
        let tty = self.tty().ok_or(PromptError::NoTerminal)?;
        let deferral = if echo {
            signals::defer()
        } else {
            signals::defer_with_stops()
        };
        let modes = if echo {
            None
        } else {
            let saved = tcgetattr(&*tty).map_err(|e| PromptError::Io(e.into()))?;
            let mut quiet = saved.clone();
            quiet.local_modes &= !LocalModes::ECHO;
            quiet.local_modes |= LocalModes::ICANON;
            tcsetattr(&*tty, OptionalActions::Flush, &quiet)
                .map_err(|e| PromptError::Io(e.into()))?;
            Some((saved, quiet))
        };
        // The prompt appears only once echo is off, so nothing typed after it is echoed.
        let result = tty
            .write_all(prompt.as_bytes())
            .and_then(|()| tty.flush())
            .map_err(PromptError::Io)
            .and_then(|()| read_line(tty, &deferral, prompt, modes.as_ref()));
        if let Some((saved, _)) = &modes {
            restore(tty, saved);
        }
        // A signal caught during the read is delivered here, after the restore.
        drop(deferral);
        result
    }
}

fn restore(tty: &mut File, saved: &Termios) {
    let _ = tcsetattr(&*tty, OptionalActions::Now, saved);
    let _ = tty.write_all(b"\n");
}

/// Reads bytes up to a newline into a buffer reserved up front, so it never reallocates and
/// leaves no copy behind. The terminal is polled, so a signal caught meanwhile ends the read.
/// `modes` holds the saved and the no-echo terminal state of a hidden read; a stop signal
/// restores the saved state, stops, and sets the no-echo state again when the process continues.
fn read_line(
    tty: &mut File,
    deferral: &signals::Deferral,
    prompt: &str,
    modes: Option<&(Termios, Termios)>,
) -> Result<Zeroizing<String>, PromptError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(INPUT_MAX));
    let mut byte = [0u8; 1];
    let tick = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let result = loop {
        if deferral.caught().is_some() {
            break Err(PromptError::Interrupted);
        }
        if deferral.take_stop() {
            if let Some((saved, _)) = modes {
                restore(tty, saved);
            }
            deferral.stop_now();
            if let Some((_, quiet)) = modes {
                let _ = tcsetattr(&*tty, OptionalActions::Flush, quiet);
            }
            buf.clear();
            let _ = tty.write_all(prompt.as_bytes()).and_then(|()| tty.flush());
            continue;
        }
        let mut fds = [PollFd::new(&*tty, PollFlags::IN)];
        match poll(&mut fds, Some(&tick)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => break Err(PromptError::Io(e.into())),
        }
        match tty.read(&mut byte) {
            // Ctrl-D on an empty line.
            Ok(0) => break Err(PromptError::Interrupted),
            Ok(_) => match byte[0] {
                b'\n' => break Ok(()),
                _ if buf.len() >= INPUT_MAX => break Err(PromptError::TooLong),
                b => buf.push(b),
            },
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(PromptError::Io(e)),
        }
    };
    byte.zeroize();
    result?;
    into_string(buf)
}

/// Strips a trailing carriage return and checks UTF-8, without copying the bytes elsewhere.
fn into_string(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, PromptError> {
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if std::str::from_utf8(&buf).is_err() {
        return Err(PromptError::NotUtf8);
    }
    let bytes = std::mem::take(&mut *buf);
    // The bytes were checked above, so the conversion keeps the same allocation.
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| PromptError::NotUtf8)
}

impl FdSource {
    /// The next line of the descriptor. A pipe is opened again through `/proc/self/fd`, which
    /// shares the pipe, so the descriptor needs no unsafe adoption; the reopened file is kept, so
    /// each call reads the line after the previous one.
    fn next_line(&mut self) -> Result<Zeroizing<String>, PromptError> {
        if self.file.is_none() {
            if self.number < 0 {
                return Err(PromptError::BadFd(self.number));
            }
            let path = format!("/proc/self/fd/{}", self.number);
            let file = File::open(path).map_err(|_| PromptError::BadFd(self.number))?;
            self.file = Some(file);
        }
        let Some(file) = self.file.as_mut() else {
            return Err(PromptError::BadFd(self.number));
        };
        read_fd_line(file)
    }
}

/// Reads one line, one byte at a time so that nothing past the newline is consumed. End of
/// input after some bytes ends the line; end of input before any is an error.
fn read_fd_line(r: &mut impl Read) -> Result<Zeroizing<String>, PromptError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(INPUT_MAX));
    let mut byte = [0u8; 1];
    let result = loop {
        match r.read(&mut byte) {
            Ok(0) if buf.is_empty() => break Err(PromptError::EndOfInput),
            Ok(0) => break Ok(()),
            Ok(_) if byte[0] == b'\n' => break Ok(()),
            Ok(_) if buf.len() >= INPUT_MAX => break Err(PromptError::TooLong),
            Ok(_) => buf.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(PromptError::Io(e)),
        }
    };
    byte.zeroize();
    result?;
    into_string(buf)
}

/// Standard input read directly from descriptor 0, bypassing the buffer of `std::io::Stdin`,
/// which would keep a copy of a secret and consume bytes past the line.
pub struct RawStdin;

impl Read for RawStdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::fd::AsFd;
        rustix::io::read(std::io::stdin().as_fd(), buf).map_err(Into::into)
    }
}

/// Reads one line from standard input, for a password piped to `vault add`.
pub fn stdin_line() -> Result<Zeroizing<String>, PromptError> {
    read_fd_line(&mut RawStdin)
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn fd_lines_are_read_one_at_a_time() {
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"first password\r\nsecond\nthird").unwrap();
        drop(w);
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        // A copy without close-on-exec, as a shell passes it.
        let n = fcntl(r.as_raw_fd(), FcntlArg::F_DUPFD(0)).unwrap();
        let cloexec = || {
            let flags = fcntl(n, FcntlArg::F_GETFD).unwrap();
            FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC)
        };
        assert!(!cloexec());
        let mut p = Prompter::with_tty(Some(n), "/nonexistent".into());
        assert!(cloexec());
        assert_eq!(p.password("ignored").unwrap().as_str(), "first password");
        assert_eq!(p.password("ignored").unwrap().as_str(), "second");
        assert_eq!(p.password("ignored").unwrap().as_str(), "third");
        assert!(matches!(p.password("x"), Err(PromptError::EndOfInput)));
        let _ = nix::unistd::close(n);
    }

    #[test]
    fn a_closed_or_invalid_fd_is_reported() {
        let mut p = Prompter::with_tty(Some(9999), "/nonexistent".into());
        assert!(matches!(p.password("x"), Err(PromptError::BadFd(9999))));
        let mut p = Prompter::with_tty(Some(-1), "/nonexistent".into());
        assert!(matches!(p.password("x"), Err(PromptError::BadFd(-1))));
    }

    #[test]
    fn fd_input_limits() {
        let long = vec![b'a'; INPUT_MAX + 1];
        assert!(matches!(
            read_fd_line(&mut &long[..]),
            Err(PromptError::TooLong)
        ));
        let exact = vec![b'a'; INPUT_MAX];
        assert_eq!(read_fd_line(&mut &exact[..]).unwrap().len(), INPUT_MAX);
        assert!(matches!(
            read_fd_line(&mut &b"\xff\xfe\n"[..]),
            Err(PromptError::NotUtf8)
        ));
        assert_eq!(read_fd_line(&mut &b"\n"[..]).unwrap().as_str(), "");
    }

    #[test]
    fn no_terminal_is_exit_code_4() {
        let mut p = Prompter::with_tty(None, "/nonexistent/tty".into());
        assert!(p.tty().is_none());
        let e = p.password("Master password: ").unwrap_err();
        assert!(matches!(e, PromptError::NoTerminal));
        assert_eq!(e.exit_code(), 4);
        assert!(matches!(p.hidden("x"), Err(PromptError::NoTerminal)));
        assert!(matches!(p.confirm("x"), Err(PromptError::NoTerminal)));
    }

    #[test]
    fn yes_answers() {
        for a in ["y", "Y", "yes", " YES \n"] {
            assert!(is_yes(a), "{a}");
        }
        for a in ["", "n", "no", "yess", "ja"] {
            assert!(!is_yes(a), "{a}");
        }
    }

    /// A pseudo-terminal pair: the master side, and the path of the terminal side.
    fn pty() -> (File, PathBuf) {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let path = PathBuf::from(name.to_str().unwrap());
        (File::from(master), path)
    }

    /// Reads the master side until `text` has appeared, and returns what was read.
    fn wait_for(master: &mut File, text: &str) -> String {
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        while !String::from_utf8_lossy(&seen).contains(text) {
            let n = master.read(&mut buf).unwrap();
            assert!(n > 0, "the terminal closed");
            seen.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Everything the master side can read within a short time.
    fn drain(master: &mut File) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        let wait = Timespec {
            tv_sec: 0,
            tv_nsec: 200_000_000,
        };
        loop {
            let mut fds = [PollFd::new(&*master, PollFlags::IN)];
            if poll(&mut fds, Some(&wait)).unwrap() == 0 {
                return out;
            }
            match master.read(&mut buf) {
                Ok(0) | Err(_) => return out,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    #[test]
    fn hidden_input_is_not_echoed_and_the_terminal_is_restored() {
        let (mut master, path) = pty();
        let mut p = Prompter::with_tty(None, path.clone());
        assert!(p.tty().is_some());
        let before = tcgetattr(p.tty.as_ref().unwrap()).unwrap();
        assert!(before.local_modes.contains(LocalModes::ECHO));
        let typist = std::thread::spawn(move || {
            wait_for(&mut master, "Secret: ");
            master.write_all(b"s3cret pass\n").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            let seen = drain(&mut master);
            (master, seen)
        });
        let got = p.hidden("Secret: ").unwrap();
        assert_eq!(got.as_str(), "s3cret pass");
        let (mut master, seen) = typist.join().unwrap();
        let seen = String::from_utf8_lossy(&seen);
        assert!(!seen.contains("s3cret"), "the input was echoed: {seen:?}");
        let after = tcgetattr(p.tty.as_ref().unwrap()).unwrap();
        assert_eq!(after.local_modes, before.local_modes);

        // Ctrl-D on an empty line ends the read, also restoring the terminal.
        let typist = std::thread::spawn(move || {
            wait_for(&mut master, "Again: ");
            master.write_all(b"\x04").unwrap();
            master
        });
        assert!(matches!(p.hidden("Again: "), Err(PromptError::Interrupted)));
        let _master = typist.join().unwrap();
        let after = tcgetattr(p.tty.as_ref().unwrap()).unwrap();
        assert_eq!(after.local_modes, before.local_modes);
    }

    #[test]
    fn a_signal_restores_the_terminal_and_then_takes_effect() {
        // The signal ends the process, so a child reads the prompt on a terminal this test owns.
        if let Some(path) = std::env::var_os("VAULT_PROMPT_CHILD") {
            let mut p = Prompter::with_tty(None, path.into());
            let _ = p.hidden("Secret: ");
            println!("not reached");
            return;
        }
        let (mut master, path) = pty();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let before = tcgetattr(&tty).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "prompt::tests::a_signal_restores_the_terminal_and_then_takes_effect",
                "--nocapture",
            ])
            .env("VAULT_PROMPT_CHILD", &path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(&mut master, "Secret: ");
        assert!(
            !tcgetattr(&tty)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(signal_hook::consts::SIGTERM));
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert!(!out.contains("not reached"));
        assert_eq!(tcgetattr(&tty).unwrap().local_modes, before.local_modes);
    }

    /// The process state letter from `/proc/<pid>/stat`.
    fn state(pid: u32) -> char {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after = &stat[stat.rfind(')').unwrap() + 2..];
        after.chars().next().unwrap()
    }

    #[test]
    fn a_stop_restores_the_terminal_and_continuing_hides_input_again() {
        if let Some(path) = std::env::var_os("VAULT_PROMPT_STOP_CHILD") {
            let mut p = Prompter::with_tty(None, path.into());
            let got = p.hidden("Secret: ").unwrap();
            println!("got {}", got.as_str());
            return;
        }
        let (mut master, path) = pty();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let echo = |t: &File| tcgetattr(t).unwrap().local_modes.contains(LocalModes::ECHO);
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "prompt::tests::a_stop_restores_the_terminal_and_continuing_hides_input_again",
                "--nocapture",
            ])
            .env("VAULT_PROMPT_STOP_CHILD", &path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(&mut master, "Secret: ");
        assert!(!echo(&tty));
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TSTP).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while state(child.id()) != 'T' {
            assert!(
                std::time::Instant::now() < deadline,
                "the child did not stop"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(echo(&tty), "echo stays off while stopped");
        rustix::process::kill_process(pid, rustix::process::Signal::CONT).unwrap();
        // The prompt repeats once echo is off again.
        wait_for(&mut master, "Secret: ");
        assert!(!echo(&tty));
        master.write_all(b"after stop\n").unwrap();
        assert!(child.wait().unwrap().success());
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert!(out.contains("got after stop"), "{out:?}");
        assert!(echo(&tty));
    }

    #[test]
    fn echoed_lines_and_confirmation() {
        let (mut master, path) = pty();
        let mut p = Prompter::with_tty(None, path);
        let typist = std::thread::spawn(move || {
            wait_for(&mut master, "Vault ID: ");
            master.write_all(b"0123abcd\n").unwrap();
            let seen = wait_for(&mut master, "Restore? [y/N] ");
            master.write_all(b"yes\n").unwrap();
            // The master stays open until the reads are done: closing it hangs up the terminal.
            (master, seen)
        });
        assert_eq!(p.line("Vault ID: ").unwrap(), "0123abcd");
        assert!(p.confirm("Restore?").unwrap());
        let (_master, seen) = typist.join().unwrap();
        assert!(
            seen.contains("0123abcd"),
            "the input was not echoed: {seen:?}"
        );
    }
}
