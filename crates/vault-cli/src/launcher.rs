//! The launchers of `vault pick`: rofi, fuzzel, and dmenu, run as a menu over lines written to
//! their standard input, as a password prompt, and as an error message.
//!
//! A launcher's output is read from a pipe into a zeroized buffer, because a password typed into
//! the menu by mistake, or the master password in password mode, passes through it.

use crate::prompt::INPUT_MAX;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// A launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launcher {
    /// rofi, in its dmenu mode.
    Rofi,
    /// fuzzel, in its dmenu mode.
    Fuzzel,
    /// dmenu, which has no password mode.
    Dmenu,
}

/// A launcher failure. Messages never contain what the launcher returned.
#[derive(Debug)]
pub enum LauncherError {
    /// No launcher was found in `$PATH`; the name when one was asked for.
    NotFound(Option<Launcher>),
    /// The launcher cannot hide a typed password.
    NoPasswordMode(Launcher),
    /// The user closed the launcher.
    Cancelled,
    /// The launcher returned more than [`INPUT_MAX`] bytes.
    TooLong,
    /// The launcher returned text that is not UTF-8.
    NotUtf8,
    /// Starting or talking to the launcher failed.
    Io(std::io::Error),
}

impl LauncherError {
    /// The exit code: 4 when the master password cannot be asked for, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            LauncherError::NoPasswordMode(_) => 4,
            _ => 1,
        }
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LauncherError::NotFound(Some(l)) => write!(f, "{} is not in $PATH", l.program()),
            LauncherError::NotFound(None) => {
                f.write_str("no launcher found in $PATH: install rofi, fuzzel, or dmenu")
            }
            LauncherError::NoPasswordMode(l) => write!(
                f,
                "{} cannot hide a typed password; run vault unlock first",
                l.program()
            ),
            LauncherError::Cancelled => f.write_str("the picker was cancelled"),
            LauncherError::TooLong => f.write_str("the launcher returned too much text"),
            LauncherError::NotUtf8 => f.write_str("the launcher returned text that is not UTF-8"),
            LauncherError::Io(e) => write!(f, "cannot run the launcher: {e}"),
        }
    }
}

impl std::error::Error for LauncherError {}

/// What a launcher is run for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode<'a> {
    /// A menu with this prompt, over lines on standard input.
    Menu(&'a str),
    /// A hidden prompt with this label, and a message to show with it.
    Password(&'a str, Option<&'a str>),
    /// An error message.
    Error(&'a str),
}

impl Launcher {
    /// The program name.
    pub fn program(self) -> &'static str {
        match self {
            Launcher::Rofi => "rofi",
            Launcher::Fuzzel => "fuzzel",
            Launcher::Dmenu => "dmenu",
        }
    }

    /// The first launcher found in `path`: fuzzel, rofi, then dmenu under Wayland, and otherwise
    /// rofi, then dmenu.
    pub fn detect(path: Option<&OsString>, wayland: bool) -> Option<Launcher> {
        let order: &[Launcher] = if wayland {
            &[Launcher::Fuzzel, Launcher::Rofi, Launcher::Dmenu]
        } else {
            &[Launcher::Rofi, Launcher::Dmenu]
        };
        order.iter().copied().find(|l| l.found_in(path))
    }

    /// Whether the program is a file in one of the directories of `path`.
    pub fn found_in(self, path: Option<&OsString>) -> bool {
        path.is_some_and(|p| {
            std::env::split_paths(p).any(|dir| Path::new(&dir).join(self.program()).is_file())
        })
    }

    fn args(self, mode: Mode<'_>) -> Vec<String> {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        match (self, mode) {
            (Launcher::Rofi, Mode::Menu(p)) => own(&["-dmenu", "-i", "-no-custom", "-p", p]),
            (Launcher::Rofi, Mode::Password(label, note)) => {
                // rofi's theme puts a colon after the prompt.
                let label = label.trim_end().trim_end_matches(':');
                let mut a = own(&["-dmenu", "-password", "-p", label]);
                if let Some(n) = note {
                    a.extend(own(&["-mesg", n]));
                }
                a
            }
            (Launcher::Rofi, Mode::Error(m)) => own(&["-e", m]),
            (Launcher::Fuzzel, Mode::Menu(p)) => own(&["--dmenu", "--prompt", &format!("{p}> ")]),
            (Launcher::Fuzzel, Mode::Password(label, note)) => {
                let prompt = match note {
                    Some(n) => format!("{n} {label}"),
                    None => label.to_owned(),
                };
                own(&["--dmenu", "--password", "--prompt", &prompt])
            }
            (Launcher::Fuzzel, Mode::Error(_)) => own(&["--dmenu", "--prompt", "vault: "]),
            (Launcher::Dmenu, Mode::Menu(p)) => own(&["-i", "-p", p]),
            (Launcher::Dmenu, Mode::Error(_)) => own(&["-p", "vault:"]),
            (Launcher::Dmenu, Mode::Password(..)) => unreachable!("refused in password"),
        }
    }

    /// Shows `lines` as a menu and returns the chosen line, without its newline.
    pub fn menu(self, prompt: &str, lines: &[String]) -> Result<Zeroizing<String>, LauncherError> {
        let mut input = lines.join("\n");
        input.push('\n');
        self.run(Mode::Menu(prompt), input.as_bytes())
    }

    /// Reads a password with what is typed hidden; `note` is a message shown with the prompt,
    /// such as one about a wrong earlier attempt.
    pub fn password(
        self,
        label: &str,
        note: Option<&str>,
    ) -> Result<Zeroizing<String>, LauncherError> {
        if self == Launcher::Dmenu {
            return Err(LauncherError::NoPasswordMode(self));
        }
        self.run(Mode::Password(label, note), b"")
    }

    /// Shows `message`; failures are ignored, because the message reports a failure already.
    pub fn show_error(self, message: &str) {
        let input = match self {
            Launcher::Rofi => String::new(),
            _ => format!("{message}\n"),
        };
        let _ = self.run(Mode::Error(message), input.as_bytes());
    }

    fn run(self, mode: Mode<'_>, input: &[u8]) -> Result<Zeroizing<String>, LauncherError> {
        crate::harden::close_on_exec_all();
        let mut child = Command::new(self.program())
            .args(self.args(mode))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => LauncherError::NotFound(Some(self)),
                _ => LauncherError::Io(e),
            })?;
        // A launcher reads all of its input before it shows anything, so the menu is written
        // before the output is read. One that exits early closes the pipe, and the exit status
        // reports that.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        let read = match child.stdout.take() {
            Some(stdout) => stdout
                .take(INPUT_MAX as u64 + 2)
                .read_to_end(&mut out)
                .map(|_| ()),
            None => Ok(()),
        };
        let status = child.wait().map_err(LauncherError::Io)?;
        read.map_err(LauncherError::Io)?;
        if !status.success() {
            return Err(LauncherError::Cancelled);
        }
        parse_output(out)
    }
}

/// The launcher's output without one final newline.
fn parse_output(mut out: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, LauncherError> {
    if out.last() == Some(&b'\n') {
        out.pop();
    }
    if out.len() > INPUT_MAX {
        return Err(LauncherError::TooLong);
    }
    if std::str::from_utf8(&out).is_err() {
        return Err(LauncherError::NotUtf8);
    }
    let bytes = std::mem::take(&mut *out);
    // Checked above, so the conversion keeps the same allocation.
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| LauncherError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_with(names: &[&str]) -> (tempfile::TempDir, OsString) {
        let dir = tempfile::tempdir().unwrap();
        for n in names {
            std::fs::write(dir.path().join(n), "").unwrap();
        }
        let p = dir.path().as_os_str().to_owned();
        (dir, p)
    }

    #[test]
    fn detection_prefers_fuzzel_under_wayland_and_rofi_under_x11() {
        let (_d, all) = path_with(&["rofi", "fuzzel", "dmenu"]);
        assert_eq!(Launcher::detect(Some(&all), true), Some(Launcher::Fuzzel));
        assert_eq!(Launcher::detect(Some(&all), false), Some(Launcher::Rofi));
        let (_d, dmenu) = path_with(&["dmenu"]);
        assert_eq!(Launcher::detect(Some(&dmenu), true), Some(Launcher::Dmenu));
        assert_eq!(Launcher::detect(Some(&dmenu), false), Some(Launcher::Dmenu));
        let (_d, fuzzel) = path_with(&["fuzzel"]);
        assert_eq!(
            Launcher::detect(Some(&fuzzel), false),
            None,
            "fuzzel is Wayland only"
        );
        assert_eq!(Launcher::detect(None, true), None);
    }

    #[test]
    fn password_modes_hide_input_and_carry_the_note() {
        let a = Launcher::Rofi.args(Mode::Password("Master password: ", Some("Wrong.")));
        assert_eq!(
            a,
            [
                "-dmenu",
                "-password",
                "-p",
                "Master password",
                "-mesg",
                "Wrong."
            ]
        );
        let a = Launcher::Fuzzel.args(Mode::Password("Master password: ", Some("Wrong.")));
        assert_eq!(
            a,
            [
                "--dmenu",
                "--password",
                "--prompt",
                "Wrong. Master password: "
            ]
        );
        assert!(matches!(
            Launcher::Dmenu.password("Master password: ", None),
            Err(LauncherError::NoPasswordMode(Launcher::Dmenu))
        ));
    }

    #[test]
    fn rofi_menus_refuse_custom_text() {
        assert!(
            Launcher::Rofi
                .args(Mode::Menu("vault"))
                .contains(&"-no-custom".to_owned())
        );
    }

    #[test]
    fn output_loses_one_newline_and_is_checked() {
        let p = |b: &[u8]| parse_output(Zeroizing::new(b.to_vec()));
        assert_eq!(p(b"line\n").unwrap().as_str(), "line");
        assert_eq!(p(b"line\n\n").unwrap().as_str(), "line\n");
        assert_eq!(p(b"").unwrap().as_str(), "");
        assert!(matches!(p(b"\xff"), Err(LauncherError::NotUtf8)));
        assert!(matches!(
            p(&vec![b'a'; INPUT_MAX + 1]),
            Err(LauncherError::TooLong)
        ));
    }
}
