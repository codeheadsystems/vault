//! The commands' view of the OS-facing modules (`prompt`, `secrets`, `agent`, `editor`, and
//! `clip`): the same operations, with their errors turned into [`CliError`] and the settings and
//! state types of the commands.

use crate::error::{CliError, Exit, Result};

fn exit_of(code: u8) -> Exit {
    match code {
        4 => Exit::Auth,
        2 => Exit::Usage,
        _ => Exit::Other,
    }
}

/// Prompts. Secrets other than the master password, lines, and confirmations come from the
/// terminal when standard input is one, and otherwise from the next line of standard input. The
/// master password comes from `--password-fd` when given, then from the launcher of `vault pick`,
/// and otherwise from the terminal.
pub mod prompt {
    use super::*;
    use crate::launcher::Launcher;
    use crate::prompt::{PromptError, Prompter, stdin_line};
    use std::io::IsTerminal;
    use std::sync::Mutex;
    use vault_core::secret::SecretString;

    struct State {
        prompter: Prompter,
        fd: bool,
        /// The launcher of `vault pick`, which asks for the master password.
        launcher: Option<Launcher>,
        /// The last message [`say`] gave, shown with the launcher's next password prompt.
        note: Option<String>,
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    fn error(e: PromptError) -> CliError {
        match e {
            PromptError::NoTerminal => CliError::no_terminal(),
            PromptError::Interrupted => CliError::other("cancelled", e.to_string()),
            PromptError::EndOfInput => {
                CliError::new(Exit::Auth, "auth.end_of_input", e.to_string())
            }
            _ => CliError::new(exit_of(e.exit_code()), "prompt", e.to_string()),
        }
    }

    fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
        let mut g = STATE.lock().unwrap_or_else(|p| p.into_inner());
        let s = g.get_or_insert_with(|| State {
            prompter: Prompter::new(None),
            fd: false,
            launcher: None,
            note: None,
        });
        f(s)
    }

    /// Sets up the prompts; `password_fd` is `--password-fd`.
    pub fn init(password_fd: Option<i32>) -> Result<()> {
        if password_fd.is_some_and(|n| n < 0) {
            return Err(CliError::usage(
                "--password-fd needs a file descriptor number",
            ));
        }
        let mut g = STATE.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(State {
            prompter: Prompter::new(password_fd),
            fd: password_fd.is_some(),
            launcher: None,
            note: None,
        });
        Ok(())
    }

    /// Asks for the master password through `launcher` from now on, unless `--password-fd` is
    /// given.
    pub fn use_launcher(launcher: Launcher) {
        with(|s| s.launcher = Some(launcher));
    }

    /// Whether the master password comes from `--password-fd`.
    pub fn password_from_fd() -> bool {
        with(|s| s.fd)
    }

    /// Whether standard input is a terminal.
    pub fn stdin_is_terminal() -> bool {
        std::io::stdin().is_terminal()
    }

    /// A message that goes with a prompt: to the terminal when standard input is one, and
    /// otherwise to standard error.
    pub fn say(text: &str) {
        with(|s| {
            if s.launcher.is_some() {
                s.note = Some(text.to_owned());
            }
        });
        if stdin_is_terminal() {
            with(|s| s.prompter.say(&format!("{text}\n")));
        } else {
            eprintln!("{text}");
        }
    }

    /// The master password.
    pub fn password(label: &str) -> Result<SecretString> {
        with(|s| match s.launcher {
            Some(l) if !s.fd => {
                let note = s.note.take();
                l.password(label, note.as_deref())
                    .map_err(super::launcher::error)
            }
            _ => s.prompter.password(label).map_err(error),
        })
    }

    /// A secret line without echo: setup text, a secret key, or an export password.
    pub fn hidden_line(label: &str) -> Result<SecretString> {
        if stdin_is_terminal() {
            with(|s| s.prompter.hidden(label)).map_err(error)
        } else {
            stdin_line().map_err(error)
        }
    }

    /// A line with echo.
    pub fn line(label: &str) -> Result<String> {
        if stdin_is_terminal() {
            with(|s| s.prompter.line(label)).map_err(error)
        } else {
            stdin_line().map(|l| l.as_str().to_owned()).map_err(error)
        }
    }

    /// A yes or no question; anything but `y` or `yes` is no.
    pub fn confirm(question: &str) -> Result<bool> {
        if stdin_is_terminal() {
            with(|s| s.prompter.confirm(question)).map_err(error)
        } else {
            match stdin_line() {
                Ok(l) => Ok(matches!(
                    l.trim().to_ascii_lowercase().as_str(),
                    "y" | "yes"
                )),
                Err(PromptError::EndOfInput) => Ok(false),
                Err(e) => Err(error(e)),
            }
        }
    }
}

/// The launchers of `vault pick`.
pub mod launcher {
    use super::*;
    use crate::launcher::{Launcher, LauncherError};

    /// The CLI error for a launcher failure.
    pub fn error(e: LauncherError) -> CliError {
        let code = match &e {
            LauncherError::NotFound(_) => "picker.no_launcher",
            LauncherError::NoPasswordMode(_) => "picker.no_password_mode",
            LauncherError::Cancelled => "cancelled",
            LauncherError::TooLong | LauncherError::NotUtf8 => "picker.bad_output",
            LauncherError::Io(_) => "picker.launcher",
        };
        CliError::new(exit_of(e.exit_code()), code, e.to_string())
    }

    /// `chosen` when it is in `$PATH`, and otherwise the launcher detection finds.
    pub fn choose(chosen: Option<Launcher>) -> Result<Launcher> {
        let path = std::env::var_os("PATH");
        match chosen {
            Some(l) if l.found_in(path.as_ref()) => Ok(l),
            Some(l) => Err(error(LauncherError::NotFound(Some(l)))),
            None => {
                let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
                Launcher::detect(path.as_ref(), wayland)
                    .ok_or_else(|| error(LauncherError::NotFound(None)))
            }
        }
    }

    /// The line the user chooses among `lines`.
    pub fn menu(launcher: Launcher, lines: &[String]) -> Result<zeroize::Zeroizing<String>> {
        launcher.menu("vault", lines).map_err(error)
    }
}

/// Secret key storage.
pub mod secrets {
    use super::*;
    use crate::paths::Paths;
    use crate::secrets::{SecretsError, StoreKind};
    use crate::settings::KeyringSetting;
    use vault_client::SecretKeyStore;
    use vault_core::secret::SecretKey;

    pub use crate::secrets::Slot;

    fn error(e: SecretsError) -> CliError {
        let code = match &e {
            SecretsError::Unreachable => "keyring.unavailable",
            SecretsError::Keyring(_) => "keyring.refused",
            SecretsError::UnsafeFile(_) => "secret_key.unsafe_file",
            SecretsError::Corrupt => "secret_key.corrupt",
            SecretsError::Io(_) => "io",
        };
        CliError::new(exit_of(e.exit_code()), code, e.to_string())
    }

    fn kind(store: SecretKeyStore) -> StoreKind {
        match store {
            SecretKeyStore::Keyring => StoreKind::Keyring,
            SecretKeyStore::File => StoreKind::File,
        }
    }

    /// The store `vault init` and `vault setup` choose.
    pub fn choose_store(setting: KeyringSetting) -> SecretKeyStore {
        match setting {
            KeyringSetting::File => SecretKeyStore::File,
            KeyringSetting::Auto if crate::secrets::keyring_available() => SecretKeyStore::Keyring,
            KeyringSetting::Auto => SecretKeyStore::File,
        }
    }

    /// The key in `slot`, if stored.
    pub fn load(
        paths: &Paths,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        slot: Slot,
    ) -> Result<Option<SecretKey>> {
        crate::secrets::open(kind(store), &paths.data)
            .get(vault_id, slot)
            .map_err(error)
    }

    /// Stores `key` in `slot`.
    pub fn store(
        paths: &Paths,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        slot: Slot,
        key: &SecretKey,
    ) -> Result<()> {
        crate::secrets::open(kind(store), &paths.data)
            .put(vault_id, slot, key)
            .map_err(error)
    }

    /// Empties `slot`.
    pub fn remove(
        paths: &Paths,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        slot: Slot,
    ) -> Result<()> {
        crate::secrets::open(kind(store), &paths.data)
            .delete(vault_id, slot)
            .map_err(error)
    }
}

/// The agent.
pub mod agent {
    use super::*;
    use crate::agent::{AgentError, AgentSettings, SyncResult};
    use crate::paths::Paths;
    use crate::settings::Settings;
    use std::process::ExitCode;
    use vault_core::secret::VaultKey;

    pub use crate::agent::AgentStatus;

    fn error(e: AgentError) -> CliError {
        let code = match &e {
            AgentError::NoRuntimeDir => "agent.no_runtime_dir",
            AgentError::Unsafe(_) => "agent.unsafe",
            AgentError::WrongPeer => "agent.wrong_peer",
            AgentError::Agent(_) => "agent.refused",
            AgentError::Protocol(_) => "agent.protocol",
            AgentError::Start(_) => "agent.start",
            AgentError::Io(_) => "agent.io",
        };
        CliError::new(exit_of(e.exit_code()), code, e.to_string())
    }

    /// The vault ID and key the running agent holds; `None` when no agent runs.
    pub fn get_key(_paths: &Paths) -> Result<Option<([u8; 16], VaultKey)>> {
        crate::agent::get_key().map_err(error)
    }

    /// Asks the agent to sync; `false` when no agent runs.
    pub fn request_sync(_paths: &Paths) -> Result<bool> {
        crate::agent::request_sync().map_err(error)
    }

    /// The agent's status; `None` when no agent runs.
    pub fn status(_paths: &Paths) -> Result<Option<AgentStatus>> {
        crate::agent::status().map_err(error)
    }

    /// Ends the agent; `false` when none ran.
    pub fn lock(_paths: &Paths) -> Result<bool> {
        crate::agent::lock().map_err(error)
    }

    /// Starts an agent holding `vault_key`.
    pub fn start(
        _paths: &Paths,
        settings: &Settings,
        vault_id: &[u8; 16],
        vault_key: &VaultKey,
    ) -> Result<()> {
        let s = AgentSettings {
            idle: settings.agent_idle,
            max: settings.agent_max,
            sync_interval: settings.sync_interval,
            sync_auto: settings.sync_auto,
        };
        crate::agent::start(vault_id, vault_key, &s).map_err(error)
    }

    /// `vault agent`: the daemon, with the background sync of [`crate::session`].
    pub fn daemon() -> ExitCode {
        let sync = |vault_id: &[u8; 16], vault_key: &VaultKey| -> SyncResult {
            match crate::session::background_sync(vault_id, vault_key) {
                Ok(()) => SyncResult::Done,
                Err(None) => SyncResult::KeyRejected,
                Err(Some(e)) => SyncResult::Failed {
                    code: e.code().to_owned(),
                    message: e.message().to_owned(),
                },
            }
        };
        match crate::agent::run_daemon(Box::new(sync)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => ExitCode::from(e.exit_code()),
        }
    }
}

/// The editor.
pub mod editor {
    use super::*;
    use crate::editor::EditorError;
    use zeroize::Zeroizing;

    /// Edits `initial` and returns the saved bytes.
    pub fn edit(initial: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::editor::edit(initial).map_err(|e| {
            let code = match &e {
                EditorError::NoRuntimeDir => "editor.no_runtime_dir",
                EditorError::NotTmpfs => "editor.not_tmpfs",
                EditorError::UnsafeDir(..) => "editor.unsafe_dir",
                EditorError::EditorFailed(_) => "editor.failed",
                EditorError::BadFile => "editor.bad_file",
                EditorError::Interrupted => "cancelled",
                EditorError::Io(_) => "io",
            };
            CliError::new(exit_of(e.exit_code()), code, e.to_string())
        })
    }
}

/// The clipboard.
pub mod clip {
    use super::*;
    use std::time::Duration;

    /// Copies `value` and clears it after `clear_after`.
    pub fn copy(value: &str, clear_after: Duration) -> Result<()> {
        crate::clip::copy(value, clear_after)
            .map_err(|e| CliError::new(exit_of(e.exit_code()), "clipboard", e.to_string()))
    }

    /// `vault clip`: the helper that owns the clipboard until it clears it.
    pub fn helper() -> std::process::ExitCode {
        match crate::clip::run_helper() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => std::process::ExitCode::from(e.exit_code()),
        }
    }
}
