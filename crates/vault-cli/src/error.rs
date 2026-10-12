//! The error every command returns: an exit code, a stable code for the JSON output, and a
//! message. Messages never carry item content other than item names, key material, tokens, or
//! setup text.

use std::borrow::Cow;
use std::fmt;
use vault_client::{ClientError, StopReason};

/// The exit codes of `docs/cli.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// 1: any other error.
    Other = 1,
    /// 2: a usage error.
    Usage = 2,
    /// 3: no item matches, or more than one does.
    Item = 3,
    /// 4: a wrong master password or secret key, or no terminal to ask for one.
    Auth = 4,
    /// 5: an integrity error; sync stopped until `vault sync --recover`.
    Integrity = 5,
    /// 6: the server is unreachable, or answered with an unexpected status.
    Server = 6,
    /// 7: the server refused the token; `vault setup` repairs it.
    Token = 7,
    /// 8: the credentials changed on another device; `vault sync` takes the change over.
    Credentials = 8,
}

/// A command's failure.
#[derive(Debug)]
pub struct CliError {
    exit: Exit,
    code: Cow<'static, str>,
    message: String,
}

/// Result with [`CliError`].
pub type Result<T> = std::result::Result<T, CliError>;

impl CliError {
    /// An error with an exit code, a stable code, and a message.
    pub fn new(exit: Exit, code: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Self {
        CliError {
            exit,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Exit code 1 with code `code`.
    pub fn other(code: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Self {
        CliError::new(Exit::Other, code, message)
    }

    /// Exit code 2 with code `usage`.
    pub fn usage(message: impl Into<String>) -> Self {
        CliError::new(Exit::Usage, "usage", message)
    }

    /// Exit code 4: a prompt is needed and no terminal is available.
    pub fn no_terminal() -> Self {
        CliError::new(
            Exit::Auth,
            "auth.no_terminal",
            "no terminal to ask for the master password; use --password-fd",
        )
    }

    /// Exit code 1 with code `io`, naming what failed.
    pub fn io(what: impl fmt::Display, e: std::io::Error) -> Self {
        CliError::other("io", format!("{what}: {e}"))
    }

    /// The exit code.
    pub fn exit(&self) -> Exit {
        self.exit
    }

    /// The stable code for the JSON output.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<vault_core::Error> for CliError {
    fn from(e: vault_core::Error) -> Self {
        use vault_core::Error as E;
        let (exit, code) = match e {
            E::Integrity(_) => (Exit::Integrity, e.code()),
            E::WrongCredentials => (Exit::Auth, "auth.wrong_password"),
            E::SecretKeyTypo => (Exit::Auth, e.code()),
            _ => (Exit::Other, e.code()),
        };
        CliError::new(exit, code, e.to_string())
    }
}

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        let code = e.code();
        let (exit, hint) = match e {
            ClientError::Core(c) => return c.into(),
            ClientError::Stopped(StopReason::Integrity) => {
                (Exit::Integrity, "; run `vault sync --recover`")
            }
            ClientError::Stopped(StopReason::Token) => (Exit::Token, "; run `vault setup`"),
            ClientError::Stopped(StopReason::Credentials) => {
                (Exit::Credentials, "; run `vault sync`")
            }
            ClientError::Token => (Exit::Token, "; run `vault setup` with new setup text"),
            ClientError::Unreachable | ClientError::Status(_) | ClientError::BadResponse => {
                (Exit::Server, "")
            }
            ClientError::CredentialsChanged
            | ClientError::RemoteUnopenable
            | ClientError::RefusedWrap
            | ClientError::PendingSecretKey => (Exit::Credentials, "; run `vault sync`"),
            ClientError::Locked => {
                return CliError::new(Exit::Auth, code, e.to_string());
            }
            _ => (Exit::Other, ""),
        };
        CliError::new(exit, code, format!("{e}{hint}"))
    }
}

impl From<vault_interop::Error> for CliError {
    fn from(e: vault_interop::Error) -> Self {
        match e {
            vault_interop::Error::Core(c) => c.into(),
            vault_interop::Error::WrongPassword => {
                CliError::new(Exit::Auth, e.code(), e.to_string())
            }
            _ => CliError::other(e.code(), e.to_string()),
        }
    }
}
