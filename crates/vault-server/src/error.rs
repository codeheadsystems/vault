//! Errors of the server and its commands.

use std::fmt;
use std::io;

/// Every error `vault-server` returns. Messages name paths and settings, never a token.
#[derive(Debug)]
pub enum Error {
    /// The data directory or an entry in it is owned by another user, is accessible to the group
    /// or to others, or is a symbolic link.
    Unsafe(String),
    /// Another `vault serve` holds `server.lock` on the data directory.
    Locked,
    /// A command-line value, `serve.toml`, or `tokens.json` breaks a rule.
    Invalid(String),
    /// An operating system or TLS error, with what the command was doing.
    Io {
        /// What the command was doing.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsafe(m) => write!(f, "unsafe data directory: {m}"),
            Error::Locked => f.write_str("another vault serve is running on this data directory"),
            Error::Invalid(m) => f.write_str(m),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Result with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Adds context to an I/O result.
pub(crate) trait Context<T> {
    /// Wraps the error with a description of the operation.
    fn context(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T> Context<T> for io::Result<T> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: what(),
            source,
        })
    }
}

pub(crate) fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}
