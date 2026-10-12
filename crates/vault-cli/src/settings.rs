//! `config.toml`: the settings of `docs/cli.md`, with their defaults.

use crate::error::{CliError, Result};
use crate::paths::Paths;
use serde::Deserialize;
use std::io;
use std::time::Duration;

/// Where `vault init` and `vault setup` store the secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyringSetting {
    /// The Secret Service when reachable, and otherwise the `secret-key` file.
    Auto,
    /// The `secret-key` file.
    File,
}

/// The settings, with every default filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `agent.enabled`: commands use the agent.
    pub agent_enabled: bool,
    /// `agent.idle`: the agent ends after this long without a request.
    pub agent_idle: Duration,
    /// `agent.max`: the agent ends this long after the unlock.
    pub agent_max: Duration,
    /// `sync.auto`: sync after writes and from the agent.
    pub sync_auto: bool,
    /// `sync.interval`: time between the agent's syncs.
    pub sync_interval: Duration,
    /// `clipboard.clear_after`: time before a copied value is cleared.
    pub clear_after: Duration,
    /// `keyring`.
    pub keyring: KeyringSetting,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            agent_enabled: true,
            agent_idle: Duration::from_secs(15 * 60),
            agent_max: Duration::from_secs(8 * 3600),
            sync_auto: true,
            sync_interval: Duration::from_secs(5 * 60),
            clear_after: Duration::from_secs(45),
            keyring: KeyringSetting::Auto,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    agent: AgentSection,
    #[serde(default)]
    sync: SyncSection,
    #[serde(default)]
    clipboard: ClipboardSection,
    keyring: Option<KeyringSetting>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AgentSection {
    enabled: Option<bool>,
    idle: Option<String>,
    max: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SyncSection {
    auto: Option<bool>,
    interval: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ClipboardSection {
    clear_after: Option<String>,
}

impl Settings {
    /// Reads `config.toml`; a missing file gives the defaults.
    pub fn load(paths: &Paths) -> Result<Settings> {
        let text = match std::fs::read_to_string(&paths.config) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
            Err(e) => return Err(CliError::io(paths.config.display(), e)),
        };
        Settings::parse(&text).map_err(|m| {
            CliError::other("config.invalid", format!("{}: {m}", paths.config.display()))
        })
    }

    fn parse(text: &str) -> std::result::Result<Settings, String> {
        let f: File = toml::from_str(text).map_err(|e| e.message().to_owned())?;
        let d = Settings::default();
        let dur = |v: Option<String>, key: &str, default: Duration| match v {
            None => Ok(default),
            Some(s) => parse_duration(&s)
                .ok_or_else(|| format!("{key} = {s:?} is not a number followed by s, m, or h")),
        };
        Ok(Settings {
            agent_enabled: f.agent.enabled.unwrap_or(d.agent_enabled),
            agent_idle: dur(f.agent.idle, "agent.idle", d.agent_idle)?,
            agent_max: dur(f.agent.max, "agent.max", d.agent_max)?,
            sync_auto: f.sync.auto.unwrap_or(d.sync_auto),
            sync_interval: dur(f.sync.interval, "sync.interval", d.sync_interval)?,
            clear_after: dur(
                f.clipboard.clear_after,
                "clipboard.clear_after",
                d.clear_after,
            )?,
            keyring: f.keyring.unwrap_or(d.keyring),
        })
    }

    /// Whether commands use the agent: `agent.enabled`, no `VAULT_NO_AGENT=1`, and a runtime
    /// directory.
    pub fn use_agent(&self, paths: &Paths) -> bool {
        self.agent_enabled
            && std::env::var_os("VAULT_NO_AGENT").is_none_or(|v| v != "1")
            && paths.runtime.is_some()
    }
}

/// A duration: a positive whole number followed by `s`, `m`, or `h`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let (n, unit) = s.split_at(s.len().checked_sub(1)?);
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = n.parse().ok().filter(|&n| n > 0)?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("45s"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("15m"), Some(Duration::from_secs(900)));
        assert_eq!(parse_duration("8h"), Some(Duration::from_secs(28800)));
        for bad in ["", "s", "0s", "1", "1d", "-1s", "1.5m", " 1s", "1 s", "+1s"] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn defaults_and_overrides() {
        assert_eq!(Settings::parse("").unwrap(), Settings::default());
        let s = Settings::parse(
            "keyring = \"file\"\n[agent]\nenabled = false\nidle = \"1m\"\n\
             [sync]\ninterval = \"30s\"\n[clipboard]\nclear_after = \"10s\"\n",
        )
        .unwrap();
        assert!(!s.agent_enabled);
        assert_eq!(s.agent_idle, Duration::from_secs(60));
        assert_eq!(s.agent_max, Settings::default().agent_max);
        assert_eq!(s.sync_interval, Duration::from_secs(30));
        assert_eq!(s.clear_after, Duration::from_secs(10));
        assert_eq!(s.keyring, KeyringSetting::File);
    }

    #[test]
    fn refusals() {
        assert!(Settings::parse("colour = true").is_err());
        assert!(Settings::parse("[agent]\nidle = \"1d\"").is_err());
        assert!(Settings::parse("keyring = \"kwallet\"").is_err());
        assert!(Settings::parse("[agent]\nenabled = \"yes\"").is_err());
    }
}
