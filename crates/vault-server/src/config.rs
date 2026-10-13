//! `serve.toml`: the URL, the quota, and the listeners.

use crate::datadir::{self, CONFIG, DataDir};
use crate::error::{Context, Result, invalid};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The contents of `serve.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The URL clients use, printed in the setup text.
    pub url: String,
    /// The storage quota, with a `MiB` or `GiB` suffix.
    pub quota: String,
    /// The HTTPS listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<HttpsConfig>,
    /// The plain HTTP listener, on a loopback address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
}

/// `[https]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsConfig {
    /// The address and port.
    pub listen: SocketAddr,
    /// The PEM certificate chain, relative to the data directory unless absolute.
    pub cert: PathBuf,
    /// The PEM private key, relative to the data directory unless absolute.
    pub key: PathBuf,
}

/// `[http]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// The address and port, which is a loopback address.
    pub listen: SocketAddr,
}

impl Config {
    /// Reads and checks `serve.toml`.
    pub(crate) fn load(data: &DataDir) -> Result<Config> {
        let path = data.path(CONFIG);
        let bytes = datadir::read(&path).context(|| format!("reading {}", path.display()))?;
        let text = String::from_utf8(bytes)
            .or_else(|_| invalid(format!("{} is not UTF-8", path.display())))?;
        let config: Config = toml::from_str(&text)
            .or_else(|e| invalid(format!("{}: {}", path.display(), e.message())))?;
        config.check()?;
        Ok(config)
    }

    /// Checks the rules `init` enforces: a valid URL and quota, at least one listener, and a
    /// loopback HTTP listener.
    pub(crate) fn check(&self) -> Result<()> {
        if vault_core::setup::check_server_url(&self.url).is_err() {
            return invalid(format!("url {:?} is refused: {URL_RULE}", self.url));
        }
        parse_quota(&self.quota)?;
        if self.https.is_none() && self.http.is_none() {
            return invalid("serve.toml needs [https], [http], or both");
        }
        if let Some(h) = &self.http {
            check_http_listen(h.listen)?;
        }
        Ok(())
    }

    /// The quota in bytes.
    pub(crate) fn quota_bytes(&self) -> u64 {
        parse_quota(&self.quota).expect("checked at load")
    }

    /// The serialised form.
    pub(crate) fn to_toml(&self) -> String {
        toml::to_string(self).expect("a Config serialises")
    }
}

/// The rule a server URL follows, for the messages that refuse one.
pub(crate) const URL_RULE: &str = "a server URL is https, or http to localhost, 127.0.0.1, or \
     [::1]; its host is an IP address or a name of dot-separated labels of 1 to 63 characters \
     from a-z, 0-9, and -; and it has no user information or fragment";

/// Refuses an HTTP listener on an address other than loopback.
pub(crate) fn check_http_listen(addr: SocketAddr) -> Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        invalid(format!(
            "the HTTP listener {addr} is not on a loopback address"
        ))
    }
}

/// Parses a quota such as `512MiB` or `2GiB`.
pub(crate) fn parse_quota(s: &str) -> Result<u64> {
    let (n, unit) = if let Some(n) = s.strip_suffix("MiB") {
        (n, 1u64 << 20)
    } else if let Some(n) = s.strip_suffix("GiB") {
        (n, 1u64 << 30)
    } else {
        return invalid(format!("quota {s:?} needs a MiB or GiB suffix"));
    };
    let digits = !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    match n.parse::<u64>() {
        Ok(n) if digits && n > 0 && n.checked_mul(unit).is_some() => Ok(n * unit),
        _ => invalid(format!(
            "quota {s:?} is not a positive whole number of MiB or GiB"
        )),
    }
}

/// Resolves a path from `serve.toml`: relative paths are relative to the data directory.
pub(crate) fn resolve(data: &DataDir, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        data.path(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota() {
        assert_eq!(parse_quota("2GiB").unwrap(), 2 << 30);
        assert_eq!(parse_quota("1MiB").unwrap(), 1 << 20);
        for bad in [
            "",
            "2",
            "2GB",
            "0MiB",
            "-1MiB",
            "+1MiB",
            "1.5GiB",
            "99999999999999GiB",
        ] {
            assert!(parse_quota(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn round_trip_and_rules() {
        let c = Config {
            url: "https://nas.lan:8443".into(),
            quota: "2GiB".into(),
            https: Some(HttpsConfig {
                listen: "0.0.0.0:8443".parse().unwrap(),
                cert: "tls/cert.pem".into(),
                key: "tls/key.pem".into(),
            }),
            http: Some(HttpConfig {
                listen: "127.0.0.1:8080".parse().unwrap(),
            }),
        };
        let text = c.to_toml();
        assert!(text.starts_with("url = \"https://nas.lan:8443\"\nquota = \"2GiB\"\n"));
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, c);
        back.check().unwrap();

        let mut public_http = c.clone();
        public_http.http = Some(HttpConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
        });
        assert!(public_http.check().is_err());
        let mut none = c.clone();
        none.https = None;
        none.http = None;
        assert!(none.check().is_err());
        let mut plain = c.clone();
        plain.url = "http://nas.lan".into();
        assert!(plain.check().is_err());
        let mut star = c;
        star.url = "https://*/".into();
        let msg = star.check().unwrap_err().to_string();
        assert!(msg.starts_with("url \"https://*/\" is refused: "), "{msg}");
        assert!(msg.ends_with(URL_RULE), "{msg}");
        assert!(
            toml::from_str::<Config>("url = \"https://a\"\nquota = \"1GiB\"\nx = 1\n").is_err()
        );
    }
}
