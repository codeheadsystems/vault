//! The commands that edit the data directory: `init` and `token add`, `ls`, and `rm`. The
//! `revisions` commands live in [`crate::revisions`].

use crate::config::{self, Config, HttpConfig, HttpsConfig, URL_RULE};
use crate::datadir::{self, CONFIG, DataDir, TLS, TOKENS};
use crate::error::{Context, Result, invalid};
use crate::revisions::Index;
use crate::tokens::{self, TokenInfo, TokensFile};
use std::net::SocketAddr;
use std::path::PathBuf;
use vault_core::secret::SecretString;

/// Options of `vault serve init`.
#[derive(Debug, Clone, clap::Args)]
pub struct InitArgs {
    /// The URL clients use, printed in the setup text
    #[arg(long)]
    pub url: String,
    /// The HTTPS address and port
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8443")]
    pub listen: SocketAddr,
    /// A plain HTTP address and port, loopback only
    #[arg(long, value_name = "ADDR")]
    pub http_listen: Option<SocketAddr>,
    /// A PEM certificate chain to serve instead of a generated certificate
    #[arg(long, value_name = "FILE", requires = "key")]
    pub cert: Option<PathBuf>,
    /// The PEM private key of --cert
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<PathBuf>,
    /// No HTTPS listener; needs --http-listen
    #[arg(long, conflicts_with_all = ["cert", "key", "listen"])]
    pub no_tls: bool,
    /// Storage quota, with a MiB or GiB suffix
    #[arg(long, value_name = "SIZE", default_value = "2GiB")]
    pub quota: String,
}

/// What `init` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    /// The SHA-256 of the served certificate, when there is an HTTPS listener.
    pub fingerprint: Option<[u8; 32]>,
    /// Warnings to show, such as a `--key` file that others can read.
    pub warnings: Vec<String>,
}

/// Creates the data directory, `serve.toml`, `tokens.json`, `revisions/`, and, without `--cert`
/// or `--no-tls`, a self-signed certificate in `tls/`. Refuses a directory that holds
/// `serve.toml`.
pub fn init(data: &DataDir, args: &InitArgs) -> Result<InitReport> {
    let Ok(url) = vault_core::setup::check_server_url(&args.url) else {
        return invalid(format!("--url {:?} is refused: {URL_RULE}", args.url));
    };
    if url.loopback_http && args.http_listen.is_none() {
        return invalid("an http URL needs --http-listen");
    }
    if args.no_tls && args.http_listen.is_none() {
        return invalid("--no-tls needs --http-listen");
    }
    if let Some(h) = args.http_listen {
        config::check_http_listen(h)?;
    }
    config::parse_quota(&args.quota)?;

    DataDir::create_dir(data.root())?;
    if std::fs::symlink_metadata(data.path(CONFIG)).is_ok() {
        return invalid(format!(
            "{} already holds serve.toml",
            data.root().display()
        ));
    }
    data.check()?;
    let _w = data.write_lock()?;
    DataDir::create_dir(&data.revisions())?;

    let https = if args.no_tls {
        None
    } else if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
        let abs =
            |p: &PathBuf| std::path::absolute(p).context(|| format!("resolving {}", p.display()));
        Some(HttpsConfig {
            listen: args.listen,
            cert: abs(cert)?,
            key: abs(key)?,
        })
    } else {
        let g = crate::tls::generate(&url.url, crate::time::now_ms())?;
        DataDir::create_dir(&data.path(TLS))?;
        datadir::write_atomic(&data.path("tls/cert.pem"), g.cert_pem.as_bytes())?;
        datadir::write_atomic(&data.path("tls/key.pem"), g.key_pem.as_bytes())?;
        Some(HttpsConfig {
            listen: args.listen,
            cert: "tls/cert.pem".into(),
            key: "tls/key.pem".into(),
        })
    };
    let warnings: Vec<String> = https
        .as_ref()
        .and_then(|h| crate::tls::key_warning(data, h))
        .into_iter()
        .collect();
    let fingerprint = match &https {
        Some(h) => {
            // Loads the pair as the server will, so a bad --cert or --key fails here.
            crate::tls::server_config(data, h)?;
            Some(crate::tls::fingerprint(data, h)?)
        }
        None => None,
    };
    let config = Config {
        url: args.url.clone(),
        quota: args.quota.clone(),
        https,
        http: args.http_listen.map(|listen| HttpConfig { listen }),
    };
    config.check()?;
    if std::fs::symlink_metadata(data.path(TOKENS)).is_err() {
        TokensFile::default().store(data)?;
    }
    // `serve.toml` last: a failed `init` leaves no `serve.toml` and can run again.
    datadir::write_atomic(&data.path(CONFIG), config.to_toml().as_bytes())?;
    Ok(InitReport {
        fingerprint,
        warnings,
    })
}

/// Options of `vault serve token add`.
#[derive(Debug, Clone, clap::Args)]
pub struct TokenAddArgs {
    /// The token's name: 1 to 32 characters from a-z, 0-9, -, and _
    pub name: String,
    /// A URL other than the one in serve.toml
    #[arg(long)]
    pub url: Option<String>,
    /// The certificate fingerprint to put in the setup text, as 64 lowercase hex characters
    #[arg(long, value_name = "HEX", conflicts_with = "no_fp")]
    pub fp: Option<String>,
    /// Leaves the fingerprint out, for a certificate that clients validate through WebPKI
    #[arg(long)]
    pub no_fp: bool,
}

/// A token that `token add` created.
pub struct TokenAdded {
    /// The setup text, which holds the token.
    pub setup_text: SecretString,
    /// The fingerprint in the setup text.
    pub fingerprint: Option<[u8; 32]>,
}

/// Creates a token and returns its setup text. The token appears nowhere else.
pub fn token_add(data: &DataDir, args: &TokenAddArgs) -> Result<TokenAdded> {
    data.check()?;
    let config = Config::load(data)?;
    let url_text = args.url.as_deref().unwrap_or(&config.url);
    let Ok(url) = vault_core::setup::check_server_url(url_text) else {
        let what = if args.url.is_some() { "--url" } else { "url" };
        return invalid(format!("{what} {url_text:?} is refused: {URL_RULE}"));
    };
    let fingerprint = if url.loopback_http || args.no_fp {
        None
    } else if let Some(fp) = &args.fp {
        let Ok(fp) = vault_core::setup::parse_fingerprint(fp) else {
            return invalid("--fp is not 64 lowercase hex characters");
        };
        Some(fp)
    } else if let Some(h) = &config.https {
        Some(crate::tls::fingerprint(data, h)?)
    } else {
        return invalid("an https URL with no HTTPS listener needs --fp or --no-fp");
    };
    let token = {
        let _w = data.write_lock()?;
        tokens::add(data, &args.name, crate::time::now_ms())?
    };
    let setup_text = vault_core::setup::format_setup(&url.url, &token, fingerprint.as_ref())
        .or_else(|e| invalid(format!("formatting the setup text: {e}")))?;
    Ok(TokenAdded {
        setup_text,
        fingerprint,
    })
}

/// Lists the tokens with each token's newest retained revision.
pub fn token_list(data: &DataDir) -> Result<Vec<TokenInfo>> {
    data.check()?;
    let file = TokensFile::load(data)?;
    let index = Index::read(&data.revisions())?;
    let revs = index.newest_first();
    Ok(file
        .tokens
        .into_iter()
        .map(|t| {
            let last_push = revs
                .iter()
                .find(|r| r.token == t.name)
                .map(|r| (r.id, r.created()));
            TokenInfo {
                name: t.name,
                created: t.created,
                last_push,
            }
        })
        .collect())
}

/// Revokes the token named `name`. A running server refuses it from its next request.
pub fn token_remove(data: &DataDir, name: &str) -> Result<()> {
    data.check()?;
    let _w = data.write_lock()?;
    tokens::remove(data, name)
}

/// A QR code of `text` in Unicode half blocks, light modules drawn, for a dark terminal.
pub(crate) fn qr(text: &str) -> Result<SecretString> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| crate::Error::Invalid(format!("making the QR code: {e}")))?;
    Ok(SecretString::new(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    ))
}

/// A warning when the running user has a client data directory or an agent socket.
pub(crate) fn client_warning() -> Option<String> {
    let mut found = Vec::new();
    if let Some(d) = datadir::xdg_data_home().map(|d| d.join("vault"))
        && std::fs::symlink_metadata(&d).is_ok()
    {
        found.push(d);
    }
    if let Some(sock) =
        std::env::var_os("XDG_RUNTIME_DIR").map(|r| PathBuf::from(r).join("vault/agent.sock"))
        && std::fs::symlink_metadata(&sock).is_ok()
    {
        found.push(sock);
    }
    if found.is_empty() {
        return None;
    }
    let paths: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
    Some(format!(
        "warning: this user also runs the vault client ({}); run vault serve as its own system \
         user so a fault in the server cannot reach the client's secret key or vault",
        paths.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_code_in_half_blocks() {
        let code = qr("vault://setup?url=https%3A%2F%2Fnas.lan&token=0123").unwrap();
        let lines: Vec<&str> = code.lines().collect();
        assert!(lines.len() > 10);
        assert!(
            lines
                .iter()
                .all(|l| l.chars().count() == lines[0].chars().count())
        );
        assert!(
            code.chars()
                .all(|c| matches!(c, ' ' | '\u{2580}' | '\u{2584}' | '\u{2588}' | '\n'))
        );
    }
}
