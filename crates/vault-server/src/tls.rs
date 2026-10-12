//! TLS: the generated certificate, the rustls server configuration with the `ring` provider, and
//! certificate fingerprints.

use crate::config::{self, HttpsConfig};
use crate::datadir::{self, DataDir};
use crate::error::{Context, Error, Result, invalid};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use url::{Host, Url};

/// A certificate and its private key in PEM form.
pub(crate) struct Generated {
    pub(crate) cert_pem: String,
    pub(crate) key_pem: zeroize::Zeroizing<String>,
}

/// Generates a self-signed ECDSA P-256 certificate, valid for ten years from today, with the
/// URL's host as its subject alternative name and common name.
pub(crate) fn generate(url: &str, now_ms: u64) -> Result<Generated> {
    let parsed = Url::parse(url).or_else(|_| invalid(format!("{url:?} is not a URL")))?;
    let (san, cn) = match parsed.host() {
        Some(Host::Domain(d)) => {
            let name = rcgen::string::Ia5String::try_from(d.to_owned())
                .or_else(|_| invalid(format!("the host of {url:?} is not a DNS name")))?;
            (rcgen::SanType::DnsName(name), d.to_owned())
        }
        Some(Host::Ipv4(a)) => (rcgen::SanType::IpAddress(a.into()), a.to_string()),
        Some(Host::Ipv6(a)) => (rcgen::SanType::IpAddress(a.into()), a.to_string()),
        None => return invalid(format!("{url:?} has no host")),
    };
    let tls_err = |e: rcgen::Error| Error::Io {
        context: "generating the certificate".into(),
        source: std::io::Error::other(e),
    };
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(tls_err)?;
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![san];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let (y, m, d) = crate::time::civil_from_days((now_ms / crate::time::DAY_MS) as i64);
    let y = i32::try_from(y).unwrap_or(9989);
    params.not_before = rcgen::date_time_ymd(y, m as u8, d as u8);
    // Ten years after 29 February is 28 February when that year has no 29 February.
    let leap = |y: i32| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let end_day = if m == 2 && d == 29 && !leap(y + 10) {
        28
    } else {
        d
    };
    params.not_after = rcgen::date_time_ymd(y + 10, m as u8, end_day as u8);
    let cert = params.self_signed(&key).map_err(tls_err)?;
    Ok(Generated {
        cert_pem: cert.pem(),
        key_pem: zeroize::Zeroizing::new(key.serialize_pem()),
    })
}

/// Reads a file named in `serve.toml`. A file inside the data directory is opened with
/// `O_NOFOLLOW`; a certificate from `--cert` and `--key` may live elsewhere, behind a link.
fn read_config_file(data: &DataDir, p: &Path) -> Result<Vec<u8>> {
    let path = config::resolve(data, p);
    let r = if p.is_absolute() {
        std::fs::read(&path)
    } else {
        datadir::read(&path)
    };
    r.context(|| format!("reading {}", path.display()))
}

/// A warning for a private key outside the data directory, from `--key`, that is owned by
/// another user or is accessible to the group or to others. The key inside the data directory
/// is refused instead, by the data directory checks.
pub(crate) fn key_warning(data: &DataDir, https: &HttpsConfig) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    if !https.key.is_absolute() {
        return None;
    }
    let path = config::resolve(data, &https.key);
    let meta = std::fs::metadata(&path).ok()?;
    let other_owner = meta.uid() != rustix::process::geteuid().as_raw();
    let open = meta.mode() & 0o077 != 0;
    (other_owner || open).then(|| {
        format!(
            "warning: the private key {} is {}",
            path.display(),
            if other_owner {
                "owned by another user"
            } else {
                "accessible to the group or others"
            }
        )
    })
}

/// Parses a PEM certificate chain.
pub(crate) fn parse_certs(pem: &[u8], what: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<_, _>>()
        .or_else(|_| invalid(format!("{} is not a PEM certificate chain", what.display())))?;
    if certs.is_empty() {
        return invalid(format!("{} holds no certificate", what.display()));
    }
    Ok(certs)
}

/// The SHA-256 of the leaf certificate's DER encoding, from the file `[https]` names.
pub(crate) fn fingerprint(data: &DataDir, https: &HttpsConfig) -> Result<[u8; 32]> {
    let pem = read_config_file(data, &https.cert)?;
    let certs = parse_certs(&pem, &https.cert)?;
    Ok(vault_core::setup::cert_fingerprint(&certs[0]))
}

/// The rustls server configuration: TLS 1.2 and 1.3 with the `ring` provider, HTTP/1.1 only.
pub(crate) fn server_config(
    data: &DataDir,
    https: &HttpsConfig,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs = parse_certs(&read_config_file(data, &https.cert)?, &https.cert)?;
    let key_pem = zeroize::Zeroizing::new(read_config_file(data, &https.key)?);
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .or_else(|_| invalid(format!("{} is not a PEM private key", https.key.display())))?;
    server_config_from(certs, key)
}

/// The rustls server configuration for a certificate chain and key.
pub(crate) fn server_config_from(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_err = |e: rustls::Error| Error::Invalid(format!("TLS configuration: {e}"));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(tls_err)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(tls_err)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A fingerprint as lowercase hex, the form `fp` and `--fp` use.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    hex::encode(fp)
}

/// A fingerprint in the colon-separated upper-case form Firefox shows.
pub fn fingerprint_colons(fp: &[u8; 32]) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colons() {
        let mut fp = [0u8; 32];
        fp[0] = 0xab;
        fp[31] = 0x01;
        let s = fingerprint_colons(&fp);
        assert!(s.starts_with("AB:00:"));
        assert!(s.ends_with(":00:01"));
        assert_eq!(s.len(), 32 * 3 - 1);
        assert_eq!(fingerprint_hex(&fp).len(), 64);
    }

    #[test]
    fn a_key_open_to_others_is_warned_about() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = DataDir::new(dir.path());
        let key = dir.path().join("key.pem");
        std::fs::write(&key, b"key").unwrap();
        let https = |key: std::path::PathBuf| HttpsConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert: "cert.pem".into(),
            key,
        };
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(key_warning(&data, &https(key.clone())), None);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let w = key_warning(&data, &https(key.clone())).unwrap();
        assert!(w.contains("accessible to the group or others"), "{w}");
        // A relative path is inside the data directory, which the directory checks cover.
        assert_eq!(key_warning(&data, &https("key.pem".into())), None);
    }

    #[test]
    fn generated_certificate_loads() {
        for url in [
            "https://nas.lan:8443",
            "https://192.168.1.2",
            "https://[::1]:8443",
        ] {
            let g = generate(url, 1_760_281_445_000).unwrap();
            let certs = parse_certs(g.cert_pem.as_bytes(), Path::new("cert")).unwrap();
            assert_eq!(certs.len(), 1);
            let key = PrivateKeyDer::from_pem_slice(g.key_pem.as_bytes()).unwrap();
            server_config_from(certs, key).unwrap();
        }
    }
}
