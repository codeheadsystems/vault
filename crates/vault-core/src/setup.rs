//! Setup text, `vault://setup?url=<server URL>&token=<token>&fp=<certificate SHA-256>`, and the
//! server URL and certificate pin rules.

use crate::body::is_lower_hex;
use crate::error::{InputKind, Result, input};
use crate::prim::sha256;
use crate::secret::{SecretString, Token};
use crate::token;
use url::{Host, Url};
use zeroize::Zeroizing;

const PREFIX: &str = "vault://setup?";

/// Parsed setup text. It holds the token, so it has no `Debug`.
pub struct SetupText {
    /// The server URL, as the WHATWG URL parser serialises it.
    pub url: String,
    /// The server token.
    pub token: Token,
    /// The SHA-256 of the server certificate's DER encoding, when the text pins one.
    pub fp: Option<[u8; 32]>,
}

/// A server URL that passed the setup rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    /// The URL as the WHATWG URL parser serialises it.
    pub url: String,
    /// Whether the URL is `http` to a loopback host, which carries no certificate and no `fp`.
    pub loopback_http: bool,
}

/// Parses a server URL as a WHATWG URL and checks the setup rules: no user information, no
/// fragment, a host that is an IPv4 address, an IPv6 address, or a domain whose labels are each 1
/// to 63 characters from `a`-`z`, `0`-`9`, and `-`, and a scheme of `https`, or `http` when the
/// host is exactly `localhost`, `127.0.0.1`, or `[::1]` after parsing.
pub fn check_server_url(text: &str) -> Result<ServerUrl> {
    let Ok(u) = Url::parse(text) else {
        return input(InputKind::ServerUrl);
    };
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return input(InputKind::ServerUrl);
    }
    // Firefox builds a host permission from the host, so a host such as `*` would grant every
    // site. After parsing, an internationalised domain is already in its `xn--` form.
    match u.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {}
        Some(Host::Domain(d)) if d.split('.').all(is_dns_label) => {}
        _ => return input(InputKind::ServerUrl),
    }
    let loopback_http = match u.scheme() {
        "https" => false,
        "http" => match u.host() {
            Some(Host::Domain("localhost")) => true,
            Some(Host::Ipv4(a)) if a == std::net::Ipv4Addr::LOCALHOST => true,
            Some(Host::Ipv6(a)) if a == std::net::Ipv6Addr::LOCALHOST => true,
            _ => return input(InputKind::ServerUrl),
        },
        _ => return input(InputKind::ServerUrl),
    };
    Ok(ServerUrl {
        url: u.into(),
        loopback_http,
    })
}

/// Whether `label` is 1 to 63 characters from `a`-`z`, `0`-`9`, and `-`.
fn is_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The SHA-256 of a certificate's DER encoding, as `fp` holds it.
pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    sha256(&[der])
}

/// Whether a leaf certificate matches the pin. The chain, the name, and the validity dates are
/// ignored.
pub fn pin_matches(fp: &[u8; 32], leaf_der: &[u8]) -> bool {
    cert_fingerprint(leaf_der) == *fp
}

/// Parses a certificate fingerprint given as 64 lowercase hex characters, as `--fp` takes it.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    if !is_lower_hex(text, 64) {
        return input(InputKind::Fingerprint);
    }
    let mut fp = [0u8; 32];
    hex::decode_to_slice(text, &mut fp)
        .map_err(|_| crate::Error::InvalidInput(InputKind::Fingerprint))?;
    Ok(fp)
}

/// Formats setup text. `url` is checked and serialised by the WHATWG URL parser, then
/// percent-encoded. The text carries `fp` only for an `https` URL; for a loopback `http` URL it
/// has none.
pub fn format_setup(url: &str, token: &Token, fp: Option<&[u8; 32]>) -> Result<SecretString> {
    let server = check_server_url(url)?;
    let mut out = Zeroizing::new(String::from(PREFIX));
    out.push_str("url=");
    percent_encode(&server.url, &mut out);
    out.push_str("&token=");
    out.push_str(&token::encode(token));
    if let (Some(fp), false) = (fp, server.loopback_http) {
        out.push_str("&fp=");
        out.push_str(&hex::encode(fp));
    }
    Ok(out)
}

/// Parses setup text. Unknown query parameters are ignored; `url` and `token` are required; a
/// repeated `url`, `token`, or `fp` is refused.
// Values are percent-decoded only, so `+` is a literal plus sign. An `fp` on a loopback `http`
// URL is refused.
pub fn parse_setup(text: &str) -> Result<SetupText> {
    let Some(query) = text.trim().strip_prefix(PREFIX) else {
        return input(InputKind::SetupText);
    };
    let (mut url, mut tok, mut fp) = (None, None, None);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name)?;
        let slot = match name.as_str() {
            "url" => &mut url,
            "token" => &mut tok,
            "fp" => &mut fp,
            _ => continue,
        };
        if slot.is_some() {
            return input(InputKind::SetupText);
        }
        *slot = Some(Zeroizing::new(percent_decode(value)?));
    }
    let (Some(url), Some(tok)) = (url, tok) else {
        return input(InputKind::SetupText);
    };
    let server = check_server_url(&url)?;
    let token = token::decode(&tok)?;
    let fp = match fp {
        Some(_) if server.loopback_http => return input(InputKind::SetupText),
        Some(f) => Some(parse_fingerprint(&f)?),
        None => None,
    };
    Ok(SetupText {
        url: server.url,
        token,
        fp,
    })
}

fn percent_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
}

/// Strict percent-decoding: every `%` starts two hex digits, and the result is UTF-8.
fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let Some(h) = b
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            else {
                return input(InputKind::SetupText);
            };
            let h = core::str::from_utf8(h).expect("ASCII hex digits");
            out.push(u8::from_str_radix(h, 16).expect("two hex digits"));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| crate::Error::InvalidInput(InputKind::SetupText))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn token() -> Token {
        Token::from_bytes([0x5a; 20])
    }

    fn setup(url: &str, extra: &str) -> String {
        let mut enc = String::new();
        percent_encode(url, &mut enc);
        format!(
            "vault://setup?url={enc}&token={}{extra}",
            token::encode(&token()).as_str()
        )
    }

    fn url_err(u: &str) -> Option<Error> {
        check_server_url(u).err()
    }

    #[test]
    fn server_url_rules() {
        let bad = Some(Error::InvalidInput(InputKind::ServerUrl));
        assert_eq!(url_err("https://vault.example:8443/base"), None);
        assert_eq!(url_err("http://localhost:8080"), None);
        assert_eq!(
            url_err("http://LOCALHOST:8080"),
            None,
            "lower-cased by the parser"
        );
        assert_eq!(url_err("http://127.0.0.1:8080"), None);
        assert_eq!(
            url_err("http://127.1:8080"),
            None,
            "127.1 parses to 127.0.0.1"
        );
        assert_eq!(url_err("http://[::1]:8080"), None);
        assert_eq!(url_err("http://[0:0:0:0:0:0:0:1]/"), None);
        assert_eq!(
            url_err("http://localhost.:8080"),
            bad,
            "localhost. is not exactly localhost"
        );
        assert_eq!(url_err("http://127.0.0.2"), bad);
        assert_eq!(url_err("http://vault.example"), bad);
        assert_eq!(url_err("http://localhost.example"), bad);
        assert_eq!(url_err("https://user@vault.example"), bad);
        assert_eq!(url_err("https://:pw@vault.example"), bad);
        assert_eq!(url_err("https://vault.example/#frag"), bad);
        assert_eq!(
            url_err("https://vault.example/#"),
            bad,
            "an empty fragment is a fragment"
        );
        assert_eq!(url_err("ftp://vault.example"), bad);
        assert_eq!(url_err("vault.example"), bad);
        assert_eq!(
            check_server_url("http://127.1:8080").unwrap().url,
            "http://127.0.0.1:8080/"
        );
        assert!(check_server_url("http://[::1]/").unwrap().loopback_http);
        assert!(
            !check_server_url("https://localhost/")
                .unwrap()
                .loopback_http
        );
    }

    #[test]
    fn host_labels() {
        let bad = Some(Error::InvalidInput(InputKind::ServerUrl));
        let l63 = "a".repeat(63);
        let l64 = "a".repeat(64);
        for (u, ok) in [
            ("https://*/", false),
            ("https://*.example/", false),
            ("https://vault_1.example/", false),
            ("https://a..b/", false),
            ("https://vault.example./", false),
            (&format!("https://{l64}.example/") as &str, false),
            (&format!("https://{l63}.example/"), true),
            ("https://xn--bcher-kva.example/", true),
            ("https://b\u{fc}cher.example/", true),
            ("https://VAULT-1.Example:8443/", true),
            ("https://10.0.0.1/", true),
            ("https://[fe80::1]/", true),
            ("https://0x7f.1/", true),
            ("https://\u{ff0a}.example/", false),
            ("https://%2a.example/", false),
            ("https:///", false),
            ("https://", false),
            ("https://-a.example/", true),
            ("https://a-.example/", true),
            ("https://B\u{dc}CHER.example/", true),
        ] {
            assert_eq!(url_err(u), if ok { None } else { bad }, "{u}");
        }
        assert_eq!(
            check_server_url("https://b\u{fc}cher.example/")
                .unwrap()
                .url,
            "https://xn--bcher-kva.example/"
        );
        assert_eq!(
            check_server_url("https://B\u{dc}CHER.example/")
                .unwrap()
                .url,
            "https://xn--bcher-kva.example/"
        );
        assert_eq!(
            format_setup("https://*/", &token(), None).err(),
            bad,
            "token add refuses it too"
        );
    }

    #[test]
    fn round_trip_with_fp() {
        let fp = [0xcd; 32];
        let t = format_setup("https://vault.example:8443/a b?q=1", &token(), Some(&fp)).unwrap();
        assert!(t.starts_with(
            "vault://setup?url=https%3A%2F%2Fvault.example%3A8443%2Fa%2520b%3Fq%3D1&token="
        ));
        assert!(t.ends_with(&format!("&fp={}", "cd".repeat(32))));
        let p = parse_setup(&t).unwrap();
        assert_eq!(p.url, "https://vault.example:8443/a%20b?q=1");
        assert_eq!(p.token.expose(), token().expose());
        assert_eq!(p.fp, Some(fp));
    }

    #[test]
    fn loopback_http_has_no_fp() {
        let t = format_setup("http://[::1]:8080", &token(), Some(&[1; 32])).unwrap();
        assert!(!t.contains("fp="));
        assert_eq!(parse_setup(&t).unwrap().fp, None);
        assert_eq!(
            parse_setup(&setup(
                "http://127.0.0.1/",
                &format!("&fp={}", "ab".repeat(32))
            ))
            .err(),
            Some(Error::InvalidInput(InputKind::SetupText))
        );
        // `127.1` and `[::1]` parse and are kept in their serialised form.
        assert_eq!(
            parse_setup(&setup("http://127.1/", "")).unwrap().url,
            "http://127.0.0.1/"
        );
        assert_eq!(
            parse_setup(&setup("http://[::1]/", "")).unwrap().url,
            "http://[::1]/"
        );
    }

    #[test]
    fn https_without_fp_and_unknown_parameters() {
        let p = parse_setup(&setup("https://vault.example", "&future=1&x")).unwrap();
        assert_eq!(p.fp, None);
        assert_eq!(p.url, "https://vault.example/");
        let reordered = format!(
            "vault://setup?v=2&token={}&url=https%3A%2F%2Fvault.example",
            token::encode(&token()).to_ascii_lowercase()
        );
        assert_eq!(
            parse_setup(&reordered).unwrap().token.expose(),
            token().expose()
        );
    }

    #[test]
    fn refusals() {
        let setup_err = Some(Error::InvalidInput(InputKind::SetupText));
        let url_bad = Some(Error::InvalidInput(InputKind::ServerUrl));
        assert_eq!(
            parse_setup(&setup("http://vault.example", "")).err(),
            url_bad
        );
        assert_eq!(parse_setup(&setup("http://localhost./", "")).err(), url_bad);
        assert_eq!(
            parse_setup(&setup("https://u@vault.example", "")).err(),
            url_bad
        );
        assert_eq!(
            parse_setup(&setup("https://vault.example/#f", "")).err(),
            url_bad
        );
        assert_eq!(parse_setup("https://vault.example").err(), setup_err);
        assert_eq!(
            parse_setup("vault://setup?url=https%3A%2F%2Fa").err(),
            setup_err
        );
        assert_eq!(
            parse_setup(&setup("https://a", "&url=https%3A%2F%2Fb")).err(),
            setup_err,
            "a repeated url"
        );
        assert_eq!(
            parse_setup(&setup("https://a", "&fp=AB")).err(),
            Some(Error::InvalidInput(InputKind::Fingerprint))
        );
        assert_eq!(
            parse_setup(&setup("https://a", &format!("&fp={}", "AB".repeat(32)))).err(),
            Some(Error::InvalidInput(InputKind::Fingerprint)),
            "upper-case hex"
        );
        assert_eq!(
            parse_setup("vault://setup?url=%zz&token=0").err(),
            setup_err
        );
        assert_eq!(parse_setup("vault://setup?url=%f&token=0").err(), setup_err);
        assert_eq!(
            parse_setup("vault://setup?url=%ff&token=0").err(),
            setup_err,
            "not UTF-8"
        );
        assert_eq!(
            parse_setup("vault://setup?url=https%3A%2F%2Fa&token=short").err(),
            Some(Error::InvalidInput(InputKind::Token))
        );
    }

    #[test]
    fn plus_is_not_a_space() {
        assert_eq!(percent_decode("a+b%20c").unwrap(), "a+b c");
        let mut enc = String::new();
        percent_encode("a+b c", &mut enc);
        assert_eq!(enc, "a%2Bb%20c");
    }

    #[test]
    fn certificate_pin() {
        let der = b"certificate bytes";
        let fp = cert_fingerprint(der);
        assert!(pin_matches(&fp, der));
        assert!(!pin_matches(&fp, b"another certificate"));
        assert_eq!(parse_fingerprint(&hex::encode(fp)).unwrap(), fp);
    }
}
