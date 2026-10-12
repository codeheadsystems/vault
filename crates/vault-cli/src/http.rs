//! The server transport: hyper's HTTP/1.1 client over rustls with the `ring` provider, on a
//! current-thread runtime that each request blocks on.
//!
//! - With `fp`, the only accepted leaf certificate is the one whose DER SHA-256 equals `fp`; the
//!   handshake signature is still checked against its key. Without `fp`, the chain is validated
//!   against the `webpki-roots` set.
//! - A `localhost` URL connects to `127.0.0.1` or `::1` without the system resolver.
//! - Connections time out after 5 s and requests after 30 s, or earlier at a deadline the caller
//!   sets. Response bodies are capped. Redirects are not followed, and no proxy is used.

use crate::store::ServerConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{self, HeaderValue};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Url};
use vault_client::{Precondition, Request, Response};
use vault_core::file::MAX_FILE_LEN;
use zeroize::Zeroizing;

/// The connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The timeout of a whole request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest revision list accepted.
pub const MAX_LIST_LEN: usize = 1 << 20;
/// The largest body of any other response.
const MAX_OTHER_LEN: usize = 1 << 20;

/// A connection to the server named in `server.json`.
pub struct Transport {
    /// Always `Some` until drop, which shuts it down without waiting for a blocked resolver.
    rt: Option<tokio::runtime::Runtime>,
    base: Url,
    host: Host<String>,
    port: u16,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    authorization: HeaderValue,
    deadline: Option<Instant>,
    /// Why the last request failed in transport, for the error message.
    pub last_error: Option<String>,
}

/// Why a server URL is refused.
#[derive(Debug)]
pub struct UrlRefused;

impl Transport {
    /// Prepares a transport. Nothing connects until the first request.
    pub fn new(server: &ServerConfig) -> Result<Transport, UrlRefused> {
        let checked = vault_core::setup::check_server_url(&server.url).map_err(|_| UrlRefused)?;
        let mut base = Url::parse(&checked.url).map_err(|_| UrlRefused)?;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let host = base.host().ok_or(UrlRefused)?.to_owned();
        let port = base.port_or_known_default().ok_or(UrlRefused)?;
        let tls = match base.scheme() {
            "https" => {
                let name = match &host {
                    Host::Domain(d) => ServerName::try_from(d.clone()).map_err(|_| UrlRefused)?,
                    Host::Ipv4(a) => ServerName::IpAddress(IpAddr::V4(*a).into()),
                    Host::Ipv6(a) => ServerName::IpAddress(IpAddr::V6(*a).into()),
                };
                Some((TlsConnector::from(Arc::new(tls_config(server.fp))), name))
            }
            // check_server_url admits plain http only to a loopback host.
            "http" if checked.loopback_http => None,
            _ => return Err(UrlRefused),
        };
        let token = vault_core::token::encode(&server.token);
        let mut bearer = Zeroizing::new(String::with_capacity(7 + token.len()));
        bearer.push_str("Bearer ");
        bearer.push_str(&token);
        // The header keeps its own copy, which hyper cannot zeroise.
        let mut authorization = HeaderValue::from_str(&bearer).map_err(|_| UrlRefused)?;
        authorization.set_sensitive(true);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("building a current-thread runtime");
        Ok(Transport {
            rt: Some(rt),
            base,
            host,
            port,
            tls,
            authorization,
            deadline: None,
            last_error: None,
        })
    }

    /// Sets a deadline that bounds every request, or clears it.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    /// Sends a request. `None` means a transport failure or a timeout; `last_error` says which.
    pub fn send(&mut self, req: &Request) -> Option<Response> {
        let timeout = match self.deadline {
            Some(d) => d
                .saturating_duration_since(Instant::now())
                .min(REQUEST_TIMEOUT),
            None => REQUEST_TIMEOUT,
        };
        let fut = self.exchange(req);
        let rt = self.rt.as_ref().expect("present until drop");
        let result = rt.block_on(async { tokio::time::timeout(timeout, fut).await });
        match result {
            Ok(Ok(resp)) => {
                self.last_error = None;
                Some(resp)
            }
            Ok(Err(e)) => {
                self.last_error = Some(e);
                None
            }
            Err(_) => {
                self.last_error = Some("the request timed out".into());
                None
            }
        }
    }

    fn exchange(&self, req: &Request) -> impl Future<Output = Result<Response, String>> + use<> {
        let (method, path, cap, body, condition) = match req {
            Request::GetVault => ("GET", "v1/vault".to_owned(), MAX_FILE_LEN, None, None),
            Request::PutVault { condition, file } => (
                "PUT",
                "v1/vault".to_owned(),
                MAX_OTHER_LEN,
                Some(Bytes::from(file.clone())),
                Some(condition.clone()),
            ),
            Request::ListRevisions => ("GET", "v1/revisions".to_owned(), MAX_LIST_LEN, None, None),
            Request::GetRevision(id) => (
                "GET",
                format!("v1/revisions/{id}"),
                MAX_FILE_LEN,
                None,
                None,
            ),
        };
        let url = self.base.join(&path).expect("a relative path");
        let target = url.path().to_owned();
        let host_header = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let authorization = self.authorization.clone();
        let host = self.host.clone();
        let port = self.port;
        let tls = self.tls.clone();
        async move {
            let mut builder = hyper::Request::builder()
                .method(method)
                .uri(target)
                .header(header::HOST, host_header)
                .header(header::AUTHORIZATION, authorization)
                .header(
                    header::USER_AGENT,
                    concat!("vault/", env!("CARGO_PKG_VERSION")),
                );
            match condition {
                Some(Precondition::IfMatch(etag)) => {
                    builder = builder.header(header::IF_MATCH, etag);
                }
                Some(Precondition::IfNoneMatch) => {
                    builder = builder.header(header::IF_NONE_MATCH, "*");
                }
                None => {}
            }
            if body.is_some() {
                builder = builder.header(header::CONTENT_TYPE, "application/octet-stream");
            }
            let request = builder
                .body(Full::new(body.unwrap_or_default()))
                .map_err(|e| format!("building the request: {e}"))?;
            if tls.is_none() {
                check_loopback_listener(port)?;
            }
            let tcp = connect(&host, port).await?;
            match tls {
                Some((connector, name)) => {
                    let stream = connector
                        .connect(name, tcp)
                        .await
                        .map_err(|e| format!("TLS handshake: {e}"))?;
                    send_on(stream, request, cap).await
                }
                None => send_on(tcp, request, cap).await,
            }
        }
    }
}

impl Drop for Transport {
    /// A name lookup runs on a blocking thread that a timeout cannot cancel; shutting down in the
    /// background leaves it behind instead of waiting for it, so the timeouts bound the command.
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Before the token goes over plain HTTP to a loopback port, checks that the socket listening on
/// that port belongs to this user or to root. Another local user who binds the port while
/// `vault serve` is down would otherwise receive the token. A port nobody listens on passes; the
/// connection then fails.
fn check_loopback_listener(port: u16) -> Result<(), String> {
    let me = rustix::process::getuid().as_raw();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        if let Some(uid) = listener_uids(&text, port)
            .into_iter()
            .find(|&u| u != me && u != 0)
        {
            return Err(format!(
                "refusing to send the token over plain HTTP: port {port} on this machine is held \
                 by another user (uid {uid}), not by this user's vault serve"
            ));
        }
    }
    Ok(())
}

/// The owners' uids of the listening sockets (state `0A`) on `port` in a `/proc/net/tcp` or
/// `/proc/net/tcp6` table.
fn listener_uids(table: &str, port: u16) -> Vec<u32> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local_port = f.get(1)?.rsplit_once(':')?.1;
            let listening = *f.get(3)? == "0A";
            let uid: u32 = f.get(7)?.parse().ok()?;
            (listening && u16::from_str_radix(local_port, 16).ok()? == port).then_some(uid)
        })
        .collect()
}

/// Connects to the server: `localhost` through `127.0.0.1` and then `::1`, an IP address
/// directly, and any other name through the system resolver.
async fn connect(host: &Host<String>, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = match host {
        Host::Domain(d) if d == "localhost" => vec![
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port),
        ],
        Host::Domain(d) => {
            tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((d.as_str(), port)))
                .await
                .map_err(|_| format!("resolving {d} timed out"))?
                .map_err(|e| format!("resolving {d}: {e}"))?
                .collect()
        }
        Host::Ipv4(a) => vec![SocketAddr::new((*a).into(), port)],
        Host::Ipv6(a) => vec![SocketAddr::new((*a).into(), port)],
    };
    let attempt = async {
        let mut last = String::from("no address to connect to");
        for a in &addrs {
            match TcpStream::connect(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("connecting to {a}: {e}"),
            }
        }
        Err(last)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, attempt)
        .await
        .map_err(|_| "connecting timed out".to_owned())?
}

async fn send_on<S>(
    stream: S,
    request: hyper::Request<Full<Bytes>>,
    cap: usize,
) -> Result<Response, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| format!("HTTP: {e}"))?;
    tokio::spawn(conn);
    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| format!("HTTP: {e}"))?;
    let status = resp.status().as_u16();
    let date = resp
        .headers()
        .get(header::DATE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date);
    let body = Limited::new(resp.into_body(), cap)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<http_body_util::LengthLimitError>() {
                format!("the response is larger than {cap} bytes")
            } else {
                format!("reading the response: {e}")
            }
        })?
        .to_bytes()
        .to_vec();
    Ok(Response { status, body, date })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The TLS client configuration: the pin with `fp`, and the `webpki-roots` set without.
fn tls_config(fp: Option<[u8; 32]>) -> rustls::ClientConfig {
    let provider = provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default versions");
    match fp {
        Some(fp) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pin {
                fp,
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
        None => {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    }
}

/// Accepts only the leaf certificate whose DER SHA-256 equals `fp`, ignoring the chain, the
/// name, and the validity dates, and checks the handshake signature against that certificate's
/// key.
#[derive(Debug)]
struct Pin {
    fp: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if vault_core::setup::pin_matches(&self.fp, end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the server certificate does not match the fingerprint in the setup text".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Parses an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) into ms.
pub fn parse_http_date(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(' ').collect();
    let [wday, day, month, year, time, "GMT"] = parts[..] else {
        return None;
    };
    if wday.len() != 4 || !wday.ends_with(',') || day.len() != 2 || year.len() != 4 {
        return None;
    }
    let num = |t: &str| -> Option<u64> {
        if t.bytes().all(|b| b.is_ascii_digit()) {
            t.parse().ok()
        } else {
            None
        }
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == month)? as u64
        + 1;
    let (day, year) = (num(day)?, num(year)?);
    let hms: Vec<&str> = time.split(':').collect();
    let [h, m, sec] = hms[..] else {
        return None;
    };
    if [h, m, sec].iter().any(|t| t.len() != 2) {
        return None;
    }
    let (h, m, sec) = (num(h)?, num(m)?, num(sec)?);
    if !(1..=31).contains(&day) || year < 1970 || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 86_400) + h * 3600 + m * 60 + sec) * 1000)
}

/// Days since 1970-01-01 of a proleptic Gregorian date, for years from 1970.
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777_000)
        );
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Mon, 12 Oct 2026 15:04:05 GMT"),
            Some(1_791_817_445_000)
        );
        for bad in [
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 25:49:37 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn loopback_listener_owners() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1002        0 2 1 0 20 4 30 10 -1
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0";
        assert_eq!(listener_uids(table, 8080), [1001], "listening only");
        assert_eq!(listener_uids(table, 80), [0]);
        assert!(listener_uids(table, 8443).is_empty());
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1003        0 4 1 0 100 0 0 10 0";
        assert_eq!(listener_uids(v6, 8443), [1003]);
    }

    #[test]
    fn our_own_listener_passes_the_check() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let me = rustix::process::getuid().as_raw();
        let text = std::fs::read_to_string("/proc/net/tcp").unwrap();
        assert!(listener_uids(&text, port).contains(&me));
        assert_eq!(check_loopback_listener(port), Ok(()));
    }

    #[test]
    fn refused_urls() {
        let cfg = |url: &str| ServerConfig {
            url: url.into(),
            token: vault_core::secret::Token::from_bytes([1; 20]),
            fp: None,
        };
        assert!(Transport::new(&cfg("http://example.com/")).is_err());
        assert!(Transport::new(&cfg("ftp://localhost/")).is_err());
        assert!(Transport::new(&cfg("http://127.0.0.1:1/")).is_ok());
        assert!(Transport::new(&cfg("https://example.com/vault")).is_ok());
    }
}
