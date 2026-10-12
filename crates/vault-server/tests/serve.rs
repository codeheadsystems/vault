//! `vault serve` over real sockets on 127.0.0.1: every row of the spec Server API table, tokens,
//! the PUT order, quota and retention, crash cleanup, locks, permissions, TLS, and the HTTP
//! listener.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use vault_server::{
    DataDir, Error, InitArgs, Server, TokenAddArgs, Tuning, init, revisions_list, revisions_prune,
    revisions_remove, token_add, token_list, token_remove,
};

const MIB: usize = 1 << 20;

// ---------------------------------------------------------------------------------------------
// Fixtures

struct Env {
    _tmp: tempfile::TempDir,
    data: DataDir,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path().join("data"));
        Env { _tmp: tmp, data }
    }

    fn root(&self) -> &Path {
        self.data.root()
    }

    fn revdir(&self) -> PathBuf {
        self.root().join("revisions")
    }

    /// A data directory with only the HTTP listener.
    fn http(quota: &str) -> Env {
        let env = Env::new();
        init(&env.data, &http_args(quota)).unwrap();
        env
    }

    fn token(&self, name: &str) -> String {
        let added = token_add(&self.data, &add_args(name)).unwrap();
        bearer(&added.setup_text)
    }

    fn revision_files(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.revdir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

fn http_args(quota: &str) -> InitArgs {
    InitArgs {
        url: "http://127.0.0.1:8080".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        http_listen: Some("127.0.0.1:0".parse().unwrap()),
        cert: None,
        key: None,
        no_tls: true,
        quota: quota.into(),
    }
}

fn https_args() -> InitArgs {
    InitArgs {
        url: "https://localhost:8443".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        http_listen: None,
        cert: None,
        key: None,
        no_tls: false,
        quota: "64MiB".into(),
    }
}

fn add_args(name: &str) -> TokenAddArgs {
    TokenAddArgs {
        name: name.into(),
        url: None,
        fp: None,
        no_fp: false,
    }
}

/// The `Authorization` value for a setup text's token.
fn bearer(setup: &str) -> String {
    let s = vault_core::setup::parse_setup(setup).unwrap();
    format!("Bearer {}", vault_core::token::encode(&s.token).as_str())
}

/// A body shaped like a vault file: `VAULT`, then `tag`, padded to `173 + 4096 * blocks` bytes.
fn vault(tag: u32, blocks: usize) -> Vec<u8> {
    let mut v = b"VAULT".to_vec();
    v.extend_from_slice(&tag.to_be_bytes());
    v.resize(173 + 4096 * blocks, 0);
    v
}

fn etag(b: &[u8]) -> String {
    vault_core::sync::etag(b)
}

struct Running {
    https: Option<SocketAddr>,
    http: Option<SocketAddr>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<vault_server::Result<()>>,
}

impl Running {
    async fn start(env: &Env) -> Running {
        Running::start_with(env, Tuning::default()).await
    }

    async fn start_with(env: &Env, tuning: Tuning) -> Running {
        let server = Server::bind_with(&env.data, tuning).await.unwrap();
        let (https, http) = (server.https_addr(), server.http_addr());
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.run(async {
            let _ = rx.await;
        }));
        Running {
            https,
            http,
            stop,
            task,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.http.or(self.https).unwrap()
    }

    async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap().unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// Client

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

/// Checks what every response carries: `Cache-Control: no-store, no-transform` and no CORS
/// header.
fn check_common(headers: &HeaderMap) {
    assert_eq!(
        headers.get("cache-control").map(HeaderValue::as_bytes),
        Some(&b"no-store, no-transform"[..])
    );
    assert!(
        headers
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-")),
        "a CORS header: {headers:?}"
    );
}

async fn send_on<I>(
    io: I,
    req: Request<http_body_util::combinators::BoxBody<Bytes, std::io::Error>>,
) -> Resp
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    check_common(&parts.headers);
    Resp {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

struct Req {
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunked: bool,
}

fn req(method: Method, path: &str) -> Req {
    Req {
        method,
        path: path.into(),
        headers: Vec::new(),
        body: Vec::new(),
        chunked: false,
    }
}

impl Req {
    fn auth(self, bearer: &str) -> Req {
        self.header("authorization", bearer)
    }

    fn header(mut self, k: &str, v: &str) -> Req {
        self.headers.push((k.into(), v.into()));
        self
    }

    fn body(mut self, b: Vec<u8>) -> Req {
        self.body = b;
        self
    }

    /// Sends the body with chunked transfer encoding, without `Content-Length`.
    fn chunked(mut self) -> Req {
        self.chunked = true;
        self
    }

    fn build(self) -> Request<http_body_util::combinators::BoxBody<Bytes, std::io::Error>> {
        let mut b = Request::builder()
            .method(self.method)
            .uri(self.path)
            .header("host", "localhost");
        for (k, v) in &self.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let body = if self.chunked {
            Chunked(
                self.body
                    .chunks(64 * 1024)
                    .map(Bytes::copy_from_slice)
                    .collect(),
            )
            .boxed()
        } else {
            Full::new(Bytes::from(self.body))
                .map_err(|e| match e {})
                .boxed()
        };
        b.body(body).unwrap()
    }

    /// Sends the request on a new connection. A PUT refused with any status but `200` carries
    /// `Connection: close`, because its body may be unread.
    async fn send(self, addr: SocketAddr) -> Resp {
        let is_put = self.method == Method::PUT;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let r = send_on(tcp, self.build()).await;
        if is_put {
            let close = r.header("connection") == Some("close");
            assert_eq!(close, r.status != StatusCode::OK, "PUT {}", r.status);
        }
        r
    }
}

/// A body of unknown length, which the client sends with chunked transfer encoding.
struct Chunked(std::collections::VecDeque<Bytes>);

impl hyper::body::Body for Chunked {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        std::task::Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
    }
}

/// Writes raw bytes and reads the response until the server closes the connection.
async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = tcp.split();
    let (_, out) = tokio::join!(
        async {
            let _ = wr.write_all(request).await;
        },
        async {
            let mut out = Vec::new();
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(20), rd.read_to_end(&mut out))
                    .await;
            out
        }
    );
    String::from_utf8_lossy(&out).into_owned()
}

fn status_of(raw: &str) -> u16 {
    raw.split(' ').nth(1).unwrap().parse().unwrap()
}

async fn put(addr: SocketAddr, auth: &str, cond: (&str, &str), body: Vec<u8>) -> Resp {
    req(Method::PUT, "/v1/vault")
        .auth(auth)
        .header(cond.0, cond.1)
        .body(body)
        .send(addr)
        .await
}

async fn get(addr: SocketAddr, auth: &str, path: &str) -> Resp {
    req(Method::GET, path).auth(auth).send(addr).await
}

// ---------------------------------------------------------------------------------------------
// Server API table

#[tokio::test(flavor = "multi_thread")]
async fn server_api_table() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();

    // GET /v1/vault before the first push.
    assert_eq!(get(a, &t, "/v1/vault").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        get(a, &t, "/v1/revisions").await.body,
        &br#"{"revisions":[]}"#[..]
    );

    // If-Match on a server with no revision does not hold.
    let r = put(a, &t, ("if-match", &etag(&vault(1, 1))), vault(1, 1)).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    // PUT with neither header.
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .body(vault(1, 1))
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);

    // PUT with If-None-Match: * stores the first revision.
    let v1 = vault(1, 1);
    let r = put(a, &t, ("if-none-match", "*"), v1.clone()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("etag"), Some(etag(&v1).as_str()));
    // ...and receives 412 once one exists.
    let r = put(a, &t, ("if-none-match", "*"), vault(2, 1)).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    // GET /v1/vault returns the file and its ETag.
    let r = get(a, &t, "/v1/vault").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, v1);
    assert_eq!(r.header("etag"), Some(etag(&v1).as_str()));
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));

    // PUT with If-Match: the current ETag stores; anything else is 412.
    let v2 = vault(2, 2);
    let r = put(a, &t, ("if-match", &etag(&v1)), v2.clone()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("etag"), Some(etag(&v2).as_str()));
    let current = etag(&v2);
    let weak = format!("W/{current}");
    let list = format!("{current}, \"other\"");
    for stale in [
        etag(&v1),
        "*".into(),
        weak,
        list,
        current.trim_matches('"').to_owned(),
    ] {
        let r = put(a, &t, ("if-match", &stale), vault(3, 1)).await;
        assert_eq!(
            r.status,
            StatusCode::PRECONDITION_FAILED,
            "If-Match: {stale}"
        );
    }
    // With both headers, both must hold, which they cannot.
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .header("if-match", &current)
        .header("if-none-match", "*")
        .body(vault(3, 1))
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);
    // Two If-Match headers form a list, which does not hold.
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .header("if-match", &current)
        .header("if-match", &current)
        .body(vault(3, 1))
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    // PUT with a body not shaped like a vault file.
    let mut bad_magic = vault(3, 1);
    bad_magic[0] = b'X';
    let mut short = vault(3, 1);
    short.truncate(4268);
    let mut odd = vault(3, 1);
    odd.push(0);
    for (body, what) in [
        (bad_magic, "magic"),
        (short, "short"),
        (odd, "size"),
        (b"VAULT".to_vec(), "tiny"),
    ] {
        let r = put(a, &t, ("if-match", &current), body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{what}");
    }

    // GET /v1/revisions lists the retained revisions, newest first.
    let r = get(a, &t, "/v1/revisions").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), Some("application/json"));
    let list: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let revs = list["revisions"].as_array().unwrap();
    assert_eq!(revs.len(), 2);
    assert_eq!(revs[0]["id"], 2);
    assert_eq!(revs[0]["etag"], etag(&v2));
    assert_eq!(revs[0]["size"], v2.len());
    assert_eq!(revs[0]["token"], "laptop");
    assert_eq!(revs[1]["id"], 1);
    let created = revs[0]["created"].as_str().unwrap();
    assert_eq!(created.len(), 20);
    assert!(created.ends_with('Z'));

    // GET /v1/revisions/<id> returns that revision; 404 when it is not retained.
    let r = get(a, &t, "/v1/revisions/1").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, v1);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(get(a, &t, "/v1/revisions/2").await.body, v2);
    assert_eq!(
        get(a, &t, "/v1/revisions/3").await.status,
        StatusCode::NOT_FOUND
    );

    // The temporary files of refused uploads are gone.
    assert_eq!(
        env.revision_files(),
        ["1.json", "1.vault", "2.json", "2.vault"]
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn paths_are_matched_exactly_and_methods_checked() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    put(a, &t, ("if-none-match", "*"), vault(1, 1)).await;
    for path in [
        "/",
        "/v1",
        "/v1/vault/",
        "/V1/vault",
        "/v1/vault/1",
        "/v1/revisions/",
        "/v1/revisions/01",
        "/v1/revisions/+1",
        "/v1/revisions/-1",
        "/v1/revisions/1x",
        "/v1/revisions/18446744073709551616",
        "/v1/revisions/1/",
        "//v1/vault",
    ] {
        assert_eq!(
            get(a, &t, path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // The query is not part of the path.
    assert_eq!(get(a, &t, "/v1/vault?x=1").await.status, StatusCode::OK);
    for (method, path, allow) in [
        (Method::POST, "/v1/vault", "GET, PUT"),
        (Method::DELETE, "/v1/vault", "GET, PUT"),
        (Method::HEAD, "/v1/vault", "GET, PUT"),
        (Method::OPTIONS, "/v1/vault", "GET, PUT"),
        (Method::PUT, "/v1/revisions", "GET"),
        (Method::DELETE, "/v1/revisions/1", "GET"),
        (Method::PUT, "/v1/revisions/1", "GET"),
    ] {
        let r = req(method.clone(), path).auth(&t).send(a).await;
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        assert_eq!(r.header("allow"), Some(allow));
    }
    // An OPTIONS preflight gets no CORS headers (checked on every response).
    let r = req(Method::OPTIONS, "/v1/vault")
        .header("origin", "moz-extension://x")
        .header("access-control-request-method", "PUT")
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    s.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Tokens

#[tokio::test(flavor = "multi_thread")]
async fn unknown_revoked_and_reloaded_tokens() {
    let env = Env::http("64MiB");
    let laptop = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();

    let unknown = format!(
        "Bearer {}",
        vault_core::token::encode(&vault_core::secret::Token::from_bytes([9; 20])).as_str()
    );
    for auth in [
        None,
        Some(unknown.as_str()),
        Some("Bearer"),
        Some("Basic abc"),
        Some("Bearer short"),
    ] {
        for (method, path) in [
            (Method::GET, "/v1/vault"),
            (Method::PUT, "/v1/vault"),
            (Method::GET, "/v1/revisions"),
            (Method::GET, "/v1/revisions/1"),
            (Method::GET, "/nope"),
        ] {
            let mut r = req(method, path);
            if let Some(v) = auth {
                r = r.auth(v);
            }
            let r = r.body(vault(1, 1)).send(a).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{auth:?} {path}");
            assert_eq!(r.header("www-authenticate"), Some("Bearer"));
        }
    }
    // The token text is accepted in lower case, as the decoder allows.
    assert_eq!(
        get(
            a,
            &laptop.to_ascii_lowercase().replace("bearer", "Bearer"),
            "/v1/vault"
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    // A token added while the server runs works on the next request.
    let phone = env.token("phone");
    assert_eq!(
        get(a, &phone, "/v1/vault").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(a, &phone, ("if-none-match", "*"), vault(1, 1))
            .await
            .status,
        StatusCode::OK
    );

    // A revoked token is refused from the next request; the other still works.
    token_remove(&env.data, "phone").unwrap();
    assert_eq!(
        get(a, &phone, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(get(a, &laptop, "/v1/vault").await.status, StatusCode::OK);
    // Its revisions keep its name.
    let list: serde_json::Value =
        serde_json::from_slice(&get(a, &laptop, "/v1/revisions").await.body).unwrap();
    assert_eq!(list["revisions"][0]["token"], "phone");

    // An unreadable tokens.json refuses every request until it is fixed.
    let tokens = env.root().join("tokens.json");
    let good = fs::read(&tokens).unwrap();
    fs::write(&tokens, b"{not json").unwrap();
    assert_eq!(
        get(a, &laptop, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    fs::write(&tokens, &good).unwrap();
    assert_eq!(get(a, &laptop, "/v1/vault").await.status, StatusCode::OK);
    // A symbolic link in its place is not followed.
    let elsewhere = env.root().parent().unwrap().join("tokens-elsewhere.json");
    fs::write(&elsewhere, &good).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&tokens).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &tokens).unwrap();
    assert_eq!(
        get(a, &laptop, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    // Neither is a file open to others.
    fs::remove_file(&tokens).unwrap();
    fs::write(&tokens, &good).unwrap();
    fs::set_permissions(&tokens, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        get(a, &laptop, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    fs::set_permissions(&tokens, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(get(a, &laptop, "/v1/vault").await.status, StatusCode::OK);
    s.stop().await;
}

#[test]
fn token_commands() {
    let env = Env::http("64MiB");
    // A loopback http URL never carries fp.
    let added = token_add(&env.data, &add_args("laptop")).unwrap();
    assert!(added.fingerprint.is_none());
    let parsed = vault_core::setup::parse_setup(&added.setup_text).unwrap();
    assert_eq!(parsed.url, "http://127.0.0.1:8080/");
    assert!(parsed.fp.is_none());
    // The stored hash is the SHA-256 of the token bytes; the token itself is not stored.
    let tokens = fs::read_to_string(env.root().join("tokens.json")).unwrap();
    let hash = hex::encode(vault_core::token::stored_hash(&parsed.token));
    assert!(tokens.contains(&hash));
    assert!(!tokens.contains(vault_core::token::encode(&parsed.token).as_str()));
    assert_eq!(
        fs::metadata(env.root().join("tokens.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // Names in use and bad names are refused.
    for bad in ["laptop", "", "Laptop", "a b", &"x".repeat(33)] {
        assert!(
            matches!(token_add(&env.data, &add_args(bad)), Err(Error::Invalid(_))),
            "{bad}"
        );
    }
    // An https URL with no HTTPS listener needs --fp or --no-fp.
    let proxy = |fp: Option<&str>, no_fp| TokenAddArgs {
        name: format!("p{}", u8::from(no_fp)),
        url: Some("https://vault.example".into()),
        fp: fp.map(Into::into),
        no_fp,
    };
    assert!(token_add(&env.data, &proxy(None, false)).is_err());
    let fp = "ab".repeat(32);
    let with_fp = token_add(&env.data, &proxy(Some(&fp), false)).unwrap();
    assert_eq!(
        vault_core::setup::parse_setup(&with_fp.setup_text)
            .unwrap()
            .fp,
        Some([0xab; 32])
    );
    let no_fp = token_add(&env.data, &proxy(None, true)).unwrap();
    assert!(
        vault_core::setup::parse_setup(&no_fp.setup_text)
            .unwrap()
            .fp
            .is_none()
    );
    assert!(
        token_add(
            &env.data,
            &TokenAddArgs {
                fp: Some("AB".repeat(32)),
                ..proxy(None, false)
            }
        )
        .is_err()
    );

    let names: Vec<String> = token_list(&env.data)
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, ["laptop", "p0", "p1"]);
    assert!(
        token_list(&env.data)
            .unwrap()
            .iter()
            .all(|t| t.last_push.is_none())
    );
    token_remove(&env.data, "p0").unwrap();
    assert!(matches!(
        token_remove(&env.data, "p0"),
        Err(Error::Invalid(_))
    ));
    assert_eq!(token_list(&env.data).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_ls_shows_the_last_retained_push() {
    let env = Env::http("64MiB");
    let laptop = env.token("laptop");
    let phone = env.token("phone");
    let s = Running::start(&env).await;
    let a = s.addr();
    let v1 = vault(1, 1);
    put(a, &laptop, ("if-none-match", "*"), v1.clone()).await;
    let v2 = vault(2, 1);
    put(a, &phone, ("if-match", &etag(&v1)), v2.clone()).await;
    put(a, &laptop, ("if-match", &etag(&v2)), vault(3, 1)).await;
    let ls = token_list(&env.data).unwrap();
    assert_eq!(ls[0].name, "laptop");
    assert_eq!(ls[0].last_push.as_ref().unwrap().0, 3);
    assert_eq!(ls[1].last_push.as_ref().unwrap().0, 2);
    s.stop().await;
}

// ---------------------------------------------------------------------------------------------
// PUT order, size, quota, and the revision cap

#[tokio::test(flavor = "multi_thread")]
async fn too_large_with_and_without_content_length() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();

    // Content-Length over 16 MiB: 413 before any body byte is read.
    let head = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nif-none-match: *\r\n\
         content-length: {}\r\n\r\n",
        16 * MIB + 1
    );
    assert_eq!(status_of(&raw(a, head.as_bytes()).await), 413);
    // Exactly 16 MiB is not refused for its size (it is refused for its shape here).
    let mut body = b"VAULT".to_vec();
    body.resize(16 * MIB, 0);
    let r = put(a, &t, ("if-none-match", "*"), body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Without Content-Length: 413 once the body grows past 16 MiB.
    let mut body = b"VAULT".to_vec();
    body.resize(16 * MIB + 1, 0);
    let mut chunked = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nif-none-match: *\r\n\
         transfer-encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    for c in body.chunks(MIB) {
        chunked.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        chunked.extend_from_slice(c);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(status_of(&raw(a, &chunked).await), 413);

    // A chunked body of the right shape is stored.
    let v = vault(1, 2);
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .header("if-none-match", "*")
        .body(v.clone())
        .chunked()
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(get(a, &t, "/v1/vault").await.body, v);
    assert_eq!(env.revision_files(), ["1.json", "1.vault"]);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn put_checks_run_in_order() {
    let env = Env::http("1MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    // 401 before 428; 428 before 412; 412 before 413; 413 before 507; 507 before 400.
    let big = format!("{}", 16 * MIB + 1);
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], u16);
    let cases: [Case<'_>; 5] = [
        ("Bearer x", &[("content-length", &big)], 401),
        (&t, &[("content-length", &big)], 428),
        (&t, &[("if-match", "\"x\""), ("content-length", &big)], 412),
        (&t, &[("if-none-match", "*"), ("content-length", &big)], 413),
        (
            &t,
            &[("if-none-match", "*"), ("content-length", "2097152")],
            507,
        ),
    ];
    for (auth, headers, want) in cases {
        let mut head = format!("PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {auth}\r\n");
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        assert_eq!(
            status_of(&raw(a, head.as_bytes()).await),
            want,
            "{headers:?}"
        );
    }
    assert!(env.revision_files().is_empty());
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_refuses_and_deletes_nothing() {
    // 1 MiB holds 256 blocks; a revision of 173 + 4096k bytes is charged k + 2 blocks.
    let env = Env::http("1MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let r = put(a, &t, ("if-none-match", "*"), vault(1, 255)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    // The same without Content-Length is refused after the body is read.
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .header("if-none-match", "*")
        .body(vault(1, 255))
        .chunked()
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    assert!(env.revision_files().is_empty());

    let v1 = vault(1, 127);
    assert_eq!(
        put(a, &t, ("if-none-match", "*"), v1.clone()).await.status,
        StatusCode::OK
    );
    // 129 + 129 blocks > 256: refused, and the first revision stays.
    let r = put(a, &t, ("if-match", &etag(&v1)), vault(2, 127)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    let r = req(Method::PUT, "/v1/vault")
        .auth(&t)
        .header("if-match", &etag(&v1))
        .body(vault(2, 127))
        .chunked()
        .send(a)
        .await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    // 129 + 127 blocks = 256 fits exactly.
    let r = put(a, &t, ("if-match", &etag(&v1)), vault(2, 125)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        env.revision_files(),
        ["1.json", "1.vault", "2.json", "2.vault"]
    );
    s.stop().await;
}

/// Writes a revision straight into `revisions/`, as a stored one looks.
fn plant(env: &Env, id: u64, bytes: &[u8], token: &str, created: &str) {
    let dir = env.revdir();
    let meta = serde_json::json!({
        "etag": etag(bytes),
        "size": bytes.len(),
        "created": created,
        "token": token,
    });
    for (name, contents) in [
        (format!("{id}.json"), serde_json::to_vec(&meta).unwrap()),
        (format!("{id}.vault"), bytes.to_vec()),
    ] {
        let p = dir.join(name);
        fs::write(&p, contents).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revision_cap() {
    let env = Env::http("1GiB");
    let t = env.token("laptop");
    for id in 1..=10_000u64 {
        plant(
            &env,
            id,
            &id.to_be_bytes(),
            &format!("t{id}"),
            "2026-01-01T00:00:00Z",
        );
    }
    let s = Running::start(&env).await;
    let a = s.addr();
    let current = etag(&10_000u64.to_be_bytes());
    assert_eq!(
        get(a, &t, "/v1/vault").await.header("etag"),
        Some(current.as_str())
    );
    let r = put(a, &t, ("if-match", &current), vault(1, 1)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(revisions_list(&env.data).unwrap().len(), 10_000);
    // One fewer retained revision makes room.
    assert_eq!(revisions_prune(&env.data, 2).unwrap(), [1]);
    let v = vault(1, 1);
    let r = put(a, &t, ("if-match", &current), v.clone()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(get(a, &t, "/v1/vault").await.body, v);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_puts_with_the_same_if_match() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let mut base = vault(0, 1);
    put(a, &t, ("if-none-match", "*"), base.clone()).await;
    for round in 1..=10u32 {
        let (x, y) = (vault(round * 2, 4), vault(round * 2 + 1, 4));
        let tag = etag(&base);
        let (rx, ry) = tokio::join!(
            put(a, &t, ("if-match", &tag), x.clone()),
            put(a, &t, ("if-match", &tag), y.clone())
        );
        let mut statuses = [rx.status.as_u16(), ry.status.as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 412], "round {round}");
        base = if rx.status == StatusCode::OK { x } else { y };
        assert_eq!(get(a, &t, "/v1/vault").await.body, base);
    }
    s.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Retention, prune, and rm

/// 2026-06-15T12:00:00Z, the fixed clock of the retention tests.
const NOW: u64 = 1_781_524_800_000;

fn fixed_clock() -> Tuning {
    Tuning {
        clock: Arc::new(|| NOW),
        ..Tuning::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stolen_token_flood_keeps_every_tokens_newest_and_daily_revisions() {
    let env = Env::http("64MiB");
    let phone = env.token("phone");
    let thief = env.token("thief");
    // The phone's history: two revisions a day. 2026-03-18 is the first of the 90 UTC days
    // ending 2026-06-15; 2026-03-17 is the day before it.
    let days = ["02-05", "03-17", "03-18", "04-16", "05-16", "06-05"];
    let mut id = 0;
    for day in days {
        for hour in ["08", "20"] {
            id += 1;
            let created = format!("2026-{day}T{hour}:00:00Z");
            plant(&env, id, &vault(1000 + id as u32, 1), "phone", &created);
        }
    }
    // A revoked token's revisions, far outside the 90 days.
    plant(
        &env,
        13,
        &vault(2013, 1),
        "old-laptop",
        "2020-01-01T00:00:00Z",
    );
    plant(
        &env,
        14,
        &vault(2014, 1),
        "old-laptop",
        "2020-01-02T00:00:00Z",
    );
    let s = Running::start_with(&env, fixed_clock()).await;
    let a = s.addr();
    let mut tag = etag(&vault(2014, 1));
    let v = vault(1, 1);
    assert_eq!(
        put(a, &phone, ("if-match", &tag), v.clone()).await.status,
        StatusCode::OK
    );
    tag = etag(&v);
    for i in 0..150 {
        let v = vault(100 + i, 1);
        assert_eq!(
            put(a, &thief, ("if-match", &tag), v.clone()).await.status,
            StatusCode::OK
        );
        tag = etag(&v);
    }
    let ids: Vec<u64> = revisions_list(&env.data)
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    // The newest 100 (all the thief's, 66 to 165); the phone's newest (15, today); the newest of
    // each of the phone's days inside the 90 days (6, 8, 10, and 12); and the old laptop's
    // newest (14).
    let mut want: Vec<u64> = (66..=165).rev().collect();
    want.extend([15, 14, 12, 10, 8, 6]);
    assert_eq!(ids, want);
    assert_eq!(get(a, &phone, "/v1/revisions/15").await.body, v);

    // Repair: revoke the thief and remove its revisions, except the current one.
    token_remove(&env.data, "thief").unwrap();
    let deleted = revisions_remove(&env.data, "thief", None).unwrap();
    assert_eq!(deleted, (66..=164).collect::<Vec<_>>());
    let ids: Vec<u64> = revisions_list(&env.data)
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, [165, 15, 14, 12, 10, 8, 6]);
    // The server sees the change at once.
    let list: serde_json::Value =
        serde_json::from_slice(&get(a, &phone, "/v1/revisions").await.body).unwrap();
    assert_eq!(list["revisions"].as_array().unwrap().len(), 7);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_thief_filling_the_quota_blocks_pushes_until_repaired() {
    // 1 MiB is 256 blocks; a revision of 173 + 4096k bytes is charged k + 2 blocks.
    let env = Env::http("1MiB");
    let phone = env.token("phone");
    let thief = env.token("thief");
    let s = Running::start(&env).await;
    let a = s.addr();
    let v1 = vault(1, 1);
    assert_eq!(
        put(a, &phone, ("if-none-match", "*"), v1.clone())
            .await
            .status,
        StatusCode::OK
    );
    let (t1, t2) = (vault(2, 124), vault(3, 124));
    assert_eq!(
        put(a, &thief, ("if-match", &etag(&v1)), t1.clone())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        put(a, &thief, ("if-match", &etag(&t1)), t2.clone())
            .await
            .status,
        StatusCode::OK
    );
    // 255 of 256 blocks are used: the honest push is refused and nothing is deleted.
    let honest = vault(4, 1);
    let r = put(a, &phone, ("if-match", &etag(&t2)), honest.clone()).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    let r = put(a, &thief, ("if-match", &etag(&t2)), vault(5, 1)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(env.revision_files().len(), 6);

    token_remove(&env.data, "thief").unwrap();
    assert_eq!(
        get(a, &thief, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(revisions_remove(&env.data, "thief", None).unwrap(), [2]);
    let r = put(a, &phone, ("if-match", &etag(&t2)), honest.clone()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(get(a, &phone, "/v1/vault").await.body, honest);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_push_evicts_nothing() {
    let env = Env::http("1MiB");
    let phone = env.token("phone");
    // 100 one-byte revisions, 2 blocks each: 200 of 256 blocks.
    for id in 1..=100u64 {
        plant(&env, id, &[id as u8], "thief", "2026-06-15T10:00:00Z");
    }
    let s = Running::start_with(&env, fixed_clock()).await;
    let a = s.addr();
    let tag = etag(&[100u8]);
    // 62 more blocks would not fit. Stored, it would have pushed revision 1 out of the newest 100.
    let r = put(a, &phone, ("if-match", &tag), vault(1, 60)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    let ids: Vec<u64> = revisions_list(&env.data)
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, (1..=100).rev().collect::<Vec<_>>());
    // 3 more blocks fit; retention then deletes revision 1.
    let r = put(a, &phone, ("if-match", &tag), vault(1, 1)).await;
    assert_eq!(r.status, StatusCode::OK);
    let ids: Vec<u64> = revisions_list(&env.data)
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, (2..=101).rev().collect::<Vec<_>>());
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn prune_and_rm_never_remove_the_current_revision() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let mut tag: Option<String> = None;
    for i in 1..=5 {
        let v = vault(i, 1);
        let cond = match &tag {
            Some(e) => ("if-match", e.as_str()),
            None => ("if-none-match", "*"),
        };
        assert_eq!(put(a, &t, cond, v.clone()).await.status, StatusCode::OK);
        tag = Some(etag(&v));
    }
    let ids = |env: &Env| -> Vec<u64> {
        revisions_list(&env.data)
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect()
    };
    assert_eq!(revisions_remove(&env.data, "laptop", Some(3)).unwrap(), [4]);
    assert_eq!(ids(&env), [5, 3, 2, 1]);
    assert_eq!(revisions_prune(&env.data, 2).unwrap(), [1]);
    assert_eq!(ids(&env), [5, 3, 2]);
    assert_eq!(revisions_prune(&env.data, u64::MAX).unwrap(), [2, 3]);
    assert_eq!(ids(&env), [5]);
    assert!(
        revisions_remove(&env.data, "laptop", None)
            .unwrap()
            .is_empty()
    );
    assert!(revisions_prune(&env.data, u64::MAX).unwrap().is_empty());
    assert_eq!(ids(&env), [5]);
    assert_eq!(
        get(a, &t, "/v1/revisions/3").await.status,
        StatusCode::NOT_FOUND
    );
    // The server still serves and accepts pushes on the current revision.
    let r = get(a, &t, "/v1/vault").await;
    assert_eq!(r.body, vault(5, 1));
    let v6 = vault(6, 1);
    assert_eq!(
        put(a, &t, ("if-match", tag.as_deref().unwrap()), v6.clone())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(ids(&env), [6, 5]);
    assert_eq!(
        env.revision_files(),
        ["5.json", "5.vault", "6.json", "6.vault"]
    );
    s.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Crash safety, locks, and permissions

#[tokio::test(flavor = "multi_thread")]
async fn start_up_removes_what_a_crash_left() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let v = vault(1, 1);
    plant(&env, 4, &v, "laptop", "2026-01-01T00:00:00Z");
    // A revision whose metadata never made it; it exists, because its .vault file does.
    let bare = vault(2, 1);
    let p = env.revdir().join("6.vault");
    fs::write(&p, &bare).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    for name in [
        "7.json",
        "upload-0123456789abcdef.tmp",
        "8.json.tmp",
        "007.json",
    ] {
        let p = env.revdir().join(name);
        fs::write(&p, b"{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let p = env.root().join("tokens.json.tmp");
    fs::write(&p, b"x").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();

    let s = Running::start(&env).await;
    let a = s.addr();
    // `007.json` is not a revision's metadata file name, so it is left alone.
    assert_eq!(
        env.revision_files(),
        ["007.json", "4.json", "4.vault", "6.vault"]
    );
    assert!(!env.root().join("tokens.json.tmp").exists());
    let r = get(a, &t, "/v1/vault").await;
    assert_eq!(r.body, bare);
    assert_eq!(r.header("etag"), Some(etag(&bare).as_str()));
    let list: serde_json::Value =
        serde_json::from_slice(&get(a, &t, "/v1/revisions").await.body).unwrap();
    assert_eq!(list["revisions"][0]["id"], 6);
    assert_eq!(list["revisions"][0]["etag"], etag(&bare));
    assert_eq!(list["revisions"][0]["size"], bare.len());
    let r = put(a, &t, ("if-match", &etag(&bare)), vault(3, 1)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(revisions_list(&env.data).unwrap()[0].id, 7);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn etag_is_computed_from_the_bytes() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let v = vault(1, 1);
    plant(&env, 1, &v, "laptop", "2026-01-01T00:00:00Z");
    // Metadata that disagrees with its revision.
    let meta = env.revdir().join("1.json");
    let wrong = format!(
        r#"{{"etag":"\"{}\"","size":1,"created":"2026-01-01T00:00:00Z","token":"laptop"}}"#,
        "0".repeat(64)
    );
    fs::write(&meta, wrong).unwrap();
    let s = Running::start(&env).await;
    let a = s.addr();
    let r = get(a, &t, "/v1/vault").await;
    assert_eq!(r.header("etag"), Some(etag(&v).as_str()));
    let r = put(
        a,
        &t,
        ("if-match", &format!("\"{}\"", "0".repeat(64))),
        vault(2, 1),
    )
    .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);
    let r = put(a, &t, ("if-match", &etag(&v)), vault(2, 1)).await;
    assert_eq!(r.status, StatusCode::OK);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_server_is_refused() {
    let env = Env::http("64MiB");
    let first = Server::bind(&env.data).await.unwrap();
    assert!(matches!(Server::bind(&env.data).await, Err(Error::Locked)));
    drop(first);
    let again = Server::bind(&env.data).await.unwrap();
    drop(again);
}

#[tokio::test(flavor = "multi_thread")]
async fn unsafe_data_directories_are_refused() {
    let refused = |env: &Env| {
        assert!(matches!(token_list(&env.data), Err(Error::Unsafe(_))));
        assert!(matches!(revisions_list(&env.data), Err(Error::Unsafe(_))));
        assert!(matches!(
            revisions_prune(&env.data, 1),
            Err(Error::Unsafe(_))
        ));
        assert!(matches!(
            token_add(&env.data, &add_args("x")),
            Err(Error::Unsafe(_))
        ));
    };
    let mode = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();

    let env = Env::http("64MiB");
    mode(env.root(), 0o750);
    refused(&env);
    assert!(matches!(
        Server::bind(&env.data).await,
        Err(Error::Unsafe(_))
    ));
    mode(env.root(), 0o700);
    token_list(&env.data).unwrap();

    mode(&env.revdir(), 0o701);
    refused(&env);
    mode(&env.revdir(), 0o700);

    let serve_toml = env.root().join("serve.toml");
    mode(&serve_toml, 0o640);
    refused(&env);
    assert!(matches!(
        Server::bind(&env.data).await,
        Err(Error::Unsafe(_))
    ));
    mode(&serve_toml, 0o600);

    let link = env.revdir().join("9.vault");
    std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
    refused(&env);
    assert!(matches!(
        Server::bind(&env.data).await,
        Err(Error::Unsafe(_))
    ));
    fs::remove_file(&link).unwrap();

    // A data directory that is itself a symbolic link.
    let linked = DataDir::new(env.root().with_file_name("linked"));
    std::os::unix::fs::symlink(env.root(), linked.root()).unwrap();
    assert!(matches!(token_list(&linked), Err(Error::Unsafe(_))));

    // The TLS key of a generated certificate is checked too.
    let tls = Env::new();
    init(&tls.data, &https_args()).unwrap();
    mode(&tls.root().join("tls/key.pem"), 0o644);
    assert!(matches!(
        Server::bind(&tls.data).await,
        Err(Error::Unsafe(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// init, TLS, and the HTTP listener

#[test]
fn init_rules() {
    let env = Env::new();
    let base = http_args("2GiB");
    let refused = |args: InitArgs| {
        let env = Env::new();
        assert!(
            matches!(init(&env.data, &args), Err(Error::Invalid(_))),
            "{args:?}"
        );
        assert!(!env.root().join("serve.toml").exists());
    };
    refused(InitArgs {
        http_listen: None,
        ..base.clone()
    });
    refused(InitArgs {
        http_listen: Some("0.0.0.0:8080".parse().unwrap()),
        ..base.clone()
    });
    refused(InitArgs {
        url: "http://nas.lan:8080".into(),
        ..base.clone()
    });
    refused(InitArgs {
        url: "ftp://nas.lan".into(),
        ..base.clone()
    });
    refused(InitArgs {
        url: "https://u@nas.lan".into(),
        ..base.clone()
    });
    refused(InitArgs {
        quota: "2GB".into(),
        ..base.clone()
    });
    refused(InitArgs {
        url: "https://nas.lan".into(),
        http_listen: None,
        ..base.clone()
    });

    init(&env.data, &base).unwrap();
    assert!(matches!(init(&env.data, &base), Err(Error::Invalid(_))));
    let toml = fs::read_to_string(env.root().join("serve.toml")).unwrap();
    assert_eq!(
        toml,
        "url = \"http://127.0.0.1:8080\"\nquota = \"2GiB\"\n\n[http]\nlisten = \"127.0.0.1:0\"\n"
    );
    for (p, m) in [
        ("", 0o700),
        ("revisions", 0o700),
        ("serve.toml", 0o600),
        ("tokens.json", 0o600),
    ] {
        let meta = fs::symlink_metadata(env.root().join(p)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, m, "{p}");
    }
    assert!(!env.root().join("tls").exists());

    // An existing directory open to others is refused.
    let open = Env::new();
    fs::create_dir(open.root()).unwrap();
    fs::set_permissions(open.root(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(init(&open.data, &base), Err(Error::Unsafe(_))));
}

#[derive(Debug)]
struct Pinned([u8; 32], Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if vault_core::setup::pin_matches(&self.0, end_entity) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate does not match the pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.1.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.1.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

async fn tls_connect(
    addr: SocketAddr,
    setup: vault_core::setup::SetupText,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned(
            setup.fp.expect("the setup text pins a certificate"),
            provider,
        )))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(name, tcp).await
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_with_the_generated_certificate_and_a_pinned_client() {
    let env = Env::new();
    let report = init(&env.data, &https_args()).unwrap();
    let fp = report.fingerprint.unwrap();
    // The certificate on disk is the one fingerprinted.
    let pem = fs::read(env.root().join("tls/cert.pem")).unwrap();
    use rustls::pki_types::pem::PemObject;
    let der = rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap();
    assert_eq!(vault_core::setup::cert_fingerprint(&der), fp);
    assert_eq!(
        fs::symlink_metadata(env.root().join("tls/key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let added = token_add(&env.data, &add_args("laptop")).unwrap();
    assert_eq!(added.fingerprint, Some(fp));
    let auth = bearer(&added.setup_text);
    let setup = || vault_core::setup::parse_setup(&added.setup_text).unwrap();
    assert_eq!(setup().fp, Some(fp));
    assert_eq!(setup().url, "https://localhost:8443/");

    let s = Running::start(&env).await;
    let a = s.https.unwrap();
    assert!(s.http.is_none());
    for versions in [
        &[&rustls::version::TLS13][..],
        &[&rustls::version::TLS12][..],
    ] {
        let tls = tls_connect(a, setup(), versions).await.unwrap();
        let r = send_on(tls, req(Method::GET, "/v1/vault").auth(&auth).build()).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    let v = vault(1, 1);
    let tls = tls_connect(a, setup(), &[&rustls::version::TLS13])
        .await
        .unwrap();
    let r = send_on(
        tls,
        req(Method::PUT, "/v1/vault")
            .auth(&auth)
            .header("if-none-match", "*")
            .body(v.clone())
            .build(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let tls = tls_connect(a, setup(), &[&rustls::version::TLS13])
        .await
        .unwrap();
    let r = send_on(tls, req(Method::GET, "/v1/vault").auth(&auth).build()).await;
    assert_eq!(r.body, v);

    // A client pinned to another certificate refuses the connection.
    let mut other = setup();
    other.fp = Some([0; 32]);
    assert!(
        tls_connect(a, other, &[&rustls::version::TLS13])
            .await
            .is_err()
    );
    // Plain HTTP on the HTTPS port gets no response.
    let out = raw(a, b"GET /v1/vault HTTP/1.1\r\nhost: x\r\n\r\n").await;
    assert!(!out.starts_with("HTTP/1.1 200"));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn https_and_http_listeners_together() {
    let env = Env::new();
    let args = InitArgs {
        http_listen: Some("127.0.0.1:0".parse().unwrap()),
        ..https_args()
    };
    init(&env.data, &args).unwrap();
    let added = token_add(&env.data, &add_args("laptop")).unwrap();
    let auth = bearer(&added.setup_text);
    // A loopback http URL for the same server carries no fp.
    let local = token_add(
        &env.data,
        &TokenAddArgs {
            url: Some("http://localhost:8080".into()),
            ..add_args("firefox")
        },
    )
    .unwrap();
    assert!(local.fingerprint.is_none());
    assert!(!local.setup_text.contains("fp="));

    let s = Running::start(&env).await;
    let v = vault(1, 1);
    let r = put(
        s.http.unwrap(),
        &bearer(&local.setup_text),
        ("if-none-match", "*"),
        v.clone(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let setup = vault_core::setup::parse_setup(&added.setup_text).unwrap();
    let tls = tls_connect(s.https.unwrap(), setup, &[&rustls::version::TLS13])
        .await
        .unwrap();
    let r = send_on(tls, req(Method::GET, "/v1/vault").auth(&auth).build()).await;
    assert_eq!(r.body, v);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn init_with_a_given_certificate() {
    // A certificate from elsewhere: generate one with a first data directory.
    let source = Env::new();
    let fp = init(&source.data, &https_args())
        .unwrap()
        .fingerprint
        .unwrap();
    let env = Env::new();
    let args = InitArgs {
        cert: Some(source.root().join("tls/cert.pem")),
        key: Some(source.root().join("tls/key.pem")),
        ..https_args()
    };
    assert_eq!(init(&env.data, &args).unwrap().fingerprint, Some(fp));
    assert!(!env.root().join("tls").exists());
    let added = token_add(&env.data, &add_args("laptop")).unwrap();
    assert_eq!(added.fingerprint, Some(fp));
    let s = Running::start(&env).await;
    let setup = vault_core::setup::parse_setup(&added.setup_text).unwrap();
    assert!(
        tls_connect(s.https.unwrap(), setup, &[&rustls::version::TLS13])
            .await
            .is_ok()
    );
    s.stop().await;
    // A key that does not load is refused at init.
    let bad = Env::new();
    let args = InitArgs {
        cert: Some(source.root().join("tls/cert.pem")),
        key: Some(source.root().join("serve.toml")),
        ..https_args()
    };
    assert!(init(&bad.data, &args).is_err());
    assert!(!bad.root().join("serve.toml").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_a_request_in_progress() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    // Headers and half a body, then shutdown, then the rest of the body.
    let v = vault(1, 1);
    let mut tcp = TcpStream::connect(a).await.unwrap();
    let head = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nif-none-match: *\r\n\
         content-length: {}\r\n\r\n",
        v.len()
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp.write_all(&v[..2000]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let stopping = tokio::spawn(s.stop());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // No new connection is accepted.
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            match TcpStream::connect(a).await {
                Err(_) => true,
                Ok(mut c) => {
                    let mut b = [0u8; 1];
                    c.write_all(b"GET /v1/vault HTTP/1.1\r\nhost: x\r\n\r\n")
                        .await
                        .ok();
                    matches!(c.read(&mut b).await, Ok(0) | Err(_))
                }
            }
        })
        .await
        .unwrap_or(true)
    );
    tcp.write_all(&v[2000..]).await.unwrap();
    let mut out = Vec::new();
    tcp.read_to_end(&mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
    stopping.await.unwrap();
    assert_eq!(env.revision_files(), ["1.json", "1.vault"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn thirty_two_connections_at_a_time() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let mut idle = Vec::new();
    for _ in 0..32 {
        idle.push(TcpStream::connect(a).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let request = format!(
        "GET /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nconnection: close\r\n\r\n"
    );
    let waiting = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let out = raw(a, request.as_bytes()).await;
        (started.elapsed(), out)
    });
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    assert!(!waiting.is_finished(), "a 33rd connection was served");
    drop(idle.pop());
    let (elapsed, out) = waiting.await.unwrap();
    assert!(elapsed >= std::time::Duration::from_millis(1000));
    assert_eq!(status_of(&out), 404);
    drop(idle);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_must_arrive_within_ten_seconds() {
    let env = Env::http("64MiB");
    let s = Running::start(&env).await;
    let mut tcp = TcpStream::connect(s.addr()).await.unwrap();
    let started = std::time::Instant::now();
    tcp.write_all(b"GET /v1/vault HTTP/1.1\r\nhost: x\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tcp.read_to_end(&mut out),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(elapsed >= std::time::Duration::from_secs(9), "{elapsed:?}");
    assert!(elapsed < std::time::Duration::from_secs(12), "{elapsed:?}");
    assert!(!String::from_utf8_lossy(&out).contains(" 200 "));
    s.stop().await;
}

// ---------------------------------------------------------------------------------------------
// Review additions: stale metadata temporary files, timeouts, disconnects, logs, and races

/// A tuning whose log lines are collected.
fn captured(tuning: Tuning) -> (Tuning, Arc<std::sync::Mutex<Vec<String>>>) {
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = lines.clone();
    let tuning = Tuning {
        log: Arc::new(move |l: &str| sink.lock().unwrap().push(l.to_owned())),
        ..tuning
    };
    (tuning, lines)
}

/// Waits until a log line contains `needle`.
async fn wait_for_log(lines: &std::sync::Mutex<Vec<String>>, needle: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !lines.lock().unwrap().iter().any(|l| l.contains(needle)) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no log line with {needle:?}: {:?}", lines.lock().unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_metadata_temporary_file_does_not_block_pushes() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let v1 = vault(1, 1);
    assert_eq!(
        put(a, &t, ("if-none-match", "*"), v1.clone()).await.status,
        StatusCode::OK
    );
    // What a failed metadata write for revision 2 would leave behind.
    let stale = env.revdir().join("2.json.tmp");
    fs::write(&stale, b"partial").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    let v2 = vault(2, 1);
    assert_eq!(
        put(a, &t, ("if-match", &etag(&v1)), v2.clone())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(get(a, &t, "/v1/vault").await.body, v2);
    assert_eq!(
        env.revision_files(),
        ["1.json", "1.vault", "2.json", "2.vault"]
    );
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_reading_is_dropped() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let big = vault(1, 4000);
    let tuning = Tuning {
        write_timeout: std::time::Duration::from_millis(300),
        ..Tuning::default()
    };
    let s = Running::start_with(&env, tuning).await;
    let a = s.addr();
    assert_eq!(
        put(a, &t, ("if-none-match", "*"), big.clone()).await.status,
        StatusCode::OK
    );
    // A small receive buffer, a request, and no reads.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(4096).unwrap();
    let mut tcp = sock.connect(a).await.unwrap();
    let request = format!("GET /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\n\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // The server gave up: what arrives ends well short of the file.
    let mut out = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tcp.read_to_end(&mut out),
    )
    .await;
    assert!(read.is_ok(), "the connection stayed open");
    assert!(out.len() < big.len(), "{} bytes arrived", out.len());
    // The server still serves others.
    assert_eq!(get(a, &t, "/v1/revisions").await.status, StatusCode::OK);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_upload_receives_408() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let tuning = Tuning {
        request_timeout: std::time::Duration::from_millis(500),
        ..Tuning::default()
    };
    let s = Running::start_with(&env, tuning).await;
    let a = s.addr();
    let v = vault(1, 1);
    let mut request = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nif-none-match: *\r\n\
         content-length: {}\r\n\r\n",
        v.len()
    )
    .into_bytes();
    request.extend_from_slice(&v[..1000]);
    let started = std::time::Instant::now();
    let out = raw(a, &request).await;
    assert!(started.elapsed() >= std::time::Duration::from_millis(450));
    assert_eq!(status_of(&out), 408);
    assert!(out.to_ascii_lowercase().contains("connection: close"));
    assert!(
        out.to_ascii_lowercase()
            .contains("cache-control: no-store, no-transform")
    );
    assert!(env.revision_files().is_empty());
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_disconnecting_mid_upload_leaves_nothing() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let (tuning, lines) = captured(Tuning::default());
    let s = Running::start_with(&env, tuning).await;
    let a = s.addr();
    let v = vault(1, 64);
    let mut tcp = TcpStream::connect(a).await.unwrap();
    let head = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {t}\r\nif-none-match: *\r\n\
         content-length: {}\r\n\r\n",
        v.len()
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp.write_all(&v[..v.len() / 2]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        env.revision_files().iter().any(|f| f.ends_with(".tmp")),
        "the upload started"
    );
    drop(tcp);
    wait_for_log(&lines, "PUT /v1/vault 400").await;
    assert!(
        env.revision_files().is_empty(),
        "{:?}",
        env.revision_files()
    );
    assert_eq!(get(a, &t, "/v1/vault").await.status, StatusCode::NOT_FOUND);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_log_never_holds_tokens_or_bodies() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let token_text = t.strip_prefix("Bearer ").unwrap().to_owned();
    let (tuning, lines) = captured(Tuning::default());
    let s = Running::start_with(&env, tuning).await;
    let a = s.addr();
    let mut v = vault(1, 1);
    v[100..120].copy_from_slice(b"BODY-MARKER-0123456!");
    assert_eq!(
        put(a, &t, ("if-none-match", "*"), v.clone()).await.status,
        StatusCode::OK
    );
    assert_eq!(get(a, &t, "/v1/vault").await.body, v);
    assert_eq!(get(a, &t, "/v1/revisions/1").await.body, v);
    // A wrong token that looks like a real one, and one sent in lower case.
    let wrong = format!("Bearer {}", "Z".repeat(32));
    assert_eq!(
        get(a, &wrong, "/v1/vault").await.status,
        StatusCode::UNAUTHORIZED
    );
    let lower = format!("Bearer {}", token_text.to_ascii_lowercase());
    assert_eq!(
        get(a, &lower, "/v1/nope%01").await.status,
        StatusCode::NOT_FOUND
    );
    s.stop().await;

    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 5, "{lines:?}");
    for line in &lines {
        let lower_line = line.to_ascii_lowercase();
        assert!(!line.contains(&token_text), "{line}");
        assert!(
            !lower_line.contains(&token_text.to_ascii_lowercase()),
            "{line}"
        );
        assert!(!line.contains(&"Z".repeat(32)), "{line}");
        assert!(!lower_line.contains("bearer"), "{line}");
        assert!(!lower_line.contains("authorization"), "{line}");
        assert!(!line.contains("BODY-MARKER"), "{line}");
        assert!(line.contains(" laptop ") || line.contains(" - "), "{line}");
    }
    assert!(
        lines[0].ends_with(&format!("PUT /v1/vault 200 laptop {}", v.len())),
        "{}",
        lines[0]
    );
    assert!(lines[3].contains("GET /v1/vault 401 - 0"), "{}", lines[3]);
}

#[tokio::test(flavor = "multi_thread")]
async fn many_concurrent_puts_from_different_tokens() {
    let env = Env::http("64MiB");
    let tokens: Vec<String> = (0..12).map(|i| env.token(&format!("device-{i}"))).collect();
    let s = Running::start(&env).await;
    let a = s.addr();
    let mut base = vault(0, 1);
    put(a, &tokens[0], ("if-none-match", "*"), base.clone()).await;
    for round in 1..=3u32 {
        let before = revisions_list(&env.data).unwrap().len();
        let tag = etag(&base);
        let mut tasks = tokio::task::JoinSet::new();
        for (i, t) in tokens.iter().enumerate() {
            let (t, tag) = (t.clone(), tag.clone());
            let body = vault(round * 100 + i as u32, 2);
            tasks.spawn(async move {
                let r = put(a, &t, ("if-match", &tag), body.clone()).await;
                (r.status, body)
            });
        }
        let results = tasks.join_all().await;
        let winners: Vec<&Vec<u8>> = results
            .iter()
            .filter(|(st, _)| *st == StatusCode::OK)
            .map(|(_, b)| b)
            .collect();
        assert_eq!(winners.len(), 1, "round {round}");
        assert!(
            results
                .iter()
                .all(|(st, _)| *st == StatusCode::OK || *st == StatusCode::PRECONDITION_FAILED)
        );
        assert_eq!(revisions_list(&env.data).unwrap().len(), before + 1);
        base = winners[0].clone();
        assert_eq!(get(a, &tokens[1], "/v1/vault").await.body, base);
    }
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn puts_wait_for_writers_holding_the_lock() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let v1 = vault(1, 1);
    put(a, &t, ("if-none-match", "*"), v1.clone()).await;

    // A writer holding `lock` holds the store back.
    let lock = fs::OpenOptions::new()
        .write(true)
        .open(env.root().join("lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let v2 = vault(2, 1);
    let pending = {
        let (t, tag, v2) = (t.clone(), etag(&v1), v2.clone());
        tokio::spawn(async move { put(a, &t, ("if-match", &tag), v2).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!pending.is_finished());
    drop(lock);
    assert_eq!(pending.await.unwrap().status, StatusCode::OK);

    // Pushes while prune, rm, and token add run over and over.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let data = env.data.clone();
    let flag = stop.clone();
    let commands = std::thread::spawn(move || {
        let mut n = 0;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            n += 1;
            revisions_prune(&data, u64::MAX).unwrap();
            revisions_remove(&data, "laptop", None).unwrap();
            token_add(&data, &add_args(&format!("t{n}"))).unwrap();
        }
        n
    });
    let mut tag = etag(&v2);
    for i in 0..40 {
        let v = vault(10 + i, 1);
        assert_eq!(
            put(a, &t, ("if-match", &tag), v.clone()).await.status,
            StatusCode::OK
        );
        tag = etag(&v);
        assert_eq!(get(a, &t, "/v1/vault").await.body, v);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(commands.join().unwrap() > 0);
    revisions_prune(&env.data, u64::MAX).unwrap();
    assert_eq!(revisions_list(&env.data).unwrap().len(), 1);
    assert_eq!(
        get(a, &t, "/v1/vault").await.header("etag"),
        Some(tag.as_str())
    );
    assert!(env.revision_files().iter().all(|f| !f.ends_with(".tmp")));
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn gets_racing_puts_see_whole_revisions() {
    let env = Env::http("64MiB");
    let t = env.token("laptop");
    let s = Running::start(&env).await;
    let a = s.addr();
    let versions: Vec<Vec<u8>> = (0..30).map(|i| vault(i, 1 + (i as usize % 4))).collect();
    put(a, &t, ("if-none-match", "*"), versions[0].clone()).await;
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let (t, done, versions) = (t.clone(), done.clone(), versions.clone());
        readers.spawn(async move {
            let mut n = 0;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let r = get(a, &t, "/v1/vault").await;
                assert_eq!(r.status, StatusCode::OK);
                assert_eq!(r.header("etag"), Some(etag(&r.body).as_str()));
                assert!(versions.iter().any(|v| *v == r.body));
                n += 1;
            }
            n
        });
    }
    for w in versions.windows(2) {
        let r = put(a, &t, ("if-match", &etag(&w[0])), w[1].clone()).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(readers.join_all().await.iter().all(|n| *n > 0));
    s.stop().await;
}
