//! The server: start-up checks, the listeners, connection limits, routing, request handling,
//! logging, and shutdown.

use crate::config::Config;
use crate::datadir::{self, DataDir};
use crate::error::{Context, Result};
use crate::revisions::{self, Index, MAX_SIZE, Revision, StoreError, Upload};
use crate::time;
use crate::tokens::TokenTable;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    HeaderValue, IF_MATCH, IF_NONE_MATCH, WWW_AUTHENTICATE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::fs::File;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

/// Connections served at a time.
const MAX_CONNECTIONS: usize = 32;
/// The smallest vault file, which a `PUT` without `Content-Length` is assumed to be at step 4.
const MIN_SIZE: u64 = 4269;
/// The longest path written to the log, in characters.
const LOG_PATH_CHARS: usize = 200;

type RespBody = BoxBody<Bytes, io::Error>;

/// The server's timeouts, clock, and log. [`Tuning::default`] holds the documented values; tests
/// shorten the timeouts, fix the clock, and capture the log.
#[doc(hidden)]
#[derive(Clone)]
pub struct Tuning {
    /// The time allowed for the TLS handshake and the request headers together: 10 s.
    pub header_timeout: Duration,
    /// The time allowed for a whole request, from its headers to the end of the response: 60 s.
    pub request_timeout: Duration,
    /// How long a write to a client may wait before the connection is dropped: 60 s.
    pub write_timeout: Duration,
    /// How long shutdown waits for requests in progress: 10 s.
    pub shutdown_grace: Duration,
    /// The time in ms since the Unix epoch.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Where log lines go: standard error.
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning {
            header_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(10),
            clock: Arc::new(time::now_ms),
            log: Arc::new(|line| eprintln!("{line}")),
        }
    }
}

/// A server with its data directory locked and its listeners bound, ready to [`Server::run`].
pub struct Server {
    shared: Arc<Shared>,
    https: Option<(TcpListener, TlsAcceptor)>,
    http: Option<TcpListener>,
}

struct Shared {
    data: DataDir,
    revdir: PathBuf,
    quota: u64,
    tokens: TokenTable,
    /// Serialises `PUT /v1/vault` from step 2 to the end.
    put_lock: tokio::sync::Mutex<()>,
    state: Mutex<State>,
    tuning: Tuning,
    /// Held for the server's lifetime.
    _server_lock: File,
}

struct State {
    index: Index,
    current: Option<Current>,
    /// The lowest ID the next revision may take, so an ID is never reused within a run.
    min_id: u64,
}

/// The current revision's bytes and the `ETag` computed from them.
#[derive(Clone)]
struct Current {
    id: u64,
    bytes: Bytes,
    etag: String,
}

impl Server {
    /// Checks the data directory, takes `server.lock`, removes what a crash left behind, and
    /// binds the listeners `serve.toml` names.
    pub async fn bind(data: &DataDir) -> Result<Server> {
        Server::bind_with(data, Tuning::default()).await
    }

    /// [`Server::bind`] with other timeouts, clock, or log.
    #[doc(hidden)]
    pub async fn bind_with(data: &DataDir, tuning: Tuning) -> Result<Server> {
        data.check()?;
        let config = Config::load(data)?;
        let server_lock = data.server_lock()?;
        let revdir = data.revisions();
        {
            let _w = data.write_lock()?;
            revisions::cleanup(&revdir)?;
            datadir::remove_stale_tmp(data.root())?;
        }
        let index = Index::read(&revdir)?;
        let https = match &config.https {
            Some(h) => {
                if let Some(w) = crate::tls::key_warning(data, h) {
                    (tuning.log)(&w);
                }
                let acceptor = TlsAcceptor::from(crate::tls::server_config(data, h)?);
                let l = TcpListener::bind(h.listen)
                    .await
                    .context(|| format!("listening on {}", h.listen))?;
                Some((l, acceptor))
            }
            None => None,
        };
        let http = match &config.http {
            Some(h) => Some(
                TcpListener::bind(h.listen)
                    .await
                    .context(|| format!("listening on {}", h.listen))?,
            ),
            None => None,
        };
        Ok(Server {
            shared: Arc::new(Shared {
                data: data.clone(),
                revdir,
                quota: config.quota_bytes(),
                tokens: TokenTable::new(data),
                put_lock: tokio::sync::Mutex::new(()),
                state: Mutex::new(State {
                    index,
                    current: None,
                    min_id: 1,
                }),
                tuning,
                _server_lock: server_lock,
            }),
            https,
            http,
        })
    }

    /// The bound address of the HTTPS listener.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https.as_ref().and_then(|(l, _)| l.local_addr().ok())
    }

    /// The bound address of the HTTP listener.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Serves until `shutdown` completes, then stops accepting connections and returns once the
    /// requests in progress finish, or after 10 s, when the rest are dropped.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        let Server {
            shared,
            https,
            http,
        } = self;
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (stop_tx, stop_rx) = watch::channel(());
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            while tasks.try_join_next().is_some() {}
            let permit = tokio::select! {
                p = permits.clone().acquire_owned() => p.expect("the semaphore is never closed"),
                () = &mut shutdown => break,
            };
            let (accepted, tls) = tokio::select! {
                r = accept(https.as_ref().map(|(l, _)| l)) => (r, https.as_ref().map(|(_, a)| a.clone())),
                r = accept(http.as_ref()) => (r, None),
                () = &mut shutdown => break,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    let conn = serve_connection(shared.clone(), tcp, peer, tls, stop_rx.clone());
                    tasks.spawn(async move {
                        conn.await;
                        drop(permit);
                    });
                }
                Err(e) => {
                    // Out of file descriptors or a reset before accept: wait, then go on.
                    shared.log(&format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        drop((https, http));
        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(shared.tuning.shutdown_grace, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        tasks.shutdown().await;
        Ok(())
    }
}

/// Completes on `SIGTERM` or `SIGINT`.
pub async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn accept(l: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match l {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

async fn serve_connection(
    shared: Arc<Shared>,
    tcp: TcpStream,
    peer: SocketAddr,
    tls: Option<TlsAcceptor>,
    stop: watch::Receiver<()>,
) {
    let start = Instant::now();
    let _ = tcp.set_nodelay(true);
    let tcp = WriteWatchdog::new(tcp, shared.tuning.write_timeout);
    let header_timeout = shared.tuning.header_timeout;
    match tls {
        Some(acceptor) => {
            if let Ok(Ok(stream)) = tokio::time::timeout(header_timeout, acceptor.accept(tcp)).await
            {
                serve_http(shared, TokioIo::new(stream), peer, start, stop).await;
            }
        }
        None => serve_http(shared, TokioIo::new(tcp), peer, start, stop).await,
    }
}

async fn serve_http<I>(
    shared: Arc<Shared>,
    io: I,
    peer: SocketAddr,
    start: Instant,
    mut stop: watch::Receiver<()>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // The handshake and the first request's headers share one 10 s budget.
    let remaining = shared.tuning.header_timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return;
    }
    let svc = service_fn(move |req| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(respond(&shared, peer, req).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(remaining);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = stop.changed() => {
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
        }
    }
}

/// A handled request: the response, the token name, and the size of the vault file received or
/// sent.
struct Outcome {
    resp: Response<RespBody>,
    token: Option<String>,
    size: u64,
}

impl Outcome {
    fn status(status: StatusCode) -> Outcome {
        Outcome {
            resp: response(status, empty()),
            token: None,
            size: 0,
        }
    }

    fn token(mut self, name: &str) -> Outcome {
        self.token = Some(name.to_owned());
        self
    }
}

async fn respond(
    shared: &Arc<Shared>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<Deadline> {
    let deadline = Instant::now() + shared.tuning.request_timeout;
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    // The deadline bounds the waits for the PUT lock and the body, never a store under way; the
    // response body carries the same deadline.
    let out = handle(shared, req, deadline).await;
    (shared.tuning.log)(&log_line(
        shared.now(),
        peer,
        method.as_str(),
        &path,
        out.resp.status(),
        out.token.as_deref(),
        out.size,
    ));
    let (mut parts, body) = out.resp.into_parts();
    parts.headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    // A refused PUT may leave its body unread, so the connection cannot carry another request.
    if method == Method::PUT && parts.status != StatusCode::OK {
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Response::from_parts(parts, Deadline::new(body, deadline))
}

async fn handle(shared: &Arc<Shared>, req: Request<Incoming>, deadline: Instant) -> Outcome {
    let auth = req.headers().get(AUTHORIZATION).map(HeaderValue::as_bytes);
    // The token is checked before the path, so any request without a valid token receives `401`.
    let Some(token) = shared.tokens.authenticate(auth) else {
        let mut out = Outcome::status(StatusCode::UNAUTHORIZED);
        out.resp
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return out;
    };
    let out = match req.uri().path() {
        "/v1/vault" => match *req.method() {
            Method::GET => get_vault(shared).await,
            Method::PUT => put_vault(shared, &token, req, deadline).await,
            _ => not_allowed("GET, PUT"),
        },
        "/v1/revisions" => match *req.method() {
            Method::GET => list_revisions(shared).await,
            _ => not_allowed("GET"),
        },
        p => match p
            .strip_prefix("/v1/revisions/")
            .and_then(revisions::parse_id)
        {
            Some(id) if req.method() == Method::GET => get_revision(shared, id).await,
            Some(_) => not_allowed("GET"),
            None => Outcome::status(StatusCode::NOT_FOUND),
        },
    };
    out.token(&token)
}

fn not_allowed(allow: &'static str) -> Outcome {
    let mut out = Outcome::status(StatusCode::METHOD_NOT_ALLOWED);
    out.resp
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static(allow));
    out
}

fn empty() -> RespBody {
    Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
}

fn full(b: Bytes) -> RespBody {
    Full::new(b).map_err(|e| match e {}).boxed()
}

fn response(status: StatusCode, body: RespBody) -> Response<RespBody> {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    r
}

fn octet_stream(r: &mut Response<RespBody>) {
    r.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
}

fn etag_header(etag: &str) -> HeaderValue {
    HeaderValue::from_str(etag).expect("an ETag is quoted hex")
}

/// Runs blocking file work on the blocking pool. An error is logged and becomes `500`.
async fn blocking<T: Send + 'static>(
    shared: &Arc<Shared>,
    f: impl FnOnce(&Shared) -> Result<T> + Send + 'static,
) -> std::result::Result<T, Outcome> {
    let worker = shared.clone();
    match tokio::task::spawn_blocking(move || f(&worker)).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => {
            shared.log(&format!("error: {e}"));
            Err(Outcome::status(StatusCode::INTERNAL_SERVER_ERROR))
        }
        Err(_) => Err(Outcome::status(StatusCode::INTERNAL_SERVER_ERROR)),
    }
}

impl Shared {
    fn log(&self, line: &str) {
        (self.tuning.log)(&format!("{} {line}", time::format(self.now())));
    }

    fn now(&self) -> u64 {
        (self.tuning.clock)()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current revision, re-read when `revisions/` no longer has the cached one as its
    /// highest.
    fn current(&self) -> Result<Option<Current>> {
        let mut st = self.state();
        st.index.refresh(&self.revdir)?;
        let Some(id) = st.index.current().map(|r| r.id) else {
            st.current = None;
            return Ok(None);
        };
        if st.current.as_ref().map(|c| c.id) != Some(id) {
            let mut f =
                revisions::open(&self.revdir, id).context(|| format!("reading revision {id}"))?;
            let mut bytes = Vec::new();
            io::Read::read_to_end(&mut f, &mut bytes)
                .context(|| format!("reading revision {id}"))?;
            st.current = Some(Current {
                id,
                etag: vault_core::sync::etag(&bytes),
                bytes: Bytes::from(bytes),
            });
        }
        st.min_id = st.min_id.max(id + 1);
        Ok(st.current.clone())
    }

    fn fits(&self, size: u64) -> Result<bool> {
        let mut st = self.state();
        st.index.refresh(&self.revdir)?;
        Ok(revisions::fits(&st.index, size, self.quota))
    }

    fn list(&self) -> Result<Vec<Revision>> {
        let mut st = self.state();
        st.index.refresh(&self.revdir)?;
        Ok(st.index.newest_first())
    }

    fn open(&self, id: u64) -> Result<Option<(File, u64)>> {
        let mut st = self.state();
        st.index.refresh(&self.revdir)?;
        if st.index.get(id).is_none() {
            return Ok(None);
        }
        match revisions::open(&self.revdir, id) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            r => {
                let f = r.context(|| format!("reading revision {id}"))?;
                let len = f
                    .metadata()
                    .context(|| format!("reading revision {id}"))?
                    .len();
                Ok(Some((f, len)))
            }
        }
    }
}

async fn get_vault(shared: &Arc<Shared>) -> Outcome {
    let current = match blocking(shared, Shared::current).await {
        Ok(c) => c,
        Err(out) => return out,
    };
    let Some(c) = current else {
        return Outcome::status(StatusCode::NOT_FOUND);
    };
    let size = c.bytes.len() as u64;
    let mut resp = response(StatusCode::OK, full(c.bytes));
    octet_stream(&mut resp);
    resp.headers_mut().insert(ETAG, etag_header(&c.etag));
    Outcome {
        resp,
        token: None,
        size,
    }
}

async fn list_revisions(shared: &Arc<Shared>) -> Outcome {
    let revs = match blocking(shared, Shared::list).await {
        Ok(r) => r,
        Err(out) => return out,
    };
    let list: Vec<serde_json::Value> = revs
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "etag": r.etag,
                "size": r.size,
                "created": r.created(),
                "token": r.token,
            })
        })
        .collect();
    let body =
        serde_json::to_vec(&serde_json::json!({ "revisions": list })).expect("the list serialises");
    let mut resp = response(StatusCode::OK, full(Bytes::from(body)));
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Outcome {
        resp,
        token: None,
        size: 0,
    }
}

async fn get_revision(shared: &Arc<Shared>, id: u64) -> Outcome {
    let opened = match blocking(shared, move |s| s.open(id)).await {
        Ok(o) => o,
        Err(out) => return out,
    };
    let Some((file, len)) = opened else {
        return Outcome::status(StatusCode::NOT_FOUND);
    };
    let body = FileBody {
        file: tokio::fs::File::from_std(file),
        remaining: len,
    };
    let mut resp = response(StatusCode::OK, body.boxed());
    octet_stream(&mut resp);
    resp.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(len));
    Outcome {
        resp,
        token: None,
        size: len,
    }
}

/// Removes an upload's temporary file unless it was stored.
struct UploadGuard(Option<PathBuf>);

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `PUT /v1/vault`, in the documented order. The body is read only at step 5.
async fn put_vault(
    shared: &Arc<Shared>,
    token: &str,
    req: Request<Incoming>,
    deadline: Instant,
) -> Outcome {
    // 1. The token was checked by the caller; a condition is required.
    let headers = req.headers();
    let if_match: Vec<&HeaderValue> = headers.get_all(IF_MATCH).iter().collect();
    let if_none: Vec<&HeaderValue> = headers.get_all(IF_NONE_MATCH).iter().collect();
    if if_match.is_empty() && if_none.is_empty() {
        return Outcome::status(StatusCode::PRECONDITION_REQUIRED);
    }
    // 2. The PUT lock.
    let Ok(_put) = tokio::time::timeout_at(deadline.into(), shared.put_lock.lock()).await else {
        return Outcome::status(StatusCode::REQUEST_TIMEOUT);
    };
    // 3. The condition.
    let current = match blocking(shared, Shared::current).await {
        Ok(c) => c,
        Err(out) => return out,
    };
    let etag = current.as_ref().map(|c| c.etag.as_bytes());
    // `If-Match` holds only for exactly the current ETag: a list, `*`, or `W/` does not.
    let match_holds = if_match.is_empty()
        || (if_match.len() == 1 && etag.is_some() && Some(if_match[0].as_bytes()) == etag);
    // `If-None-Match` holds only for exactly `*` with no revision stored.
    let none_holds =
        if_none.is_empty() || (if_none.len() == 1 && if_none[0] == "*" && current.is_none());
    if !(match_holds && none_holds) {
        return Outcome::status(StatusCode::PRECONDITION_FAILED);
    }
    // 4. Content-Length and the quota.
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if length.is_some_and(|n| n > MAX_SIZE) {
        return Outcome::status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    // Without `Content-Length`, the body counts as the smallest vault file here; step 7 checks
    // the quota again for the size received.
    let expected = length.unwrap_or(MIN_SIZE);
    match blocking(shared, move |s| s.fits(expected)).await {
        Ok(true) => {}
        Ok(false) => return Outcome::status(StatusCode::INSUFFICIENT_STORAGE),
        Err(out) => return out,
    }
    // 5. The body, to a temporary file in `revisions/`.
    let path = revisions::upload_path(&shared.revdir);
    let file = match datadir::create_new(&path) {
        Ok(f) => f,
        Err(e) => {
            shared.log(&format!("error: creating {}: {e}", path.display()));
            return Outcome::status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let mut guard = UploadGuard(Some(path.clone()));
    let mut file = tokio::fs::File::from_std(file);
    let mut body = req.into_body();
    let mut bytes = Vec::with_capacity(expected.min(MAX_SIZE) as usize);
    loop {
        let frame = match tokio::time::timeout_at(deadline.into(), body.frame()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => return Outcome::status(StatusCode::REQUEST_TIMEOUT),
        };
        let Ok(frame) = frame else {
            return Outcome::status(StatusCode::BAD_REQUEST);
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if (bytes.len() + data.len()) as u64 > MAX_SIZE {
            return Outcome::status(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if let Err(e) = file.write_all(&data).await {
            shared.log(&format!("error: writing {}: {e}", path.display()));
            return Outcome::status(StatusCode::INTERNAL_SERVER_ERROR);
        }
        bytes.extend_from_slice(&data);
    }
    if let Err(e) = async {
        file.flush().await?;
        file.sync_all().await
    }
    .await
    {
        shared.log(&format!("error: writing {}: {e}", path.display()));
        return Outcome::status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    drop(file);
    let size = bytes.len() as u64;
    // 6. The shape of a vault file.
    if !revisions::vault_shaped(&bytes) {
        let mut out = Outcome::status(StatusCode::BAD_REQUEST);
        out.size = size;
        return out;
    }
    // 7. Store and apply retention.
    let etag = vault_core::sync::etag(&bytes);
    let bytes = Bytes::from(bytes);
    let token_name = token.to_owned();
    let stored = {
        let (etag, bytes) = (etag.clone(), bytes.clone());
        blocking(shared, move |s| s.store(&path, etag, bytes, &token_name)).await
    };
    let mut out = match stored {
        Ok(Ok(_)) => {
            guard.0 = None;
            let mut out = Outcome::status(StatusCode::OK);
            out.resp.headers_mut().insert(ETAG, etag_header(&etag));
            out
        }
        Ok(Err(())) => Outcome::status(StatusCode::INSUFFICIENT_STORAGE),
        Err(out) => out,
    };
    out.size = size;
    out
}

impl Shared {
    /// Stores an upload under the writer lock and caches it as the current revision.
    /// `Ok(Err(()))` means the quota or the revision cap would be exceeded.
    fn store(
        &self,
        upload: &Path,
        etag: String,
        bytes: Bytes,
        token: &str,
    ) -> Result<std::result::Result<Revision, ()>> {
        let _w = self.data.write_lock()?;
        let mut st = self.state();
        let st = &mut *st;
        let up = Upload {
            path: upload,
            etag: etag.clone(),
            size: bytes.len() as u64,
            token,
        };
        match revisions::store(
            &self.revdir,
            &mut st.index,
            st.min_id,
            up,
            self.quota,
            self.now(),
        ) {
            Ok((rev, retention)) => {
                // The revision is stored; a failed deletion leaves extra revisions for the next
                // store to delete.
                if let Some(e) = retention {
                    self.log(&format!("error: applying retention: {e}"));
                }
                st.min_id = rev.id + 1;
                st.current = Some(Current {
                    id: rev.id,
                    bytes,
                    etag,
                });
                Ok(Ok(rev))
            }
            Err(StoreError::Full) => Ok(Err(())),
            Err(StoreError::Io(e)) => Err(e),
        }
    }
}

/// A connection's I/O that fails a write or flush left waiting longer than the limit, so a
/// client that stops reading cannot hold a connection.
struct WriteWatchdog<S> {
    inner: S,
    limit: Duration,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> WriteWatchdog<S> {
    fn new(inner: S, limit: Duration) -> WriteWatchdog<S> {
        WriteWatchdog {
            inner,
            limit,
            timer: None,
        }
    }

    /// Clears the timer on progress; on `Pending`, starts it or fails once it has run out.
    fn watch<T>(
        &mut self,
        cx: &mut TaskContext<'_>,
        r: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if r.is_ready() {
            self.timer = None;
            return r;
        }
        let limit = self.limit;
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client stopped reading",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteWatchdog<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteWatchdog<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(cx, r)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.watch(cx, r)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        self.watch(cx, r)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.watch(cx, r)
    }
}

/// A response body that fails once the request's 60 s are up, which closes the connection.
struct Deadline {
    inner: RespBody,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl Deadline {
    fn new(inner: RespBody, at: Instant) -> Deadline {
        Deadline {
            inner,
            sleep: Box::pin(tokio::time::sleep_until(at.into())),
        }
    }
}

impl Body for Deadline {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        if self.sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the request took longer than 60 s",
            ))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A revision's file, read in chunks of up to 64 KiB.
struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut buf = vec![0u8; self.remaining.min(64 * 1024) as usize];
        let mut rb = ReadBuf::new(&mut buf);
        ready!(Pin::new(&mut self.file).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        if n == 0 {
            return Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())));
        }
        buf.truncate(n);
        self.remaining -= n as u64;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// One log line: the time, the peer, the method, the path, the status, the token name, and the
/// body size. The method and path are cut and escaped; nothing else in them is attacker-chosen.
fn log_line(
    now_ms: u64,
    peer: SocketAddr,
    method: &str,
    path: &str,
    status: StatusCode,
    token: Option<&str>,
    size: u64,
) -> String {
    format!(
        "{} {peer} {} {} {} {} {size}",
        time::format(now_ms),
        escape(method, 16),
        escape(path, LOG_PATH_CHARS),
        status.as_u16(),
        token.unwrap_or("-"),
    )
}

/// Cuts `s` to `max` characters and escapes control characters, spaces, and backslashes.
fn escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().take(max) {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\x20"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_are_escaped_and_cut() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let line = log_line(
            0,
            peer,
            "GET",
            "/v1/vault",
            StatusCode::OK,
            Some("laptop"),
            4269,
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00Z 127.0.0.1:5000 GET /v1/vault 200 laptop 4269"
        );
        let line = log_line(
            0,
            peer,
            "GET",
            "/a\nb\x1b c\\",
            StatusCode::NOT_FOUND,
            None,
            0,
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00Z 127.0.0.1:5000 GET /a\\u{a}b\\u{1b}\\x20c\\\\ 404 - 0"
        );
        let long = "/".repeat(500);
        let line = log_line(0, peer, "GET", &long, StatusCode::NOT_FOUND, None, 0);
        assert!(line.contains(&format!(" {} 404", "/".repeat(200))));
        assert!(!line.contains(&"/".repeat(201)));
    }
}
