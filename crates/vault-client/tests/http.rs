//! Sync, recovery, and a credential change over real HTTP against `vault serve` on 127.0.0.1, with
//! a token thief pushing garbage, rolling back, and filling the quota. A small HTTP/1.1 adapter
//! over a TCP stream stands in for the CLI's transport.

mod common;

use common::{Client, Run, pw};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vault_client::passwd::{PasswdChange, PasswdOptions, passwd};
use vault_client::recover::recover;
use vault_client::setup::{init, setup};
use vault_client::sync::{Mode, SyncOutcome, sync};
use vault_client::{
    Answer, ClientError, ClientState, Input, Keys, Machine, Precondition, Request, Response,
    SecretKeyStore, Step, StopReason,
};
use vault_core::header::MAX_GENERATION;
use vault_core::kdf::FLOOR;
use vault_core::sync::etag;
use vault_core::{Error, IntegrityKind};
use vault_server::{DataDir, InitArgs, Server, TokenAddArgs};

const PW: &str = "correct horse battery staple";
const PW2: &str = "a brand new passphrase";

/// A raw HTTP/1.1 exchange: one request per connection.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Raw {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth}\r\nConnection: close\r\n"
    );
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    if method == "PUT" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(out[..split].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (n, v) = l.split_once(':').unwrap();
            (n.trim().to_owned(), v.trim().to_owned())
        })
        .collect();
    Raw {
        status,
        headers,
        body: out[split + 4..].to_vec(),
    }
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) in ms.
fn http_date(s: &str) -> Option<u64> {
    let p: Vec<&str> = s.split([' ', ':']).collect();
    let [_, day, mon, year, h, m, sec, "GMT"] = p[..] else {
        return None;
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|x| *x == mon)? as i64
        + 1;
    let (y, d): (i64, i64) = (year.parse().ok()?, day.parse().ok()?);
    // Days from civil, after Howard Hinnant.
    let y = if month <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400
        + h.parse::<i64>().ok()? * 3600
        + m.parse::<i64>().ok()? * 60
        + sec.parse::<i64>().ok()?;
    Some(secs as u64 * 1000)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The CLI's transport for one request.
async fn send(addr: SocketAddr, auth: &str, r: &Request) -> Response {
    let raw = match r {
        Request::GetVault => http(addr, "GET", "/v1/vault", auth, &[], &[]).await,
        Request::PutVault { condition, file } => {
            let h = match condition {
                Precondition::IfMatch(e) => ("If-Match", e.clone()),
                Precondition::IfNoneMatch => ("If-None-Match", "*".to_owned()),
            };
            http(addr, "PUT", "/v1/vault", auth, &[h], file).await
        }
        Request::ListRevisions => http(addr, "GET", "/v1/revisions", auth, &[], &[]).await,
        Request::GetRevision(id) => {
            http(addr, "GET", &format!("/v1/revisions/{id}"), auth, &[], &[]).await
        }
    };
    Response {
        status: raw.status,
        date: raw.header("Date").and_then(http_date),
        body: raw.body,
    }
}

/// Runs a machine over HTTP, answering prompts in order, committing saves and the end into
/// `client` as the CLI does.
async fn run<T: 'static>(
    client: &mut Client,
    make: impl FnOnce(ClientState, Keys, common::TestRng) -> Machine<T>,
    addr: SocketAddr,
    answers: Vec<Answer>,
) -> Run<T> {
    let mut started = client.state.clone();
    let mut machine = make(started.clone(), client.keys(), client.rng());
    let mut answers: std::collections::VecDeque<Answer> = answers.into();
    let (mut prompts, mut saves, mut requests) = (Vec::new(), Vec::new(), Vec::new());
    let auth = client.token.clone();
    let mut step = machine.start(now_ms());
    let finished = loop {
        step = match step {
            Step::Request(r) => {
                let resp = send(addr, &auth, &r).await;
                requests.push(r);
                machine.step(Input::Response(resp), now_ms())
            }
            Step::Prompt(p) => {
                prompts.push(p);
                let a = answers.pop_front().expect("an answer");
                machine.step(Input::Answer(a), now_ms())
            }
            Step::Save(s) => {
                let mut rng = client.rng();
                if let Some(st) = s
                    .commit(&started, &client.state, now_ms(), &mut rng)
                    .unwrap()
                    .state
                {
                    client.state = st;
                }
                started = s.state.clone();
                saves.push(s);
                machine.step(Input::Saved, now_ms())
            }
            Step::Done(f) => break f,
        };
    };
    client.commit(&started, &finished, now_ms());
    Run {
        finished,
        prompts,
        saves,
        requests,
    }
}

struct Served {
    _tmp: tempfile::TempDir,
    data: DataDir,
    addr: SocketAddr,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Served {
    async fn start(quota: &str) -> Served {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path().join("data"));
        vault_server::init(
            &data,
            &InitArgs {
                url: "http://127.0.0.1:8080".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                http_listen: Some("127.0.0.1:0".parse().unwrap()),
                cert: None,
                key: None,
                no_tls: true,
                quota: quota.into(),
            },
        )
        .unwrap();
        let server = Server::bind(&data).await.unwrap();
        let addr = server.http_addr().unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(server.run(async {
            let _ = rx.await;
        }));
        Served {
            _tmp: tmp,
            data,
            addr,
            _stop: stop,
        }
    }

    fn token(&self, name: &str) -> String {
        let added = vault_server::token_add(
            &self.data,
            &TokenAddArgs {
                name: name.into(),
                url: None,
                fp: None,
                no_fp: false,
            },
        )
        .unwrap();
        let s = vault_core::setup::parse_setup(&added.setup_text).unwrap();
        format!("Bearer {}", vault_core::token::encode(&s.token).as_str())
    }
}

fn placeholder() -> Client {
    let fx = common::Fixture::new(1);
    let mut c = Client::new(
        fx.state(fx.file(1, &vault_core::body::Body::default(), 1)),
        fx.key(),
        0,
    );
    c.vk = None;
    c
}

/// The thief's `PUT` over the current revision.
async fn thief_put(s: &Served, auth: &str, body: &[u8]) -> u16 {
    let cur = http(s.addr, "GET", "/v1/vault", auth, &[], &[]).await;
    let h = [("If-Match", etag(&cur.body))];
    http(s.addr, "PUT", "/v1/vault", auth, &h, body)
        .await
        .status
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_recovery_and_passwd_over_http() {
    let s = Served::start("1MiB").await;
    let (ta, tb, thief) = (s.token("phone"), s.token("laptop"), s.token("thief"));

    // `vault init` on A and `vault setup` on B.
    let mut a = placeholder();
    a.token = ta.clone();
    let mut saved = None;
    {
        let mut machine = init(FLOOR, false, SecretKeyStore::Keyring, a.rng());
        let mut step = machine.start(now_ms());
        let finished = loop {
            step = match step {
                Step::Request(r) => {
                    let resp = send(s.addr, &ta, &r).await;
                    machine.step(Input::Response(resp), now_ms())
                }
                Step::Prompt(_) => machine.step(Input::Answer(pw(PW)), now_ms()),
                Step::Save(sv) => {
                    a.state = sv.state.clone();
                    a.sk = Some(sv.secret_key.key().clone_secret());
                    saved = Some(sv.state.clone());
                    machine.step(Input::Saved, now_ms())
                }
                Step::Done(f) => break f,
            };
        };
        assert!(finished.result.is_ok());
        a.commit(&saved.unwrap(), &finished, now_ms());
    }
    let mut b = placeholder();
    b.token = tb.clone();
    b.device = [0xb2; 16];
    let sk = a.sk.as_ref().unwrap().clone_secret();
    let r = run(
        &mut b,
        |_, _, rng| setup(SecretKeyStore::File, rng),
        s.addr,
        vec![
            Answer::SecretKey(sk.clone_secret()),
            Answer::VaultId(Some(a.state.vault_id)),
            pw(PW),
        ],
    )
    .await;
    assert!(r.finished.result.is_ok());
    b.state = r.finished.state.clone().unwrap();
    b.sk = Some(sk);

    // The server's ETag is the client's own, and the conditional requests behave as assumed.
    let cur = http(s.addr, "GET", "/v1/vault", &ta, &[], &[]).await;
    assert_eq!(cur.header("ETag"), Some(etag(&cur.body).as_str()));
    assert!(
        cur.header("Date").and_then(http_date).is_some(),
        "a Date header for the clock check"
    );
    let stale = [("If-Match", etag(b"stale"))];
    assert_eq!(
        http(s.addr, "PUT", "/v1/vault", &ta, &stale, &cur.body)
            .await
            .status,
        412
    );
    let star = [("If-None-Match", "*".to_owned())];
    assert_eq!(
        http(s.addr, "PUT", "/v1/vault", &ta, &star, &cur.body)
            .await
            .status,
        412
    );
    assert_eq!(
        http(s.addr, "PUT", "/v1/vault", &ta, &[], &cur.body)
            .await
            .status,
        428
    );
    assert_eq!(
        http(s.addr, "GET", "/v1/revisions/999", &ta, &[], &[])
            .await
            .status,
        404
    );
    assert_eq!(
        http(s.addr, "GET", "/v1/vault", "Bearer nope", &[], &[])
            .await
            .status,
        401
    );

    let bg = Mode::Background;
    let edit = |c: &mut Client, name: &str| {
        c.edit(|body, rng, dev| {
            common::add_login(body, rng, dev, name, "pw", now_ms());
        })
    };
    edit(&mut a, "from a");
    let r = run(&mut a, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(r.ok().outcome, SyncOutcome::Pushed);
    let r = run(&mut b, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(r.ok().outcome, SyncOutcome::Adopted);
    let honest = b.state.file.clone();

    // A thief pushes garbage at the top generation under the current wrap.
    let mut garbage = vault_core::file::seal_file(
        &b.state.header().unwrap().with_generation(MAX_GENERATION),
        b.vk.as_ref().unwrap(),
        &[1; 24],
        &vault_core::body::Body::default(),
    )
    .unwrap();
    let last = garbage.len() - 1;
    garbage[last] ^= 1;
    assert_eq!(thief_put(&s, &thief, &garbage).await, 200);
    let r = run(&mut b, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(
        r.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::Aead))
    );
    assert_eq!(
        b.state.stopped.as_ref().unwrap().reason,
        StopReason::Integrity
    );
    let r = run(&mut b, recover, s.addr, vec![]).await;
    assert_eq!(
        r.ok().generation,
        3,
        "above the honest generation 2, not the garbage"
    );
    assert!(b.state.stopped.is_none());

    // The thief re-serves an old honest file.
    assert_eq!(thief_put(&s, &thief, &honest).await, 200);
    let r = run(&mut b, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(
        r.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::GenerationRollback))
    );
    run(&mut b, recover, s.addr, vec![]).await.ok();
    let r = run(&mut a, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(r.ok().outcome, SyncOutcome::Adopted);

    // The thief fills the quota; honest pushes get 507 until the thief's revisions are removed.
    for blocks in [64, 8, 1] {
        let mut blob = b"VAULT".to_vec();
        blob.resize(173 + 4096 * blocks, 0);
        while thief_put(&s, &thief, &blob).await == 200 {}
    }
    edit(&mut a, "while full");
    let r = run(&mut a, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(
        r.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::FormatVersion))
    );
    let r = run(&mut a, recover, s.addr, vec![]).await;
    assert_eq!(r.err(), ClientError::Status(507));
    assert!(a.state.unpushed(), "the edit stays local");
    // `vault serve revisions rm --token thief` keeps only the current revision of the thief.
    vault_server::revisions_remove(&s.data, "thief", None).unwrap();
    let r = run(&mut a, recover, s.addr, vec![]).await;
    r.ok();
    assert!(!a.state.unpushed() && a.state.stopped.is_none());
    // B never saw the blob: recovery replaced it before B's sync.
    let r = run(&mut b, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(r.ok().outcome, SyncOutcome::Adopted);
    assert_eq!(a.state.file, b.state.file);

    // A changes the password; B takes the change over.
    let opts = PasswdOptions {
        change: PasswdChange::NewPassword,
        kdf: FLOOR,
        test_kdf: false,
    };
    let r = run(
        &mut a,
        |st, k, rng| passwd(st, k, opts, rng),
        s.addr,
        vec![pw(PW2)],
    )
    .await;
    let report = r.ok().clone();
    assert!(report.retired_revision.is_some());
    let r = run(
        &mut b,
        |st, k, rng| sync(st, k, Mode::Interactive { ask_again: false }, rng),
        s.addr,
        vec![pw(PW2)],
    )
    .await;
    assert!(r.ok().credentials_changed);
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
    assert_eq!(b.state.retired, a.state.retired);
    let r = run(&mut a, |st, k, rng| sync(st, k, bg, rng), s.addr, vec![]).await;
    assert_eq!(r.ok().outcome, SyncOutcome::UpToDate);
    assert_eq!(a.state.file, b.state.file);
}
