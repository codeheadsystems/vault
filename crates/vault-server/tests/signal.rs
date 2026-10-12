//! `SIGTERM` stops `vault serve`, and requests still in progress after the grace period are
//! dropped. The test signals its own process, so it has a test binary to itself.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vault_server::{DataDir, InitArgs, Server, TokenAddArgs, Tuning, init, token_add};

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_ends_the_server_after_the_grace_period() {
    // Installs the handler first, so the signal cannot end the test process.
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let data = DataDir::new(tmp.path().join("data"));
    init(
        &data,
        &InitArgs {
            url: "http://127.0.0.1:8080".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            http_listen: Some("127.0.0.1:0".parse().unwrap()),
            cert: None,
            key: None,
            no_tls: true,
            quota: "64MiB".into(),
        },
    )
    .unwrap();
    let added = token_add(
        &data,
        &TokenAddArgs {
            name: "laptop".into(),
            url: None,
            fp: None,
            no_fp: false,
        },
    )
    .unwrap();
    let token = vault_core::setup::parse_setup(&added.setup_text)
        .unwrap()
        .token;
    let auth = format!("Bearer {}", vault_core::token::encode(&token).as_str());

    let grace = Duration::from_secs(1);
    let tuning = Tuning {
        shutdown_grace: grace,
        ..Tuning::default()
    };
    let server = Server::bind_with(&data, tuning).await.unwrap();
    let addr = server.http_addr().unwrap();
    let task = tokio::spawn(server.run(vault_server::shutdown_signal()));

    // An upload that never finishes.
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "PUT /v1/vault HTTP/1.1\r\nhost: x\r\nauthorization: {auth}\r\nif-none-match: *\r\n\
         content-length: 4269\r\n\r\nVAULT"
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sent = Instant::now();
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    term.recv().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the server did not stop")
        .unwrap()
        .unwrap();
    let elapsed = sent.elapsed();
    assert!(elapsed >= grace - Duration::from_millis(50), "{elapsed:?}");
    assert!(elapsed < grace + Duration::from_secs(2), "{elapsed:?}");
    // The upload's connection is closed and nothing was stored.
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut out)).await;
    assert!(!String::from_utf8_lossy(&out).contains(" 200 "));
    let left: Vec<_> = std::fs::read_dir(data.root().join("revisions"))
        .unwrap()
        .collect();
    assert!(left.is_empty());
    assert!(TcpStream::connect(addr).await.is_err());
}
