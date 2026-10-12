//! The `vault` binary against an in-process `vault serve` on 127.0.0.1: devices with their own
//! XDG directories, the `file` secret key store, no agent, and the master password through
//! `--password-fd`. Run with `VAULT_EXPECT_TEST_KDF=1 cargo test -p vault-cli --features
//! insecure-test-kdf`; the binary uses the test KDF parameters when `VAULT_TEST_KDF=1`.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use vault_server::{DataDir, InitArgs, Server, TokenAddArgs, init, token_add, token_remove};

const PW: &str = "correct horse battery staple";
const NEW_PW: &str = "a different long passphrase";
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../vault-interop/tests/fixtures"
);

// ---------------------------------------------------------------------------------------------
// The server

struct TestServer {
    _tmp: tempfile::TempDir,
    data: DataDir,
    addr: SocketAddr,
    https: bool,
    rt: tokio::runtime::Runtime,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestServer {
    fn start(https: bool) -> TestServer {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path().join("data"));
        let args = InitArgs {
            url: if https {
                "https://localhost:8443".into()
            } else {
                "http://127.0.0.1:8080".into()
            },
            listen: "127.0.0.1:0".parse().unwrap(),
            http_listen: (!https).then(|| "127.0.0.1:0".parse().unwrap()),
            cert: None,
            key: None,
            no_tls: !https,
            quota: "256MiB".into(),
        };
        init(&data, &args).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(Server::bind(&data)).unwrap();
        let addr = if https {
            server.https_addr()
        } else {
            server.http_addr()
        }
        .unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        rt.spawn(server.run(async {
            let _ = rx.await;
        }));
        TestServer {
            _tmp: tmp,
            data,
            addr,
            https,
            rt,
            stop: Some(stop),
        }
    }

    fn url(&self) -> String {
        if self.https {
            format!("https://localhost:{}", self.addr.port())
        } else {
            format!("http://127.0.0.1:{}", self.addr.port())
        }
    }

    /// Creates a token and returns its setup text.
    fn token(&self, name: &str) -> String {
        self.token_with(name, None)
    }

    fn token_with(&self, name: &str, fp: Option<String>) -> String {
        let added = token_add(
            &self.data,
            &TokenAddArgs {
                name: name.into(),
                url: Some(self.url()),
                fp,
                no_fp: false,
            },
        )
        .unwrap();
        added.setup_text.as_str().to_owned()
    }

    fn revoke(&self, name: &str) {
        token_remove(&self.data, name).unwrap();
    }

    /// A raw request over plain HTTP, with the token of `setup`.
    fn request(
        &self,
        method: &str,
        path: &str,
        setup: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (u16, Vec<u8>) {
        assert!(!self.https);
        let s = vault_core::setup::parse_setup(setup).unwrap();
        let bearer = format!("Bearer {}", vault_core::token::encode(&s.token).as_str());
        let addr = self.addr;
        let mut b = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1")
            .header("authorization", bearer);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = b.body(Full::new(Bytes::from(body))).unwrap();
        self.rt.block_on(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .unwrap();
            tokio::spawn(conn);
            let resp = sender.send_request(req).await.unwrap();
            let status = resp.status().as_u16();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body.to_vec())
        })
    }

    /// The server's current vault file.
    fn current(&self, setup: &str) -> Vec<u8> {
        let (status, body) = self.request("GET", "/v1/vault", setup, &[], Vec::new());
        assert_eq!(status, 200);
        body
    }

    /// Replaces the current vault file with `file`, as a hostile or broken writer would.
    fn overwrite(&self, setup: &str, file: Vec<u8>) {
        let etag = vault_core::sync::etag(&self.current(setup));
        let (status, _) = self.request("PUT", "/v1/vault", setup, &[("if-match", &etag)], file);
        assert_eq!(status, 200);
    }

    /// The retained revisions, newest first.
    fn revisions(&self, setup: &str) -> Vec<Value> {
        let (status, body) = self.request("GET", "/v1/revisions", setup, &[], Vec::new());
        assert_eq!(status, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        v["revisions"].as_array().unwrap().clone()
    }

    fn revision(&self, setup: &str, id: u64) -> Vec<u8> {
        let (status, body) = self.request(
            "GET",
            &format!("/v1/revisions/{id}"),
            setup,
            &[],
            Vec::new(),
        );
        assert_eq!(status, 200);
        body
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Devices

struct Device {
    tmp: tempfile::TempDir,
    /// Whether commands use the agent.
    agent: bool,
    /// A runtime directory on a tmpfs, for the editor, when the machine has `/dev/shm`.
    runtime: Option<tempfile::TempDir>,
}

/// The outcome of one command.
#[derive(Debug)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(self) -> Run {
        assert_eq!(self.code, 0, "{self:#?}");
        self
    }

    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| panic!("{e}: {self:#?}"))
    }

    fn result(&self) -> Value {
        let v = self.json();
        assert_eq!(v["v"], 1, "{self:#?}");
        v["result"].clone()
    }

    fn error_code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap().to_owned()
    }
}

/// What a command reads: lines of `--password-fd`, and of standard input.
#[derive(Default)]
struct Input<'a> {
    passwords: &'a [&'a str],
    stdin: &'a str,
    env: &'a [(&'a str, &'a str)],
}

fn pw(passwords: &'static [&'static str]) -> Input<'static> {
    Input {
        passwords,
        ..Input::default()
    }
}

impl Device {
    fn new() -> Device {
        Device::with_agent(false)
    }

    fn with_agent(agent: bool) -> Device {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config/vault");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("config.toml"),
            format!("keyring = \"file\"\n[agent]\nenabled = {agent}\nidle = \"2m\"\n"),
        )
        .unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("vault-cli-test")
            .tempdir_in("/dev/shm")
            .ok();
        if let Some(r) = &runtime {
            std::fs::set_permissions(r.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Device {
            tmp,
            agent,
            runtime,
        }
    }

    fn data(&self) -> PathBuf {
        self.tmp.path().join("data/vault")
    }

    fn command(&self, args: &[&str], input: &Input<'_>) -> (Command, Option<std::fs::File>) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vault"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.tmp.path())
            .env("XDG_DATA_HOME", self.tmp.path().join("data"))
            .env("XDG_CONFIG_HOME", self.tmp.path().join("config"))
            .env("VAULT_TEST_KDF", "1");
        if !self.agent {
            cmd.env("VAULT_NO_AGENT", "1");
        }
        if let Some(r) = &self.runtime {
            cmd.env("XDG_RUNTIME_DIR", r.path());
        }
        for (k, v) in input.env {
            cmd.env(k, v);
        }
        let mut fd_file = None;
        if !input.passwords.is_empty() {
            let path = self.tmp.path().join(format!(
                "passwords-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut text = input.passwords.join("\n");
            text.push('\n');
            std::fs::write(&path, text).unwrap();
            let f = std::fs::File::open(&path).unwrap();
            // Inherited by the child at the same number.
            rustix::io::fcntl_setfd(&f, rustix::io::FdFlags::empty()).unwrap();
            cmd.arg("--password-fd").arg(f.as_raw_fd().to_string());
            fd_file = Some(f);
        }
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        (cmd, fd_file)
    }

    fn run(&self, args: &[&str], input: Input<'_>) -> Run {
        let (mut cmd, fd_file) = self.command(args, &input);
        let mut child = cmd.spawn().unwrap();
        drop(fd_file);
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(input.stdin.as_bytes());
        drop(stdin);
        finish(child)
    }

    /// `vault init`: answers the setup text, the master password, and the kit's last group,
    /// and returns the secret key text form.
    fn init(&self, setup: &str) -> String {
        let (run, key) = self.with_kit(&["init"], &[PW], &format!("{setup}\n"));
        run.ok();
        key
    }

    /// Runs a command that prints an emergency kit and asks for its last group, answering it;
    /// returns the outcome and the kit's secret key.
    fn with_kit(&self, args: &[&str], passwords: &[&str], stdin_first: &str) -> (Run, String) {
        let input = Input {
            passwords,
            ..Input::default()
        };
        let (mut cmd, fd_file) = self.command(args, &input);
        let mut child = cmd.spawn().unwrap();
        drop(fd_file);
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(stdin_first.as_bytes()).unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut kit = String::new();
        let key = loop {
            let mut line = String::new();
            assert!(out.read_line(&mut line).unwrap() > 0, "no kit: {kit}");
            kit.push_str(&line);
            if let Some(k) = line.strip_prefix("Secret key:") {
                break k.trim().to_owned();
            }
        };
        // Typed in lower case, as the decoder allows.
        let last = key.rsplit('-').next().unwrap().to_lowercase();
        writeln!(stdin, "{last}").unwrap();
        drop(stdin);
        let mut rest = String::new();
        out.read_to_string(&mut rest).unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = child.wait().unwrap();
        assert!(rest.contains("Vault ID:"), "{kit}{rest}");
        let run = Run {
            code: status.code().unwrap_or(-1),
            stdout: format!("{kit}{rest}"),
            stderr,
        };
        (run, key)
    }

    /// An editor script with `body` as its shell commands; `$1` is the file.
    fn script(&self, name: &str, body: &str) -> String {
        let path = self.tmp.path().join(format!("{name}.sh"));
        std::fs::write(&path, format!("#!/bin/sh\nset -e\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.display().to_string()
    }

    /// A file holding the master password, for `--password-fd` in a nested command.
    fn password_file(&self) -> String {
        let p = self.tmp.path().join("master-password");
        std::fs::write(&p, format!("{PW}\n")).unwrap();
        p.display().to_string()
    }

    /// `vault setup` on a new device.
    fn setup(&self, setup: &str, secret_key: &str) -> Run {
        self.run(
            &["setup"],
            Input {
                passwords: &[PW],
                stdin: &format!("{setup}\n{secret_key}\n\n"),
                ..Input::default()
            },
        )
    }

    /// `vault add <name> --username <user>` with the item password on standard input.
    fn add(&self, name: &str, item_pw: &str, extra: &[&str]) -> Run {
        let mut args = vec!["--json", "add", name, "--username", "ned"];
        args.extend_from_slice(extra);
        self.run(
            &args,
            Input {
                passwords: &[PW],
                stdin: &format!("{item_pw}\n"),
                ..Input::default()
            },
        )
    }

    /// The item as `show --json --reveal` prints it.
    fn show(&self, item: &str, password: &'static str) -> Value {
        self.run(
            &["--json", "show", item, "--reveal"],
            Input {
                passwords: &[password],
                ..Input::default()
            },
        )
        .ok()
        .result()
    }

    fn names(&self, password: &'static str) -> Vec<String> {
        let r = self
            .run(
                &["--json", "ls"],
                Input {
                    passwords: &[password],
                    ..Input::default()
                },
            )
            .ok();
        r.result()["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap().to_owned())
            .collect()
    }

    /// An editor that replaces the line starting with `key = ` with `key = "<value>"`, writing
    /// the file in place.
    fn editor(&self, key: &str, value: &str) -> String {
        let script = self.tmp.path().join(format!("edit-{key}.sh"));
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nsed 's/^{key} = .*/{key} = \"{value}\"/' \"$1\" > \"$1.x\" && cat \"$1.x\" > \"$1\" && rm \"$1.x\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script.display().to_string()
    }
}

fn finish(child: Child) -> Run {
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A server, and a device with a new vault on it; returns the setup text and the secret key.
fn one_device() -> (TestServer, Device, String, String) {
    let server = TestServer::start(false);
    let setup = server.token("laptop");
    let a = Device::new();
    let sk = a.init(&setup);
    (server, a, setup, sk)
}

fn password_of(item: &Value) -> &str {
    item["login"]["password"].as_str().unwrap()
}

fn history_of(item: &Value) -> Vec<String> {
    item["password_history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["password"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Tests

#[test]
fn init_then_setup_on_a_second_device_and_an_edit_syncs_across() {
    let (server, a, _, sk) = one_device();
    assert!(a.data().join("local.json").exists());
    assert_eq!(
        std::fs::metadata(a.data()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for f in ["local.json", "server.json", "device-id", "secret-key"] {
        let mode = std::fs::metadata(a.data().join(f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{f}");
    }
    let added = a
        .add("GitHub", "hunter2-long", &["--uri", "https://github.com"])
        .ok();
    assert_eq!(added.result()["synced"], true, "{added:#?}");

    let b = Device::new();
    let setup_b = server.token("phone");
    let r = b.setup(&setup_b, &sk).ok();
    assert!(r.stderr.contains("set up"), "{r:#?}");
    assert_eq!(b.names(PW), ["GitHub"]);
    let item = b.show("github", PW);
    assert_eq!(password_of(&item), "hunter2-long");
    assert_eq!(item["login"]["uris"][0]["uri"], "https://github.com");

    // An edit on B reaches A.
    if b.runtime.is_some() {
        let editor = b.editor("password", "edited-on-b");
        let r = b
            .run(
                &["--json", "edit", "GitHub"],
                Input {
                    passwords: &[PW],
                    env: &[("VISUAL", &editor)],
                    ..Input::default()
                },
            )
            .ok();
        assert_eq!(r.result()["synced"], true, "{r:#?}");
        let item = a.show("GitHub", PW);
        assert_eq!(password_of(&item), "edited-on-b");
        assert_eq!(history_of(&item), ["hunter2-long"]);
    }

    // A wrong kit vault ID is refused before the password is asked.
    let c = Device::new();
    let r = c.run(
        &["--json", "setup"],
        Input {
            passwords: &[PW],
            stdin: &format!("{}\n{sk}\n{}\n", server.token("tablet"), "00".repeat(16)),
            ..Input::default()
        },
    );
    assert_eq!(r.code, 5, "{r:#?}");
    assert_eq!(r.error_code(), "integrity.vault_id_mismatch");
}

#[test]
fn concurrent_edits_merge_and_keep_the_losing_password_in_history() {
    let (server, a, _, sk) = one_device();
    let b = Device::new();
    if a.runtime.is_none() {
        eprintln!("skipped: no /dev/shm for the editor");
        return;
    }
    b.setup(&server.token("phone"), &sk).ok();
    a.add("Mail", "start-password", &[]).ok();
    assert_eq!(b.names(PW), ["Mail"]);

    let edit_offline = |d: &Device, value: &str| {
        let editor = d.editor("password", value);
        d.run(
            &["--offline", "edit", "Mail"],
            Input {
                passwords: &[PW],
                env: &[("VISUAL", &editor)],
                ..Input::default()
            },
        )
        .ok();
    };
    edit_offline(&a, "from-a");
    std::thread::sleep(std::time::Duration::from_millis(20));
    edit_offline(&b, "from-b");

    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "pushed");
    let r = b.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "pushed", "{r:#?}");
    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "adopted");

    for d in [&a, &b] {
        let item = d.show("Mail", PW);
        assert_eq!(password_of(&item), "from-b");
        let h = history_of(&item);
        assert!(h.contains(&"from-a".to_owned()), "{h:?}");
        assert!(h.contains(&"start-password".to_owned()), "{h:?}");
    }
}

#[test]
fn offline_writes_stay_local_and_sync_later() {
    let (server, a, _, sk) = one_device();
    let b = Device::new();
    b.setup(&server.token("phone"), &sk).ok();

    let r = a.add("Offline item", "pw-offline-1", &["--offline"]).ok();
    assert_eq!(r.result()["synced"], false);
    let r = a.run(&["--json", "status"], Input::default()).ok();
    assert_eq!(r.result()["unpushed"], true);
    assert!(b.names(PW).is_empty());

    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "pushed");
    let r = a.run(&["--json", "status"], Input::default()).ok();
    assert_eq!(r.result()["unpushed"], false);
    assert_eq!(b.names(PW), ["Offline item"]);
}

#[test]
fn rollback_and_garbage_stop_sync_with_exit_5_until_recover() {
    let (server, a, setup, _) = one_device();
    a.add("One", "pw-one-111111", &[]).ok();
    a.add("Two", "pw-two-222222", &[]).ok();
    let revisions = server.revisions(&setup);
    let oldest = revisions.last().unwrap()["id"].as_u64().unwrap();
    let old = server.revision(&setup, oldest);

    // A rollback to generation 1.
    server.overwrite(&setup, old);
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!(r.code, 5, "{r:#?}");
    assert_eq!(r.error_code(), "integrity.generation_rollback");
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"]["reason"], "integrity");
    // Reads and local writes go on; sync stays stopped.
    assert_eq!(a.names(PW), ["One", "Two"]);
    let r = a.add("Three", "pw-three-33333", &[]).ok();
    assert_eq!(r.result()["synced"], false);
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!((r.code, r.error_code().as_str()), (5, "sync.stopped"));

    let r = a.run(&["--json", "sync", "--recover"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "pushed");
    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "up_to_date");

    // A file that is not a vault file at all, shaped like one.
    let mut garbage = b"VAULT".to_vec();
    garbage.extend_from_slice(&[0xff; 4]);
    garbage.resize(173 + 4096, 7);
    server.overwrite(&setup, garbage);
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!(r.code, 5, "{r:#?}");
    assert!(r.error_code().starts_with("integrity."), "{r:#?}");
    a.run(&["--json", "sync", "--recover"], pw(&[PW])).ok();

    // A second device sees every item, including the one written while sync was stopped.
    let b = Device::new();
    let sk_text = a.run(&["key", "show"], pw(&[PW])).ok().stdout;
    b.setup(&server.token("phone"), sk_text.trim()).ok();
    assert_eq!(b.names(PW), ["One", "Three", "Two"]);
}

#[test]
fn a_revoked_token_gives_exit_7_and_setup_repairs_it() {
    let (server, a, _, _) = one_device();
    server.revoke("laptop");
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!(r.code, 7, "{r:#?}");
    assert_eq!(r.error_code(), "server.token");
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"]["reason"], "token");
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!((r.code, r.error_code().as_str()), (7, "sync.stopped"));

    let r = a
        .run(
            &["--json", "setup"],
            Input {
                stdin: &format!("{}\n", server.token("laptop-2")),
                ..Input::default()
            },
        )
        .ok();
    assert!(r.result()["vault_id"].is_string());
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"], Value::Null);
    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "up_to_date");
}

#[test]
fn passwd_elsewhere_gives_exit_8_and_sync_takes_it_over() {
    let (server, a, _, sk) = one_device();
    let b = Device::new();
    b.setup(&server.token("phone"), &sk).ok();
    a.add("Bank", "bank-password-1", &[]).ok();

    let r = a.run(&["--json", "passwd"], pw(&[PW, NEW_PW])).ok();
    assert!(r.result()["generation"].as_u64().unwrap() >= 3);
    // A opens with the new password only.
    assert_eq!(a.names(NEW_PW), ["Bank"]);
    let r = a.run(&["--json", "ls"], pw(&[PW, PW, PW]));
    assert_eq!(
        (r.code, r.error_code().as_str()),
        (4, "auth.wrong_password")
    );

    // B still knows only the old password: the unlock finds the new wrap and cannot open it.
    let r = b.run(
        &["--json", "ls"],
        Input {
            passwords: &[PW, PW],
            stdin: "\n",
            ..Input::default()
        },
    );
    assert_eq!(r.code, 8, "{r:#?}");
    let st = b.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"]["reason"], "credentials");

    // With the new password, `vault sync` takes the change over.
    let r = b.run(&["--json", "sync"], pw(&[NEW_PW])).ok();
    assert_eq!(r.result()["outcome"], "adopted", "{r:#?}");
    assert_eq!(b.names(NEW_PW), ["Bank"]);
    let st = b.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"], Value::Null);
}

#[test]
fn import_bitwarden_fixtures_and_export_round_trip() {
    let (server, a, _, _) = one_device();
    let full = format!("{FIXTURES}/full.json");
    let r = a
        .run(
            &["--json", "import", "bitwarden", &full, "--dry-run"],
            pw(&[PW]),
        )
        .ok();
    let dry = r.result();
    assert!(dry["added"].as_u64().unwrap() >= 2, "{r:#?}");
    assert!(a.names(PW).is_empty(), "a dry run saves nothing");

    let r = a
        .run(&["--json", "import", "bitwarden", &full], pw(&[PW]))
        .ok();
    let first = r.result();
    assert_eq!(first["added"], dry["added"]);
    assert!(first["skipped"].as_u64().unwrap() >= 1);
    assert!(r.stderr.contains("delete"), "{r:#?}");
    let names = a.names(PW);
    assert!(names.contains(&"AWS console".to_owned()), "{names:?}");

    // The same items, password-protected: nothing new.
    for f in ["protected-pbkdf2.json", "protected-argon2id.json"] {
        let r = a
            .run(
                &["--json", "import", "bitwarden", &format!("{FIXTURES}/{f}")],
                Input {
                    passwords: &[PW],
                    stdin: "correct horse battery staple\n",
                    ..Input::default()
                },
            )
            .ok();
        let res = r.result();
        assert_eq!(res["added"], 0, "{f}: {r:#?}");
        assert_eq!(res["unchanged"], first["added"], "{f}: {r:#?}");
    }

    // A plain Bitwarden export imports into a new vault with the same items.
    let out = a.tmp.path().join("export.json");
    let out_s = out.display().to_string();
    let r = a
        .run(
            &[
                "export",
                "--format",
                "bitwarden",
                "--plaintext",
                "-o",
                &out_s,
            ],
            pw(&[PW]),
        )
        .ok();
    assert!(r.stderr.contains("not encrypted"), "{r:#?}");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let other = TestServer::start(false);
    let c = Device::new();
    c.init(&other.token("c"));
    let r = c
        .run(&["--json", "import", "bitwarden", &out_s], pw(&[PW]))
        .ok();
    assert_eq!(r.result()["added"], first["added"]);
    assert_eq!(c.names(PW), names);
    drop(server);

    // The json export is the body; the vault export is the local file.
    let r = a
        .run(&["export", "--format", "json", "--plaintext"], pw(&[PW]))
        .ok();
    let body: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(body["v"], 1);
    assert_eq!(body["items"].as_array().unwrap().len(), names.len());
    let vault_out = a.tmp.path().join("vault.bin");
    a.run(
        &[
            "export",
            "--format",
            "vault",
            "-o",
            &vault_out.display().to_string(),
        ],
        Input::default(),
    )
    .ok();
    assert!(std::fs::read(&vault_out).unwrap().starts_with(b"VAULT"));
}

#[test]
fn plaintext_exports_are_refused_without_the_flag_and_over_an_existing_file() {
    let (_server, a, _, _) = one_device();
    for format in ["bitwarden", "json"] {
        let r = a.run(&["--json", "export", "--format", format], pw(&[PW]));
        assert_eq!((r.code, r.error_code().as_str()), (2, "usage"), "{r:#?}");
    }
    let existing = a.tmp.path().join("exists");
    std::fs::write(&existing, "keep").unwrap();
    let r = a.run(
        &[
            "--json",
            "export",
            "--format",
            "json",
            "--plaintext",
            "-o",
            &existing.display().to_string(),
        ],
        pw(&[PW]),
    );
    assert_eq!(r.code, 1, "{r:#?}");
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep");
}

#[test]
fn item_selection_resolves_ids_names_and_parts_and_reports_ambiguity() {
    let (_server, a, _, _) = one_device();
    let work = a
        .add("GitHub", "pw-work-1111", &["--folder", "Work"])
        .ok()
        .result();
    a.add("GitHub", "pw-home-2222", &["--folder", "Home"]).ok();
    a.add("GitLab", "pw-lab-33333", &[]).ok();

    let r = a.run(&["--json", "show", "github"], pw(&[PW]));
    assert_eq!((r.code, r.error_code().as_str()), (3, "item.ambiguous"));
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Work/GitHub")
    );
    let r = a.run(&["--json", "show", "git"], pw(&[PW]));
    assert_eq!((r.code, r.error_code().as_str()), (3, "item.ambiguous"));
    let r = a.run(&["--json", "show", "nothing"], pw(&[PW]));
    assert_eq!((r.code, r.error_code().as_str()), (3, "item.not_found"));

    let id = work["id"].as_str().unwrap();
    assert_eq!(a.show("work/GITHUB", PW)["id"], id);
    assert_eq!(a.show(&id[..8], PW)["id"], id);
    assert_eq!(a.show("lab", PW)["login"]["password"], "pw-lab-33333");

    // rm and mv take the same selection.
    a.run(&["--json", "mv", "home/github", "Personal"], pw(&[PW]))
        .ok();
    a.run(&["--json", "rm", "work/github"], pw(&[PW])).ok();
    let r = a
        .run(
            &["--json", "show", "github", "--field", "password"],
            pw(&[PW]),
        )
        .ok();
    assert_eq!(r.result()["value"], "pw-home-2222");
    let r = a
        .run(&["show", "github", "--field", "password"], pw(&[PW]))
        .ok();
    assert_eq!(r.stdout, "pw-home-2222\n");
}

#[test]
fn json_output_shapes_and_exit_codes() {
    let (_server, a, _, _) = one_device();
    let added = a
        .add("Site", "site-password", &["--uri", "https://site.example"])
        .ok();
    let res = added.result();
    assert!(res["id"].is_string() && res["synced"].is_boolean());

    let ls = a.run(&["--json", "ls"], pw(&[PW])).ok().result();
    let item = &ls["items"][0];
    for k in [
        "id",
        "type",
        "name",
        "folder",
        "username",
        "favourite",
        "review",
    ] {
        assert!(item.get(k).is_some(), "{k} in {item}");
    }
    let found = a
        .run(&["--json", "find", "SITE.example"], pw(&[PW]))
        .ok()
        .result();
    assert_eq!(found["items"].as_array().unwrap().len(), 1);

    let shown = a.run(&["--json", "show", "Site"], pw(&[PW])).ok().result();
    assert_eq!(shown["login"]["password"], Value::Null);
    assert_eq!(shown["password_history"], Value::Null);
    assert_eq!(shown["login"]["username"], "ned");
    let text = a.run(&["show", "Site"], pw(&[PW])).ok().stdout;
    assert!(text.starts_with("# vault item\n") && text.contains("password = \"********\""));
    assert!(!text.contains("site-password"));

    let g = a.run(&["--json", "gen"], Input::default()).ok().result();
    assert_eq!(g["value"].as_str().unwrap().len(), 25);
    assert!(g["bits"].as_f64().unwrap() > 100.0);
    let g = a
        .run(&["--json", "gen", "--words", "5"], Input::default())
        .ok()
        .result();
    assert_eq!(g["value"].as_str().unwrap().split('-').count(), 5);
    assert!((g["bits"].as_f64().unwrap() - 55.0).abs() < 0.01);

    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    for k in ["unlocked", "last_sync", "unpushed", "stopped", "review"] {
        assert!(st.get(k).is_some(), "{k} in {st}");
    }
    let sync = a.run(&["--json", "sync"], pw(&[PW])).ok().result();
    assert_eq!(sync["outcome"], "up_to_date");
    assert!(sync["generation"].is_u64() && sync["dropped"].is_array());
    let h = a
        .run(&["--json", "history"], Input::default())
        .ok()
        .result();
    let revs = h["revisions"].as_array().unwrap();
    assert!(revs.len() >= 2);
    assert_eq!(revs[0]["token"], "laptop");
    let key = a.run(&["--json", "key", "show"], pw(&[PW])).ok().result();
    assert!(key["secret_key"].as_str().unwrap().starts_with("VLT1-"));

    // Wrong master password: exit 4.
    let r = a.run(&["--json", "ls"], pw(&["wrong", "wrong", "wrong"]));
    assert_eq!(
        (r.code, r.error_code().as_str()),
        (4, "auth.wrong_password")
    );
    // Usage errors: exit 2, as JSON.
    let r = a.run(&["--json", "ls", "--no-such-option"], Input::default());
    assert_eq!((r.code, r.error_code().as_str()), (2, "usage"));
    // A device without a vault.
    let empty = Device::new();
    let r = empty.run(&["--json", "ls"], Input::default());
    assert_eq!((r.code, r.error_code().as_str()), (1, "state.no_vault"));
    // gen works without a vault.
    empty.run(&["gen"], Input::default()).ok();
}

#[test]
fn restore_adds_changes_and_removes_items() {
    let (server, a, setup, _) = one_device();
    a.add("Keep", "keep-password-1", &[]).ok();
    a.add("Other", "other-password-1", &[]).ok();
    let before = server.revisions(&setup)[0]["id"]
        .as_u64()
        .unwrap()
        .to_string();
    a.run(&["--json", "rm", "Keep"], pw(&[PW])).ok();
    a.add("Later", "later-password-1", &[]).ok();
    assert_eq!(a.names(PW), ["Later", "Other"]);

    // One item: only that item comes back; nothing is removed.
    let r = a
        .run(
            &["--json", "restore", &before, "--item", "keep", "-y"],
            pw(&[PW]),
        )
        .ok()
        .result();
    assert_eq!(
        (&r["added"], &r["changed"], &r["removed"]),
        (&1.into(), &0.into(), &0.into())
    );
    assert_eq!(a.names(PW), ["Keep", "Later", "Other"]);

    // The whole vault: items absent from the revision are deleted as local edits.
    let r = a
        .run(&["--json", "restore", &before, "-y"], pw(&[PW]))
        .ok()
        .result();
    assert_eq!(
        (&r["added"], &r["changed"], &r["removed"]),
        (&0.into(), &2.into(), &1.into())
    );
    assert_eq!(r["synced"], true);
    assert_eq!(a.names(PW), ["Keep", "Other"]);
}

#[test]
fn the_pin_refuses_a_different_certificate() {
    let server = TestServer::start(true);
    // The right pin works over TLS.
    let a = Device::new();
    a.init(&server.token("laptop"));
    a.add("Pinned", "pinned-password", &[]).ok();
    let r = a.run(&["--json", "sync"], pw(&[PW])).ok();
    assert_eq!(r.result()["outcome"], "up_to_date");

    // A pin for another certificate is refused.
    let b = Device::new();
    let wrong = server.token_with("phone", Some("ab".repeat(32)));
    let r = b.run(
        &["--json", "setup"],
        Input {
            stdin: &format!("{wrong}\n"),
            ..Input::default()
        },
    );
    assert_eq!(
        (r.code, r.error_code().as_str()),
        (6, "server.unreachable"),
        "{r:#?}"
    );
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("fingerprint"),
        "{r:#?}"
    );
    assert!(!b.data().join("local.json").exists());
}

#[test]
fn plain_http_to_a_non_loopback_host_is_refused() {
    let server = TestServer::start(false);
    let real = server.token("laptop");
    let token = real
        .split("token=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let a = Device::new();
    for url in [
        "http%3A%2F%2Fexample.com%3A8080",
        "http%3A%2F%2F192.168.1.2",
    ] {
        let text = format!("vault://setup?url={url}&token={token}");
        let r = a.run(
            &["--json", "setup"],
            Input {
                stdin: &format!("{text}\n"),
                ..Input::default()
            },
        );
        assert_eq!(r.code, 2, "{r:#?}");
        assert_eq!(r.error_code(), "input.server_url");
        assert!(
            !r.stdout.contains(token) && !r.stderr.contains(token),
            "no echo"
        );
    }
    // A server.json edited to such a URL is refused too.
    a.init(&real);
    let p = a.data().join("server.json");
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, text.replace("127.0.0.1", "example.com")).unwrap();
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_ne!(r.code, 0, "{r:#?}");
}

#[test]
fn the_agent_serves_the_key_and_syncs_after_a_write() {
    let server = TestServer::start(false);
    let a = Device::with_agent(true);
    if a.runtime.is_none() {
        eprintln!("skipped: no /dev/shm for the runtime directory");
        return;
    }
    let sk = a.init(&server.token("laptop"));
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["unlocked"], true, "init starts the agent: {st}");
    assert_eq!(st["review"], Value::Null, "status never asks for the key");

    // No master password while the agent runs.
    let r = a
        .run(
            &["--json", "add", "Agent item", "--username", "ned"],
            Input {
                stdin: "agent-item-pw\n",
                ..Input::default()
            },
        )
        .ok();
    assert_eq!(r.result()["synced"], false, "the agent syncs: {r:#?}");
    let b = Device::new();
    b.setup(&server.token("phone"), &sk).ok();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while b.names(PW).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent never synced"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert_eq!(b.names(PW), ["Agent item"]);

    // `key show` asks for the master password even while the agent runs.
    let r = a.run(&["--json", "key", "show"], Input::default());
    assert_ne!(r.code, 0, "{r:#?}");
    let r = a.run(&["--json", "lock"], Input::default()).ok();
    assert_eq!(r.result()["locked"], true);
    // Immediately after the lock, the agent is gone: status reads locked, and a command asks
    // for the master password; it never gets the key.
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["unlocked"], false);
    assert_eq!(a.names(PW), ["Agent item"]);
    a.run(&["lock"], Input::default()).ok();
    let r = a.run(&["--json", "unlock"], pw(&[PW])).ok();
    assert_eq!(r.result()["unlocked"], true);
    assert_eq!(a.names(PW), ["Agent item"]);
    a.run(&["lock"], Input::default()).ok();
}

#[test]
fn a_data_directory_open_to_others_is_refused() {
    let (_server, a, _, _) = one_device();
    std::fs::set_permissions(a.data(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = a.run(&["--json", "status"], Input::default());
    assert_eq!((r.code, r.error_code().as_str()), (1, "config.directory"));
    std::fs::set_permissions(a.data(), std::fs::Permissions::from_mode(0o700)).unwrap();
    a.run(&["--json", "status"], Input::default()).ok();
}

#[test]
fn completions_print_for_each_shell() {
    let d = Device::new();
    for shell in ["bash", "zsh", "fish"] {
        let r = d.run(&["completions", shell], Input::default()).ok();
        assert!(r.stdout.contains("vault"), "{shell}");
    }
}

/// Edits `item` on `d` with the editor script `editor`, with extra environment variables.
fn edit_with(d: &Device, item: &str, editor: &str, env: &[(&str, &str)]) -> Run {
    let mut all = vec![("VISUAL", editor)];
    all.extend_from_slice(env);
    d.run(
        &["--json", "edit", item],
        Input {
            passwords: &[PW],
            env: &all,
            ..Input::default()
        },
    )
}

#[test]
fn edit_reopens_after_an_error_and_keeps_note_lines_that_look_like_errors() {
    let (_server, a, _, _) = one_device();
    if a.runtime.is_none() {
        eprintln!("skipped: no /dev/shm for the editor");
        return;
    }
    a.add("Item", "item-password-1", &[]).ok();

    // The first round saves an invalid value; the second sees the error comment and fixes it.
    let runs = a.tmp.path().join("runs");
    let fix = a.script(
        "fix",
        &format!(
            r#"echo x >> "{runs}"
if grep -q '^# error: ' "$1"; then v=true; else v=1; fi
sed "s/^favourite = .*/favourite = $v/" "$1" > "$1.x"; cat "$1.x" > "$1"; rm "$1.x""#,
            runs = runs.display()
        ),
    );
    let r = edit_with(&a, "Item", &fix, &[]).ok();
    assert_eq!(r.result()["synced"], true);
    assert_eq!(std::fs::read_to_string(&runs).unwrap().lines().count(), 2);
    assert_eq!(a.show("Item", PW)["favourite"], true);

    // A note line that reads like an error comment is item text and is kept.
    let note = a.script(
        "note",
        r#"sed '/^notes = """$/a # error: keep me' "$1" > "$1.x"; cat "$1.x" > "$1"; rm "$1.x""#,
    );
    edit_with(&a, "Item", &note, &[]).ok();
    assert_eq!(a.show("Item", PW)["notes"], "# error: keep me\n");
    // A later edit of another key leaves the note alone.
    let user = a.editor("username", "someone");
    edit_with(&a, "Item", &user, &[]).ok();
    let item = a.show("Item", PW);
    assert_eq!(item["notes"], "# error: keep me\n");
    assert_eq!(item["login"]["username"], "someone");
}

#[test]
fn edit_applies_only_the_changed_keys_onto_a_change_made_meanwhile() {
    let (_server, a, _, _) = one_device();
    if a.runtime.is_none() {
        eprintln!("skipped: no /dev/shm for the editor");
        return;
    }
    a.add("Mail", "mail-password-0", &[]).ok();
    let pwfile = a.password_file();
    let vault = env!("CARGO_BIN_EXE_vault");

    // While the editor is open, another command moves the item.
    let edit = a.script(
        "concurrent",
        &format!(
            r#""{vault}" --offline --password-fd 9 mv Mail Moved 9<"{pwfile}" >/dev/null 2>&1
sed 's/^password = .*/password = "mail-password-1"/' "$1" > "$1.x"; cat "$1.x" > "$1"; rm "$1.x""#
        ),
    );
    edit_with(&a, "Mail", &edit, &[]).ok();
    let item = a.show("Mail", PW);
    assert_eq!(item["folder"], "Moved", "the move made meanwhile is kept");
    assert_eq!(password_of(&item), "mail-password-1");
    assert_eq!(history_of(&item), ["mail-password-0"]);

    // An item deleted while the editor is open is reported, and nothing is saved.
    let gone = a.script(
        "gone",
        &format!(
            r#""{vault}" --offline --password-fd 9 rm Mail 9<"{pwfile}" >/dev/null 2>&1
sed 's/^password = .*/password = "mail-password-2"/' "$1" > "$1.x"; cat "$1.x" > "$1"; rm "$1.x""#
        ),
    );
    let r = edit_with(&a, "Mail", &gone, &[]);
    assert_eq!(
        (r.code, r.error_code().as_str()),
        (3, "item.not_found"),
        "{r:#?}"
    );
    assert!(a.names(PW).is_empty());
}

#[test]
fn add_with_the_editor() {
    let (_server, a, _, _) = one_device();
    if a.runtime.is_none() {
        eprintln!("skipped: no /dev/shm for the editor");
        return;
    }
    let user = a.editor("username", "from-editor");
    let r = a
        .run(
            &["--json", "add", "Site", "-e"],
            Input {
                passwords: &[PW],
                stdin: "site-password-1\n",
                env: &[("VISUAL", &user)],
            },
        )
        .ok();
    let id = r.result()["id"].as_str().unwrap().to_owned();
    let item = a.show(&id, PW);
    assert_eq!(item["login"]["username"], "from-editor");
    assert_eq!(password_of(&item), "site-password-1");
}

#[test]
fn passwd_new_secret_key_end_to_end() {
    let (server, a, _, old_key) = one_device();
    let b = Device::new();
    b.setup(&server.token("phone"), &old_key).ok();
    a.add("Bank", "bank-password-1", &[]).ok();

    let (r, new_key) = a.with_kit(
        &["passwd", "--new-secret-key", "--keep-password"],
        &[PW],
        "",
    );
    assert_eq!(r.code, 0, "{r:#?}");
    assert_ne!(new_key, old_key);
    let shown = a.run(&["--json", "key", "show"], pw(&[PW])).ok().result();
    assert_eq!(shown["secret_key"], new_key.as_str());
    assert_eq!(a.names(PW), ["Bank"]);

    // B holds the old key: the stored key fails, and the new one from the kit opens the vault.
    let r = b
        .run(
            &["--json", "sync"],
            Input {
                passwords: &[PW, PW],
                stdin: &format!("{new_key}\n"),
                ..Input::default()
            },
        )
        .ok();
    assert_eq!(r.result()["outcome"], "adopted", "{r:#?}");
    let shown = b.run(&["--json", "key", "show"], pw(&[PW])).ok().result();
    assert_eq!(shown["secret_key"], new_key.as_str());
    assert_eq!(b.names(PW), ["Bank"]);
}

#[test]
fn a_refused_token_does_not_replace_an_earlier_stop() {
    let (server, a, setup, _) = one_device();
    a.add("One", "pw-one-111111", &[]).ok();
    let oldest = server.revisions(&setup).last().unwrap()["id"]
        .as_u64()
        .unwrap();
    server.overwrite(&setup, server.revision(&setup, oldest));
    let r = a.run(&["--json", "sync"], pw(&[PW]));
    assert_eq!(r.code, 5);
    server.revoke("laptop");
    let r = a.run(&["--json", "history"], Input::default());
    assert_eq!((r.code, r.error_code().as_str()), (7, "server.token"));
    let st = a.run(&["--json", "status"], Input::default()).ok().result();
    assert_eq!(st["stopped"]["reason"], "integrity");
}

#[test]
fn text_output_escapes_controls_and_bidi_characters() {
    let (_server, a, _, _) = one_device();
    let name = "evil\u{1b}[31m\u{202e}gnp.exe";
    a.add(name, "evil-password-1", &[]).ok();
    let r = a.run(&["ls"], pw(&[PW])).ok();
    assert!(
        !r.stdout.contains('\u{1b}') && !r.stdout.contains('\u{202e}'),
        "{r:#?}"
    );
    assert!(
        r.stdout.contains(r"evil\u{1b}[31m\u{202e}gnp.exe"),
        "{r:#?}"
    );
    // JSON is data: the name is exact.
    let names = a.names(PW);
    assert_eq!(names, [name]);
}

/// Adds an item of a type this client does not know straight to the local file, as another
/// client's newer version would, and returns its ID.
fn inject_unknown_item(d: &Device, secret_key: &str) -> String {
    struct Rng;
    impl vault_core::rng::Rng for Rng {
        fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
            getrandom::getrandom(dest).map_err(|_| vault_core::Error::Rng)
        }
    }
    let path = d.data().join("local.json");
    let mut state = vault_client::ClientState::from_json(&std::fs::read(&path).unwrap()).unwrap();
    let sk = vault_core::secret_key_text::decode(secret_key).unwrap();
    let u = vault_core::file::unlock(&state.file, PW, &sk).unwrap();
    let id = "77777777-0000-4000-8000-000000000000".to_owned();
    let item = format!(
        r#"{{"id":"{id}","type":"card","modified":1,"modified_by":"{}","number":"4111111111111111"}}"#,
        "ab".repeat(16)
    );
    let mut body = u.body.to_value();
    if let vault_core::json::Value::Object(m) = &mut body
        && let Some(vault_core::json::Value::Array(items)) = m.get_mut("items")
    {
        items.push(vault_core::json::parse(item.as_bytes()).unwrap());
    }
    let body = vault_core::body::Body::from_value(body).unwrap();
    state.file =
        vault_core::file::seal_file_with_rng(&mut Rng, &u.header, &u.vault_key, &body).unwrap();
    std::fs::write(&path, state.to_json()).unwrap();
    id
}

#[test]
fn an_unknown_item_type_shows_only_its_id_and_type_without_reveal() {
    let (_server, a, _, sk) = one_device();
    let id = inject_unknown_item(&a, &sk);
    let r = a
        .run(&["--json", "--offline", "show", &id[..8]], pw(&[PW]))
        .ok()
        .result();
    assert_eq!(r, serde_json::json!({"id": id, "type": "card"}));
    let r = a
        .run(
            &["--json", "--offline", "show", &id[..8], "--reveal"],
            pw(&[PW]),
        )
        .ok()
        .result();
    assert_eq!(r["number"], "4111111111111111");
    let r = a.run(&["--offline", "show", &id[..8]], pw(&[PW])).ok();
    assert_eq!(r.stdout, format!("id: {id}\ntype: card\n"));
    // `edit` refuses it, `rm` deletes it.
    let r = a.run(&["--json", "--offline", "edit", &id[..8]], pw(&[PW]));
    assert_eq!(r.error_code(), "input.unsupported_item");
    a.run(&["--json", "--offline", "rm", &id[..8]], pw(&[PW]))
        .ok();
}
