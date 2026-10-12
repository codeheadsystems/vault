//! Sync and recovery at the procedure level against the in-memory server, with cached vault keys
//! so that nothing runs Argon2id except the few prompts for credentials that cannot open.

mod common;

use common::*;
use vault_client::recover::recover;
use vault_client::setup::{repair_token, setup};
use vault_client::sync::{SyncOutcome, sync};
use vault_client::{
    Answer, ClientError, Confirmation, Precondition, Prompt, Purpose, Request, Response, StopReason,
};
use vault_core::body::Body;
use vault_core::clock::BUILD_TIME_MS;
use vault_core::file::{open_file, read_header};
use vault_core::header::MAX_GENERATION;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::{Error, IntegrityKind};

fn integrity(code: &str) -> ClientError {
    let k = [
        IntegrityKind::Truncated,
        IntegrityKind::Aead,
        IntegrityKind::VaultIdMismatch,
        IntegrityKind::GenerationRollback,
        IntegrityKind::GenerationFork,
        IntegrityKind::RetiredWrapNonce,
    ]
    .into_iter()
    .find(|k| k.code() == code)
    .unwrap_or_else(|| panic!("unmapped {code}"));
    ClientError::Core(Error::Integrity(k))
}

/// The vector client: the accepted file of `sync.json` as the local file, with its vault key.
fn vector_client(state: &serde_json::Value) -> Client {
    let cs = cases("sync.json");
    let accepted = case(&cs, "the accepted file itself");
    let vk = VaultKey::from_bytes(arr(accepted, "vault_key"));
    Client::new(vector_state(state, hex_of(accepted, "file")), vk, 0xaa)
}

#[test]
fn vector_remote_checks_at_procedure_level() {
    for c in cases("sync.json")
        .iter()
        .filter(|c| c["op"] == "check_remote")
    {
        let name = c["name"].as_str().unwrap();
        let mut server = Server::default();
        server.store(hex_of(c, "file"), "laptop");
        let mut client = vector_client(&c["state"]);
        let before = client.state.clone();
        let changed = c["wrap"] == "changed";
        let mode = if changed { background() } else { interactive() };
        let run = client.sync(&mut server, mode, T0, vec![]);
        let error = c["error"]
            .as_str()
            .or(c["open"].as_str().filter(|o| *o != "ok"));
        if let Some(code) = error {
            assert_eq!(run.err(), integrity(code), "{name}");
            let stopped = client.state.stopped.as_ref().expect(name);
            assert_eq!(
                (stopped.reason, stopped.code.as_str()),
                (StopReason::Integrity, code)
            );
            assert_eq!(client.state.file, before.file, "{name}: local file kept");
            assert_eq!(client.state.accepted, before.accepted, "{name}");
            assert_eq!(run.puts(), 0, "{name}");
        } else if changed {
            assert_eq!(run.err(), ClientError::CredentialsChanged, "{name}");
            assert_eq!(
                client.state.stopped.as_ref().unwrap().reason,
                StopReason::Credentials
            );
            assert!(run.prompts.is_empty(), "background never prompts");
        } else {
            let report = run.ok();
            let remote = read_header(&hex_of(c, "file")).unwrap();
            assert!(report.generation >= remote.generation, "{name}");
            assert!(client.state.stopped.is_none());
            if name == "the accepted file itself" {
                assert_eq!(report.outcome, SyncOutcome::UpToDate);
                assert_eq!(run.puts(), 0);
            }
        }
    }
}

#[test]
fn vector_setup_checks_at_procedure_level() {
    for c in cases("sync.json")
        .iter()
        .filter(|c| c["op"] == "check_setup")
    {
        let mut server = Server::default();
        server.store(hex_of(c, "file"), "laptop");
        let kit = (!c["kit_vault_id"].is_null()).then(|| arr::<16>(c, "kit_vault_id"));
        let mut answers = vec![
            Answer::SecretKey(SecretKey::from_bytes([1; 16])),
            Answer::VaultId(kit),
        ];
        let ok = c["result"] == "ok";
        if ok {
            answers.push(Answer::Declined);
        }
        let run = drive(
            setup(vault_client::SecretKeyStore::File, TestRng(1)),
            &mut server,
            TOKEN,
            T0,
            answers,
        );
        if ok {
            assert_eq!(
                run.err(),
                ClientError::Cancelled,
                "reached the password prompt"
            );
            assert!(matches!(
                run.prompts.last(),
                Some(Prompt::MasterPassword { .. })
            ));
        } else {
            assert_eq!(run.err(), integrity(c["result"].as_str().unwrap()));
            assert_eq!(run.prompts, vec![Prompt::SecretKey, Prompt::KitVaultId]);
        }
        assert!(run.finished.state.is_none());
    }
}

#[test]
fn vector_adopt_or_push_at_procedure_level() {
    let cs = cases("sync.json");
    let accepted = case(&cs, "the accepted file itself");
    let header = read_header(&hex_of(accepted, "file")).unwrap();
    let vk = VaultKey::from_bytes(arr(accepted, "vault_key"));
    let seal = |generation: u64, body: &Body, nonce: u8| {
        vault_core::file::seal_file(&header.with_generation(generation), &vk, &[nonce; 24], body)
            .unwrap()
    };
    for c in cs.iter().filter(|c| c["op"] == "adopt") {
        let name = c["name"].as_str().unwrap();
        let body = |k: &str| Body::from_json(&serde_json::to_vec(&c[k]).unwrap()).unwrap();
        let generation = c["remote_generation"].as_u64().unwrap();
        let mut server = Server::default();
        server.store(seal(generation, &body("remote"), 1), "laptop");
        let mut state = vector_state(&accepted["state"], seal(generation - 2, &body("local"), 2));
        state.accepted.as_mut().unwrap().generation = generation - 1;
        let mut client = Client::new(state, vk.clone_secret(), 0xaa);
        let run = client.sync(
            &mut server,
            interactive(),
            c["now"].as_u64().unwrap(),
            vec![],
        );
        let report = run.ok();
        match c["result"]["action"].as_str().unwrap() {
            "adopt" => {
                assert_eq!(report.outcome, SyncOutcome::Adopted, "{name}");
                assert_eq!(run.puts(), 0, "{name}");
                assert_eq!(client.state.file, server.current_file());
            }
            "push" => {
                let expected = c["result"]["generation"].as_u64().unwrap();
                assert_eq!(
                    (report.outcome, report.generation),
                    (SyncOutcome::Pushed, expected),
                    "{name}"
                );
                assert_eq!(
                    read_header(&server.current_file()).unwrap().generation,
                    expected
                );
                assert_eq!(client.state.file, server.current_file());
            }
            a => panic!("{a}"),
        }
        assert!(!client.state.unpushed());
    }
}

#[test]
fn vector_not_found_at_procedure_level() {
    let cs = cases("sync.json");
    for c in cs.iter().filter(|c| c["op"] == "not_found") {
        let name = c["name"].as_str().unwrap();
        let mut server = Server::default();
        if c["state"].is_null() {
            let run = drive(
                setup(vault_client::SecretKeyStore::Keyring, TestRng(2)),
                &mut server,
                TOKEN,
                T0,
                vec![],
            );
            assert_eq!(run.err(), ClientError::NoVault, "{name}");
            assert!(run.prompts.is_empty() && run.puts() == 0);
            continue;
        }
        let mut client = vector_client(&c["state"]);
        let run = client.sync(&mut server, background(), T0, vec![]);
        let expected = c["result"]["generation"].as_u64().unwrap();
        assert_eq!(run.ok().generation, expected, "{name}");
        assert!(matches!(
            run.requests.last(),
            Some(Request::PutVault {
                condition: Precondition::IfNoneMatch,
                ..
            })
        ));
        assert_eq!(
            read_header(&server.current_file()).unwrap().generation,
            expected
        );
        assert_eq!(client.state.accepted.as_ref().unwrap().generation, expected);
    }
}

#[test]
fn vector_recovery_at_procedure_level() {
    let cs = cases("sync.json");
    for c in cs.iter().filter(|c| c["op"] == "recovery") {
        let name = c["name"].as_str().unwrap();
        let mut server = Server::default();
        let revisions = c["revisions"].as_array().unwrap();
        server.next_id = revisions[0]["id"].as_u64().unwrap();
        for r in revisions {
            assert_eq!(
                server.store(hex_of(r, "file"), "laptop"),
                r["id"].as_u64().unwrap()
            );
        }
        let mut client = vector_client(&c["state"]);
        client.state.stopped = Some(vault_client::Stopped {
            reason: StopReason::Integrity,
            code: "integrity.aead".into(),
            at: T0,
        });
        let started = client.state.clone();
        let unknown = c["plan"] == "credential_change" || c["past_unknown_wraps"] == true;
        let mut answers = vec![];
        if unknown {
            // The credential change flow fails: neither the password with the stored secret
            // key nor the second prompt opens the unknown wraps.
            answers.push(pw("not the password"));
            answers.push(Answer::Declined);
            answers.push(Answer::Confirmed(c["past_unknown_wraps"] == true));
        }
        client.sk = Some(SecretKey::from_bytes([7; 16]));
        let run = drive(
            recover(started.clone(), client.keys(), TestRng(3)),
            &mut server,
            TOKEN,
            T0,
            answers,
        );
        if unknown {
            assert_eq!(
                run.prompts,
                vec![
                    Prompt::MasterPassword {
                        purpose: Purpose::Recovery,
                        failed: 0
                    },
                    Prompt::MasterPasswordAndSecretKey {
                        purpose: Purpose::Recovery
                    },
                    Prompt::Confirm(Confirmation::NoCredentialChange),
                ],
                "{name}"
            );
        }
        if c["plan"] == "credential_change" {
            assert_eq!(run.err(), ClientError::Cancelled, "{name}");
            assert_eq!(run.puts(), 0);
            continue;
        }
        let report = run.ok();
        assert_eq!(report.revision, c["chosen"].as_u64(), "{name}");
        assert_eq!(
            report.generation,
            c["push_generation"].as_u64().unwrap(),
            "{name}"
        );
        client.commit(&started, &run.finished, T0);
        assert!(client.state.stopped.is_none(), "{name}");
        assert_eq!(client.state.file, server.current_file());
        if unknown {
            let unknown_wrap = read_header(&hex_of(&revisions[1], "file"))
                .unwrap()
                .wrap_nonce;
            assert!(
                client.state.refused.contains(&unknown_wrap),
                "{name}: remembered"
            );
        }
        // The next sync accepts what recovery pushed.
        let again = client.sync(&mut server, background(), T0, vec![]);
        assert_eq!(again.ok().outcome, SyncOutcome::UpToDate, "{name}");
    }
}

#[test]
fn vector_clock_refusals_at_procedure_level() {
    let cs = cases("sync.json");
    let accepted = case(&cs, "the accepted file itself");
    for c in cs.iter().filter(|c| c["op"] == "clock") {
        let name = c["name"].as_str().unwrap();
        if c["build_time"].as_u64() != Some(BUILD_TIME_MS) {
            continue;
        }
        let mut server = Server::default();
        server.store(hex_of(accepted, "file"), "laptop");
        server.date = c["server_date"].as_u64();
        let mut client = vector_client(&accepted["state"]);
        let before = client.state.clone();
        let now = c["now"].as_u64().unwrap();
        let run = client.sync(&mut server, background(), now, vec![]);
        match c["result"].as_str().unwrap() {
            "ok" => assert_eq!(run.ok().outcome, SyncOutcome::UpToDate, "{name}"),
            code => {
                assert_eq!(run.err().code(), code, "{name}");
                assert!(run.finished.state.is_none(), "{name}: nothing to commit");
                assert_eq!(client.state, before);
                if code == "clock_before_build_time" {
                    assert!(run.requests.is_empty(), "{name}: refused before the pull");
                }
            }
        }
    }
}

#[test]
fn vector_retry_limits_at_procedure_level() {
    let cs = cases("sync.json");
    let accepted = case(&cs, "the accepted file itself");
    for c in cs.iter().filter(|c| c["op"] == "retry") {
        let name = c["name"].as_str().unwrap();
        let conditions: Vec<String> = c["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let remote = hex_of(accepted, "file");
        let mut server = Server::default();
        let mut gets = conditions.clone().into_iter();
        server.hook = Some(Box::new(move |s: &mut Server, r: &Request| match r {
            Request::GetVault => Some(Some(match gets.next().as_deref() {
                Some("if_none_match") => s.response(404, vec![]),
                _ => s.response(200, remote.clone()),
            })),
            Request::PutVault { .. } => Some(Some(s.response(412, vec![]))),
            _ => None,
        }));
        let mut client = vector_client(&accepted["state"]);
        client.edit(|b, rng, dev| {
            add_login(b, rng, dev, "unpushed", "pw", T0);
        });
        let run = client.sync(&mut server, background(), T0, vec![]);
        assert_eq!(run.err(), ClientError::Conflicts, "{name}");
        let put_conditions: Vec<&str> = run
            .requests
            .iter()
            .filter_map(|r| match r {
                Request::PutVault {
                    condition: Precondition::IfMatch(_),
                    ..
                } => Some("if_match"),
                Request::PutVault {
                    condition: Precondition::IfNoneMatch,
                    ..
                } => Some("if_none_match"),
                _ => None,
            })
            .collect();
        assert_eq!(put_conditions, conditions, "{name}: gave up after the last");
        assert!(
            client.state.unpushed(),
            "{name}: the local file is unaffected"
        );
        assert!(
            client.state.stopped.is_none(),
            "{name}: the next sync starts afresh"
        );
    }
}

/// Two clients on one vault, the first having pushed generation 1.
fn two_clients(server: &mut Server) -> (Client, Client, Fixture) {
    let fx = Fixture::new(9);
    let file = fx.file(1, &Body::default(), 1);
    let mut a = Client::new(fx.state(file.clone()), fx.key(), 0xa1);
    a.sync(server, background(), T0, vec![]).ok();
    let mut b = Client::new(fx.state(file), fx.key(), 0xb2);
    b.token = "laptop".into();
    b.sync(server, background(), T0, vec![]).ok();
    (a, b, fx)
}

#[test]
fn concurrent_pushes_merge_after_412() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "from a", "pa", T0 + 1);
    });
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "from b", "pb", T0 + 2);
    });
    // B pushes between A's pull and A's push.
    let b = std::rc::Rc::new(std::cell::RefCell::new(b));
    let other = b.clone();
    let mut pushed = false;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        if !pushed && matches!(r, Request::PutVault { .. }) {
            pushed = true;
            let run = other.borrow_mut().sync(s, background(), T0 + 3, vec![]);
            assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
        }
        None
    }));
    let run = a.sync(&mut server, background(), T0 + 3, vec![]);
    server.hook = None;
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    let kinds: Vec<bool> = run
        .requests
        .iter()
        .map(|r| matches!(r, Request::PutVault { .. }))
        .collect();
    assert_eq!(
        kinds,
        vec![false, true, false, true],
        "pull, 412, pull, push"
    );
    let mut b = std::rc::Rc::try_unwrap(b).ok().unwrap().into_inner();
    b.sync(&mut server, background(), T0 + 4, vec![]).ok();
    let names = |c: &Client| {
        let mut n: Vec<String> = c
            .body()
            .items
            .iter()
            .map(|i| i.fields().unwrap().name.clone())
            .collect();
        n.sort();
        n
    };
    assert_eq!(names(&a), vec!["from a", "from b"]);
    assert_eq!(a.state.file, b.state.file);
    assert_eq!(a.state.file, server.current_file());
}

#[test]
fn token_thief_garbage_stops_sync_until_recover() {
    let mut server = Server::default();
    let (mut a, mut b, fx) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "mail", "secret-1", T0);
    });
    a.sync(&mut server, background(), T0, vec![]).ok();
    // The thief pushes a well-formed header with a garbage body at the top generation.
    let mut garbage = fx.file(MAX_GENERATION, &Body::default(), 7);
    let last = garbage.len() - 1;
    garbage[last] ^= 1;
    server.store(garbage, "thief");

    let run = b.sync(&mut server, background(), T0 + 1, vec![]);
    assert_eq!(
        run.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::Aead))
    );
    let stopped = b.state.stopped.clone().unwrap();
    assert_eq!(
        (stopped.reason, stopped.code.as_str()),
        (StopReason::Integrity, "integrity.aead")
    );
    // Stopped: neither background nor interactive syncs contact the server.
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "offline edit", "secret-2", T0 + 2);
    });
    for mode in [background(), interactive()] {
        let run = b.sync(&mut server, mode, T0 + 2, vec![]);
        assert_eq!(run.err(), ClientError::Stopped(StopReason::Integrity));
        assert!(run.requests.is_empty());
    }

    let started = b.state.clone();
    let run = drive(
        recover(started.clone(), b.keys(), TestRng(9)),
        &mut server,
        "laptop",
        T0 + 3,
        vec![],
    );
    let report = run.ok();
    assert_eq!(
        report.revision,
        Some(2),
        "the honest revision with the item"
    );
    assert_eq!(report.generation, 3);
    assert!(
        run.prompts.is_empty(),
        "the cached vault key opens everything"
    );
    b.commit(&started, &run.finished, T0 + 3);
    assert!(b.state.stopped.is_none());
    let mut names: Vec<String> = b
        .body()
        .items
        .iter()
        .map(|i| i.fields().unwrap().name.clone())
        .collect();
    names.sort();
    assert_eq!(names, vec!["mail", "offline edit"]);

    // A never saw the garbage and converges on the recovered file.
    assert_eq!(
        a.sync(&mut server, background(), T0 + 4, vec![])
            .ok()
            .outcome,
        SyncOutcome::Adopted
    );
    assert_eq!(a.state.file, b.state.file);
}

#[test]
fn token_thief_rollback_stops_sync_until_recover() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    let old = server.current_file();
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "new", "pw-new", T0 + 1);
    });
    a.sync(&mut server, background(), T0 + 1, vec![]).ok();
    b.sync(&mut server, background(), T0 + 1, vec![]).ok();
    assert_eq!(b.state.accepted.as_ref().unwrap().generation, 2);
    // The thief re-serves the old revision as the current one.
    server.store(old, "thief");
    let run = b.sync(&mut server, background(), T0 + 2, vec![]);
    assert_eq!(
        run.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::GenerationRollback))
    );
    assert_eq!(
        b.state.stopped.as_ref().unwrap().reason,
        StopReason::Integrity
    );

    let started = b.state.clone();
    let run = drive(
        recover(started.clone(), b.keys(), TestRng(9)),
        &mut server,
        "laptop",
        T0 + 3,
        vec![],
    );
    let report = run.ok();
    assert_eq!(
        report.revision,
        Some(2),
        "the rolled-back revision is below the accepted one"
    );
    assert_eq!(report.generation, 3);
    b.commit(&started, &run.finished, T0 + 3);
    assert_eq!(b.body().items.len(), 1);
    assert_eq!(
        a.sync(&mut server, background(), T0 + 4, vec![])
            .ok()
            .outcome,
        SyncOutcome::Adopted
    );
}

#[test]
fn a_401_stops_sync_until_the_token_is_repaired() {
    let mut server = Server::default();
    let (_, mut b, _) = two_clients(&mut server);
    server.tokens.retain(|t| t != "laptop");
    let run = b.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::Token);
    assert_eq!(b.state.stopped.as_ref().unwrap().code, "server.token");
    let run = b.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(run.err(), ClientError::Stopped(StopReason::Token));
    assert!(run.requests.is_empty());

    // Setup with a new token on this device.
    server.tokens.push("laptop-2".into());
    b.token = "laptop-2".into();
    let started = b.state.clone();
    let run = drive(
        repair_token(started.clone(), TestRng(1)),
        &mut server,
        "laptop-2",
        T0,
        vec![],
    );
    run.ok();
    b.commit(&started, &run.finished, T0);
    assert!(b.state.stopped.is_none());
    assert_eq!(
        b.sync(&mut server, background(), T0, vec![]).ok().outcome,
        SyncOutcome::UpToDate
    );

    // A server holding another vault is refused.
    let other = Fixture::new(3);
    server.store(other.file(1, &Body::default(), 1), "laptop-2");
    let run = drive(
        repair_token(b.state.clone(), TestRng(1)),
        &mut server,
        "laptop-2",
        T0,
        vec![],
    );
    assert_eq!(
        run.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::VaultIdMismatch))
    );
}

#[test]
fn background_sync_never_prompts() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "x", "y", T0);
    });
    a.sync(&mut server, background(), T0, vec![]).ok();
    // Without the vault key.
    b.vk = None;
    let run = b.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::Locked);
    assert!(
        b.state.stopped.is_none(),
        "a locked vault is not a sync problem"
    );
    // A pending secret key needs a prompt.
    b.state.pending_secret_key = true;
    let run = b.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::PendingSecretKey);
    assert!(run.requests.is_empty());
    assert_eq!(
        b.state.stopped.as_ref().unwrap().reason,
        StopReason::Credentials
    );
}

#[test]
fn a_server_that_lost_its_data_gets_the_local_file_back() {
    let mut server = Server::default();
    let (mut a, _, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "keep", "pw", T0);
    });
    a.sync(&mut server, background(), T0, vec![]).ok();
    let generation = a.state.accepted.as_ref().unwrap().generation;
    server.revisions.clear();
    let run = a.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.ok().generation, generation + 1);
    assert_eq!(server.current_file(), a.state.file);
    assert_eq!(
        open_file(&server.current_file(), a.vk.as_ref().unwrap())
            .unwrap()
            .1
            .items
            .len(),
        1
    );
}

#[test]
fn local_edits_during_a_sync_stay_local_and_unpushed() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "remote", "r", T0);
    });
    b.sync(&mut server, background(), T0, vec![]).ok();

    let started = a.state.clone();
    let m = sync(started.clone(), a.keys(), background(), TestRng(4));
    let run = drive(m, &mut server, TOKEN, T0 + 1, vec![]);
    assert_eq!(run.ok().outcome, SyncOutcome::Adopted);
    // A command edits the file while the sync runs, before its commit.
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "during sync", "d", T0 + 1);
    });
    let c = a.commit(&started, &run.finished, T0 + 1);
    assert!(c.merged_local_changes);
    assert!(a.state.unpushed());
    assert_eq!(
        a.state.accepted.as_ref().unwrap().generation,
        2,
        "the sync's result"
    );
    assert_eq!(a.body().items.len(), 2);

    let run = a.sync(&mut server, background(), T0 + 2, vec![]);
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    assert!(!a.state.unpushed());
    assert_eq!(
        open_file(&server.current_file(), a.vk.as_ref().unwrap())
            .unwrap()
            .1
            .items
            .len(),
        2
    );
}

#[test]
fn a_commit_after_another_sync_committed_is_superseded() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "remote", "r", T0);
    });
    b.sync(&mut server, background(), T0, vec![]).ok();
    let started = a.state.clone();
    let first = drive(
        sync(started.clone(), a.keys(), background(), TestRng(1)),
        &mut server,
        TOKEN,
        T0,
        vec![],
    );
    let second = drive(
        sync(started.clone(), a.keys(), background(), TestRng(2)),
        &mut server,
        TOKEN,
        T0,
        vec![],
    );
    a.commit(&started, &first.finished, T0);
    let mut rng = TestRng(3);
    assert_eq!(
        second
            .finished
            .commit(&started, &a.state, true, T0, &mut rng)
            .err(),
        Some(ClientError::Superseded)
    );
}

#[test]
fn a_background_sync_records_dropped_items() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    // B deletes an item and purges the tombstone 181 days later, raising the horizon.
    let day = 86_400_000;
    b.edit(|body, rng, dev| {
        let id = add_login(body, rng, dev, "gone", "g", T0);
        vault_core::edit::delete_item(body, &id, T0 + 1, dev).unwrap();
    });
    let later = T0 + 181 * day;
    server.date = Some(later);
    b.sync(&mut server, background(), later, vec![]).ok();
    // A, offline since before the horizon, holds a local item older than it.
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "stale", "s", T0);
    });
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "fresh", "f", later);
        let purge = vault_core::merge::merge(&Body::default(), body, later).body;
        *body = purge;
    });
    b.sync(&mut server, background(), later, vec![]).ok();
    assert!(
        open_file(&server.current_file(), b.vk.as_ref().unwrap())
            .unwrap()
            .1
            .horizon
            > T0
    );
    let run = a.sync(&mut server, background(), later, vec![]);
    assert_eq!(run.ok().expired, vec!["stale".to_owned()]);
    assert_eq!(a.state.dropped, vec!["stale".to_owned()]);
    let run = a.sync(&mut server, interactive(), later, vec![]);
    assert!(run.ok().expired.is_empty());
}

#[test]
fn unexpected_status_and_unreachable_change_nothing() {
    let mut server = Server::default();
    let (mut a, _, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "unpushed", "u", T0);
    });
    let before = a.state.clone();
    // On the pull, then on the push.
    for put_only in [false, true] {
        server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
            (!put_only || matches!(r, Request::PutVault { .. }))
                .then(|| Some(s.response(503, vec![])))
        }));
        let run = a.sync(&mut server, background(), T0, vec![]);
        assert_eq!(run.err(), ClientError::Status(503));
        assert_eq!(run.puts(), usize::from(put_only));
        server.hook = Some(Box::new(move |_: &mut Server, r: &Request| {
            (!put_only || matches!(r, Request::PutVault { .. })).then_some(None)
        }));
        let run = a.sync(&mut server, background(), T0, vec![]);
        assert_eq!(run.err(), ClientError::Unreachable);
        assert_eq!(a.state, before);
    }
    assert_eq!(server.revisions.len(), 1, "nothing stored");
}

#[test]
fn a_push_whose_response_was_lost_is_adopted_by_the_next_sync() {
    let mut server = Server::default();
    let (mut a, _, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "pushed", "p", T0);
    });
    let before = a.state.clone();
    let mut lost = true;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| match r {
        Request::PutVault { file, .. } if lost => {
            lost = false;
            s.store(file.clone(), TOKEN);
            Some(None)
        }
        _ => None,
    }));
    let run = a.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::Unreachable);
    assert_eq!(a.state, before, "nothing committed");
    let run = a.sync(&mut server, background(), T0 + 1, vec![]);
    assert_eq!(run.ok().outcome, SyncOutcome::Adopted, "its own file");
    assert_eq!(run.puts(), 0);
    assert!(!a.state.unpushed());
    assert_eq!(a.state.file, server.current_file());
}

#[test]
fn recovery_gives_up_after_five_412_responses() {
    let mut server = Server::default();
    let (_, b, _) = two_clients(&mut server);
    server.hook = Some(Box::new(|s: &mut Server, r: &Request| {
        matches!(r, Request::PutVault { .. }).then(|| Some(s.response(412, vec![])))
    }));
    let started = b.state.clone();
    let run = drive(
        recover(started, b.keys(), TestRng(2)),
        &mut server,
        "laptop",
        T0,
        vec![],
    );
    assert_eq!(run.err(), ClientError::Conflicts);
    assert_eq!(run.puts(), 5);
    let lists = run
        .requests
        .iter()
        .filter(|r| matches!(r, Request::ListRevisions))
        .count();
    assert_eq!(lists, 5, "each round lists the revisions again");
}

/// A runs a sync to `Done` and a command then edits A's file before the commit.
fn commit_after_edit(
    server: &mut Server,
    a: &mut Client,
    edit: impl FnOnce(&mut Body, &mut TestRng, &[u8; 16]),
) -> (
    vault_client::commit::Commit,
    Run<vault_client::sync::SyncReport>,
) {
    let started = a.state.clone();
    let run = drive(
        sync(started.clone(), a.keys(), background(), TestRng(6)),
        server,
        TOKEN,
        T0 + 1,
        vec![],
    );
    a.edit(edit);
    let c = a.commit_as(&started, &run.finished, true, T0 + 1);
    (c, run)
}

#[test]
fn commit_rule_branches() {
    // The result pushed: the concurrent edit stays local and unpushed.
    let mut server = Server::default();
    let (mut a, _, _) = two_clients(&mut server);
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "pushed", "p", T0);
    });
    let (c, run) = commit_after_edit(&mut server, &mut a, |body, rng, dev| {
        add_login(body, rng, dev, "concurrent", "c", T0 + 1);
    });
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    assert!(c.merged_local_changes);
    assert!(a.state.unpushed());
    assert_eq!(a.state.accepted.as_ref().unwrap().generation, 2);
    assert_eq!(a.body().items.len(), 2);

    // Up to date: the result keeps the file it started from, so the edited file stands.
    let mut server = Server::default();
    let (mut a, _, _) = two_clients(&mut server);
    let (c, run) = commit_after_edit(&mut server, &mut a, |body, rng, dev| {
        add_login(body, rng, dev, "concurrent", "c", T0 + 1);
    });
    assert_eq!(run.ok().outcome, SyncOutcome::UpToDate);
    assert!(!c.merged_local_changes);
    assert!(a.state.unpushed());
    assert_eq!(a.body().items.len(), 1);
    assert_eq!(a.state.last_sync, Some(T0 + 1));

    // The file changed on disk without new content (a re-seal): the merge equals the result.
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "remote", "r", T0);
    });
    b.sync(&mut server, background(), T0, vec![]).ok();
    let (c, run) = commit_after_edit(&mut server, &mut a, |_, _, _| {});
    assert_eq!(run.ok().outcome, SyncOutcome::Adopted);
    assert!(!c.merged_local_changes);
    assert_eq!(a.state.file, server.current_file());
    assert!(!a.state.unpushed());
}

#[test]
fn commit_refuses_a_clock_before_the_build_time() {
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    b.edit(|body, rng, dev| {
        add_login(body, rng, dev, "remote", "r", T0);
    });
    b.sync(&mut server, background(), T0, vec![]).ok();
    let started = a.state.clone();
    let run = drive(
        sync(started.clone(), a.keys(), background(), TestRng(6)),
        &mut server,
        TOKEN,
        T0,
        vec![],
    );
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "concurrent", "c", T0);
    });
    let mut rng = TestRng(1);
    assert_eq!(
        run.finished
            .commit(&started, &a.state, true, 0, &mut rng)
            .err(),
        Some(ClientError::Core(Error::ClockBeforeBuildTime))
    );
}

#[test]
fn commit_merges_dropped_refused_and_stopped_three_ways() {
    let fx = Fixture::new(2);
    let started = {
        let mut s = fx.state(fx.file(1, &Body::default(), 1));
        s.refused = vec![[1; 24], [2; 24]];
        s.dropped = vec!["old".into()];
        s
    };
    let mut on_disk = started.clone();
    on_disk.refused = vec![[1; 24], [3; 24]];
    on_disk.dropped = vec![];
    on_disk.stopped = Some(vault_client::Stopped {
        reason: StopReason::Token,
        code: "server.token".into(),
        at: T0,
    });
    let mut result = started.clone();
    result.refused = vec![[2; 24], [4; 24]];
    result.dropped = vec!["old".into(), "new".into()];
    result.last_sync = Some(T0);
    let mut rng = TestRng(1);
    let keys = vault_client::commit::CommitKeys::default();
    let c = vault_client::commit::commit(&started, &on_disk, &result, keys, true, T0, &mut rng)
        .unwrap();
    let out = c.state.unwrap();
    assert_eq!(
        out.refused,
        vec![[3; 24], [4; 24]],
        "removed by the run: 1; added: 4; on disk: 3"
    );
    assert_eq!(
        out.dropped,
        vec!["new".to_owned()],
        "the list cleared on disk stays cleared"
    );
    assert_eq!(
        out.stopped, on_disk.stopped,
        "the run did not change stopped"
    );
    assert_eq!(out.last_sync, Some(T0));
    // A run that changed stopped wins.
    result.stopped = None;
    let mut started2 = started.clone();
    started2.stopped = on_disk.stopped.clone();
    let c = vault_client::commit::commit(&started2, &on_disk, &result, keys, true, T0, &mut rng)
        .unwrap();
    assert!(c.state.unwrap().stopped.is_none());
}

#[test]
fn a_background_commit_records_items_its_merge_drops() {
    let day = 86_400_000;
    let later = T0 + 181 * day;
    let mut server = Server::default();
    let (mut a, mut b, _) = two_clients(&mut server);
    b.edit(|body, rng, dev| {
        let id = add_login(body, rng, dev, "gone", "g", T0);
        vault_core::edit::delete_item(body, &id, T0 + 1, dev).unwrap();
    });
    server.date = Some(later);
    b.sync(&mut server, background(), later, vec![]).ok();
    b.edit(|body, _, _| *body = vault_core::merge::merge(&Body::default(), body, later).body);
    b.sync(&mut server, background(), later, vec![]).ok();
    let started = a.state.clone();
    let run = drive(
        sync(started.clone(), a.keys(), background(), TestRng(6)),
        &mut server,
        TOKEN,
        later,
        vec![],
    );
    run.ok();
    // A command adds an item stamped before the new horizon while the sync runs.
    a.edit(|body, rng, dev| {
        add_login(body, rng, dev, "stale", "s", T0);
    });
    let c = a.commit_as(&started, &run.finished, true, later);
    assert_eq!(c.expired, vec!["stale".to_owned()]);
    assert_eq!(a.state.dropped, vec!["stale".to_owned()]);
}

#[test]
fn stepping_a_finished_machine_reports_unexpected_input() {
    let mut server = Server::default();
    let (a, _, _) = two_clients(&mut server);
    let mut m = sync(a.state.clone(), a.keys(), background(), TestRng(1));
    assert!(matches!(
        m.start(T0),
        vault_client::Step::Request(Request::GetVault)
    ));
    // An answer where a response is expected.
    match m.step(vault_client::Input::Saved, T0) {
        vault_client::Step::Done(f) => {
            assert_eq!(f.result.err(), Some(ClientError::UnexpectedInput))
        }
        _ => panic!("expected the end"),
    }
    match m.step(
        vault_client::Input::Response(Response {
            status: 200,
            body: vec![],
            date: None,
        }),
        T0,
    ) {
        vault_client::Step::Done(f) => {
            assert_eq!(f.result.err(), Some(ClientError::UnexpectedInput))
        }
        _ => panic!("expected the end"),
    }
}
