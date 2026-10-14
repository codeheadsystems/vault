//! Procedures that unlock with typed credentials: init, setup, unlock, credential changes here
//! and on another device, pending secret keys, recovery into a credential change, and restore.
//! They use the test KDF parameters, so this target needs the `insecure-test-kdf` feature.

mod common;

use common::*;
use vault_client::passwd::{PasswdChange, PasswdOptions, PasswdReport, passwd};
use vault_client::recover::recover;
use vault_client::restore::{RestoreScope, RestoreSummary, fetch_revision, restore};
use vault_client::setup::{init, setup};
use vault_client::sync::{Mode, SyncOutcome};
use vault_client::unlock::unlock;
use vault_client::{
    Answer, ClientError, Confirmation, Prompt, Purpose, Request, SecretKeyStore, StopReason,
};
use vault_core::body::Body;
use vault_core::credentials::PendingKeyOutcome;
use vault_core::file::{open_file, read_header, unlock as core_unlock};
use vault_core::header::{Header, MAX_GENERATION};
use vault_core::kdf::TEST;
use vault_core::secret::{Kek, SecretKey, VaultKey};
use vault_core::sync::{Accepted, file_hash};
use vault_core::{Error, IntegrityKind};

const PW: &str = "correct horse battery staple";
const PW2: &str = "a brand new passphrase";

fn opts(change: PasswdChange) -> PasswdOptions {
    PasswdOptions {
        change,
        kdf: TEST,
        test_kdf: true,
    }
}

fn pw_sk(p: &str, sk: &SecretKey) -> Answer {
    Answer::PasswordAndSecretKey(zeroize::Zeroizing::new(p.to_owned()), sk.clone_secret())
}

fn unlock_prompt(failed: u32) -> Prompt {
    Prompt::MasterPassword {
        purpose: Purpose::Unlock,
        failed,
    }
}

fn changed_prompt() -> Prompt {
    Prompt::MasterPassword {
        purpose: Purpose::CredentialsChanged,
        failed: 0,
    }
}

/// `vault init` on an empty server, committed.
fn init_client(server: &mut Server, seed: u64) -> Client {
    let mut saved = None;
    let run = drive_with(
        init(TEST, true, SecretKeyStore::Keyring, TestRng(seed)),
        server,
        TOKEN,
        T0,
        vec![pw(PW)],
        &mut |s| saved = Some((s.state.clone(), s.secret_key.key().clone_secret())),
    );
    run.ok();
    let (state, sk) = saved.unwrap();
    let mut c = Client::new(
        state.clone(),
        run.finished.vault_key.as_ref().unwrap().clone_secret(),
        0xa1,
    );
    c.sk = Some(sk);
    c.commit(&state, &run.finished, T0);
    c
}

/// `vault setup` with the secret key and the master password, committed.
fn setup_client(server: &mut Server, sk: &SecretKey, token: &str, device: u8) -> Client {
    let run = drive(
        setup(SecretKeyStore::File, TestRng(device as u64)),
        server,
        token,
        T0,
        vec![
            Answer::SecretKey(sk.clone_secret()),
            Answer::VaultId(None),
            pw(PW),
        ],
    );
    run.ok();
    let state = run.state().clone();
    let mut c = Client::new(
        state,
        run.finished.vault_key.as_ref().unwrap().clone_secret(),
        device,
    );
    c.sk = Some(sk.clone_secret());
    c.token = token.into();
    c
}

fn two_devices(server: &mut Server) -> (Client, Client) {
    let a = init_client(server, 1);
    let b = setup_client(server, a.sk.as_ref().unwrap(), "laptop", 0xb2);
    (a, b)
}

fn run_passwd(
    c: &mut Client,
    server: &mut Server,
    change: PasswdChange,
    answers: Vec<Answer>,
) -> Run<PasswdReport> {
    c.run(|s, k, r| passwd(s, k, opts(change), r), server, T0, answers)
}

fn names(c: &Client) -> Vec<String> {
    let mut n: Vec<String> = c
        .body()
        .items
        .iter()
        .map(|i| i.fields().unwrap().name.clone())
        .collect();
    n.sort();
    n
}

fn add(c: &mut Client, name: &str, password: &str) -> String {
    let mut id = String::new();
    c.edit(|b, rng, dev| id = add_login(b, rng, dev, name, password, T0));
    id
}

#[test]
fn vector_vault_init() {
    let c = cases("credentials.json");
    let v = case(&c, "vault init");
    let draws: Vec<Vec<u8>> = v["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| hex::decode(d.as_str().unwrap()).unwrap())
        .collect();
    let password = String::from_utf8(hex_of(v, "password_hex")).unwrap();
    let mut server = Server::default();
    let run = drive(
        init(TEST, true, SecretKeyStore::Keyring, Fixed::new(&draws)),
        &mut server,
        TOKEN,
        T0,
        vec![pw(&password)],
    );
    assert_eq!(
        run.ok().vault_id,
        read_header(&hex_of(v, "file")).unwrap().vault_id
    );
    assert_eq!(
        run.prompts,
        vec![Prompt::NewMasterPassword { rejected: None }]
    );
    assert_eq!(run.saves.len(), 1);
    assert_eq!(run.saves[0].secret_key.key().expose(), &draws[0][..]);
    assert!(
        run.saves[0].state.accepted.is_none(),
        "saved before the push"
    );
    assert_eq!(server.current_file(), hex_of(v, "file"));
    let state = run.state();
    assert_eq!(state.accepted.as_ref().unwrap().generation, 1);
    assert_eq!(state.file, hex_of(v, "file"));
    assert!(!state.unpushed());
}

fn draws(v: &serde_json::Value) -> Vec<Vec<u8>> {
    v["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| hex::decode(d.as_str().unwrap()).unwrap())
        .collect()
}

/// A client whose local and accepted file is the vectors' `vault init` file, which the server
/// also holds, with the vault key cached.
fn base_client(server: &mut Server) -> Client {
    let c = cases("credentials.json");
    let v = case(&c, "vault init");
    let base = hex_of(v, "file");
    server.store(base.clone(), "laptop");
    let h = read_header(&base).unwrap();
    let state = vault_client::ClientState::new(
        vault_core::sync::SyncState {
            vault_id: h.vault_id,
            accepted: Some(Accepted {
                generation: 1,
                file_hash: file_hash(&base),
            }),
            wrap_nonce: h.wrap_nonce,
            retired_wrap_nonces: Vec::new(),
        },
        base,
        SecretKeyStore::Keyring,
    );
    let d = draws(v);
    let mut client = Client::new(
        state,
        VaultKey::from_bytes(d[2].clone().try_into().unwrap()),
        0xa1,
    );
    client.sk = Some(SecretKey::from_bytes(d[0].clone().try_into().unwrap()));
    client
}

#[test]
fn vector_passwd_new_password() {
    let c = cases("credentials.json");
    let v = case(&c, "passwd: the old header opens only old revisions");
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    let new_pw = String::from_utf8(hex_of(v, "password_hex")).unwrap();
    let old_wrap = client.state.wrap_nonce;
    let run = client.run(
        |s, k, _| passwd(s, k, opts(PasswdChange::NewPassword), Fixed::new(&draws(v))),
        &mut server,
        T0,
        vec![pw(&new_pw)],
    );
    // With the vault key cached, only the new password is asked for.
    assert_eq!(
        run.prompts,
        vec![Prompt::NewMasterPassword { rejected: None }]
    );
    assert_eq!(
        run.ok(),
        &PasswdReport {
            generation: 2,
            retired_revision: Some(2),
            expired: vec![]
        }
    );
    assert_eq!(server.current_file(), hex_of(v, "file"));
    assert_eq!(client.state.file, hex_of(v, "file"));
    assert_eq!(
        client.state.wrap_nonce,
        read_header(&hex_of(v, "file")).unwrap().wrap_nonce
    );
    assert_eq!(
        client.state.retired,
        vec![vault_client::Retired {
            nonce: old_wrap,
            revision: Some(2)
        }]
    );
    assert!(core_unlock(&client.state.file, &new_pw, client.sk.as_ref().unwrap()).is_ok());
    // The new vault key is handed out for the agent.
    assert!(open_file(&client.state.file, client.vk.as_ref().unwrap()).is_ok());
}

#[test]
fn vector_rekey_and_the_forged_old_wrap() {
    let c = cases("credentials.json");
    let v = case(
        &c,
        "--rekey: the old password still opens the old wrap, refused through the retired list",
    );
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    let run = client.run(
        |s, k, _| passwd(s, k, opts(PasswdChange::Rekey), Fixed::new(&draws(v))),
        &mut server,
        T0,
        vec![pw(PW)],
    );
    // --rekey keeps the password, so it asks for the current one even with the key cached.
    assert_eq!(run.prompts, vec![unlock_prompt(0)]);
    run.ok();
    assert_eq!(server.current_file(), hex_of(v, "file"));
    let after = &v["state_after"];
    assert_eq!(
        client.state.accepted,
        Some(Accepted {
            generation: after["accepted"]["generation"].as_u64().unwrap(),
            file_hash: arr(&after["accepted"], "file_hash"),
        })
    );
    assert_eq!(client.state.wrap_nonce, arr::<24>(after, "wrap_nonce"));
    let retired: Vec<[u8; 24]> = client.state.retired.iter().map(|r| r.nonce).collect();
    let expected: Vec<[u8; 24]> = after["retired_wrap_nonces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            hex::decode(n.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    assert_eq!(retired, expected);

    // Someone with the old vault key forges a file under the old wrap.
    server.store(hex_of(v, "forged"), "thief");
    let run = client.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(run.err().code(), v["forged_check"].as_str().unwrap());
    assert_eq!(
        client.state.stopped.as_ref().unwrap().reason,
        StopReason::Integrity
    );
}

#[test]
fn vector_new_secret_key() {
    let c = cases("credentials.json");
    let v = case(&c, "--new-secret-key");
    let new_sk = hex_of(v, "secret_key");
    let mut script = vec![new_sk.clone()];
    script.extend(draws(v));
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    let old_sk = client.sk.as_ref().unwrap().clone_secret();
    let run = client.run(
        |s, k, _| {
            passwd(
                s,
                k,
                opts(PasswdChange::NewSecretKey {
                    new_password: false,
                }),
                Fixed::new(&script),
            )
        },
        &mut server,
        T0,
        vec![pw(PW)],
    );
    run.ok();
    assert_eq!(run.saves.len(), 1);
    assert!(
        run.saves[0].state.pending_secret_key,
        "the pending key is saved before the push"
    );
    assert_eq!(run.saves[0].secret_key.key().expose(), &new_sk[..]);
    assert_eq!(server.current_file(), hex_of(v, "file"));
    assert!(matches!(
        run.finished.secret_key,
        Some(vault_client::SecretKeyChange::PromotePending)
    ));
    assert_eq!(client.sk.as_ref().unwrap().expose(), &new_sk[..]);
    assert!(client.pending.is_none());
    assert!(!client.state.pending_secret_key);
    assert_eq!(
        core_unlock(&client.state.file, PW, &old_sk).err(),
        Some(Error::WrongCredentials)
    );
}

/// A passwd whose first push meets `remote`, stored by another device just before it.
fn passwd_meeting(remote: Vec<u8>, change: PasswdChange) -> (Client, Server, Run<PasswdReport>) {
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    let mut remote = Some(remote);
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        match (r, remote.take()) {
            (Request::PutVault { .. }, Some(f)) => {
                s.store(f, "laptop");
                Some(Some(s.response(412, vec![])))
            }
            (_, f) => {
                remote = f;
                None
            }
        }
    }));
    let run = run_passwd(&mut client, &mut server, change, vec![pw(PW2)]);
    server.hook = None;
    (client, server, run)
}

#[test]
fn vector_412_during_passwd_with_the_old_wrap_merges_and_retries() {
    let c = cases("credentials.json");
    let remote = hex_of(
        case(&c, "412 during passwd, the old wrap_nonce: retry"),
        "remote",
    );
    let remote_body = open_file(
        &remote,
        &VaultKey::from_bytes(draws(case(&c, "vault init"))[2].clone().try_into().unwrap()),
    )
    .unwrap()
    .1;
    let (client, server, run) = passwd_meeting(remote, PasswdChange::NewPassword);
    assert_eq!(run.ok().generation, 3, "rebuilt on the remote's generation");
    assert_eq!(run.puts(), 2);
    assert_eq!(client.state.file, server.current_file());
    let body = client.body();
    for item in &remote_body.items {
        assert!(
            body.item(&item.id).is_some(),
            "the other device's edit is kept"
        );
    }
    assert!(core_unlock(&client.state.file, PW2, client.sk.as_ref().unwrap()).is_ok());
}

#[test]
fn vector_412_during_passwd_with_a_new_wrap_aborts() {
    let c = cases("credentials.json");
    let remote = hex_of(
        case(&c, "412 during passwd, a new wrap_nonce: abort"),
        "remote",
    );
    let (client, _, run) =
        passwd_meeting(remote, PasswdChange::NewSecretKey { new_password: true });
    assert_eq!(run.err(), ClientError::CredentialChangeWon);
    assert_eq!(run.puts(), 1);
    // The push did not land, so the pending key is void at once.
    assert!(!client.state.pending_secret_key);
    assert!(client.pending.is_none());
    assert!(matches!(
        run.finished.secret_key,
        Some(vault_client::SecretKeyChange::DiscardPending)
    ));
    assert!(client.state.retired.is_empty());
}

#[test]
fn vector_412_during_passwd_with_a_retired_wrap_is_an_integrity_error() {
    let c = cases("credentials.json");
    let v = case(
        &c,
        "412 during passwd, a retired wrap_nonce: integrity error",
    );
    let rekey = case(
        &c,
        "--rekey: the old password still opens the old wrap, refused through the retired list",
    );
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    client
        .run(
            |s, k, _| passwd(s, k, opts(PasswdChange::Rekey), Fixed::new(&draws(rekey))),
            &mut server,
            T0,
            vec![pw(PW)],
        )
        .ok();
    let mut remote = Some(hex_of(v, "remote"));
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| match r {
        Request::PutVault { .. } if remote.is_some() => {
            s.store(remote.take().unwrap(), "thief");
            Some(Some(s.response(412, vec![])))
        }
        _ => None,
    }));
    let run = run_passwd(
        &mut client,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    );
    assert_eq!(run.err().code(), v["result"].as_str().unwrap());
    assert_eq!(
        client.state.stopped.as_ref().unwrap().reason,
        StopReason::Integrity
    );
}

fn pending_client(remote: Vec<u8>) -> (Client, Server) {
    let c = cases("credentials.json");
    let mut server = Server::default();
    let mut client = base_client(&mut server);
    server.store(remote, "phone");
    client.state.pending_secret_key = true;
    client.pending = Some(SecretKey::from_bytes(
        hex_of(
            case(&c, "lost --new-secret-key response: the push landed"),
            "pending_secret_key",
        )
        .try_into()
        .unwrap(),
    ));
    (client, server)
}

#[test]
fn vector_lost_new_secret_key_response_landed() {
    let c = cases("credentials.json");
    let v = case(&c, "lost --new-secret-key response: the push landed");
    let (mut client, mut server) = pending_client(hex_of(v, "remote"));
    let password = String::from_utf8(hex_of(v, "password_hex")).unwrap();
    let old_wrap = client.state.wrap_nonce;
    let run = client.sync(&mut server, interactive(), T0, vec![pw(&password)]);
    assert_eq!(
        run.prompts,
        vec![Prompt::MasterPassword {
            purpose: Purpose::PendingSecretKey,
            failed: 0
        }]
    );
    assert_eq!(run.ok().pending_secret_key, Some(PendingKeyOutcome::Landed));
    assert!(run.ok().credentials_changed);
    assert_eq!(
        client.sk.as_ref().unwrap().expose(),
        &hex_of(v, "pending_secret_key")[..]
    );
    assert!(client.pending.is_none() && !client.state.pending_secret_key);
    assert_eq!(
        client.state.wrap_nonce,
        read_header(&hex_of(v, "remote")).unwrap().wrap_nonce
    );
    assert_eq!(client.state.retired[0].nonce, old_wrap);
    assert_eq!(
        client.state.retired[0].revision,
        Some(2),
        "the revision with the new wrap"
    );
}

#[test]
fn vector_lost_new_secret_key_response_not_landed() {
    let c = cases("credentials.json");
    let v = case(&c, "lost --new-secret-key response: the push did not land");
    let (mut client, mut server) = pending_client(hex_of(v, "remote"));
    let old_sk = client.sk.as_ref().unwrap().expose().to_vec();
    // The remote still carries the old wrap: no prompt with the vault key cached.
    let run = client.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(
        run.ok().pending_secret_key,
        Some(PendingKeyOutcome::NotLanded)
    );
    assert!(matches!(
        run.finished.secret_key,
        Some(vault_client::SecretKeyChange::DiscardPending)
    ));
    assert_eq!(client.sk.as_ref().unwrap().expose(), &old_sk[..]);
    assert!(client.pending.is_none() && !client.state.pending_secret_key);
    // Without the cached key, the password is tried with both keys and the old one opens.
    let (mut client, mut server) = pending_client(hex_of(v, "remote"));
    client.vk = None;
    let password = String::from_utf8(hex_of(v, "password_hex")).unwrap();
    let run = client.sync(&mut server, interactive(), T0, vec![pw(&password)]);
    assert_eq!(
        run.ok().pending_secret_key,
        Some(PendingKeyOutcome::NotLanded)
    );
}

#[test]
fn lost_new_secret_key_response_end_to_end() {
    for lands in [true, false] {
        let mut server = Server::default();
        let mut a = init_client(&mut server, 4);
        let old_sk = a.sk.as_ref().unwrap().expose().to_vec();
        let mut lost = true;
        server.hook = Some(Box::new(move |s: &mut Server, r: &Request| match r {
            Request::PutVault { file, .. } if lost => {
                lost = false;
                if lands {
                    s.store(file.clone(), TOKEN);
                }
                Some(None)
            }
            _ => None,
        }));
        let run = run_passwd(
            &mut a,
            &mut server,
            PasswdChange::NewSecretKey { new_password: true },
            vec![pw(PW2)],
        );
        assert_eq!(run.err(), ClientError::OutcomeUnknown);
        assert!(run.finished.state.is_none(), "the saved state stands");
        assert!(a.state.pending_secret_key && a.pending.is_some());
        let new_sk = a.pending.as_ref().unwrap().expose().to_vec();
        let answers = if lands { vec![pw(PW2)] } else { vec![] };
        let run = a.sync(&mut server, interactive(), T0, answers);
        let expected = if lands {
            PendingKeyOutcome::Landed
        } else {
            PendingKeyOutcome::NotLanded
        };
        assert_eq!(run.ok().pending_secret_key, Some(expected));
        assert!(!a.state.pending_secret_key && a.pending.is_none());
        let sk = a.sk.as_ref().unwrap().expose().to_vec();
        assert_eq!(sk, if lands { new_sk } else { old_sk });
        assert_eq!(a.state.retired.len(), usize::from(lands));
    }
}

#[test]
fn credential_change_on_another_device_new_password() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed on b", "pb");
    let old_wrap = b.state.wrap_nonce;
    let report = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    );
    let passwd_revision = server.current().unwrap().id;
    assert_eq!(report.ok().retired_revision, Some(passwd_revision));

    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
    assert_eq!(run.prompts, vec![changed_prompt()]);
    let r = run.ok();
    assert!(r.credentials_changed);
    assert_eq!(r.outcome, SyncOutcome::Pushed);
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
    assert_eq!(
        b.state.retired,
        vec![vault_client::Retired {
            nonce: old_wrap,
            revision: Some(passwd_revision)
        }]
    );
    assert!(
        open_file(&b.state.file, b.vk.as_ref().unwrap()).is_ok(),
        "the new vault key"
    );
    assert_eq!(
        a.sync(&mut server, background(), T0, vec![]).ok().outcome,
        SyncOutcome::Adopted
    );
    assert_eq!(names(&a), vec!["unpushed on b"]);
}

#[test]
fn credential_change_on_another_device_new_secret_key() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewSecretKey { new_password: true },
        vec![pw(PW2)],
    )
    .ok();
    let new_sk = a.sk.as_ref().unwrap().clone_secret();
    let run = b.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw(PW2), pw_sk(PW2, &new_sk)],
    );
    assert_eq!(
        run.prompts,
        vec![
            changed_prompt(),
            Prompt::MasterPasswordAndSecretKey {
                purpose: Purpose::CredentialsChanged
            }
        ]
    );
    run.ok();
    assert!(matches!(
        run.finished.secret_key,
        Some(vault_client::SecretKeyChange::Replace(_))
    ));
    assert_eq!(b.sk.as_ref().unwrap().expose(), new_sk.expose());
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
}

#[test]
fn credential_change_on_another_device_asks_for_the_old_password() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed", "x");
    b.vk = None;
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let run = b.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw(PW2), pw("wrong old"), pw(PW)],
    );
    assert_eq!(
        run.prompts,
        vec![
            changed_prompt(),
            Prompt::OldMasterPassword { failed: 0 },
            Prompt::OldMasterPassword { failed: 1 }
        ]
    );
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    assert_eq!(names(&b), vec!["unpushed"]);
}

#[test]
fn credential_change_on_another_device_after_rekey_needs_one_password() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed", "x");
    b.vk = None;
    run_passwd(&mut a, &mut server, PasswdChange::Rekey, vec![pw(PW)]).ok();
    // The typed password opens the new wrap and, with the same secret key, the local file.
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW)]);
    assert_eq!(run.prompts, vec![changed_prompt()]);
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
}

#[test]
fn credential_change_on_another_device_discards_after_confirmation() {
    for discard in [true, false] {
        let mut server = Server::default();
        let (mut a, mut b) = two_devices(&mut server);
        add(&mut a, "pushed by a", "x");
        a.sync(&mut server, background(), T0, vec![]).ok();
        b.sync(&mut server, background(), T0, vec![]).ok();
        add(&mut b, "unpushed", "x");
        b.vk = None;
        let before = b.state.clone();
        run_passwd(
            &mut a,
            &mut server,
            PasswdChange::NewPassword,
            vec![pw(PW2)],
        )
        .ok();
        let run = b.sync(
            &mut server,
            interactive(),
            T0,
            vec![pw(PW2), Answer::Declined, Answer::Confirmed(discard)],
        );
        assert_eq!(
            run.prompts,
            vec![
                changed_prompt(),
                Prompt::OldMasterPassword { failed: 0 },
                Prompt::Confirm(Confirmation::DiscardLocalChanges)
            ]
        );
        if discard {
            assert_eq!(run.ok().outcome, SyncOutcome::Adopted);
            assert_eq!(names(&b), vec!["pushed by a"]);
            assert_eq!(b.state.file, server.current_file());
        } else {
            assert_eq!(run.err(), ClientError::Cancelled);
            assert_eq!(b.state, before, "nothing committed");
        }
    }
}

#[test]
fn nothing_unpushed_needs_no_old_password() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    b.vk = None;
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
    assert_eq!(run.prompts, vec![changed_prompt()]);
    assert_eq!(run.ok().outcome, SyncOutcome::Adopted);
}

/// A file under a fresh wrap that no credentials open, at `generation`.
fn garbage_wrap(of: &Client, generation: u64, seed: u8) -> Vec<u8> {
    let h = Header::wrap(
        true,
        of.state.vault_id,
        generation,
        TEST,
        [seed; 16],
        [seed; 24],
        &Kek::from_bytes([seed; 32]),
        &VaultKey::from_bytes([seed; 32]),
    );
    vault_core::file::seal_file(
        &h,
        &VaultKey::from_bytes([seed; 32]),
        &[seed; 24],
        &Body::default(),
    )
    .unwrap()
}

#[test]
fn a_wrap_that_does_not_open_is_remembered() {
    let mut server = Server::default();
    let (_, mut b) = two_devices(&mut server);
    server.store(garbage_wrap(&b, 2, 0x66), "thief");
    let sk = b.sk.as_ref().unwrap().clone_secret();
    let before = b.state.file.clone();
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW), pw_sk(PW, &sk)]);
    assert_eq!(run.err(), ClientError::RemoteUnopenable);
    assert_eq!(run.puts(), 0, "never pushes over a remote it cannot open");
    assert_eq!(b.state.file, before);
    assert_eq!(b.state.refused, vec![[0x66; 24]]);
    assert_eq!(
        b.state.stopped.as_ref().unwrap().code,
        "sync.remote_unopenable"
    );
    // Later syncs report it without asking.
    let run = b.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(run.err(), ClientError::RefusedWrap);
    assert!(run.prompts.is_empty());
    let run = b.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::Stopped(StopReason::Credentials));
    assert!(run.requests.is_empty());
    // A sync the user asks for asks again.
    let run = b.sync(
        &mut server,
        Mode::Interactive { ask_again: true },
        T0,
        vec![pw(PW), Answer::Declined],
    );
    assert_eq!(run.prompts.len(), 2);
    assert_eq!(run.err(), ClientError::RemoteUnopenable);
    assert_eq!(b.state.refused, vec![[0x66; 24]], "recorded once");
}

#[test]
fn background_stops_on_a_credential_change_and_interactive_repairs_it() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let run = b.sync(&mut server, background(), T0, vec![]);
    assert_eq!(run.err(), ClientError::CredentialsChanged);
    assert_eq!(
        b.state.stopped.as_ref().unwrap().reason,
        StopReason::Credentials
    );
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
    run.ok();
    assert!(b.state.stopped.is_none());
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
}

#[test]
fn passwd_refuses_while_stopped_or_pending() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 5);
    a.state.pending_secret_key = true;
    let run = run_passwd(&mut a, &mut server, PasswdChange::NewPassword, vec![]);
    assert_eq!(run.err(), ClientError::PendingSecretKey);
    a.state.pending_secret_key = false;
    a.state.stopped = Some(vault_client::Stopped {
        reason: StopReason::Integrity,
        code: "integrity.aead".into(),
        at: T0,
    });
    let run = run_passwd(&mut a, &mut server, PasswdChange::NewPassword, vec![]);
    assert_eq!(run.err(), ClientError::Stopped(StopReason::Integrity));
    assert!(run.requests.is_empty());
}

#[test]
fn passwd_without_the_agent_asks_for_the_current_password_first() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 6);
    a.vk = None;
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw("wrong"), pw(PW), pw("short"), pw(PW2)],
    );
    assert_eq!(
        run.prompts,
        vec![
            unlock_prompt(0),
            unlock_prompt(1),
            Prompt::NewMasterPassword { rejected: None },
            Prompt::NewMasterPassword {
                rejected: Some(Error::InvalidInput(vault_core::InputKind::PasswordTooShort))
            },
        ]
    );
    run.ok();
    assert!(core_unlock(&a.state.file, PW2, a.sk.as_ref().unwrap()).is_ok());
}

#[test]
fn passwd_aborts_on_an_unseen_credential_change() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let run = run_passwd(&mut b, &mut server, PasswdChange::Rekey, vec![pw(PW)]);
    assert_eq!(run.err(), ClientError::CredentialsChanged);
    assert_eq!(run.puts(), 0);
}

#[test]
fn restore_refuses_revisions_written_under_a_retired_wrap_after_retirement() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let id = add(&mut a, "bank", "p1");
    a.sync(&mut server, background(), T0, vec![]).ok();
    let with_p1 = server.current().unwrap().id;
    a.edit(|body, _, dev| {
        let mut f = body.item(&id).unwrap().fields().unwrap().clone();
        f.login.as_mut().unwrap().password = "p2".into();
        vault_core::edit::update_item(body, &id, f, T0 + 1, dev).unwrap();
    });
    a.sync(&mut server, background(), T0 + 1, vec![]).ok();
    let old_vk = a.vk.as_ref().unwrap().clone_secret();
    let old_header = a.state.header().unwrap();
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let retired_at = a.state.retired[0].revision.unwrap();
    assert_eq!(retired_at, server.current().unwrap().id);
    b.sync(&mut server, interactive(), T0, vec![pw(PW2)]).ok();
    // A thief holding the old vault key pushes under the old wrap.
    let forged = vault_core::file::seal_file(
        &old_header.with_generation(MAX_GENERATION),
        &old_vk,
        &[9; 24],
        &Body::default(),
    )
    .unwrap();
    let forged_id = server.store(forged, "thief");
    let run = b.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(
        run.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::RetiredWrapNonce))
    );

    let fetch = |a: &mut Client, server: &mut Server, id: u64, answers| {
        let m = fetch_revision(a.state.clone(), a.keys(), id, a.rng());
        drive(m, server, TOKEN, T0, answers)
    };
    let run = fetch(&mut a, &mut server, forged_id, vec![]);
    assert_eq!(run.err(), ClientError::RevisionRefused);
    assert!(run.prompts.is_empty());

    // An older revision under the old wrap needs that revision's credentials.
    let run = fetch(&mut a, &mut server, with_p1, vec![pw(PW)]);
    assert_eq!(
        run.prompts,
        vec![Prompt::MasterPassword {
            purpose: Purpose::Revision,
            failed: 0
        }]
    );
    let revision = match run.finished.result {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let local = a.body();
    assert_eq!(
        vault_client::restore::restore_preview(&local, &revision, RestoreScope::Item(&id)).unwrap(),
        RestoreSummary {
            added: 0,
            changed: 1,
            removed: 0
        }
    );
    let mut rng = a.rng();
    let vk = a.vk.as_ref().unwrap().clone_secret();
    let (state, summary) = restore(
        &a.state,
        &vk,
        &revision,
        RestoreScope::Item(&id),
        &a.device,
        T0 + 2,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        summary,
        RestoreSummary {
            added: 0,
            changed: 1,
            removed: 0
        }
    );
    a.state = state;
    let body = a.body();
    let item = body.item(&id).unwrap();
    assert_eq!(item.login().unwrap().password, "p1");
    assert_eq!(
        item.fields().unwrap().password_history[0].password,
        "p2",
        "the current password is kept"
    );
    assert!(a.state.unpushed());
    // The forged file is still current, so the restore reaches the server through recovery.
    let run = a.run(recover, &mut server, T0 + 2, vec![]);
    assert_eq!(run.ok().revision, Some(retired_at));
    assert!(!a.state.unpushed());

    // A revision under the current wrap opens with the cached key.
    let current = server.current().unwrap().id;
    let run = fetch(&mut a, &mut server, current, vec![]);
    assert!(run.prompts.is_empty());
    run.ok();
    // A retired wrap without a recorded revision refuses every revision under it.
    a.state.retired[0].revision = None;
    assert_eq!(
        fetch(&mut a, &mut server, with_p1, vec![]).err(),
        ClientError::RevisionRefused
    );
    // Another vault's file is refused.
    let other = init_client(&mut Server::default(), 9);
    let other_id = server.store(other.state.file.clone(), "thief");
    assert_eq!(
        fetch(&mut a, &mut server, other_id, vec![]).err(),
        ClientError::Core(Error::Integrity(IntegrityKind::VaultIdMismatch))
    );
    assert_eq!(
        fetch(&mut a, &mut server, 999, vec![]).err(),
        ClientError::RevisionNotFound
    );
}

#[test]
fn restore_of_the_whole_vault() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 7);
    let keep = add(&mut a, "keep", "k");
    let gone = add(&mut a, "deleted later", "d");
    a.sync(&mut server, background(), T0, vec![]).ok();
    let rev = server.current().unwrap().id;
    a.edit(|body, _, dev| vault_core::edit::delete_item(body, &gone, T0 + 1, dev).unwrap());
    let new_id = add(&mut a, "new", "n");
    a.sync(&mut server, background(), T0 + 1, vec![]).ok();
    let m = fetch_revision(a.state.clone(), a.keys(), rev, a.rng());
    let revision = match drive(m, &mut server, TOKEN, T0, vec![]).finished.result {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(revision.id, rev);
    let mut rng = a.rng();
    let vk = a.vk.as_ref().unwrap().clone_secret();
    let (state, summary) = restore(
        &a.state,
        &vk,
        &revision,
        RestoreScope::All,
        &a.device,
        T0 + 2,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        summary,
        RestoreSummary {
            added: 1,
            changed: 1,
            removed: 1
        }
    );
    a.state = state;
    assert_eq!(
        names(&a),
        vec!["deleted later", "keep"],
        "the newer item is removed"
    );
    assert!(a.body().tombstones.iter().any(|t| t.id == new_id));
    assert!(a.body().item(&keep).is_some());
    // The clock check applies to a restore as to any edit.
    assert_eq!(
        restore(
            &a.state,
            &vk,
            &revision,
            RestoreScope::All,
            &a.device,
            0,
            &mut rng
        )
        .err(),
        Some(ClientError::Core(Error::ClockBeforeBuildTime))
    );
}

#[test]
fn setup_allows_three_attempts_and_checks_the_kit() {
    let mut server = Server::default();
    let a = init_client(&mut server, 8);
    let sk = a.sk.as_ref().unwrap();
    let answers = |p: Vec<&str>, kit: Option<[u8; 16]>| {
        let mut v = vec![Answer::SecretKey(sk.clone_secret()), Answer::VaultId(kit)];
        v.extend(p.into_iter().map(pw));
        v
    };
    let run = drive(
        setup(SecretKeyStore::File, TestRng(1)),
        &mut server,
        "laptop",
        T0,
        answers(vec!["x", "y", PW], Some(a.state.vault_id)),
    );
    run.ok();
    assert_eq!(
        run.prompts[2..],
        [unlock_prompt(0), unlock_prompt(1), unlock_prompt(2)]
    );
    assert_eq!(
        run.state().accepted,
        a.state.accepted,
        "accepts what it first pulls"
    );
    assert_eq!(run.state().secret_key_store, SecretKeyStore::File);
    let run = drive(
        setup(SecretKeyStore::File, TestRng(1)),
        &mut server,
        "laptop",
        T0,
        answers(vec!["x", "y", "z"], None),
    );
    assert_eq!(run.err(), ClientError::Core(Error::WrongCredentials));
    assert!(run.finished.state.is_none());
}

#[test]
fn init_refuses_a_server_that_holds_a_vault() {
    let mut server = Server::default();
    init_client(&mut server, 1);
    let run = drive(
        init(TEST, true, SecretKeyStore::Keyring, TestRng(2)),
        &mut server,
        TOKEN,
        T0,
        vec![],
    );
    assert_eq!(run.err(), ClientError::VaultExists);
    assert!(run.prompts.is_empty() && run.saves.is_empty());
}

#[test]
fn unlock_pulls_first() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut a, "from a", "x");
    a.sync(&mut server, background(), T0, vec![]).ok();
    // The remote is under the current wrap: the local file opens and a sync follows.
    b.vk = None;
    let run = b.run(unlock, &mut server, T0, vec![pw("wrong"), pw(PW)]);
    assert_eq!(run.prompts, vec![unlock_prompt(0), unlock_prompt(1)]);
    assert_eq!(
        run.ok().sync.as_ref().ok().unwrap().outcome,
        SyncOutcome::Adopted
    );
    assert!(b.vk.is_some());
    assert_eq!(names(&b), vec!["from a"]);

    // The server does not answer in time: the local file opens.
    b.vk = None;
    server.hook = Some(Box::new(|_: &mut Server, _: &Request| Some(None)));
    let run = b.run(unlock, &mut server, T0, vec![pw(PW)]);
    assert_eq!(
        run.ok().sync.as_ref().err(),
        Some(&ClientError::Unreachable)
    );
    assert!(b.vk.is_some());
    server.hook = None;

    // Credentials changed elsewhere: the new password is not reported as wrong.
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    b.vk = None;
    let run = b.run(unlock, &mut server, T0, vec![pw(PW2)]);
    assert_eq!(run.prompts, vec![changed_prompt()]);
    assert!(run.ok().sync.as_ref().ok().unwrap().credentials_changed);
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
    assert!(open_file(&b.state.file, b.vk.as_ref().unwrap()).is_ok());

    // Sync stopped by an integrity error: the unlock does not pull.
    b.state.stopped = Some(vault_client::Stopped {
        reason: StopReason::Integrity,
        code: "integrity.aead".into(),
        at: T0,
    });
    b.vk = None;
    let run = b.run(unlock, &mut server, T0, vec![pw(PW2)]);
    assert!(run.requests.is_empty());
    assert_eq!(
        run.ok().sync.as_ref().err(),
        Some(&ClientError::Stopped(StopReason::Integrity))
    );
}

#[test]
fn recovery_finds_a_credential_change_behind_garbage() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed on b", "x");
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let change_revision = server.current().unwrap().id;
    // A thief buries the change under garbage that claims b's current wrap.
    let mut garbage = vault_core::file::seal_file(
        &b.state.header().unwrap().with_generation(MAX_GENERATION),
        b.vk.as_ref().unwrap(),
        &[3; 24],
        &Body::default(),
    )
    .unwrap();
    let last = garbage.len() - 1;
    garbage[last] ^= 1;
    server.store(garbage, "thief");
    let run = b.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(
        run.err(),
        ClientError::Core(Error::Integrity(IntegrityKind::Aead))
    );

    let run = b.run(recover, &mut server, T0, vec![pw(PW2)]);
    assert_eq!(
        run.prompts,
        vec![Prompt::MasterPassword {
            purpose: Purpose::Recovery,
            failed: 0
        }]
    );
    let report = run.ok();
    assert!(report.credentials_changed);
    assert_eq!(report.revision, Some(change_revision));
    assert_eq!(
        report.generation, 3,
        "above the change and the accepted generation"
    );
    assert!(b.state.stopped.is_none());
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
    assert_eq!(b.state.retired[0].revision, Some(change_revision));
    assert_eq!(names(&b), vec!["unpushed on b"]);
    assert_eq!(
        a.sync(&mut server, background(), T0, vec![]).ok().outcome,
        SyncOutcome::Adopted
    );
    assert_eq!(a.state.file, b.state.file);
}

// Review additions.

/// B, with an unpushed edit and its vault key, starts taking over A's new password; B's push
/// then meets a `412` from `hook`'s change to the server.
fn takeover_meeting(
    hook: impl FnMut(&mut Server, &Client) + 'static,
) -> (
    Client,
    Server,
    Run<vault_client::sync::SyncReport>,
    [u8; 24],
) {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed", "x");
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let old_wrap = b.state.wrap_nonce;
    let snapshot = Client {
        state: b.state.clone(),
        vk: b.vk.as_ref().map(VaultKey::clone_secret),
        sk: None,
        pending: None,
        device: b.device,
        token: b.token.clone(),
        rng: 99,
    };
    let mut hook = Some(hook);
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        if matches!(r, Request::PutVault { .. })
            && let Some(mut h) = hook.take()
        {
            h(s, &snapshot);
            return Some(Some(s.response(412, vec![])));
        }
        None
    }));
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
    server.hook = None;
    (b, server, run, old_wrap)
}

#[test]
fn a_takeover_is_dropped_when_the_remote_returns_to_the_old_wrap() {
    // Another device pushes under the old wrap at a higher generation before B's push.
    let (b, server, run, old_wrap) = takeover_meeting(|s, b| {
        let generation = read_header(&s.current_file()).unwrap().generation + 1;
        let file = vault_core::file::seal_file(
            &b.state.header().unwrap().with_generation(generation),
            b.vk.as_ref().unwrap(),
            &[4; 24],
            &Body::default(),
        )
        .unwrap();
        s.store(file, "thief");
    });
    let report = run.ok();
    assert!(!report.credentials_changed);
    assert_eq!(report.outcome, SyncOutcome::Pushed);
    assert_eq!(
        b.state.wrap_nonce, old_wrap,
        "the new wrap is not rotated in"
    );
    assert!(b.state.retired.is_empty());
    assert!(run.finished.secret_key.is_none());
    assert!(
        open_file(&b.state.file, b.vk.as_ref().unwrap()).is_ok(),
        "the old vault key"
    );
    assert_eq!(b.state.file, server.current_file());
}

#[test]
fn a_takeover_is_dropped_when_a_404_re_pushes_the_local_file() {
    let (b, server, run, old_wrap) = takeover_meeting(|s, _| s.revisions.clear());
    assert!(!run.ok().credentials_changed);
    assert_eq!(b.state.wrap_nonce, old_wrap);
    assert!(b.state.retired.is_empty());
    assert!(open_file(&b.state.file, b.vk.as_ref().unwrap()).is_ok());
    assert_eq!(
        read_header(&server.current_file()).unwrap().wrap_nonce,
        old_wrap
    );
    assert!(matches!(
        run.requests.last(),
        Some(Request::PutVault {
            condition: vault_client::Precondition::IfNoneMatch,
            ..
        })
    ));
}

#[test]
fn a_failed_push_after_a_takeover_keeps_the_new_credentials() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed", "x");
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let change_revision = server.current().unwrap().id;
    b.vk = None;
    server.hook = Some(Box::new(|s: &mut Server, r: &Request| {
        matches!(r, Request::PutVault { .. }).then(|| Some(s.response(503, vec![])))
    }));
    let run = b.run(unlock, &mut server, T0, vec![pw(PW2), pw(PW)]);
    server.hook = None;
    assert_eq!(
        run.ok().sync.as_ref().err(),
        Some(&ClientError::Status(503))
    );
    assert_eq!(
        b.state.wrap_nonce, a.state.wrap_nonce,
        "the takeover is kept"
    );
    assert_eq!(b.state.retired[0].revision, Some(change_revision));
    assert!(
        open_file(&b.state.file, b.vk.as_ref().unwrap()).is_ok(),
        "the new vault key"
    );
    assert!(
        b.state.unpushed(),
        "the merged edit waits for the next sync"
    );
    assert_eq!(names(&b), vec!["unpushed"]);
    // The next sync needs no credentials and pushes the edit.
    let run = b.sync(&mut server, interactive(), T0, vec![]);
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    assert_eq!(
        a.sync(&mut server, background(), T0, vec![]).ok().outcome,
        SyncOutcome::Adopted
    );
    assert_eq!(names(&a), vec!["unpushed"]);
}

/// A device whose `--new-secret-key` push never landed, and a second device that then changed
/// the secret key itself.
fn pending_and_new_secret_key() -> (Client, Client, Server, SecretKey) {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    a.state.pending_secret_key = true;
    a.pending = Some(SecretKey::from_bytes([0x5a; 16]));
    run_passwd(
        &mut b,
        &mut server,
        PasswdChange::NewSecretKey { new_password: true },
        vec![pw(PW2)],
    )
    .ok();
    let sk2 = b.sk.as_ref().unwrap().clone_secret();
    (a, b, server, sk2)
}

#[test]
fn recovery_into_another_secret_key_also_discards_the_pending_one() {
    let (mut a, b, mut server, sk2) = pending_and_new_secret_key();
    let run = a.run(recover, &mut server, T0, vec![pw(PW2), pw_sk(PW2, &sk2)]);
    let report = run.ok();
    assert!(report.credentials_changed);
    assert_eq!(
        report.pending_secret_key,
        Some(PendingKeyOutcome::NotLanded)
    );
    assert!(matches!(
        run.finished.secret_key,
        Some(vault_client::SecretKeyChange::ReplaceAndDiscardPending(_))
    ));
    assert_eq!(a.sk.as_ref().unwrap().expose(), sk2.expose());
    assert!(a.pending.is_none() && !a.state.pending_secret_key);
    assert_eq!(a.state.wrap_nonce, b.state.wrap_nonce);
}

#[test]
fn a_pending_key_and_another_devices_new_secret_key() {
    let (mut a, b, mut server, sk2) = pending_and_new_secret_key();
    let run = a.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw(PW2), pw(PW2), pw(PW2), pw_sk(PW2, &sk2)],
    );
    let pending = |failed| Prompt::MasterPassword {
        purpose: Purpose::PendingSecretKey,
        failed,
    };
    assert_eq!(
        run.prompts,
        vec![
            pending(0),
            pending(1),
            pending(2),
            Prompt::MasterPasswordAndSecretKey {
                purpose: Purpose::PendingSecretKey
            }
        ]
    );
    assert_eq!(
        run.ok().pending_secret_key,
        Some(PendingKeyOutcome::NotLanded)
    );
    assert_eq!(a.sk.as_ref().unwrap().expose(), sk2.expose());
    assert!(a.pending.is_none() && !a.state.pending_secret_key);
    assert_eq!(a.state.wrap_nonce, b.state.wrap_nonce);
}

#[test]
fn a_pending_key_and_garbage_under_a_new_wrap_is_refused() {
    let c = cases("credentials.json");
    let (mut client, mut server) = pending_client(hex_of(
        case(&c, "lost --new-secret-key response: the push did not land"),
        "remote",
    ));
    server.store(garbage_wrap(&client, 2, 0x77), "thief");
    let sk = client.sk.as_ref().unwrap().clone_secret();
    let before = client.state.file.clone();
    let run = client.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw(PW), pw(PW), pw(PW), pw_sk(PW, &sk)],
    );
    assert_eq!(run.err(), ClientError::RemoteUnopenable);
    assert_eq!(run.puts(), 0);
    assert_eq!(client.state.refused, vec![[0x77; 24]]);
    assert_eq!(
        client.state.stopped.as_ref().unwrap().code,
        "sync.remote_unopenable"
    );
    assert!(client.state.pending_secret_key, "still unsettled");
    assert_eq!(client.state.file, before);
}

#[test]
fn passwd_reports_items_a_merge_after_a_412_drops() {
    let day = 86_400_000;
    let later = T0 + 200 * day;
    let mut server = Server::default();
    let mut a = init_client(&mut server, 11);
    add(&mut a, "stale", "s");
    a.sync(&mut server, background(), T0, vec![]).ok();
    server.date = Some(later);
    // Another device deleted the item and purged its tombstone, raising the horizon.
    let header = a.state.header().unwrap();
    let vk = a.vk.as_ref().unwrap().clone_secret();
    let mut remote = Body::default();
    remote.horizon = vault_core::merge::cutoff(later);
    let mut generation = read_header(&server.current_file()).unwrap().generation;
    let mut once = true;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        if once && matches!(r, Request::PutVault { .. }) {
            once = false;
            generation += 1;
            let f = vault_core::file::seal_file(
                &header.with_generation(generation),
                &vk,
                &[5; 24],
                &remote,
            )
            .unwrap();
            s.store(f, "laptop");
            return Some(Some(s.response(412, vec![])));
        }
        None
    }));
    let run = a.run(
        |s, k, r| passwd(s, k, opts(PasswdChange::NewPassword), r),
        &mut server,
        later,
        vec![pw(PW2)],
    );
    assert_eq!(run.ok().expired, vec!["stale".to_owned()]);
    assert!(names(&a).is_empty());
}

#[test]
fn passwd_gives_up_after_five_412_responses_and_reports_a_lost_vault() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 12);
    server.hook = Some(Box::new(|s: &mut Server, r: &Request| {
        matches!(r, Request::PutVault { .. }).then(|| Some(s.response(412, vec![])))
    }));
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewSecretKey { new_password: true },
        vec![pw(PW2)],
    );
    assert_eq!(run.err(), ClientError::Conflicts);
    assert_eq!(run.puts(), 5);
    assert!(
        !a.state.pending_secret_key && a.pending.is_none(),
        "known not to have landed"
    );
    let mut once = true;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        if once && matches!(r, Request::PutVault { .. }) {
            once = false;
            s.revisions.clear();
            return Some(Some(s.response(412, vec![])));
        }
        None
    }));
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    );
    assert_eq!(run.err(), ClientError::NoVault);
}

#[test]
fn recovery_reuses_an_opened_wrap_after_a_412() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let mut once = true;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| {
        if once && matches!(r, Request::PutVault { .. }) {
            once = false;
            return Some(Some(s.response(412, vec![])));
        }
        None
    }));
    let run = b.run(recover, &mut server, T0, vec![pw(PW2)]);
    server.hook = None;
    assert!(run.ok().credentials_changed);
    assert_eq!(run.prompts.len(), 1, "asked once");
    let lists = run
        .requests
        .iter()
        .filter(|r| matches!(r, Request::ListRevisions))
        .count();
    assert!(lists >= 2, "listed again after the 412");
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
}

#[test]
fn init_failures_after_the_save() {
    use vault_client::InitRefusal;
    for (status, expected) in [
        (Some(412), ClientError::UndoSave(InitRefusal::VaultExists)),
        (Some(401), ClientError::UndoSave(InitRefusal::Token)),
        (Some(500), ClientError::UndoSave(InitRefusal::Status(500))),
        (None, ClientError::Unreachable),
    ] {
        let mut server = Server {
            hook: Some(Box::new(move |s: &mut Server, r: &Request| {
                matches!(r, Request::PutVault { .. })
                    .then(|| status.map(|st| s.response(st, vec![])))
            })),
            ..Server::default()
        };
        let run = drive(
            init(TEST, true, SecretKeyStore::Keyring, TestRng(3)),
            &mut server,
            TOKEN,
            T0,
            vec![pw(PW)],
        );
        assert_eq!(run.err(), expected);
        assert_eq!(run.saves.len(), 1, "saved before the push");
        assert!(run.finished.state.is_none());
    }
}

#[test]
fn commit_after_a_takeover_with_a_concurrent_edit() {
    for rekey in [true, false] {
        let mut server = Server::default();
        let (mut a, mut b) = two_devices(&mut server);
        if rekey {
            run_passwd(&mut a, &mut server, PasswdChange::Rekey, vec![pw(PW)]).ok();
        } else {
            run_passwd(
                &mut a,
                &mut server,
                PasswdChange::NewPassword,
                vec![pw(PW2)],
            )
            .ok();
        }
        // The sync runs without the vault key and with nothing unpushed.
        let started = b.state.clone();
        let mut keys = b.keys();
        keys.vault_key = None;
        let typed = if rekey { PW } else { PW2 };
        let run = drive(
            vault_client::sync::sync(started.clone(), keys, interactive(), TestRng(8)),
            &mut server,
            "laptop",
            T0,
            vec![pw(typed)],
        );
        run.ok();
        // A command with the old key edits the local file meanwhile.
        add(&mut b, "during sync", "d");
        let mut rng = TestRng(9);
        let c = run.finished.commit(&started, &b.state, false, T0, &mut rng);
        if rekey {
            // The typed password opens the old wrap too, so the commit has both keys.
            let c = c.unwrap();
            assert!(c.merged_local_changes);
            let st = c.state.unwrap();
            assert_eq!(st.wrap_nonce, a.state.wrap_nonce);
            assert!(st.unpushed());
            let body = open_file(&st.file, run.finished.vault_key.as_ref().unwrap())
                .unwrap()
                .1;
            assert_eq!(body.items.len(), 1);
        } else {
            assert_eq!(
                c.err(),
                Some(ClientError::Locked),
                "the old vault key is not known"
            );
        }
    }
}

#[test]
fn overlapping_syncs_keep_a_refused_nonce() {
    let mut server = Server::default();
    let (_, mut b) = two_devices(&mut server);
    server.store(garbage_wrap(&b, 2, 0x55), "thief");
    let started = b.state.clone();
    let background_run = drive(
        vault_client::sync::sync(started.clone(), b.keys(), background(), TestRng(1)),
        &mut server,
        "laptop",
        T0,
        vec![],
    );
    let sk = b.sk.as_ref().unwrap().clone_secret();
    let interactive_run = drive(
        vault_client::sync::sync(started.clone(), b.keys(), interactive(), TestRng(2)),
        &mut server,
        "laptop",
        T0 + 1,
        vec![pw(PW), pw_sk(PW, &sk)],
    );
    b.commit(&started, &interactive_run.finished, T0 + 1);
    assert_eq!(b.state.refused, vec![[0x55; 24]]);
    // The background sync, which started before, commits last.
    b.commit_as(&started, &background_run.finished, true, T0 + 2);
    assert_eq!(b.state.refused, vec![[0x55; 24]], "kept from the disk");
    assert_eq!(
        b.state.stopped.as_ref().unwrap().code,
        "sync.credentials_changed"
    );
}

#[test]
fn credential_change_on_another_device_new_secret_key_without_the_cached_key() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    add(&mut b, "unpushed", "x");
    b.vk = None;
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewSecretKey { new_password: true },
        vec![pw(PW2)],
    )
    .ok();
    let sk2 = a.sk.as_ref().unwrap().clone_secret();
    let run = b.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw(PW2), pw_sk(PW2, &sk2), pw(PW)],
    );
    assert_eq!(
        run.prompts,
        vec![
            changed_prompt(),
            Prompt::MasterPasswordAndSecretKey {
                purpose: Purpose::CredentialsChanged
            },
            Prompt::OldMasterPassword { failed: 0 }
        ]
    );
    assert_eq!(run.ok().outcome, SyncOutcome::Pushed);
    assert_eq!(b.sk.as_ref().unwrap().expose(), sk2.expose());
    assert_eq!(names(&b), vec!["unpushed"]);
}

#[test]
fn a_wrong_first_password_and_the_old_password_attempt_limit() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    // A typo at the first prompt: the second prompt, with the stored secret key, opens it.
    let sk = b.sk.as_ref().unwrap().clone_secret();
    let mut c = Client {
        state: b.state.clone(),
        vk: None,
        sk: Some(sk.clone_secret()),
        pending: None,
        device: b.device,
        token: b.token.clone(),
        rng: 5,
    };
    let run = c.sync(
        &mut server,
        interactive(),
        T0,
        vec![pw("typo"), pw_sk(PW2, &sk)],
    );
    run.ok();
    assert_eq!(c.state.wrap_nonce, a.state.wrap_nonce);

    // Three wrong old passwords, then the discard question.
    add(&mut b, "unpushed", "x");
    b.vk = None;
    let before = b.state.clone();
    let run = b.sync(
        &mut server,
        interactive(),
        T0,
        vec![
            pw(PW2),
            pw("w1"),
            pw("w2"),
            pw("w3"),
            Answer::Confirmed(false),
        ],
    );
    assert_eq!(
        run.prompts[1..],
        [
            Prompt::OldMasterPassword { failed: 0 },
            Prompt::OldMasterPassword { failed: 1 },
            Prompt::OldMasterPassword { failed: 2 },
            Prompt::Confirm(Confirmation::DiscardLocalChanges)
        ]
    );
    assert_eq!(run.err(), ClientError::Cancelled);
    assert_eq!(b.state, before);
}

#[test]
fn a_refused_nonce_does_not_block_a_later_legitimate_change() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    server.store(garbage_wrap(&b, 2, 0x44), "thief");
    let sk = b.sk.as_ref().unwrap().clone_secret();
    assert_eq!(
        b.sync(
            &mut server,
            interactive(),
            T0,
            vec![pw(PW), Answer::Declined]
        )
        .err(),
        ClientError::RemoteUnopenable
    );
    // Honest devices recover past the garbage, and A then changes its password over it.
    let run = a.run(
        recover,
        &mut server,
        T0,
        vec![pw(PW), pw_sk(PW, &sk), Answer::Confirmed(true)],
    );
    run.ok();
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    );
    run.ok();
    // B is asked for the new wrap without `ask_again`: it is not the refused one.
    let run = b.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
    assert_eq!(run.prompts, vec![changed_prompt()]);
    run.ok();
    assert_eq!(b.state.wrap_nonce, a.state.wrap_nonce);
    assert!(b.state.stopped.is_none());
    assert_eq!(b.state.refused, vec![[0x44; 24]]);
}

#[test]
fn passwd_over_thief_garbage_needs_recovery_first() {
    let mut server = Server::default();
    let (mut a, _) = two_devices(&mut server);
    server.store(garbage_wrap(&a, 2, 0x33), "thief");
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    );
    assert_eq!(run.err(), ClientError::CredentialsChanged);
    assert_eq!(run.puts(), 0);
}

fn fetch(
    c: &mut Client,
    server: &mut Server,
    id: u64,
    answers: Vec<Answer>,
) -> Run<vault_client::restore::Revision> {
    let m = fetch_revision(c.state.clone(), c.keys(), id, c.rng());
    let token = c.token.clone();
    drive(m, server, &token, T0, answers)
}

#[test]
fn restore_of_a_revision_under_an_old_secret_key() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 13);
    let old_sk = a.sk.as_ref().unwrap().clone_secret();
    add(&mut a, "before", "b");
    a.sync(&mut server, background(), T0, vec![]).ok();
    let old_rev = server.current().unwrap().id;
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewSecretKey {
            new_password: false,
        },
        vec![pw(PW)],
    )
    .ok();
    let revision_prompt = |failed| Prompt::MasterPassword {
        purpose: Purpose::Revision,
        failed,
    };
    let run = fetch(
        &mut a,
        &mut server,
        old_rev,
        vec![pw(PW), pw(PW), pw(PW), pw_sk(PW, &old_sk)],
    );
    assert_eq!(
        run.prompts,
        vec![
            revision_prompt(0),
            revision_prompt(1),
            revision_prompt(2),
            Prompt::MasterPasswordAndSecretKey {
                purpose: Purpose::Revision
            }
        ]
    );
    assert_eq!(run.ok().body.items.len(), 1);
    let run = fetch(
        &mut a,
        &mut server,
        old_rev,
        vec![pw("x"), pw("y"), pw("z"), pw_sk("w", &old_sk)],
    );
    assert_eq!(run.err(), ClientError::Core(Error::WrongCredentials));
    // The boundary: a revision with the ID recorded at retirement is allowed.
    a.state.retired[0].revision = Some(old_rev);
    let run = fetch(
        &mut a,
        &mut server,
        old_rev,
        vec![pw(PW), pw(PW), pw(PW), pw_sk(PW, &old_sk)],
    );
    run.ok();
    a.state.retired[0].revision = Some(old_rev - 1);
    assert_eq!(
        fetch(&mut a, &mut server, old_rev, vec![]).err(),
        ClientError::RevisionRefused
    );
}

#[test]
fn restore_checks_the_server_date_and_records_a_401() {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 14);
    let rev = server.current().unwrap().id;
    server.date = Some(T0 + 3 * 86_400_000);
    let run = fetch(&mut a, &mut server, rev, vec![]);
    let revision = match run.finished.result {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let vk = a.vk.as_ref().unwrap().clone_secret();
    let mut rng = a.rng();
    assert_eq!(
        restore(
            &a.state,
            &vk,
            &revision,
            RestoreScope::All,
            &a.device,
            T0,
            &mut rng
        )
        .err(),
        Some(ClientError::Core(Error::ClockSkew))
    );
    server.tokens.retain(|t| t != TOKEN);
    let run = fetch(&mut a, &mut server, rev, vec![]);
    assert_eq!(run.err(), ClientError::Token);
    assert_eq!(
        run.state().stopped.as_ref().unwrap().reason,
        StopReason::Token
    );
}

#[test]
fn a_takeover_records_the_lowest_revision_under_the_new_wrap() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewPassword,
        vec![pw(PW2)],
    )
    .ok();
    let change_revision = server.current().unwrap().id;
    add(&mut a, "after the change", "x");
    a.sync(&mut server, background(), T0, vec![]).ok();
    assert!(server.current().unwrap().id > change_revision);
    b.sync(&mut server, interactive(), T0, vec![pw(PW2)]).ok();
    assert_eq!(b.state.retired[0].revision, Some(change_revision));
}

/// A host that stops after `writes` writes, as a crash does: the writes before it land, and
/// nothing after.
struct Crash<'a> {
    slots: Slots<'a>,
    writes: usize,
}

impl Crash<'_> {
    fn step(&mut self) -> Result<(), &'static str> {
        if self.writes == 0 {
            return Err("crash");
        }
        self.writes -= 1;
        Ok(())
    }
}

impl vault_client::commit::CommitHost for Crash<'_> {
    type Error = &'static str;

    fn store_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), &'static str> {
        self.step()?;
        self.slots.store_current(store, vault_id, key)
    }

    fn store_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), &'static str> {
        self.step()?;
        self.slots.store_pending(store, vault_id, key)
    }

    fn copy_pending_to_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), &'static str> {
        self.step()?;
        self.slots.copy_pending_to_current(store, vault_id)
    }

    fn delete_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), &'static str> {
        self.step()?;
        self.slots.delete_pending(store, vault_id)
    }

    fn write_state(&mut self, state: &vault_client::ClientState) -> Result<(), &'static str> {
        self.step()?;
        self.slots.write_state(state)
    }
}

/// Runs an interactive sync on `c` without committing it, then commits it with a crash after
/// `writes` writes. The cached vault key is dropped, as for a client without an agent.
fn sync_and_crash(
    c: &mut Client,
    server: &mut Server,
    answers: Vec<Answer>,
    writes: usize,
) -> Option<vault_client::SecretKeyChange> {
    use vault_client::commit::apply;
    let started = c.state.clone();
    let m = vault_client::sync::sync(started.clone(), c.keys(), interactive(), c.rng());
    let token = c.token.clone();
    let run = drive(m, server, &token, T0, answers);
    run.ok();
    let on_disk = c.state.clone();
    let mut rng = c.rng();
    let mut host = Crash {
        slots: Slots {
            state: &mut c.state,
            current: &mut c.sk,
            pending: &mut c.pending,
        },
        writes,
    };
    let _ = apply(
        &run.finished,
        &started,
        &on_disk,
        false,
        T0,
        &mut rng,
        &mut host,
    );
    c.vk = None;
    run.finished.secret_key
}

/// A client whose `--new-secret-key` push landed, or not, but whose response was lost.
fn lost_new_secret_key(lands: bool) -> (Client, Server) {
    let mut server = Server::default();
    let mut a = init_client(&mut server, 4);
    let mut lost = true;
    server.hook = Some(Box::new(move |s: &mut Server, r: &Request| match r {
        Request::PutVault { file, .. } if lost => {
            lost = false;
            if lands {
                s.store(file.clone(), TOKEN);
            }
            Some(None)
        }
        _ => None,
    }));
    let run = run_passwd(
        &mut a,
        &mut server,
        PasswdChange::NewSecretKey { new_password: true },
        vec![pw(PW2)],
    );
    assert_eq!(run.err(), ClientError::OutcomeUnknown);
    (a, server)
}

#[test]
fn a_crash_while_promoting_a_pending_key_is_settled_by_the_next_sync() {
    // Writes: copy the pending key to current, write the state, delete the pending key.
    for writes in 0..=3 {
        let (mut a, mut server) = lost_new_secret_key(true);
        let new_sk = a.pending.as_ref().unwrap().expose().to_vec();
        let change = sync_and_crash(&mut a, &mut server, vec![pw(PW2)], writes);
        assert!(matches!(
            change,
            Some(vault_client::SecretKeyChange::PromotePending)
        ));
        // Whatever landed, the stored slots open the remote: the next sync settles it.
        let run = a.sync(&mut server, interactive(), T0, vec![pw(PW2)]);
        run.ok();
        assert!(!a.state.pending_secret_key, "after {writes} writes");
        assert_eq!(a.sk.as_ref().unwrap().expose().to_vec(), new_sk);
        assert!(open_file(&a.state.file, a.vk.as_ref().unwrap()).is_ok());
    }
}

#[test]
fn a_crash_while_discarding_a_pending_key_is_settled_by_the_next_sync() {
    // Writes: write the state, delete the pending key.
    for writes in 0..=2 {
        let (mut a, mut server) = lost_new_secret_key(false);
        let old_sk = a.sk.as_ref().unwrap().expose().to_vec();
        // The cached vault key still opens the remote, under the current wrap.
        let change = sync_and_crash(&mut a, &mut server, vec![], writes);
        assert!(matches!(
            change,
            Some(vault_client::SecretKeyChange::DiscardPending)
        ));
        a.sync(&mut server, interactive(), T0, vec![pw(PW)]).ok();
        assert!(!a.state.pending_secret_key, "after {writes} writes");
        assert_eq!(a.sk.as_ref().unwrap().expose().to_vec(), old_sk);
    }
}

#[test]
fn a_crash_while_taking_over_a_new_secret_key_is_settled_by_the_next_sync() {
    // Writes: store the new current key, write the state.
    for writes in 0..=2 {
        let mut server = Server::default();
        let (mut a, mut b) = two_devices(&mut server);
        run_passwd(
            &mut a,
            &mut server,
            PasswdChange::NewSecretKey { new_password: true },
            vec![pw(PW2)],
        )
        .ok();
        let new_sk = a.sk.as_ref().unwrap().clone_secret();
        let change = sync_and_crash(
            &mut b,
            &mut server,
            vec![pw(PW2), pw_sk(PW2, &new_sk)],
            writes,
        );
        assert!(matches!(
            change,
            Some(vault_client::SecretKeyChange::Replace(_))
        ));
        // Before the key write the sync asks for the new key again; after it, the stored key
        // opens the remote, or the state.
        let answers = if writes == 0 {
            vec![pw(PW2), pw_sk(PW2, &new_sk)]
        } else {
            vec![pw(PW2)]
        };
        b.sync(&mut server, interactive(), T0, answers).ok();
        assert_eq!(b.sk.as_ref().unwrap().expose(), new_sk.expose());
        assert_eq!(
            b.state.wrap_nonce, a.state.wrap_nonce,
            "after {writes} writes"
        );
    }
}

#[test]
fn a_pending_key_equal_to_the_current_one_settles_as_landed() {
    // After a crash between copying the pending key and writing the state, both slots hold the
    // new key.
    let (a, server) = lost_new_secret_key(true);
    let header = read_header(&server.current_file()).unwrap();
    let new_sk = a.pending.as_ref().unwrap();
    assert_eq!(
        vault_core::credentials::resolve_pending_secret_key(&header, PW2, new_sk, new_sk),
        Ok(PendingKeyOutcome::Landed)
    );
}
