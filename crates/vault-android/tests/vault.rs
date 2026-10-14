//! The vault through the binding layer's Rust API: the idle lock, unlocking and the biometric
//! key, edits through the host, autofill on a session, and procedures committed through the
//! state lock.

mod common;

use common::*;
use std::sync::atomic::Ordering;
use vault_android::{
    AppMatch, AppPage, Applied, Binding, ItemUri, KeySlot, NewItem, Outcome, Page, PasswdChange,
    Procedure, Prompt, Report, SaveOffer, Step, SyncMode, SyncOutcome, Vault,
    explicit_choice_allowed,
};

const IDLE: u64 = vault_android::DEFAULT_IDLE_MS;

fn login(name: &str, username: &str, password: &str, uris: &[(&str, &str)]) -> NewItem {
    NewItem {
        item_type: "login".into(),
        name: name.into(),
        folder: String::new(),
        favourite: false,
        notes: String::new(),
        username: username.into(),
        password: password.into(),
        uris: uris
            .iter()
            .map(|(u, m)| ItemUri {
                uri: (*u).into(),
                match_value: (*m).into(),
            })
            .collect(),
    }
}

fn app(signer: &str) -> AppPage {
    AppPage {
        package_name: "com.bank".into(),
        signers: vec![signer.into()],
        history: vec![signer.into()],
        multiple_signers: false,
    }
}

fn web(scheme: &str, host: &str) -> Page {
    Page::AndroidWeb {
        scheme: scheme.into(),
        host: host.into(),
    }
}

fn applied(p: &Procedure, background: bool) -> Applied {
    p.apply(background).unwrap()
}

/// Pushes the new vault's first generation, so the server holds it.
fn push_first(vault: &std::sync::Arc<Vault>, server: &mut Server) {
    let p = vault.clone().begin_sync(SyncMode::Background).unwrap();
    match run(&p, Some(server), vec![]) {
        Step::Done {
            report: Report::Sync { sync },
        } => assert_eq!(sync.outcome, SyncOutcome::Pushed),
        s => panic!("{s:?}"),
    }
    assert!(applied(&p, true).written);
}

#[test]
fn the_idle_lock_runs_before_every_call() {
    let v = new_vault(1);
    let (host, vault) = vault_with(&v);
    reopen(&host, &vault, &v.vault_key);
    assert!(vault.is_unlocked());

    // Calls that are not user activity do not hold the lock open.
    host.advance(IDLE - 1);
    assert!(vault.list(None, None).is_ok());
    assert!(!vault.lock_if_idle());
    host.advance(1);
    assert!(vault.lock_if_idle(), "the idle time has passed");
    assert!(!vault.is_unlocked());
    assert!(!vault.lock_if_idle(), "already locked");

    // User activity holds it open; the first call after the idle time locks before it runs.
    reopen(&host, &vault, &v.vault_key);
    host.advance(IDLE - 1);
    vault.record_activity();
    host.advance(IDLE - 1);
    assert!(vault.is_unlocked());
    host.advance(1);
    assert_eq!(code(vault.list(None, None)), "sync.locked");
    assert_eq!(code(vault.vault_key()), "sync.locked");

    vault.set_idle_time(10);
    reopen(&host, &vault, &v.vault_key);
    host.advance(10);
    assert_eq!(code(vault.credential("x".into())), "sync.locked");
}

#[test]
fn unlock_reopen_and_the_vault_key_for_the_biometric_wrap() {
    let v = new_vault(2);
    let (host, vault) = vault_with(&v);
    assert_eq!(
        code(vault.unlock("wrong password!".into())),
        "wrong_credentials"
    );
    vault.unlock(PW.into()).unwrap();
    let k = vault.vault_key().unwrap();
    assert_eq!(k.vault_key, v.vault_key.expose().to_vec());
    assert_eq!(k.wrap_nonce, v.state.wrap_nonce.to_vec());
    vault.lock();
    assert_eq!(code(vault.vault_key()), "sync.locked");

    // A wrap stored for another wrap_nonce is refused before the key is tried.
    assert_eq!(
        code(vault.reopen(k.vault_key.clone(), vec![0; 24])),
        "biometric.stale"
    );
    assert_eq!(
        code(vault.reopen(vec![9; 32], k.wrap_nonce.clone())),
        "integrity.aead"
    );
    assert_eq!(
        code(vault.reopen(vec![9; 31], k.wrap_nonce.clone())),
        "usage"
    );
    vault.reopen(k.vault_key, k.wrap_nonce).unwrap();
    assert!(vault.is_unlocked());

    assert_eq!(
        code(vault.secret_key_text("wrong password!".into())),
        "wrong_credentials"
    );
    let text = vault.secret_key_text(PW.into()).unwrap();
    assert_eq!(
        vault_android::decode_secret_key(text).unwrap(),
        v.secret_key.expose().to_vec()
    );

    *host.current.lock().unwrap() = None;
    vault.lock();
    assert_eq!(code(vault.unlock(PW.into())), "secret_key.missing");
}

#[test]
fn edits_read_apply_and_write_through_the_host() {
    let v = new_vault(3);
    let (host, vault) = vault_with(&v);
    assert_eq!(code(vault.add(login("a", "u", "p", &[]))), "sync.locked");
    reopen(&host, &vault, &v.vault_key);
    let summary = vault.state_summary().unwrap().unwrap();
    assert_eq!(summary.vault_id, hex::encode(v.state.vault_id));
    assert_eq!(summary.generation, None, "not pushed yet");
    assert_eq!(summary.wrap_nonce, v.state.wrap_nonce.to_vec());

    let id = vault
        .add(login("Bank", "ned", "p1", &[("bank.com", "base_domain")]))
        .unwrap();
    let id2 = vault.add(login("Other", "ned", "p2", &[])).unwrap();
    assert_eq!(
        host.device_writes.load(Ordering::SeqCst),
        1,
        "one device ID"
    );
    let names: Vec<String> = vault
        .list(None, None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["Bank", "Other"]);
    assert_eq!(vault.credential(id.clone()).unwrap().password, "p1");

    // The edited copy of item() goes back as JSON; only the changed key is applied.
    let base = vault.item(id.clone()).unwrap();
    let edited = base.replace("\"name\":\"Bank\"", "\"name\":\"My bank\"");
    assert_ne!(base, edited);
    vault.update(id.clone(), base, edited).unwrap();
    assert_eq!(
        vault
            .list(Some(String::new()), Some("my".into()))
            .unwrap()
            .len(),
        1
    );
    vault.remove(id2).unwrap();
    assert_eq!(vault.list(None, None).unwrap().len(), 1);

    // The session follows the state written; a fresh session over the same files agrees.
    let other = Vault::new(host.clone());
    reopen(&host, &other, &v.vault_key);
    assert_eq!(
        other.list(None, None).unwrap(),
        vault.list(None, None).unwrap()
    );

    // A failed write returns the session to the state on disk, and the next edit starts from
    // it: the lost item never reaches the disk or the session.
    let before = host.state.lock().unwrap().clone();
    host.fail_writes.store(true, Ordering::SeqCst);
    assert_eq!(code(vault.add(login("Lost", "u", "p", &[]))), "host.io");
    assert!(vault.is_unlocked());
    assert_eq!(vault.list(None, None).unwrap().len(), 1);
    assert_eq!(*host.state.lock().unwrap(), before);
    host.fail_writes.store(false, Ordering::SeqCst);
    vault.add(login("Kept", "u", "p", &[])).unwrap();
    let names: Vec<String> = vault
        .list(None, None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["Kept", "My bank"]);
    assert_eq!(
        other_view(&host, &v),
        names,
        "the disk agrees with the session"
    );
    assert_eq!(
        host.wrap_deletes.load(Ordering::SeqCst),
        0,
        "edits keep wrap_nonce"
    );
}

#[test]
fn autofill_on_the_session_with_the_compiled_in_list() {
    let v = new_vault(4);
    let (host, vault) = vault_with(&v);
    reopen(&host, &vault, &v.vault_key);
    let page = web("https", "www.bank.co.uk");

    // A new login on an Android web page: the host as its name, the origin as its URI.
    let offer = vault
        .save_offer(page.clone(), "ned".into(), "p1".into())
        .unwrap();
    let SaveOffer::New { name, uris, apps } = offer.clone() else {
        panic!("{offer:?}")
    };
    assert_eq!(name, "www.bank.co.uk");
    assert_eq!(uris[0].uri, "https://www.bank.co.uk");
    assert_eq!(uris[0].match_value, "base_domain");
    assert!(apps.is_empty());
    let id = vault
        .apply_save_offer(offer, "ned".into(), "p1".into())
        .unwrap()
        .unwrap();

    // The registrable domain comes from the compiled-in list: co.uk is a public suffix.
    let c = vault.candidates(web("https", "login.bank.co.uk")).unwrap();
    assert_eq!(
        (c.len(), c[0].outcome, c[0].app_match),
        (1, Outcome::Fill, None)
    );
    assert!(
        vault
            .candidates(web("https", "evil.co.uk"))
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .candidates(web("http", "www.bank.co.uk"))
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .candidates(web("https", "bank.co.uk:443"))
            .unwrap()
            .is_empty()
    );

    // The same username with a new password updates it.
    let offer = vault
        .save_offer(page.clone(), "ned".into(), "p2".into())
        .unwrap();
    assert_eq!(offer, SaveOffer::Update { id: id.clone() });
    assert_eq!(
        vault
            .apply_save_offer(offer, "ned".into(), "p2".into())
            .unwrap(),
        Some(id.clone())
    );
    assert_eq!(vault.credential(id.clone()).unwrap().password, "p2");
    assert!(
        vault
            .item(id)
            .unwrap()
            .contains("\"password_history\":[{\"password\":\"p1\"")
    );
    assert_eq!(
        vault.save_offer(page, "ned".into(), "p2".into()).unwrap(),
        SaveOffer::None
    );
    assert_eq!(
        vault
            .apply_save_offer(SaveOffer::None, String::new(), String::new())
            .unwrap(),
        None
    );

    assert!(explicit_choice_allowed(web("https", "bank.com")));
    assert!(!explicit_choice_allowed(web("http", "bank.com")));
    assert!(explicit_choice_allowed(web("http", "nas.lan")));
    assert!(explicit_choice_allowed(web("http", "192.168.1.2")));
    assert!(!explicit_choice_allowed(web("ftp", "bank.com")));
    assert!(explicit_choice_allowed(Page::App { app: app("aa") }));
}

#[test]
fn app_saves_and_bindings_after_a_pull() {
    let v = new_vault(5);
    let (host, vault) = vault_with(&v);
    reopen(&host, &vault, &v.vault_key);
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let page = Page::App { app: app(&a) };

    // A new item for an app with one signer records a bound association.
    let offer = vault
        .save_offer(page.clone(), "ned".into(), "p1".into())
        .unwrap();
    let id = vault
        .apply_save_offer(offer, "ned".into(), "p1".into())
        .unwrap()
        .unwrap();
    assert!(vault.item(id.clone()).unwrap().contains(&format!(
        "\"apps\":[{{\"cert_sha256\":\"{a}\",\"package\":\"com.bank\"}}]"
    )));
    let c = vault.candidates(page.clone()).unwrap();
    assert_eq!(
        (c[0].outcome, c[0].app_match),
        (Outcome::Fill, Some(AppMatch::Fill))
    );

    // An unbound association confirms, and binds only after a pull in the same unlock.
    let unbound = vault
        .add(login(
            "Imported",
            "ned",
            "p9",
            &[("androidapp://com.bank", "base_domain")],
        ))
        .unwrap();
    let c = vault.candidates(page.clone()).unwrap();
    let found = c.iter().find(|c| c.id == unbound).unwrap();
    assert_eq!(
        (found.outcome, found.app_match),
        (Outcome::Confirm, Some(AppMatch::Bind))
    );
    assert_eq!(
        vault.record_app_fill(unbound.clone(), app(&a)).unwrap(),
        Binding::NotPulled
    );
    // A fill of the bound item records nothing, so it needs no pull.
    assert_eq!(
        vault.record_app_fill(id.clone(), app(&a)).unwrap(),
        Binding::Unchanged
    );
    let mut server = Server::default();
    push_first(&vault, &mut server);
    assert_eq!(
        vault.record_app_fill(unbound.clone(), app(&a)).unwrap(),
        Binding::Recorded
    );
    let c = vault.candidates(page).unwrap();
    assert!(c.iter().all(|c| c.app_match == Some(AppMatch::Fill)));

    // A rotated key rebinds; an app whose signature changed binds nothing.
    let rotated = AppPage {
        package_name: "com.bank".into(),
        signers: vec![b.clone()],
        history: vec![a.clone(), b.clone()],
        multiple_signers: false,
    };
    let c = vault
        .candidates(Page::App {
            app: rotated.clone(),
        })
        .unwrap();
    assert!(c.iter().all(|c| c.app_match == Some(AppMatch::Rebind)));
    assert_eq!(
        vault.record_app_fill(id.clone(), rotated.clone()).unwrap(),
        Binding::Recorded
    );
    assert_eq!(
        vault
            .record_app_fill(id.clone(), app(&"c".repeat(64)))
            .unwrap(),
        Binding::Unchanged
    );
    assert!(vault.item(id.clone()).unwrap().contains(&b));

    // A lock forgets the pull: a rebind waits again, a fill still records nothing.
    vault.lock();
    reopen(&host, &vault, &v.vault_key);
    assert_eq!(
        vault.record_app_fill(unbound, rotated).unwrap(),
        Binding::NotPulled
    );
    assert_eq!(
        vault.record_app_fill(id, app(&b)).unwrap(),
        Binding::Unchanged
    );
}

#[test]
fn procedures_commit_under_the_state_lock() {
    let v = new_vault(6);
    let (host, vault) = vault_with(&v);
    let mut server = Server::default();

    // A background sync while locked has no vault key; it stops at the prompt it cannot ask.
    let p = vault.clone().begin_sync(SyncMode::Background).unwrap();
    assert_eq!(code(p.apply(true)), "usage", "not finished");
    let step = run(&p, Some(&mut server), vec![]);
    assert!(matches!(step, Step::Failed { .. }), "{step:?}");
    p.apply(true).unwrap();
    assert!(!vault.is_unlocked());

    // The unlock procedure asks for the master password and opens the session.
    let p = vault.clone().begin_unlock().unwrap();
    let step = run(&p, Some(&mut server), vec![password(PW)]);
    let Step::Done {
        report: Report::Unlock { sync, sync_error },
    } = step
    else {
        panic!("{step:?}")
    };
    assert!(sync_error.is_none(), "{sync_error:?}");
    assert_eq!(sync.unwrap().outcome, SyncOutcome::Pushed);
    let a = applied(&p, false);
    assert!(a.written && a.unlocked && !a.superseded && !a.wrap_changed);
    assert!(vault.is_unlocked());
    assert_eq!(server.files.len(), 1);
    assert_eq!(host.state().accepted.unwrap().generation, 1);

    // A sync that started unlocked commits after a lock, but does not unlock again.
    vault.add(login("Bank", "ned", "p1", &[])).unwrap();
    let p = vault.clone().begin_sync(SyncMode::Background).unwrap();
    vault.lock();
    assert!(matches!(
        run(&p, Some(&mut server), vec![]),
        Step::Done { .. }
    ));
    let a = applied(&p, true);
    assert!(a.written && !a.unlocked);
    assert_eq!(server.files.len(), 2);

    // A new master password changes wrap_nonce: the biometric wrap goes with the commit.
    reopen(&host, &vault, &v.vault_key);
    let old_wrap = host.state().wrap_nonce;
    let deletes = host.wrap_deletes.load(Ordering::SeqCst);
    let p = vault
        .clone()
        .begin_passwd(PasswdChange::NewPassword, None)
        .unwrap();
    let step = run(
        &p,
        Some(&mut server),
        vec![password("another long password")],
    );
    assert!(
        matches!(
            step,
            Step::Done {
                report: Report::Passwd { .. }
            }
        ),
        "{step:?}"
    );
    let a = applied(&p, false);
    assert!(a.written && a.wrap_changed && a.unlocked);
    assert_eq!(host.wrap_deletes.load(Ordering::SeqCst), deletes + 1);
    assert_ne!(host.state().wrap_nonce, old_wrap);
    assert_eq!(
        vault.list(None, None).unwrap().len(),
        1,
        "the session follows the commit"
    );
    vault.lock();
    assert_eq!(
        code(vault.reopen(v.vault_key.expose().to_vec(), old_wrap.to_vec())),
        "biometric.stale"
    );
    vault.unlock("another long password".into()).unwrap();

    // A setup needs a phone without a vault.
    assert_eq!(code(vault.clone().begin_setup()), "usage");
}

#[test]
fn a_new_secret_key_is_saved_then_promoted() {
    let v = new_vault(7);
    let (host, vault) = vault_with(&v);
    let mut server = Server::default();
    reopen(&host, &vault, &v.vault_key);
    push_first(&vault, &mut server);

    let p = vault
        .clone()
        .begin_passwd(PasswdChange::NewSecretKey, Some(64))
        .unwrap();
    let mut step = p.start().unwrap();
    let mut saved = false;
    loop {
        step = match step {
            Step::Request { request } => p.step(server.handle(&request)).unwrap(),
            Step::Prompt {
                prompt: Prompt::OldMasterPassword { .. } | Prompt::MasterPassword { .. },
            } => p
                .step(vault_android::Input::Answer {
                    answer: password(PW),
                })
                .unwrap(),
            Step::Save {
                slot,
                kit,
                vault_id,
            } => {
                assert_eq!(slot, KeySlot::Pending);
                assert_eq!(vault_id, hex::encode(v.state.vault_id));
                let key = vault_android::decode_secret_key(kit).unwrap();
                p.apply_save().unwrap();
                assert_eq!(host.pending.lock().unwrap().as_ref(), Some(&key));
                assert!(host.state().pending_secret_key);
                assert_eq!(code(p.apply_save()), "usage", "one save, applied once");
                saved = true;
                p.step(vault_android::Input::Saved).unwrap()
            }
            Step::Done { .. } => break,
            s => panic!("{s:?}"),
        };
    }
    assert!(saved);
    let pending = host.pending.lock().unwrap().clone().unwrap();
    let a = applied(&p, false);
    assert!(a.written && !a.pending_left);
    assert_eq!(host.current.lock().unwrap().as_ref(), Some(&pending));
    assert!(host.pending.lock().unwrap().is_none());
    assert!(!host.state().pending_secret_key);
    let text = vault.secret_key_text(PW.into()).unwrap();
    assert_eq!(vault_android::decode_secret_key(text).unwrap(), pending);
}

#[test]
fn setup_then_restore_from_a_revision() {
    // A laptop's vault on the server; the phone sets up from it.
    let v = new_vault(8);
    let (laptop_host, laptop) = vault_with(&v);
    let mut server = Server::default();
    reopen(&laptop_host, &laptop, &v.vault_key);
    laptop.add(login("Bank", "ned", "p1", &[])).unwrap();
    push_first(&laptop, &mut server);
    laptop.add(login("Mail", "ned", "p2", &[])).unwrap();
    let p = laptop.clone().begin_sync(SyncMode::Background).unwrap();
    run(&p, Some(&mut server), vec![]);
    applied(&p, true);
    assert_eq!(server.files.len(), 2);

    let host = MemHost::new();
    let vault = Vault::new(host.clone());
    assert!(vault.state_summary().unwrap().is_none());
    assert_eq!(
        code(vault.clone().begin_sync(SyncMode::Background)),
        "state.no_vault"
    );
    let p = vault.clone().begin_setup().unwrap();
    // Setup asks for the secret key, then the kit's vault ID, then the master password.
    let answers = vec![
        vault_android::Answer::SecretKey {
            secret_key: v.secret_key.expose().to_vec(),
        },
        vault_android::Answer::VaultId { vault_id: None },
        password(PW),
    ];
    let step = run(&p, Some(&mut server), answers);
    assert!(
        matches!(
            step,
            Step::Done {
                report: Report::Setup
            }
        ),
        "{step:?}"
    );
    let a = applied(&p, false);
    assert!(a.written && a.unlocked && a.wrap_changed);
    assert_eq!(
        host.current.lock().unwrap().as_ref(),
        Some(&v.secret_key.expose().to_vec())
    );
    assert_eq!(vault.list(None, None).unwrap().len(), 2);

    // Restore the first revision's items over the current ones.
    let r = vault.clone().begin_fetch_revision(1).unwrap();
    let step = run(&r, Some(&mut server), vec![]);
    assert!(
        matches!(
            step,
            Step::Done {
                report: Report::Revision { id: 1, .. }
            }
        ),
        "{step:?}"
    );
    let preview = r.restore_preview(None).unwrap();
    assert_eq!((preview.added, preview.removed), (0, 1), "{preview:?}");
    let done = r.restore(None).unwrap();
    assert_eq!(done, preview);
    let names: Vec<String> = vault
        .list(None, None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["Bank"]);
    let not_a_revision = vault.clone().begin_sync(SyncMode::Background).unwrap();
    assert_eq!(code(not_a_revision.restore_preview(None)), "usage");
}

#[test]
fn a_superseded_save_leaves_the_pending_slot_untouched() {
    let v = new_vault(10);
    let (host, vault) = vault_with(&v);
    let mut server = Server::default();
    reopen(&host, &vault, &v.vault_key);
    push_first(&vault, &mut server);

    let p = vault
        .clone()
        .begin_passwd(PasswdChange::NewSecretKey, None)
        .unwrap();
    let mut step = p.start().unwrap();
    while !matches!(step, Step::Save { .. }) {
        step = match step {
            Step::Request { request } => p.step(server.handle(&request)).unwrap(),
            Step::Prompt { .. } => p
                .step(vault_android::Input::Answer {
                    answer: password(PW),
                })
                .unwrap(),
            s => panic!("{s:?}"),
        };
    }
    // Another sync commits while the kit is shown: its accepted generation moves on.
    let mut other = host.state();
    other.accepted.as_mut().unwrap().generation += 1;
    host.set_state(&other);
    assert_eq!(code(p.apply_save()), "state.superseded");
    assert!(host.pending.lock().unwrap().is_none(), "no key was written");
    assert!(host.state() == other, "no state was written");
    assert_eq!(
        host.current.lock().unwrap().as_ref(),
        Some(&v.secret_key.expose().to_vec())
    );
}

#[test]
fn app_pages_go_through_the_spec_shape() {
    let v = new_vault(11);
    let (host, vault) = vault_with(&v);
    reopen(&host, &vault, &v.vault_key);
    let a = "a".repeat(64);
    let id = vault
        .apply_save_offer(
            SaveOffer::New {
                name: "com.bank".into(),
                uris: Vec::new(),
                apps: vec![vault_android::AppBinding {
                    package_name: "com.bank".into(),
                    cert_sha256: a.clone(),
                }],
            },
            "ned".into(),
            "p1".into(),
        )
        .unwrap()
        .unwrap();
    let mut server = Server::default();
    push_first(&vault, &mut server);
    let page = |signers: Vec<String>, history: Vec<String>, multiple_signers| Page::App {
        app: AppPage {
            package_name: "com.bank".into(),
            signers,
            history,
            multiple_signers,
        },
    };
    let kind = |p: Page| {
        let c = vault.candidates(p).unwrap();
        (c[0].outcome, c[0].app_match)
    };
    let fill = (Outcome::Fill, Some(AppMatch::Fill));
    let unverified = (Outcome::Confirm, Some(AppMatch::Unverified));
    assert_eq!(kind(page(vec![a.clone()], vec![a.clone()], false)), fill);
    // Signing information that does not fit the spec's shape counts as unread.
    for (signers, history, multiple) in [
        (vec![a.to_uppercase()], vec![a.to_uppercase()], false),
        (vec![a.clone()], vec![], false),
        (vec![a.clone()], vec![a.clone(), "b".repeat(64)], false),
        (vec![a.clone(), "b".repeat(64)], vec![], false),
        (vec![a.clone()], vec![a.clone()], true),
    ] {
        let p = page(signers, history, multiple);
        assert_eq!(kind(p.clone()), unverified, "{p:?}");
        let Page::App { app } = p else { unreachable!() };
        assert_eq!(
            vault.record_app_fill(id.clone(), app).unwrap(),
            Binding::Unchanged
        );
    }
    let empty = AppPage {
        package_name: String::new(),
        signers: vec![a.clone()],
        history: vec![a],
        multiple_signers: false,
    };
    assert_eq!(
        code(vault.candidates(Page::App { app: empty.clone() })),
        "usage"
    );
    assert_eq!(code(vault.record_app_fill(id, empty)), "usage");
    assert!(!explicit_choice_allowed(Page::App {
        app: AppPage {
            package_name: String::new(),
            signers: Vec::new(),
            history: Vec::new(),
            multiple_signers: false,
        }
    }));
}

/// The item names a fresh vault over the same files lists.
fn other_view(host: &std::sync::Arc<MemHost>, v: &NewVault) -> Vec<String> {
    let other = Vault::new(host.clone());
    reopen(host, &other, &v.vault_key);
    other
        .list(None, None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[test]
fn a_panic_under_the_state_lock_locks_the_session() {
    let v = new_vault(12);
    let (host, vault) = vault_with(&v);
    reopen(&host, &vault, &v.vault_key);
    vault.add(login("Bank", "ned", "p1", &[])).unwrap();

    // A host method that panics while the lock is held poisons it.
    host.panic_reads.store(true, Ordering::SeqCst);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vault.add(login("Lost", "u", "p", &[]))
    }));
    assert!(r.is_err(), "the panic reached the caller");
    host.panic_reads.store(false, Ordering::SeqCst);

    // The next call takes the lock over with the session zeroed, and the vault keeps working.
    assert!(!vault.is_unlocked());
    assert_eq!(code(vault.list(None, None)), "sync.locked");
    assert!(vault.state_summary().unwrap().is_some());
    reopen(&host, &vault, &v.vault_key);
    vault.add(login("Kept", "u", "p", &[])).unwrap();
    assert_eq!(other_view(&host, &v), ["Bank", "Kept"]);
}
