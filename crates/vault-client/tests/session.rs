//! The shared session and procedure driver (`vault_client::session`) that the Firefox and
//! Android bindings wrap: items and edits, autofill entry points, restore, and procedures whose
//! saves and ends commit through a host, including the first state after setup and a pending
//! secret key promoted without reading the host's pending slot.

mod common;

use common::*;
use vault_client::autofill::{AppPage, Outcome, SaveOffer};
use vault_client::commit::{ApplyError, CommitHost};
use vault_client::passwd::{PasswdChange, PasswdOptions};
use vault_client::session::{Event, NewItem, Procedure, Report, Session};
use vault_client::sync::Mode;
use vault_client::{Answer, ClientError, ClientState, Input, Keys, SecretKeyStore};
use vault_core::body::{Body, LoginUri};
use vault_core::kdf::FLOOR;
use vault_core::secret::{SecretKey, VaultKey};
use vault_core::sync::SyncState;
use vault_core::{Error, InputKind};

const PW: &str = "correct horse battery staple";

fn com(host: &str) -> Option<String> {
    (host == "com" || host.ends_with(".com")).then(|| "com".to_owned())
}

fn uri(u: &str) -> LoginUri {
    LoginUri {
        uri: u.into(),
        match_value: "base_domain".into(),
        extra: Default::default(),
    }
}

/// A session over an empty vault that opens with a cached key.
fn session() -> (Session, ClientState) {
    let fx = Fixture::new(3);
    let state = fx.state(fx.file(1, &Body::default(), 1));
    (Session::reopen(state.clone(), fx.key()).unwrap(), state)
}

#[test]
fn items_edits_and_locking() {
    let (mut s, state) = session();
    let dev = [9; 16];
    let (id, next) = s
        .add(
            &state,
            &dev,
            T0,
            &mut TestRng(1),
            NewItem {
                item_type: "login".into(),
                name: "GitHub".into(),
                folder: "Work/Code".into(),
                username: "ned".into(),
                password: "hunter2-hunter2".into(),
                uris: vec![uri("github.com")],
                ..NewItem::default()
            },
        )
        .unwrap();
    let state = next.expect("a changed state");
    assert_eq!(s.state(), &state, "the session holds the state it returned");
    let list = s.list(None, None).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].name.as_str(), list[0].username.as_str()),
        ("GitHub", "ned")
    );
    assert_eq!(list[0].modified, T0);
    assert!(list[0].supported && !list[0].review);
    assert_eq!(s.folders().unwrap(), ["Work", "Work/Code"]);
    assert_eq!(s.list(Some("Home"), None).unwrap().len(), 0);
    assert_eq!(s.list(Some("Work"), Some("git")).unwrap().len(), 1);
    assert_eq!(
        s.credential(&id).unwrap().password.as_str(),
        "hunter2-hunter2"
    );

    // The user edits the username while another change sets the password: both survive.
    let base = s.item(&id).unwrap().fields().unwrap().clone();
    let mut other = base.clone();
    other.login.as_mut().unwrap().password = "from-a-sync-1".into();
    let state = s
        .update(&state, &dev, T0 + 1, &mut TestRng(2), &id, &base, &other)
        .unwrap()
        .unwrap();
    let mut edited = base.clone();
    edited.login.as_mut().unwrap().username = "ned2".into();
    let state = s
        .update(&state, &dev, T0 + 2, &mut TestRng(3), &id, &base, &edited)
        .unwrap()
        .unwrap();
    let c = s.credential(&id).unwrap();
    assert_eq!(
        (c.username.as_str(), c.password.as_str()),
        ("ned2", "from-a-sync-1")
    );
    assert!(
        s.update(&state, &dev, T0 + 3, &mut TestRng(4), &id, &base, &base)
            .unwrap()
            .is_none(),
        "an unchanged edit writes nothing"
    );

    // Autofill over the session's items.
    let cands = s.candidates("https://github.com/login", &com).unwrap();
    assert_eq!(cands.len(), 1);
    assert_eq!(
        (cands[0].id.as_str(), cands[0].outcome),
        (id.as_str(), Outcome::Fill)
    );
    assert_eq!(
        s.suffix_hosts("https://github.com/x").unwrap(),
        ["github.com"]
    );
    assert_eq!(
        s.save_offer("https://github.com/", "ned2", "new-pw", &com)
            .unwrap(),
        SaveOffer::Update { id: id.clone() }
    );

    // A note, an unknown type, a missing item.
    let (note, state) = s
        .add(
            &state,
            &dev,
            T0 + 4,
            &mut TestRng(5),
            NewItem {
                item_type: "note".into(),
                name: "Note".into(),
                ..NewItem::default()
            },
        )
        .unwrap();
    let state = state.unwrap();
    assert!(s.credential(&note).is_err(), "a note has no credential");
    let bad = NewItem {
        item_type: "card".into(),
        name: "x".into(),
        ..NewItem::default()
    };
    assert_eq!(
        s.add(&state, &dev, T0, &mut TestRng(6), bad).err(),
        Some(ClientError::Core(Error::InvalidInput(
            InputKind::UnsupportedItem
        )))
    );
    assert_eq!(
        s.remove(&state, &dev, T0, &mut TestRng(7), "nope").err(),
        Some(ClientError::Core(Error::InvalidInput(InputKind::NotFound)))
    );
    let state = s
        .remove(&state, &dev, T0 + 5, &mut TestRng(8), &id)
        .unwrap()
        .unwrap();
    assert_eq!(s.list(None, None).unwrap().len(), 1);

    // Another context reloads; a lock zeroes the key and the body.
    let vk = s.vault_key().unwrap().clone_secret();
    let mut other = Session::reopen(state.clone(), vk).unwrap();
    other.reload(state).unwrap();
    assert!(!other.read_only().unwrap());
    s.lock();
    assert_eq!(s.list(None, None).err(), Some(ClientError::Locked));
    assert!(s.vault_key().is_err());
    assert_eq!(
        s.reload(other.state().clone()).err(),
        Some(ClientError::Locked)
    );
}

#[test]
fn a_clock_before_the_build_time_refuses_an_edit() {
    let (mut s, state) = session();
    let note = NewItem {
        item_type: "note".into(),
        name: "n".into(),
        ..NewItem::default()
    };
    assert_eq!(
        s.add(&state, &[1; 16], 0, &mut TestRng(1), note).err(),
        Some(ClientError::Core(Error::ClockBeforeBuildTime))
    );
}

/// Runs a procedure, answering from `server` and `answers`, carrying out saves through `host`.
fn run(
    p: &mut Procedure,
    server: &mut Server,
    started: &mut ClientState,
    on_disk: &mut ClientState,
    host_slots: &mut (Option<SecretKey>, Option<SecretKey>),
    mut answers: Vec<Answer>,
) -> bool {
    let mut input = None;
    loop {
        let event = match input.take() {
            None => p.start(T0),
            Some(i) => p.step(i, T0),
        };
        input = Some(match event {
            Event::Request(r) => match server.handle(TOKEN, &r) {
                Some(resp) => Input::Response(resp),
                None => Input::Unreachable,
            },
            Event::Prompt(_) => Input::Answer(answers.remove(0)),
            Event::Save(save) => {
                let saved = save.state.clone();
                let snapshot = on_disk.clone();
                let mut host = Slots {
                    state: on_disk,
                    current: &mut host_slots.0,
                    pending: &mut host_slots.1,
                };
                let _ = p
                    .apply_save(started, &snapshot, T0, &mut TestRng(9), &mut host)
                    .unwrap_or_else(|_| panic!("save"));
                *started = saved;
                Input::Saved
            }
            Event::Done(f) => return f.result.is_ok(),
        });
    }
}

#[test]
fn procedures_commit_saves_and_ends_through_a_host() {
    let v = vault_core::credentials::create_vault(&mut TestRng(40), PW, FLOOR, false).unwrap();
    let mut state = ClientState::new(
        SyncState {
            vault_id: v.state.vault_id,
            accepted: None,
            wrap_nonce: v.state.wrap_nonce,
            retired_wrap_nonces: Vec::new(),
        },
        v.file,
        SecretKeyStore::File,
    );
    let mut server = Server::default();
    let keys = |vk: &VaultKey, sk: Option<&SecretKey>| Keys {
        vault_key: Some(vk.clone_secret()),
        secret_key: sk.map(SecretKey::clone_secret),
        pending_secret_key: None,
    };
    let mut slots = (Some(v.secret_key.clone_secret()), None);

    // A sync pushes generation 1.
    let mut p = Procedure::sync(
        state.clone(),
        keys(&v.vault_key, None),
        Mode::Background,
        TestRng(41),
    );
    let mut on_disk = state.clone();
    assert!(run(
        &mut p,
        &mut server,
        &mut state.clone(),
        &mut on_disk,
        &mut slots,
        vec![]
    ));
    assert!(matches!(p.finished().unwrap().result, Ok(Report::Sync(_))));
    let mut host = Slots {
        state: &mut on_disk,
        current: &mut slots.0,
        pending: &mut slots.1,
    };
    let snapshot = state.clone();
    p.apply(
        Some(&state),
        Some(&snapshot),
        true,
        T0,
        &mut TestRng(42),
        &mut host,
    )
    .unwrap()
    .unwrap();
    state = on_disk.clone();

    // --new-secret-key: the save stores the pending key first; the end promotes it from the
    // key the procedure holds, then writes the state, then deletes the pending key.
    let sk = slots.0.as_ref().unwrap().clone_secret();
    let options = PasswdOptions {
        change: PasswdChange::NewSecretKey {
            new_password: false,
        },
        kdf: FLOOR,
        test_kdf: false,
    };
    let mut p = Procedure::passwd(
        state.clone(),
        keys(&v.vault_key, Some(&sk)),
        options,
        TestRng(43),
    );
    let mut started = state.clone();
    assert!(run(
        &mut p,
        &mut server,
        &mut started,
        &mut on_disk,
        &mut slots,
        vec![pw(PW)]
    ));
    let pending = slots
        .1
        .as_ref()
        .expect("the save stored the pending key")
        .clone_secret();
    assert!(on_disk.pending_secret_key, "the saved state records it");
    // A host that cannot read its pending slot still promotes it.
    let mut host = NoPendingRead {
        slots: Slots {
            state: &mut on_disk,
            current: &mut slots.0,
            pending: &mut slots.1,
        },
    };
    let snapshot = host.slots.state.clone();
    p.apply(
        Some(&started),
        Some(&snapshot),
        false,
        T0,
        &mut TestRng(44),
        &mut host,
    )
    .unwrap()
    .unwrap();
    assert_eq!(slots.0.as_ref().unwrap().expose(), pending.expose());
    assert!(slots.1.is_none(), "the pending slot is deleted");
    assert!(!on_disk.pending_secret_key);
    let new_vk = p.vault_key().unwrap().clone_secret();
    assert!(Session::reopen(on_disk.clone(), new_vk).is_ok());
    assert_eq!(
        Session::unlock(on_disk.clone(), &sk, PW).err(),
        Some(ClientError::Core(Error::WrongCredentials))
    );

    // Setup on a second client: no earlier state, so the first state is written as it is.
    let mut p = Procedure::setup(SecretKeyStore::Keyring, TestRng(45));
    let mut fresh = ClientState::new(
        SyncState {
            vault_id: [0; 16],
            accepted: None,
            wrap_nonce: [0; 24],
            retired_wrap_nonces: Vec::new(),
        },
        Vec::new(),
        SecretKeyStore::Keyring,
    );
    let mut second = (None, None);
    let answers = vec![
        Answer::SecretKey(pending.clone_secret()),
        Answer::VaultId(None),
        pw(PW),
    ];
    assert!(run(
        &mut p,
        &mut server,
        &mut fresh.clone(),
        &mut fresh,
        &mut second,
        answers
    ));
    let mut written = fresh.clone();
    let mut host = Slots {
        state: &mut written,
        current: &mut second.0,
        pending: &mut second.1,
    };
    assert!(matches!(
        p.apply(Some(&on_disk), None, false, T0, &mut TestRng(46), &mut host),
        Err(ApplyError::Client(ClientError::UnexpectedInput))
    ));
    let a = p
        .apply(None, None, false, T0, &mut TestRng(46), &mut host)
        .unwrap()
        .expect("written");
    assert_eq!(a.commit.state.as_ref(), Some(&written));
    assert_eq!(second.0.as_ref().unwrap().expose(), pending.expose());
    assert_eq!(written.secret_key_store, SecretKeyStore::Keyring);
    assert_eq!(written.accepted, on_disk.accepted);

    // Restore through a fetched revision: generation 1's body, under the old wrap.
    let mut p = Procedure::fetch_revision(
        on_disk.clone(),
        keys(p.vault_key().unwrap(), Some(&pending)),
        1,
        TestRng(47),
    );
    let mut scratch = on_disk.clone();
    let ok = run(
        &mut p,
        &mut server,
        &mut on_disk.clone(),
        &mut scratch,
        &mut (None, None),
        vec![pw(PW), Answer::Declined],
    );
    // The revision is under the retired wrap, at or below its record, so it needs the old
    // credentials; declining the second prompt ends the fetch.
    assert!(!ok);
    assert!(p.revision().is_none());
}

/// A host that only queues writes, as an IndexedDB transaction does: it cannot read a slot.
struct NoPendingRead<'a> {
    slots: Slots<'a>,
}

impl CommitHost for NoPendingRead<'_> {
    type Error = &'static str;

    fn store_current(
        &mut self,
        s: SecretKeyStore,
        id: &[u8; 16],
        k: &SecretKey,
    ) -> Result<(), Self::Error> {
        self.slots.store_current(s, id, k)
    }

    fn store_pending(
        &mut self,
        s: SecretKeyStore,
        id: &[u8; 16],
        k: &SecretKey,
    ) -> Result<(), Self::Error> {
        self.slots.store_pending(s, id, k)
    }

    fn copy_pending_to_current(
        &mut self,
        _: SecretKeyStore,
        _: &[u8; 16],
    ) -> Result<(), Self::Error> {
        Err("this host cannot read its pending slot")
    }

    fn delete_pending(&mut self, s: SecretKeyStore, id: &[u8; 16]) -> Result<(), Self::Error> {
        self.slots.delete_pending(s, id)
    }

    fn write_state(&mut self, state: &ClientState) -> Result<(), Self::Error> {
        self.slots.write_state(state)
    }
}

#[test]
fn restore_through_a_fetched_revision() {
    let fx = Fixture::new(5);
    let mut client = Client::new(fx.state(fx.file(1, &Body::default(), 1)), fx.key(), 7);
    let mut server = Server::default();
    client.edit(|b, rng, dev| {
        add_login(b, rng, dev, "kept", "k", T0);
    });
    client.sync(&mut server, Mode::Background, T0, vec![]);
    let revision_id = server.current().unwrap().id;
    client.edit(|b, rng, dev| {
        add_login(b, rng, dev, "later", "l", T0 + 1);
    });
    client.sync(&mut server, Mode::Background, T0 + 1, vec![]);

    let mut p =
        Procedure::fetch_revision(client.state.clone(), client.keys(), revision_id, TestRng(3));
    let mut state = client.state.clone();
    assert!(run(
        &mut p,
        &mut server,
        &mut state.clone(),
        &mut state,
        &mut (None, None),
        vec![]
    ));
    let rev = p.revision().expect("the opened revision");
    let mut s = Session::reopen(
        client.state.clone(),
        client.vk.as_ref().unwrap().clone_secret(),
    )
    .unwrap();
    let preview = s.restore_preview(rev, None).unwrap();
    assert_eq!((preview.added, preview.changed, preview.removed), (0, 1, 1));
    let (next, summary) = s
        .restore(
            &client.state,
            &client.device,
            T0 + 2,
            &mut TestRng(4),
            rev,
            None,
        )
        .unwrap();
    assert_eq!(summary, preview);
    assert_eq!(s.state(), &next);
    let names: Vec<String> = s
        .list(None, None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["kept"]);
}

#[test]
fn app_pages_bind_after_a_confirmed_fill() {
    use vault_client::autofill::{Offer, Page, android_web_page, page_url};
    let (mut s, state) = session();
    let dev = [9; 16];
    let digest = "ab".repeat(32);
    let app = AppPage::new(
        "com.example.bank".into(),
        vec![digest.clone()],
        vec![digest.clone()],
        false,
    )
    .unwrap();
    let (id, state) = s
        .add(
            &state,
            &dev,
            T0,
            &mut TestRng(1),
            NewItem {
                item_type: "login".into(),
                name: "Bank".into(),
                username: "ned".into(),
                password: "pw-pw-pw-pw".into(),
                uris: vec![uri("androidapp://com.example.bank"), uri("bank.com")],
                ..NewItem::default()
            },
        )
        .unwrap();
    let state = state.unwrap();
    let page = Page::App(app.clone());
    let none = |_: &str| -> Option<String> { panic!("an app page looks up no suffix") };

    // An unbound association confirms, and a confirmed fill binds the current certificate.
    let c = s.page_candidates(&page, &none).unwrap();
    assert_eq!(
        (c[0].id.as_str(), c[0].outcome),
        (id.as_str(), Outcome::Confirm)
    );
    assert_eq!(
        s.page_suffix_hosts(&page).unwrap(),
        ["bank.com"],
        "an app page: the item URI domains only"
    );
    let state = s
        .record_app_fill(&state, &dev, T0 + 1, &mut TestRng(2), &id, &app)
        .unwrap()
        .expect("a binding");
    let apps = &s.item(&id).unwrap().login().unwrap().apps;
    assert_eq!(apps.len(), 1);
    assert_eq!(
        (apps[0].package.as_str(), apps[0].cert_sha256.as_str()),
        ("com.example.bank", digest.as_str())
    );
    assert_eq!(
        s.item(&id).unwrap().modified,
        T0 + 1,
        "a binding is a stamped local edit"
    );
    let c = s.page_candidates(&page, &none).unwrap();
    assert_eq!(c[0].outcome, Outcome::Fill);
    assert!(
        s.record_app_fill(&state, &dev, T0 + 2, &mut TestRng(3), &id, &app)
            .unwrap()
            .is_none(),
        "a bound fill records nothing"
    );

    // More than one signer: confirms and never binds.
    let unverified = AppPage::new(
        "com.example.other".into(),
        vec![digest.clone(), "cd".repeat(32)],
        Vec::new(),
        true,
    )
    .unwrap();
    let (other, state2) = s
        .add(
            &state,
            &dev,
            T0 + 3,
            &mut TestRng(4),
            NewItem {
                item_type: "login".into(),
                name: "Other".into(),
                uris: vec![uri("androidapp://com.example.other")],
                ..NewItem::default()
            },
        )
        .unwrap();
    let state2 = state2.unwrap();
    assert!(
        s.record_app_fill(&state2, &dev, T0 + 4, &mut TestRng(5), &other, &unverified)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        s.record_app_fill(&state2, &dev, T0 + 4, &mut TestRng(6), "missing", &app)
            .err(),
        Some(ClientError::Core(Error::InvalidInput(InputKind::NotFound)))
    );

    // Save offers and suffix hosts on pages.
    match s
        .page_save_offer(&Page::App(app.clone()), "alice", "pw", &none)
        .unwrap()
    {
        Offer::New(n) => assert_eq!(n.apps[0].package, "com.example.bank"),
        o => panic!("{o:?}"),
    }
    let android_web = Page::AndroidWeb(android_web_page("https", "www.bank.com").unwrap());
    assert_eq!(
        s.page_suffix_hosts(&android_web).unwrap(),
        ["bank.com", "www.bank.com"],
        "an Android web page: its host and the item URI domains"
    );
    assert_eq!(s.page_candidates(&android_web, &com).unwrap()[0].id, id);
    let web = Page::Web(page_url("https://www.bank.com/login").unwrap());
    assert_eq!(
        s.page_suffix_hosts(&web).unwrap(),
        ["bank.com", "www.bank.com"]
    );
    let c = s.page_candidates(&web, &com).unwrap();
    assert_eq!(c[0].id, id);
}
