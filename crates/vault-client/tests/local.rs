//! What a host shares across clients besides the procedures: the commit with its secret key
//! writes, local edits, and listing, search, and edit merges of items.

mod common;

use common::*;
use vault_client::commit::{ApplyError, CommitHost, apply, apply_first, apply_save};
use vault_client::edit::{EditError, local_edit};
use vault_client::items::{apply_changes, in_folder, matches_text, sorted};
use vault_client::{
    ClientError, ClientState, Finished, Save, SavedKey, SecretKeyChange, SecretKeyStore,
};
use vault_core::body::{Body, CustomField, HistoryEntry, Item, ItemData, LoginUri, TYPE_LOGIN};
use vault_core::file::{open_file, read_header};
use vault_core::header::HEADER_LEN;
use vault_core::json::{Map, Value};
use vault_core::merge::DAY;
use vault_core::secret::SecretKey;
use vault_core::sync::{Accepted, file_hash};

const DEVICE: [u8; 16] = [0xdd; 16];

/// Records the host's writes in order, checks the store and vault ID each one names, and fails
/// the write named in `fail`.
struct Recorder {
    store: SecretKeyStore,
    vault_id: [u8; 16],
    calls: Vec<&'static str>,
    written: Option<ClientState>,
    fail: Option<&'static str>,
}

impl Recorder {
    fn new(expect: &ClientState) -> Recorder {
        Recorder {
            store: expect.secret_key_store,
            vault_id: expect.vault_id,
            calls: Vec::new(),
            written: None,
            fail: None,
        }
    }

    fn failing(expect: &ClientState, what: &'static str) -> Recorder {
        Recorder {
            fail: Some(what),
            ..Recorder::new(expect)
        }
    }

    fn call(
        &mut self,
        what: &'static str,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), &'static str> {
        assert_eq!((store, *vault_id), (self.store, self.vault_id), "{what}");
        self.calls.push(what);
        if self.fail == Some(what) {
            return Err(what);
        }
        Ok(())
    }
}

impl CommitHost for Recorder {
    type Error = &'static str;

    fn store_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        key: &SecretKey,
    ) -> Result<(), &'static str> {
        assert_eq!(key.expose(), &[9; 16]);
        self.call("store_current", store, vault_id)
    }

    fn store_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
        _: &SecretKey,
    ) -> Result<(), &'static str> {
        self.call("store_pending", store, vault_id)
    }

    fn copy_pending_to_current(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), &'static str> {
        self.call("copy_pending", store, vault_id)
    }

    fn delete_pending(
        &mut self,
        store: SecretKeyStore,
        vault_id: &[u8; 16],
    ) -> Result<(), &'static str> {
        self.call("delete_pending", store, vault_id)
    }

    fn write_state(&mut self, state: &ClientState) -> Result<(), &'static str> {
        self.calls.push("write_state");
        if self.fail == Some("write_state") {
            return Err("write_state");
        }
        self.written = Some(state.clone());
        Ok(())
    }
}

fn started() -> ClientState {
    let fx = Fixture::new(3);
    fx.state(fx.file(1, &Body::default(), 1))
}

fn finished(secret_key: Option<SecretKeyChange>) -> Finished<()> {
    let mut next = started();
    next.last_sync = Some(T0);
    Finished {
        result: Ok(()),
        state: Some(next),
        vault_key: None,
        started_vault_key: None,
        secret_key,
    }
}

fn key() -> SecretKey {
    SecretKey::from_bytes([9; 16])
}

fn run(f: &Finished<()>, host: &mut Recorder) -> Result<bool, ApplyError<&'static str>> {
    let s = started();
    apply(f, &s, &s, false, T0, &mut TestRng(1), host)
        .map(|a| a.expect("not superseded").pending_left.is_some())
}

#[test]
fn keys_the_new_state_needs_go_first_and_deletions_last() {
    let cases: [(Option<SecretKeyChange>, &[&str]); 5] = [
        (None, &["write_state"]),
        (
            Some(SecretKeyChange::Replace(key())),
            &["store_current", "write_state"],
        ),
        (
            Some(SecretKeyChange::ReplaceAndDiscardPending(key())),
            &["store_current", "write_state", "delete_pending"],
        ),
        (
            Some(SecretKeyChange::PromotePending),
            &["copy_pending", "write_state", "delete_pending"],
        ),
        (
            Some(SecretKeyChange::DiscardPending),
            &["write_state", "delete_pending"],
        ),
    ];
    for (change, order) in cases {
        let mut host = Recorder::new(&started());
        let left = run(&finished(change), &mut host).unwrap();
        assert!(!left);
        assert_eq!(host.calls, order);
        assert_eq!(host.written.unwrap().last_sync, Some(T0));
    }
}

#[test]
fn a_failed_write_stops_the_writes_after_it() {
    let cases: [(SecretKeyChange, &str, &[&str]); 4] = [
        (
            SecretKeyChange::Replace(key()),
            "store_current",
            &["store_current"],
        ),
        (
            SecretKeyChange::PromotePending,
            "copy_pending",
            &["copy_pending"],
        ),
        (
            SecretKeyChange::DiscardPending,
            "write_state",
            &["write_state"],
        ),
        (
            SecretKeyChange::ReplaceAndDiscardPending(key()),
            "write_state",
            &["store_current", "write_state"],
        ),
    ];
    for (change, fail, calls) in cases {
        let mut host = Recorder::failing(&started(), fail);
        match run(&finished(Some(change)), &mut host) {
            Err(ApplyError::Host(e)) => assert_eq!(e, fail),
            _ => panic!("expected the host error from {fail}"),
        }
        assert_eq!(host.calls, calls);
        assert!(host.written.is_none());
    }
}

#[test]
fn a_failed_pending_deletion_after_the_state_is_a_leftover() {
    for change in [
        SecretKeyChange::PromotePending,
        SecretKeyChange::DiscardPending,
        SecretKeyChange::ReplaceAndDiscardPending(key()),
    ] {
        let mut host = Recorder::failing(&started(), "delete_pending");
        let left = run(&finished(Some(change)), &mut host).unwrap();
        assert!(left, "the commit stands with the error reported");
        assert!(host.written.is_some());
    }
}

#[test]
fn a_superseded_commit_writes_nothing() {
    let s = started();
    let mut host = Recorder::new(&s);
    // Another sync accepted a file while this procedure ran.
    let mut on_disk = s.clone();
    on_disk.accepted = Some(Accepted {
        generation: 2,
        file_hash: [7; 32],
    });
    for result in [Ok(()), Err(ClientError::Unreachable)] {
        let mut f = finished(Some(SecretKeyChange::Replace(key())));
        f.result = result;
        let out = apply(&f, &s, &on_disk, true, T0, &mut TestRng(1), &mut host).unwrap();
        assert!(out.is_none());
    }
    assert!(host.calls.is_empty());
}

#[test]
fn another_commit_error_writes_nothing() {
    let fx = Fixture::new(3);
    let s = started();
    // A command changed the local file meanwhile, and no vault key is at hand to merge it.
    let mut on_disk = s.clone();
    on_disk.file = fx.file(1, &Body::default(), 2);
    let mut f = finished(Some(SecretKeyChange::Replace(key())));
    f.state.as_mut().unwrap().file = fx.file(1, &Body::default(), 3);
    let mut host = Recorder::new(&s);
    match apply(&f, &s, &on_disk, false, T0, &mut TestRng(1), &mut host) {
        Err(ApplyError::Client(ClientError::Locked)) => {}
        _ => panic!("expected the commit rule's error"),
    }
    assert!(host.calls.is_empty());
}

#[test]
fn without_a_state_change_only_the_key_writes_run() {
    // The procedure's state equals the state on disk, so there is nothing to write; its key
    // change still applies.
    let s = started();
    let mut f = finished(Some(SecretKeyChange::DiscardPending));
    f.state = None;
    let mut host = Recorder::new(&s);
    let a = apply(&f, &s, &s, false, T0, &mut TestRng(1), &mut host)
        .unwrap()
        .unwrap();
    assert!(a.commit.state.is_none());
    assert_eq!(host.calls, ["delete_pending"]);
}

#[test]
fn the_store_on_disk_names_the_key_writes() {
    // The procedure ran from a state recording another store; the store on disk, chosen at
    // setup, is the one written to and kept.
    let s = started();
    let mut f = finished(Some(SecretKeyChange::Replace(key())));
    f.state.as_mut().unwrap().secret_key_store = SecretKeyStore::File;
    assert_eq!(s.secret_key_store, SecretKeyStore::Keyring);
    let mut host = Recorder::new(&s);
    apply(&f, &s, &s, false, T0, &mut TestRng(1), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(
        host.written.unwrap().secret_key_store,
        SecretKeyStore::Keyring
    );
}

#[test]
fn local_changes_made_meanwhile_merge_and_dropped_items_follow_the_caller() {
    let fx = Fixture::new(5);
    let base = fx.file(1, &Body::default(), 1);
    let mut s = fx.state(base.clone());
    s.accepted = Some(Accepted {
        generation: 1,
        file_hash: file_hash(&base),
    });
    // Meanwhile a command added two items: one older than the remote's purge horizon.
    let mut local = Body::default();
    add_login(&mut local, &mut TestRng(7), &DEVICE, "ancient", "a", 1);
    add_login(&mut local, &mut TestRng(8), &DEVICE, "fresh", "f", T0);
    let mut on_disk = s.clone();
    on_disk.file = fx.file(1, &local, 2);
    // The sync accepted a remote at generation 2 with a horizon past the old item.
    let mut remote = Body::default();
    add_login(&mut remote, &mut TestRng(9), &[0xee; 16], "remote", "r", T0);
    remote.horizon = T0 - 200 * DAY;
    let mut result = s.clone();
    result.accept(2, fx.file(2, &remote, 3));
    for background in [true, false] {
        let f = Finished {
            result: Ok(()),
            state: Some(result.clone()),
            vault_key: Some(fx.key()),
            started_vault_key: Some(fx.key()),
            secret_key: None,
        };
        let mut host = Recorder::new(&s);
        let a = apply(&f, &s, &on_disk, background, T0, &mut TestRng(1), &mut host)
            .unwrap()
            .unwrap();
        assert!(a.commit.merged_local_changes);
        assert_eq!(a.commit.expired, ["ancient"]);
        let written = host.written.unwrap();
        let mut names: Vec<String> = open_file(&written.file, &fx.key())
            .unwrap()
            .1
            .items
            .iter()
            .map(|i| i.fields().unwrap().name.clone())
            .collect();
        names.sort();
        assert_eq!(names, ["fresh", "remote"]);
        assert!(
            written.unpushed(),
            "the local change waits for the next sync"
        );
        let dropped: &[&str] = if background { &["ancient"] } else { &[] };
        assert_eq!(written.dropped, dropped);
    }
}

#[test]
fn local_edits_seal_under_the_same_header_and_skip_no_change() {
    let fx = Fixture::new(4);
    let file = fx.file(5, &Body::default(), 1);
    let mut state = fx.state(file.clone());
    state.accepted = Some(Accepted {
        generation: 5,
        file_hash: file_hash(&file),
    });
    state.last_sync = Some(T0 - 1);
    let vk = fx.key();

    // An edit that changes nothing writes nothing.
    let (r, next) = local_edit(&state, &vk, &DEVICE, T0, &mut TestRng(2), |_, _, _| {
        Ok::<_, ()>(7)
    })
    .unwrap();
    assert_eq!((r, next.is_none()), (7, true));

    let (id, next) = local_edit(&state, &vk, &DEVICE, T0, &mut TestRng(2), add_item_at).unwrap();
    let next = next.expect("changed");
    assert_eq!(
        read_header(&next.file).unwrap(),
        read_header(&state.file).unwrap(),
        "the wrap, vault_id, KDF parameters, and generation stay"
    );
    assert_eq!(next.file[..HEADER_LEN], state.file[..HEADER_LEN]);
    assert_ne!(
        next.file[HEADER_LEN..HEADER_LEN + 24],
        state.file[HEADER_LEN..HEADER_LEN + 24],
        "a fresh body_nonce"
    );
    let body = open_file(&next.file, &vk).unwrap().1;
    let item = body.item(&id).unwrap();
    assert_eq!(
        (item.modified, item.modified_by.as_str()),
        (T0, &*"dd".repeat(16))
    );
    assert_eq!(next.accepted, state.accepted);
    assert_eq!(next.last_sync, state.last_sync);
    assert!(next.unpushed());
    let mut same = next.clone();
    same.file = state.file.clone();
    assert!(same == state, "only the file changes");
}

fn add_item_at(body: &mut Body, now: u64, dev: &[u8; 16]) -> Result<String, ()> {
    Ok(add_login(body, &mut TestRng(3), dev, "Mail", "pw", now))
}

#[test]
fn local_edits_check_the_clock_and_report_the_edits_error() {
    let fx = Fixture::new(4);
    let state = fx.state(fx.file(1, &Body::default(), 1));
    let vk = fx.key();
    match local_edit(&state, &vk, &DEVICE, 0, &mut TestRng(2), |_, _, _| {
        Ok::<_, ()>(())
    }) {
        Err(EditError::Client(ClientError::Core(vault_core::Error::ClockBeforeBuildTime))) => {}
        _ => panic!("a 1970 clock is refused"),
    }
    match local_edit(&state, &vk, &DEVICE, T0, &mut TestRng(2), |_, _, _| {
        Err::<(), _>("nope")
    }) {
        Err(EditError::Edit("nope")) => {}
        _ => panic!("the edit's error comes back"),
    }
    let wrong = Fixture::new(9).key();
    match local_edit(&state, &wrong, &DEVICE, T0, &mut TestRng(2), |_, _, _| {
        Ok::<_, ()>(())
    }) {
        Err(EditError::Client(ClientError::Core(vault_core::Error::Integrity(_)))) => {}
        _ => panic!("a key that does not open the file"),
    }
}

fn item(id: u8, name: &str, folder: &str, username: &str, uri: &str) -> Item {
    let mut f = login(name, "pw");
    f.folder = folder.into();
    let l = f.login.as_mut().unwrap();
    l.username = username.into();
    if !uri.is_empty() {
        l.uris.push(LoginUri {
            uri: uri.into(),
            match_value: "base_domain".into(),
            extra: Map::new(),
        });
    }
    Item {
        id: format!("{id:02x}000000-0000-4000-8000-000000000000"),
        item_type: TYPE_LOGIN.into(),
        modified: 1,
        modified_by: "aa".repeat(16),
        review: None,
        data: ItemData::Known(Box::new(f)),
    }
}

fn unknown(id: u8) -> Item {
    Item {
        id: format!("{id:02x}000000-0000-4000-8000-000000000000"),
        item_type: "card".into(),
        modified: 1,
        modified_by: "aa".repeat(16),
        review: None,
        data: ItemData::Unknown(Map::new()),
    }
}

#[test]
fn folders_cover_their_subfolders_and_the_empty_folder_is_the_top_level() {
    let i = item(1, "AWS", "Work/AWS", "", "");
    assert!(in_folder(&i, "Work"));
    assert!(in_folder(&i, "/Work/"));
    assert!(in_folder(&i, "Work/AWS"));
    assert!(!in_folder(&i, "Wor"));
    assert!(!in_folder(&i, "Work/AW"));
    assert!(!in_folder(&i, ""), "\"\" holds only items without a folder");
    assert!(in_folder(&item(2, "x", "", "", ""), ""));
    assert!(in_folder(&item(2, "x", "", "", ""), "/"));
    assert!(!in_folder(&unknown(3), ""));
}

#[test]
fn search_covers_names_folders_usernames_and_uris_but_no_secrets() {
    let mut i = item(1, "GitHub", "Work", "Ned", "https://a.example/login");
    for q in ["github", "WORK", "ned", "A.EXAMPLE", "hub"] {
        assert!(matches_text(&i, q), "{q}");
    }
    assert!(!matches_text(&i, "gitlab"));
    if let ItemData::Known(f) = &mut i.data {
        f.notes = "secret note".into();
        f.fields.push(CustomField {
            name: "code".into(),
            value: "fieldvalue".into(),
            hidden: true,
            extra: Map::new(),
        });
        let l = f.login.as_mut().unwrap();
        l.password = "hunter2".into();
        l.totp = Some("JBSWY3DP".into());
    }
    for q in ["hunter2", "secret note", "fieldvalue", "code", "JBSWY3DP"] {
        assert!(!matches_text(&i, q), "{q}");
    }
    assert!(!matches_text(&unknown(2), "card"));
}

#[test]
fn listing_order_is_folder_name_and_id_with_unknown_types_last() {
    let items = [
        unknown(9),
        item(5, "mail", "", "", ""),
        item(1, "beta", "work", "", ""),
        item(2, "Alpha", "Work", "", ""),
        item(3, "zeta", "", "", ""),
        item(6, "Mail", "", "", ""),
        unknown(4),
    ];
    let order = |items: Vec<&Item>| -> Vec<String> {
        sorted(items).iter().map(|i| i.id[..2].to_owned()).collect()
    };
    let expected = ["05", "06", "03", "02", "01", "04", "09"];
    assert_eq!(order(items.iter().collect()), expected);
    // Names equal without regard to case order the same whatever the input order.
    assert_eq!(order(items.iter().rev().collect()), expected);
}

#[test]
fn changes_apply_onto_the_current_item() {
    let mut base = login("Mail", "old");
    base.fields.push(CustomField {
        name: "pin".into(),
        value: "1".into(),
        hidden: true,
        extra: Map::new(),
    });
    base.login.as_mut().unwrap().passkeys = vec![Value::Number(1)];
    // Meanwhile, a sync moved the item, changed its username, retired a password, and added an
    // unknown field.
    let mut current = base.clone();
    current.folder = "Moved".into();
    current.login.as_mut().unwrap().username = "synced".into();
    current.password_history.push(HistoryEntry {
        password: "older".into(),
        retired: 9,
        extra: Map::new(),
    });
    current.extra.insert("newer".into(), Value::Bool(true));
    // The user changed the name, favourite, notes, password, TOTP, URIs, and custom fields.
    let mut edited = base.clone();
    edited.name = "Post".into();
    edited.favourite = true;
    edited.notes = "new notes".into();
    edited.fields[0].value = "2".into();
    let l = edited.login.as_mut().unwrap();
    l.password = "typed".into();
    l.totp = Some("JBSWY3DP".into());
    l.uris.push(LoginUri {
        uri: "https://mail.example".into(),
        match_value: "host".into(),
        extra: Map::new(),
    });
    edited.extra.insert("ignored".into(), Value::Bool(true));
    let out = apply_changes(&base, &edited, &current);
    assert_eq!(
        (out.name.as_str(), out.folder.as_str(), out.favourite),
        ("Post", "Moved", true)
    );
    assert_eq!(out.notes, "new notes");
    assert_eq!(out.fields[0].value, "2");
    let l = out.login.as_ref().unwrap();
    assert_eq!(
        (l.username.as_str(), l.password.as_str()),
        ("synced", "typed")
    );
    assert_eq!(l.totp.as_deref(), Some("JBSWY3DP"));
    assert_eq!(l.uris.len(), 1);
    assert_eq!(l.passkeys.len(), 1);
    assert_eq!(
        out.password_history.len(),
        1,
        "history from the current item"
    );
    assert!(out.extra.contains_key("newer") && !out.extra.contains_key("ignored"));
    // No change from the user: the current item stays as it is.
    assert!(apply_changes(&base, &base, &current) == current);
    // Where both changed the same key, the user's edit wins.
    let mut edited = base.clone();
    edited.folder = "Mine".into();
    assert_eq!(apply_changes(&base, &edited, &current).folder, "Mine");
}

#[test]
fn login_data_comes_from_the_current_item_unless_both_sides_have_it() {
    let base = login("Mail", "old");
    let mut note = base.clone();
    note.login = None;
    // The current item has no login data: the user's login edits have nothing to apply to.
    let mut edited = base.clone();
    edited.login.as_mut().unwrap().password = "typed".into();
    assert!(apply_changes(&base, &edited, &note).login.is_none());
    // The edit started from a note: the current login data stays.
    let mut current = base.clone();
    current.login.as_mut().unwrap().password = "current".into();
    let out = apply_changes(&note, &note, &current);
    assert_eq!(out.login.as_ref().unwrap().password, "current");
}

/// A `--new-secret-key` save of `started`: the state records the pending key.
fn pending_save(slot: fn(SecretKey) -> SavedKey) -> Save {
    let mut state = started();
    state.pending_secret_key = true;
    Save {
        state,
        secret_key: slot(key()),
        vault_key: Fixture::new(3).key(),
    }
}

fn save_with(
    save: &Save,
    on_disk: &ClientState,
    host: &mut Recorder,
) -> Result<(), ApplyError<&'static str>> {
    apply_save(save, &started(), on_disk, T0, &mut TestRng(1), host).map(|_| ())
}

#[test]
fn a_save_writes_the_key_then_the_state() {
    for (slot, call) in [
        (
            SavedKey::Pending as fn(SecretKey) -> SavedKey,
            "store_pending",
        ),
        (SavedKey::Current, "store_current"),
    ] {
        let save = pending_save(slot);
        let mut host = Recorder::new(&save.state);
        save_with(&save, &started(), &mut host).unwrap();
        assert_eq!(host.calls, [call, "write_state"]);
        assert!(host.written.as_ref() == Some(&save.state));
    }
}

#[test]
fn a_failed_key_write_writes_nothing_else() {
    let save = pending_save(SavedKey::Pending);
    let mut host = Recorder::failing(&save.state, "store_pending");
    assert!(matches!(
        save_with(&save, &started(), &mut host),
        Err(ApplyError::Host("store_pending"))
    ));
    assert_eq!(host.calls, ["store_pending"]);
    assert!(host.written.is_none());
}

#[test]
fn a_superseded_save_is_refused_before_any_write() {
    let save = pending_save(SavedKey::Pending);
    // Another sync committed a newer generation while the credential change ran.
    let mut on_disk = started();
    on_disk.accepted = Some(Accepted {
        generation: 9,
        file_hash: [7; 32],
    });
    let mut host = Recorder::new(&save.state);
    assert!(matches!(
        save_with(&save, &on_disk, &mut host),
        Err(ApplyError::Client(ClientError::Superseded))
    ));
    assert!(
        host.calls.is_empty(),
        "the commit rule runs before the key write"
    );
}

#[test]
fn a_failed_state_write_after_the_key_is_reported_with_the_key_written() {
    let save = pending_save(SavedKey::Pending);
    let mut host = Recorder::failing(&save.state, "write_state");
    assert!(matches!(
        save_with(&save, &started(), &mut host),
        Err(ApplyError::Host("write_state"))
    ));
    // The key write was issued: a transactional host discards it, a file host keeps an unused
    // pending key that no state names.
    assert_eq!(host.calls, ["store_pending", "write_state"]);
    assert!(host.written.is_none());
}

#[test]
fn a_first_state_writes_the_key_then_the_state() {
    let f = finished(Some(SecretKeyChange::Replace(key())));
    let mut host = Recorder::new(f.state.as_ref().unwrap());
    let a = apply_first(&f, &mut host).unwrap().expect("written");
    assert_eq!(host.calls, ["store_current", "write_state"]);
    assert!(a.commit.state == f.state && host.written == f.state);

    // A crash between the key and the state: the key write was issued, the state was not.
    let mut host = Recorder::failing(f.state.as_ref().unwrap(), "write_state");
    assert!(matches!(
        apply_first(&f, &mut host),
        Err(ApplyError::Host("write_state"))
    ));
    assert_eq!(host.calls, ["store_current", "write_state"]);
    assert!(host.written.is_none());

    // No state, nothing written.
    let mut none = finished(None);
    none.state = None;
    let mut host = Recorder::new(&started());
    assert!(apply_first(&none, &mut host).unwrap().is_none());
    assert!(host.calls.is_empty());
}

#[test]
fn a_first_state_refuses_pending_key_changes_before_any_write() {
    for change in [
        SecretKeyChange::PromotePending,
        SecretKeyChange::DiscardPending,
        SecretKeyChange::ReplaceAndDiscardPending(key()),
    ] {
        let f = finished(Some(change));
        let mut host = Recorder::new(f.state.as_ref().unwrap());
        assert!(matches!(
            apply_first(&f, &mut host),
            Err(ApplyError::Client(ClientError::UnexpectedInput))
        ));
        assert!(host.calls.is_empty());
        assert!(host.written.is_none());
    }
}
