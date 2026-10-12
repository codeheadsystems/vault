//! Property tests for the merge rule.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use std::collections::{BTreeMap, BTreeSet};
use vault_core::body::{Body, ItemFields, MAX_PASSWORD_HISTORY, TYPE_LOGIN};
use vault_core::edit::{add_item, delete_item, update_item};
use vault_core::merge::{DAY, cutoff, merge, same_content};

const IDS: usize = 8;
const DEVICES: [&str; 3] = [
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
];
const PASSWORDS: [&str; 14] = [
    "", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "hunter2", "\u{e9}",
];
/// The largest `ms` value, `2^53 - 1`.
const MAX_MS: u64 = (1 << 53) - 1;

fn id(n: usize) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

#[derive(Debug, Clone)]
enum Spec {
    Login {
        modified: u64,
        by: usize,
        password: usize,
        history: Vec<(usize, u64)>,
        review: bool,
        extra: String,
    },
    Note {
        modified: u64,
        by: usize,
    },
    Unknown {
        modified: u64,
        by: usize,
        extra: String,
    },
    Tombstone {
        modified: u64,
        by: usize,
    },
}

impl Spec {
    fn stamp_mut(&mut self) -> (&mut u64, &mut usize) {
        match self {
            Spec::Login { modified, by, .. }
            | Spec::Note { modified, by }
            | Spec::Unknown { modified, by, .. }
            | Spec::Tombstone { modified, by } => (modified, by),
        }
    }
}

#[derive(Debug, Clone)]
struct BodySpec {
    horizon: u64,
    entries: BTreeMap<usize, Spec>,
    /// Unknown top-level keys, as JSON text.
    extra: BTreeMap<usize, String>,
    /// A prefix for the unknown top-level keys, so that bodies can be given disjoint keys.
    key_prefix: String,
    /// Whether history entries carry an unknown field.
    history_extra: bool,
}

/// Any JSON value under the body rules, nested up to three levels, as text: numbers near both
/// ends of the range, and arrays and objects whose keys collide across bodies with values of
/// other types.
fn json_text() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("null".to_owned()),
        any::<bool>().prop_map(|b| b.to_string()),
        prop_oneof![0u64..10, (MAX_MS - 3)..=MAX_MS].prop_map(|n| n.to_string()),
        "[a-c]{0,3}".prop_map(|s| format!("\"{s}\"")),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(|v| format!("[{}]", v.join(","))),
            prop::collection::btree_map("[a-c]", inner, 0..3).prop_map(|m| {
                let kv: Vec<String> = m.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
                format!("{{{}}}", kv.join(","))
            }),
        ]
    })
}

/// Stamps spread over 1970, the recent past, and the future, with the boundaries of every rule:
/// `cutoff` and `now + DAY` plus or minus 1 and 2, and values near `2^53 - 1`.
fn stamp(now: u64) -> impl Strategy<Value = u64> {
    let c = cutoff(now);
    let top = now.saturating_add(DAY);
    let edges: Vec<u64> = vec![
        c.saturating_sub(2),
        c.saturating_sub(1),
        c,
        c + 1,
        c + 2,
        top - 1,
        top,
        top + 1,
        top + 2,
        MAX_MS - 1,
        MAX_MS,
    ];
    prop_oneof![
        1 => 0..=DAY,
        3 => now.saturating_sub(200 * DAY)..=now.saturating_add(3 * DAY),
        1 => now.saturating_sub(5)..=now.saturating_add(5),
        2 => prop::sample::select(edges),
    ]
    .prop_map(|x| x.min(MAX_MS))
}

/// Horizons, including exactly `cutoff` and `cutoff + DAY` and one past it.
fn horizon(now: u64) -> impl Strategy<Value = u64> {
    let c = cutoff(now);
    prop_oneof![
        stamp(now),
        prop::sample::select(
            vec![0, c, c + DAY, c + DAY + 1]
                .into_iter()
                .map(|x| x.min(MAX_MS))
                .collect::<Vec<_>>()
        ),
    ]
}

/// A small set of `retired` values, so that equal `retired` values are common.
fn retired(now: u64) -> impl Strategy<Value = u64> {
    prop_oneof![stamp(now), Just(now.saturating_sub(DAY)), Just(7u64)]
}

fn spec(now: u64) -> impl Strategy<Value = Spec> {
    let history = prop::collection::vec((0..PASSWORDS.len(), retired(now)), 0..14);
    prop_oneof![
        4 => (
            stamp(now),
            0..DEVICES.len(),
            0..PASSWORDS.len(),
            history,
            any::<bool>(),
            json_text(),
        )
            .prop_map(|(modified, by, password, history, review, extra)| Spec::Login {
                modified,
                by,
                password,
                history,
                review,
                extra,
            }),
        1 => (stamp(now), 0..DEVICES.len()).prop_map(|(modified, by)| Spec::Note { modified, by }),
        1 => (stamp(now), 0..DEVICES.len(), json_text())
            .prop_map(|(modified, by, extra)| Spec::Unknown { modified, by, extra }),
        2 => (stamp(now), 0..DEVICES.len())
            .prop_map(|(modified, by)| Spec::Tombstone { modified, by }),
    ]
}

fn body_spec(now: u64) -> impl Strategy<Value = BodySpec> {
    (
        horizon(now),
        prop::collection::btree_map(0..IDS, spec(now), 0..IDS),
        prop::collection::btree_map(0..5usize, json_text(), 0..4),
    )
        .prop_map(|(horizon, entries, extra)| BodySpec {
            horizon,
            entries,
            extra,
            key_prefix: String::new(),
            history_extra: true,
        })
}

/// A normalised history, as an edit or a merge leaves it: no empty password and not the item's
/// current password, deduplicated by password, sorted in history order, and cut to 10.
fn history_json(history: &[(usize, u64)], with_extra: bool, current: &str) -> String {
    let mut newest: BTreeMap<&str, u64> = BTreeMap::new();
    for (p, r) in history
        .iter()
        .filter(|(p, _)| !PASSWORDS[*p].is_empty() && PASSWORDS[*p] != current)
    {
        let e = newest.entry(PASSWORDS[*p]).or_insert(*r);
        *e = (*e).max(*r);
    }
    let mut h: Vec<(&str, u64)> = newest.into_iter().collect();
    h.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.as_bytes().cmp(b.0.as_bytes())));
    h.truncate(MAX_PASSWORD_HISTORY);
    let x = if with_extra { r#","x":1"# } else { "" };
    let e: Vec<String> = h
        .iter()
        .map(|(p, r)| format!(r#"{{"password":"{p}","retired":{r}{x}}}"#))
        .collect();
    e.join(",")
}

fn build(s: &BodySpec) -> Body {
    let mut items = Vec::new();
    let mut tombs = Vec::new();
    for (n, e) in &s.entries {
        let id = id(*n);
        match e {
            Spec::Login {
                modified,
                by,
                password,
                history,
                review,
                extra,
            } => items.push(format!(
                r#"{{"id":"{id}","type":"login","name":"n{n}","folder":"","favourite":false,
                "notes":"","fields":[],"password_history":[{}],"created":0,
                "modified":{modified},"modified_by":"{}",{}"lx":{extra},"login":{{"username":"u",
                "password":"{}","uris":[],"apps":[],"totp":null,"passkeys":[],"ly":[{n}]}}}}"#,
                history_json(history, s.history_extra, PASSWORDS[*password]),
                DEVICES[*by],
                if *review { r#""review":"clamped","# } else { "" },
                PASSWORDS[*password],
            )),
            Spec::Note { modified, by } => items.push(format!(
                r#"{{"id":"{id}","type":"note","name":"n","folder":"f","favourite":true,
                "notes":"x","fields":[],"password_history":[],"created":1,
                "modified":{modified},"modified_by":"{}"}}"#,
                DEVICES[*by]
            )),
            Spec::Unknown { modified, by, extra } => items.push(format!(
                r#"{{"id":"{id}","type":"card","modified":{modified},"modified_by":"{}","k":{extra}}}"#,
                DEVICES[*by]
            )),
            Spec::Tombstone { modified, by } => tombs.push(format!(
                r#"{{"id":"{id}","modified":{modified},"modified_by":"{}"}}"#,
                DEVICES[*by]
            )),
        }
    }
    let extra: String = s
        .extra
        .iter()
        .map(|(k, v)| format!(r#","{}k{k}":{v}"#, s.key_prefix))
        .collect();
    let json = format!(
        r#"{{"v":1,"horizon":{},"items":[{}],"tombstones":[{}]{extra}}}"#,
        s.horizon,
        items.join(","),
        tombs.join(",")
    );
    Body::from_json(json.as_bytes()).expect("generated bodies follow the body rules")
}

/// Moves every stamp into the range a merge leaves alone at `now`: nothing later than
/// `now + DAY`, no horizon later than `cutoff + DAY`, and no tombstone older than `cutoff`.
fn settle(s: &mut BodySpec, now: u64) {
    let c = cutoff(now);
    let top = now.saturating_add(DAY);
    s.horizon = s.horizon.min(c.saturating_add(DAY));
    for e in s.entries.values_mut() {
        match e {
            Spec::Login {
                modified, history, ..
            } => {
                *modified = (*modified).min(top);
                for (_, r) in history {
                    *r = (*r).min(top);
                }
            }
            Spec::Note { modified, .. } | Spec::Unknown { modified, .. } => {
                *modified = (*modified).min(top)
            }
            Spec::Tombstone { modified, .. } => *modified = (*modified).clamp(c, top),
        }
    }
}

/// Gives every entry of a body the same device, distinct per body, so two bodies never hold a
/// full tie (the same stamp with different content), and prefixes its unknown top-level keys,
/// so two bodies never disagree on one.
fn own_device(s: &mut BodySpec, k: usize) {
    for e in s.entries.values_mut() {
        *e.stamp_mut().1 = k;
    }
    s.key_prefix = format!("b{k}_");
}

/// Makes the kind of every entry depend on its `id` only (login, note, unknown type, or
/// tombstone), so that every body agrees on it.
fn same_kind_per_id(s: &mut BodySpec) {
    for (n, e) in s.entries.iter_mut() {
        let (modified, by) = {
            let (m, b) = e.stamp_mut();
            (*m, *b)
        };
        let fits = matches!(
            (n % 4, &*e),
            (0, Spec::Login { .. })
                | (1, Spec::Note { .. })
                | (2, Spec::Unknown { .. })
                | (3, Spec::Tombstone { .. })
        );
        if !fits {
            *e = match n % 4 {
                0 => Spec::Login {
                    modified,
                    by,
                    password: 1,
                    history: Vec::new(),
                    review: false,
                    extra: "null".into(),
                },
                1 => Spec::Note { modified, by },
                2 => Spec::Unknown {
                    modified,
                    by,
                    extra: "null".into(),
                },
                _ => Spec::Tombstone { modified, by },
            };
        }
    }
}

fn nows() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(1_000u64),
        Just(15_552_000_000 - 1),
        Just(15_552_000_000),
        Just(1_800_000_000_000),
        Just(MAX_MS),
        0u64..2_000_000_000_000,
    ]
}

fn with_now() -> impl Strategy<Value = (u64, BodySpec, BodySpec)> {
    nows().prop_flat_map(|now| (Just(now), body_spec(now), body_spec(now)))
}

fn with_now3() -> impl Strategy<Value = (u64, BodySpec, BodySpec, BodySpec)> {
    nows().prop_flat_map(|now| (Just(now), body_spec(now), body_spec(now), body_spec(now)))
}

fn shuffled(b: &Body, items: &[usize], tombs: &[usize]) -> Body {
    let mut out = b.clone();
    out.items = items
        .iter()
        .filter_map(|&i| b.items.get(i).cloned())
        .collect();
    out.tombstones = tombs
        .iter()
        .filter_map(|&i| b.tombstones.get(i).cloned())
        .collect();
    assert_eq!(out.items.len(), b.items.len());
    assert_eq!(out.tombstones.len(), b.tombstones.len());
    out
}

fn permutation() -> impl Strategy<Value = Vec<usize>> {
    Just((0..IDS).collect::<Vec<_>>()).prop_shuffle()
}

/// A local edit applied to a body: a password change, a rename, a delete, or a new login.
#[derive(Debug, Clone)]
enum Op {
    SetPassword(usize, usize),
    Rename(usize),
    Delete(usize),
    Add(usize),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    let op = prop_oneof![
        4 => (0..IDS, 0..PASSWORDS.len()).prop_map(|(i, p)| Op::SetPassword(i, p)),
        1 => (0..IDS).prop_map(Op::Rename),
        1 => (0..IDS).prop_map(Op::Delete),
        1 => (0..PASSWORDS.len()).prop_map(Op::Add),
    ];
    prop::collection::vec(op, 0..40)
}

struct Counter(u8);

impl vault_core::rng::Rng for Counter {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(37);
            *b = self.0;
        }
        Ok(())
    }
}

/// Applies `ops` at increasing times up to `now`. Edits that do not apply (a missing item, an
/// unknown type) are skipped, as a client would refuse them.
fn apply(body: &mut Body, ops: &[Op], now: u64) {
    let device = [0x44; 16];
    let mut rng = Counter(0);
    let start = now.saturating_sub(ops.len() as u64);
    for (n, op) in ops.iter().enumerate() {
        let t = start + n as u64;
        let target = |i: usize| {
            body.items
                .get(i % body.items.len().max(1))
                .map(|x| x.id.clone())
        };
        match op {
            Op::SetPassword(i, p) => {
                let Some(id) = target(*i) else { continue };
                let Some(mut f) = body.item(&id).and_then(|x| x.fields().cloned()) else {
                    continue;
                };
                if let Some(l) = f.login.as_mut() {
                    l.password = PASSWORDS[*p].to_owned();
                }
                update_item(body, &id, f, t, &device).unwrap();
            }
            Op::Rename(i) => {
                let Some(id) = target(*i) else { continue };
                let Some(mut f) = body.item(&id).and_then(|x| x.fields().cloned()) else {
                    continue;
                };
                f.name.push('x');
                update_item(body, &id, f, t, &device).unwrap();
            }
            Op::Delete(i) => {
                let Some(id) = target(*i) else { continue };
                delete_item(body, &id, t, &device).unwrap();
            }
            Op::Add(p) => {
                let Some(f): Option<ItemFields> = body
                    .items
                    .iter()
                    .find_map(|x| x.fields().filter(|f| f.login.is_some()).cloned())
                else {
                    continue;
                };
                let mut f = f;
                f.login.as_mut().unwrap().password = PASSWORDS[*p].to_owned();
                add_item(body, &mut rng, TYPE_LOGIN, f, t, &device).unwrap();
            }
        }
    }
}

fn text(b: &Body) -> String {
    String::from_utf8_lossy(&b.to_json()).into_owned()
}

/// The entry that step 4 picks for `id`, as `(is_tombstone, clamped modified)`: the greater
/// clamped `(modified, modified_by)`, the remote one on a full tie.
fn winner(l: &Body, r: &Body, id: &str, now: u64) -> Option<(bool, u64)> {
    let clamp = |m: u64| if m > now.saturating_add(DAY) { now } else { m };
    let entry = |b: &Body| {
        b.item(id)
            .map(|i| (false, clamp(i.modified), i.modified_by.clone()))
            .or_else(|| {
                b.tombstones
                    .iter()
                    .find(|t| t.id == id)
                    .map(|t| (true, clamp(t.modified), t.modified_by.clone()))
            })
    };
    match (entry(l), entry(r)) {
        (Some(a), Some(b)) => Some(if (a.1, &a.2) > (b.1, &b.2) {
            (a.0, a.1)
        } else {
            (b.0, b.1)
        }),
        (a, b) => a.or(b).map(|e| (e.0, e.1)),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn an_edited_body_merges_with_itself_unchanged((now, mut s, _) in with_now(), ops in ops()) {
        settle(&mut s, now);
        let mut b = build(&s);
        apply(&mut b, &ops, now);
        prop_assert!(b.to_checked_json().is_ok(), "edits keep the body rules");
        let m = merge(&b, &b, now);
        prop_assert!(m.expired.is_empty());
        prop_assert!(same_content(&m.body, &b), "{}", text(&m.body));
    }

    #[test]
    fn merging_a_body_with_itself_changes_nothing((now, mut s, _) in with_now()) {
        settle(&mut s, now);
        let b = build(&s);
        let m = merge(&b, &b, now);
        prop_assert!(m.expired.is_empty());
        prop_assert!(same_content(&m.body, &b), "{}", text(&m.body));
    }

    #[test]
    fn results_follow_the_body_rules((now, l, r) in with_now()) {
        let (l, r) = (build(&l), build(&r));
        let m = merge(&l, &r, now);
        let mut ids = BTreeSet::new();
        for i in &m.body.items {
            prop_assert!(ids.insert(i.id.clone()), "an id twice among items");
        }
        for t in &m.body.tombstones {
            prop_assert!(ids.insert(t.id.clone()), "an id in items and tombstones");
        }
        for e in &m.expired {
            prop_assert!(!ids.contains(&e.id), "an expired item in the result");
        }
        for i in &m.body.items {
            if let Some(f) = i.fields() {
                let h = &f.password_history;
                prop_assert!(h.len() <= MAX_PASSWORD_HISTORY);
                for w in h.windows(2) {
                    prop_assert!(
                        w[0].retired > w[1].retired
                            || (w[0].retired == w[1].retired
                                && w[0].password.as_bytes() <= w[1].password.as_bytes()),
                        "history order"
                    );
                }
            }
            prop_assert!(i.modified <= now.saturating_add(DAY));
        }
        prop_assert!(m.body.to_checked_json().is_ok(), "the merged body is writable");
    }

    #[test]
    fn items_on_both_sides_never_expire_and_fresh_tombstones_survive((now, l, r) in with_now()) {
        let (l, r) = (build(&l), build(&r));
        let m = merge(&l, &r, now);
        for n in 0..IDS {
            let id = id(n);
            if l.item(&id).is_some() && r.item(&id).is_some() {
                prop_assert!(m.body.item(&id).is_some(), "{id} dropped");
                prop_assert!(m.expired.iter().all(|e| e.id != id), "{id} expired");
            }
            if let Some((true, modified)) = winner(&l, &r, &id, now)
                && modified >= cutoff(now)
            {
                prop_assert!(m.body.tombstones.iter().any(|t| t.id == id), "{id} purged");
            }
        }
    }

    #[test]
    fn results_do_not_depend_on_input_order(
        (now, l, r) in with_now(),
        p1 in permutation(), p2 in permutation(), p3 in permutation(), p4 in permutation(),
    ) {
        let (l, r) = (build(&l), build(&r));
        let a = merge(&l, &r, now);
        let b = merge(&shuffled(&l, &p1, &p2), &shuffled(&r, &p3, &p4), now);
        prop_assert!(a.body == b.body);
        prop_assert!(a.expired == b.expired);
    }

    #[test]
    fn merging_again_with_either_input_is_stable((now, mut l, mut r) in with_now()) {
        own_device(&mut l, 0);
        own_device(&mut r, 1);
        let (l, r) = (build(&l), build(&r));
        let once = merge(&l, &r, now).body;
        for (local, remote) in [(&once, &r), (&once, &l), (&l, &once)] {
            let again = merge(local, remote, now).body;
            prop_assert!(same_content(&again, &once), "{}\n{}", text(&again), text(&once));
        }
    }

    /// Convergence holds when every body agrees on the kind of each entry, no two bodies hold a
    /// full tie, nothing is clamped, expired, or purged, and no history holds a password that is
    /// current on another body. The kind and password restrictions follow the paragraph after the
    /// seven steps of the spec's "Merge rule", which accepts two order dependences: a login that
    /// loses to a tombstone or to an item of another type loses its password with it, and the
    /// `retired` time of an entry removed as another version's current password can differ. Full
    /// ties and conflicting unknown top-level keys are order-dependent by design, because the
    /// remote side wins them.
    #[test]
    fn three_bodies_converge_in_every_order((now, mut a, mut b, mut c) in with_now3()) {
        for (k, s) in [&mut a, &mut b, &mut c].into_iter().enumerate() {
            same_kind_per_id(s);
            settle(s, now);
            s.horizon = 0;
            s.history_extra = false;
            own_device(s, k);
            // The spec's "Merge rule", in the paragraph after the seven steps, accepts that "the
            // `retired` time of a history entry can also depend on the order of merges, when one
            // device's newer entry for a password is removed because that password is another
            // item version's current one". Current passwords distinct per body and absent from
            // every history keep that case out.
            for e in s.entries.values_mut() {
                if let Spec::Login {
                    password, history, ..
                } = e
                {
                    *password = k + 1;
                    history.retain(|(p, _)| !(1..=3).contains(p));
                }
            }
        }
        let bodies = [build(&a), build(&b), build(&c)];
        let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        let results: Vec<Body> = orders
            .iter()
            .map(|[x, y, z]| {
                let first = merge(&bodies[*x], &bodies[*y], now).body;
                merge(&first, &bodies[*z], now).body
            })
            .collect();
        for (o, r) in orders.iter().zip(&results).skip(1) {
            prop_assert!(same_content(r, &results[0]), "{o:?}\n{}\n{}", text(r), text(&results[0]));
        }
    }

    #[test]
    fn merging_twice_is_stable((now, l, r) in with_now()) {
        let (l, r) = (build(&l), build(&r));
        let once = merge(&l, &r, now).body;
        let twice = merge(&l, &once, now);
        prop_assert!(same_content(&twice.body, &once));
    }
}
