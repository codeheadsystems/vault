//! The merge rule: combines a local body and a remote body at local time `now`.

use crate::body::{Body, HistoryEntry, Item, ItemData, Tombstone};
use crate::json::Map;
use std::collections::BTreeMap;

/// One day, in ms.
pub const DAY: u64 = 86_400_000;
/// How long tombstones are kept: 180 days, in ms.
pub const TOMBSTONE_LIFETIME: u64 = 15_552_000_000;

/// The result of a merge.
pub struct MergeResult {
    /// The merged body, with items and tombstones sorted by `id`.
    pub body: Body,
    /// Items left out because they were older than the other side's horizon, sorted by `id`. A
    /// client shows them for review and never pushes them back.
    pub expired: Vec<Item>,
}

#[derive(Clone)]
enum Entry {
    Item(Item),
    Tombstone(Tombstone),
}

impl Entry {
    fn stamp(&self) -> (u64, &str) {
        match self {
            Entry::Item(i) => (i.modified, &i.modified_by),
            Entry::Tombstone(t) => (t.modified, &t.modified_by),
        }
    }
}

/// `cutoff = now ⊖ 180 days`.
pub fn cutoff(now: u64) -> u64 {
    now.saturating_sub(TOMBSTONE_LIFETIME)
}

/// Step 1, clamp: stamps and `retired` values later than `now + DAY` become `now`, an item with a
/// clamped `modified` gets `review = "clamped"`, the history of every login or note is normalised
/// (a note has no current password), and a `horizon` later than `cutoff + DAY` becomes `cutoff`.
fn clamp(body: &mut Body, now: u64) {
    let limit = now.saturating_add(DAY);
    for item in &mut body.items {
        if item.modified > limit {
            item.modified = now;
            item.flag_clamped();
        }
        // On an item of unknown `type`, only `modified` is clamped.
        if let ItemData::Known(f) = &mut item.data {
            for h in &mut f.password_history {
                if h.retired > limit {
                    h.retired = now;
                }
            }
            f.normalise_history();
        }
    }
    for t in &mut body.tombstones {
        if t.modified > limit {
            t.modified = now;
        }
    }
    let c = cutoff(now);
    if body.horizon > c.saturating_add(DAY) {
        body.horizon = c;
    }
}

/// Step 5, keep passwords, for a winner and a loser that are both login items.
fn keep_passwords(winner: &mut Item, loser: &Item) {
    let (Some(lose_login), lose_fields) = (loser.login(), loser.fields()) else {
        return;
    };
    let lose_history = lose_fields.map_or(&[][..], |f| &f.password_history[..]);
    let lose_modified = loser.modified;
    let ItemData::Known(f) = &mut winner.data else {
        return;
    };
    f.password_history.extend(lose_history.iter().cloned());
    f.password_history.push(HistoryEntry {
        password: lose_login.password.clone(),
        retired: lose_modified,
        extra: Map::new(),
    });
    // Winner entries come first, so on equal `retired` the winner's entry is kept. Normalising
    // removes the winner's own current password, which a loser's password may equal.
    f.normalise_history();
}

fn sides(mut body: Body) -> BTreeMap<String, Entry> {
    let mut m = BTreeMap::new();
    for i in core::mem::take(&mut body.items) {
        m.insert(i.id.clone(), Entry::Item(i));
    }
    for t in core::mem::take(&mut body.tombstones) {
        m.insert(t.id.clone(), Entry::Tombstone(t));
    }
    m
}

/// Merges the local body `local` into the remote body `remote` at local time `now`, following
/// the seven steps of the merge rule. Both bodies satisfy the body rules, as
/// [`Body::from_json`] guarantees. The merge is deterministic: the order of items and tombstones
/// in the inputs does not change the result.
///
/// The result's `v` is the greater of the inputs' `v`.
pub fn merge(local: &Body, remote: &Body, now: u64) -> MergeResult {
    // Step 1: clamp.
    let mut l = local.clone();
    let mut r = remote.clone();
    clamp(&mut l, now);
    clamp(&mut r, now);
    let (l_horizon, r_horizon) = (l.horizon, r.horizon);
    let v = l.v.max(r.v);
    // Step 7 is independent of the others: the greater `v`, remote values of unknown keys, plus
    // keys present only locally.
    let mut extra = r.extra.clone();
    for (k, x) in &l.extra {
        extra.entry(k.clone()).or_insert_with(|| x.clone());
    }

    // Step 2: pair.
    let mut ls = sides(l);
    let rs = sides(r);
    let mut items = Vec::new();
    let mut tombstones = Vec::new();
    let mut expired = Vec::new();
    let mut keep = |e: Entry| match e {
        Entry::Item(i) => items.push(i),
        Entry::Tombstone(t) => tombstones.push(t),
    };
    let mut paired: BTreeMap<String, (Option<Entry>, Option<Entry>)> = BTreeMap::new();
    for (id, e) in rs {
        let le = ls.remove(&id);
        paired.insert(id, (le, Some(e)));
    }
    for (id, e) in ls {
        paired.insert(id, (Some(e), None));
    }

    for (_, pair) in paired {
        match pair {
            // Step 3: expire an item present on one side only, older than the other side's
            // horizon.
            (Some(Entry::Item(i)), None) if i.modified < r_horizon => expired.push(i),
            (None, Some(Entry::Item(i))) if i.modified < l_horizon => expired.push(i),
            (Some(e), None) | (None, Some(e)) => keep(e),
            // Step 4: choose the greater `(modified, modified_by)`; the remote wins a full tie.
            (Some(le), Some(re)) => {
                let (mut winner, loser) = if le.stamp() > re.stamp() {
                    (le, re)
                } else {
                    (re, le)
                };
                // Step 5: keep passwords.
                if let (Entry::Item(w), Entry::Item(lo)) = (&mut winner, &loser)
                    && w.login().is_some()
                    && lo.login().is_some()
                {
                    keep_passwords(w, lo);
                }
                keep(winner);
            }
            (None, None) => unreachable!("every paired id has at least one entry"),
        }
    }

    // Step 6: purge.
    let c = cutoff(now);
    let before = tombstones.len();
    tombstones.retain(|t| t.modified >= c);
    let mut horizon = l_horizon.max(r_horizon);
    if tombstones.len() < before {
        horizon = horizon.max(c);
    }

    MergeResult {
        body: Body {
            v,
            horizon,
            items,
            tombstones,
            extra,
        },
        expired,
    }
}

/// The adopt test: items and tombstones compared as sets keyed by `id` with values compared as
/// JSON, and `v`, `horizon`, and every unknown top-level key compared as JSON.
pub fn same_content(a: &Body, b: &Body) -> bool {
    use crate::json::Value;
    fn items(body: &Body) -> BTreeMap<&str, Value> {
        body.items
            .iter()
            .map(|i| (i.id.as_str(), i.to_value()))
            .collect()
    }
    fn tombstones(body: &Body) -> BTreeMap<&str, Value> {
        body.tombstones
            .iter()
            .map(|t| (t.id.as_str(), t.to_value()))
            .collect()
    }
    a.v == b.v
        && a.horizon == b.horizon
        && a.extra == b.extra
        && a.items.len() == b.items.len()
        && a.tombstones.len() == b.tombstones.len()
        && items(a) == items(b)
        && tombstones(a) == tombstones(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::tests::{DEV_A, ID1};
    use crate::json::{self, Value};

    const DEV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID2: &str = "00000000-0000-4000-8000-000000000002";
    const NOW: u64 = 1_800_000_000_000;

    fn login(id: &str, modified: u64, by: &str, pw: &str, hist: &[(&str, u64)]) -> String {
        let h: Vec<String> = hist
            .iter()
            .map(|(p, r)| format!(r#"{{"password":"{p}","retired":{r}}}"#))
            .collect();
        format!(
            r#"{{"id":"{id}","type":"login","name":"n","folder":"","favourite":false,"notes":"",
            "fields":[],"password_history":[{}],"created":0,"modified":{modified},
            "modified_by":"{by}","login":{{"username":"u","password":"{pw}","uris":[],
            "apps":[],"totp":null,"passkeys":[]}}}}"#,
            h.join(",")
        )
    }

    fn tomb(id: &str, modified: u64, by: &str) -> String {
        format!(r#"{{"id":"{id}","modified":{modified},"modified_by":"{by}"}}"#)
    }

    fn body(horizon: u64, items: &[String], tombs: &[String], extra: &str) -> Body {
        let j = format!(
            r#"{{"v":1,"horizon":{horizon},"items":[{}],"tombstones":[{}]{extra}}}"#,
            items.join(","),
            tombs.join(",")
        );
        Body::from_json(j.as_bytes()).unwrap()
    }

    fn history(b: &Body, id: &str) -> Vec<(String, u64)> {
        b.item(id)
            .unwrap()
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|h| (h.password.clone(), h.retired))
            .collect()
    }

    fn pw(b: &Body, id: &str) -> String {
        b.item(id).unwrap().login().unwrap().password.clone()
    }

    #[test]
    fn concurrent_edits_keep_the_losing_password() {
        let l = body(
            0,
            &[login(ID1, NOW - 10, DEV_A, "local", &[("old", 5)])],
            &[],
            "",
        );
        let r = body(
            0,
            &[login(ID1, NOW - 20, DEV_B, "remote", &[("older", 1)])],
            &[],
            "",
        );
        let m = merge(&l, &r, NOW);
        assert_eq!(pw(&m.body, ID1), "local");
        assert_eq!(
            history(&m.body, ID1),
            vec![
                ("remote".into(), NOW - 20),
                ("old".into(), 5),
                ("older".into(), 1)
            ]
        );
        assert!(m.expired.is_empty());
        assert!(m.body.to_checked_json().is_ok());
    }

    #[test]
    fn history_dedup_tie_order_and_cut() {
        // "dup" appears on both sides with different `retired`: the newer is kept. Equal
        // `retired` values sort by password bytes.
        let lh: Vec<(&str, u64)> = vec![("dup", 50), ("a", 40), ("c", 30)];
        let rh: Vec<(&str, u64)> = vec![("dup", 60), ("b", 40), ("d", 30), ("e", 20), ("f", 10)];
        let l = body(0, &[login(ID1, 100, DEV_A, "x", &lh)], &[], "");
        let r = body(0, &[login(ID1, 200, DEV_B, "y", &rh)], &[], "");
        let m = merge(&l, &r, NOW);
        let h = history(&m.body, ID1);
        let names: Vec<&str> = h.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names, ["x", "dup", "a", "b", "c", "d", "e", "f"]);
        assert_eq!(
            h[0].1, 100,
            "the loser's password is retired at the loser's modified"
        );
        assert_eq!(h[1].1, 60);
        // Ten at most.
        let many: Vec<(String, u64)> = (0..10).map(|i| (format!("p{i:02}"), 1000 - i)).collect();
        let many: Vec<(&str, u64)> = many.iter().map(|(p, r)| (p.as_str(), *r)).collect();
        let l = body(0, &[login(ID1, 100, DEV_A, "x", &many)], &[], "");
        let r = body(0, &[login(ID1, 200, DEV_B, "y", &[("zz", 5000)])], &[], "");
        let m = merge(&l, &r, NOW);
        let h = history(&m.body, ID1);
        assert_eq!(h.len(), 10);
        assert_eq!(h[0], ("zz".into(), 5000));
        assert_eq!(
            h[9],
            ("p08".into(), 992),
            "x at 100 and p09 at 991 fall off"
        );
    }

    #[test]
    fn empty_passwords_never_enter_the_history() {
        let l = body(
            0,
            &[login(ID1, 100, DEV_A, "", &[("", 7), ("old", 5)])],
            &[],
            "",
        );
        let r = body(0, &[login(ID1, 200, DEV_B, "new", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(history(&m.body, ID1), vec![("old".into(), 5)]);
    }

    #[test]
    fn an_unsorted_history_from_another_client_is_written_back_sorted() {
        // Another client wrote a history out of order, with a duplicate and its own current
        // password; any merge normalises it.
        let r = body(
            0,
            &[login(
                ID1,
                100,
                DEV_B,
                "cur",
                &[("a", 1), ("b", 9), ("cur", 5), ("a", 3)],
            )],
            &[],
            "",
        );
        let l = body(0, &[], &[], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(
            history(&m.body, ID1),
            vec![("b".into(), 9), ("a".into(), 3)]
        );
        let json = m.body.to_checked_json().unwrap();
        let back = Body::from_json(&json).unwrap();
        assert_eq!(history(&back, ID1), vec![("b".into(), 9), ("a".into(), 3)]);
    }

    #[test]
    fn a_note_history_is_normalised_after_clamping() {
        // Written in history order: `x` at now + 2 days, then `y` at now + 12 h. Clamping `x` to
        // `now` would leave it after `y` without step 1's normalisation.
        let note = format!(
            r#"{{"id":"{ID1}","type":"note","name":"n","folder":"","favourite":false,"notes":"",
            "fields":[],"password_history":[{{"password":"x","retired":{}}},
            {{"password":"y","retired":{}}}],"created":0,"modified":100,"modified_by":"{DEV_A}"}}"#,
            NOW + 2 * DAY,
            NOW + DAY / 2
        );
        let m = merge(&body(0, &[note], &[], ""), &body(0, &[], &[], ""), NOW);
        assert_eq!(
            history(&m.body, ID1),
            vec![("y".into(), NOW + DAY / 2), ("x".into(), NOW)]
        );
    }

    #[test]
    fn a_losing_password_equal_to_the_winners_is_not_kept() {
        let l = body(
            0,
            &[login(ID1, 100, DEV_A, "same", &[("same", 50)])],
            &[],
            "",
        );
        let r = body(0, &[login(ID1, 200, DEV_B, "same", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        assert!(history(&m.body, ID1).is_empty());
    }

    #[test]
    fn origin_travels_with_the_winning_item() {
        let with_origin = |m: u64, by: &str, src: &str| {
            login(ID1, m, by, "pw", &[]).replace(
                r#""name":"n""#,
                &format!(r#""name":"n","origin":{{"bitwarden":{{"src":"{src}"}}}}"#),
            )
        };
        let l = body(0, &[with_origin(100, DEV_A, "local")], &[], "");
        let r = body(0, &[with_origin(200, DEV_B, "remote")], &[], "");
        let m = merge(&l, &r, NOW);
        let o = m
            .body
            .item(ID1)
            .unwrap()
            .fields()
            .unwrap()
            .origin
            .clone()
            .unwrap();
        assert!(o["bitwarden"] == json::parse(br#"{"src":"remote"}"#).unwrap());
        // A winner without `origin` does not take the loser's.
        let r = body(0, &[login(ID1, 200, DEV_B, "pw", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        assert!(m.body.item(ID1).unwrap().fields().unwrap().origin.is_none());
    }

    #[test]
    fn same_password_adds_nothing() {
        let l = body(0, &[login(ID1, 100, DEV_A, "same", &[])], &[], "");
        let r = body(0, &[login(ID1, 200, DEV_B, "same", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        assert!(history(&m.body, ID1).is_empty());
    }

    #[test]
    fn local_password_change_wins_and_keeps_history() {
        // The local device changed the password at NOW - 5; the remote still has the old one.
        let r = body(0, &[login(ID1, 100, DEV_B, "old", &[])], &[], "");
        let l = body(
            0,
            &[login(ID1, NOW - 5, DEV_A, "new", &[("old", NOW - 5)])],
            &[],
            "",
        );
        let m = merge(&l, &r, NOW);
        assert_eq!(pw(&m.body, ID1), "new");
        assert_eq!(history(&m.body, ID1), vec![("old".into(), NOW - 5)]);
    }

    #[test]
    fn full_tie_takes_the_remote_entry() {
        let t = NOW - 100;
        let l = body(0, &[login(ID1, t, DEV_A, "local", &[])], &[], "");
        let r = body(0, &[login(ID1, t, DEV_A, "remote", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(pw(&m.body, ID1), "remote");
        assert_eq!(history(&m.body, ID1), vec![("local".into(), t)]);
        // A tie between an item and a tombstone also goes to the remote side.
        let r = body(0, &[], &[tomb(ID1, t, DEV_A)], "");
        let m = merge(&l, &r, NOW);
        assert!(m.body.items.is_empty());
        assert_eq!(m.body.tombstones.len(), 1);
        let m = merge(&r, &l, NOW);
        assert_eq!(m.body.items.len(), 1);
        assert!(m.body.tombstones.is_empty());
    }

    #[test]
    fn modified_by_breaks_ties_as_a_string() {
        let l = body(0, &[login(ID1, 100, DEV_B, "b", &[])], &[], "");
        let r = body(0, &[login(ID1, 100, DEV_A, "a", &[])], &[], "");
        assert_eq!(pw(&merge(&l, &r, NOW).body, ID1), "b");
        assert_eq!(pw(&merge(&r, &l, NOW).body, ID1), "b");
    }

    #[test]
    fn edit_against_delete() {
        let item = login(ID1, NOW - 100, DEV_A, "pw", &[]);
        let newer_delete = body(0, &[], &[tomb(ID1, NOW - 50, DEV_B)], "");
        let m = merge(
            &body(0, std::slice::from_ref(&item), &[], ""),
            &newer_delete,
            NOW,
        );
        assert!(m.body.items.is_empty());
        assert_eq!(m.body.tombstones[0].modified, NOW - 50);
        let older_delete = body(0, &[], &[tomb(ID1, NOW - 150, DEV_B)], "");
        let m = merge(&body(0, &[item], &[], ""), &older_delete, NOW);
        assert_eq!(m.body.items.len(), 1);
        assert!(m.body.tombstones.is_empty());
    }

    #[test]
    fn clamping_stamps_retired_and_horizon() {
        let future = NOW + DAY + 1;
        let l = body(
            future,
            &[login(
                ID1,
                future,
                DEV_A,
                "pw",
                &[("old", future), ("older", 5)],
            )],
            &[tomb(ID2, future, DEV_A)],
            "",
        );
        let r = body(0, &[], &[], "");
        let m = merge(&l, &r, NOW);
        let i = m.body.item(ID1).unwrap();
        assert_eq!(i.modified, NOW);
        assert_eq!(i.review.as_deref(), Some("clamped"));
        assert_eq!(
            history(&m.body, ID1),
            vec![("old".into(), NOW), ("older".into(), 5)]
        );
        assert_eq!(m.body.tombstones[0].modified, NOW);
        assert_eq!(m.body.horizon, cutoff(NOW));
        // Exactly now + DAY is not clamped.
        let edge = NOW + DAY;
        let l = body(
            cutoff(NOW) + DAY,
            &[login(ID1, edge, DEV_A, "pw", &[])],
            &[],
            "",
        );
        let m = merge(&l, &r, NOW);
        assert_eq!(m.body.item(ID1).unwrap().modified, edge);
        assert_eq!(m.body.item(ID1).unwrap().review, None);
        assert_eq!(m.body.horizon, cutoff(NOW) + DAY);
    }

    #[test]
    fn clamped_item_can_lose_to_a_later_honest_edit() {
        let l = body(
            0,
            &[login(ID1, NOW + 10 * DAY, DEV_A, "future", &[])],
            &[],
            "",
        );
        let r = body(0, &[login(ID1, NOW, DEV_B, "honest", &[])], &[], "");
        let m = merge(&l, &r, NOW);
        // Both stamps are NOW after clamping; DEV_B > DEV_A wins.
        assert_eq!(pw(&m.body, ID1), "honest");
        assert_eq!(m.body.item(ID1).unwrap().review, None);
    }

    #[test]
    fn clock_in_1970_clamps_everything_and_purges_nothing_early() {
        let now = 1000;
        let l = body(
            NOW,
            &[login(ID1, NOW, DEV_A, "pw", &[])],
            &[tomb(ID2, NOW - DAY, DEV_A)],
            "",
        );
        let m = merge(&l, &l, now);
        let i = m.body.item(ID1).unwrap();
        assert_eq!(i.modified, now);
        assert_eq!(i.review.as_deref(), Some("clamped"));
        assert_eq!(m.body.horizon, 0, "cutoff is 0 when now is under 180 days");
        assert_eq!(
            m.body.tombstones.len(),
            1,
            "no tombstone is older than cutoff 0"
        );
        assert_eq!(m.body.tombstones[0].modified, now);
    }

    #[test]
    fn now_under_180_days_saturates() {
        let now = TOMBSTONE_LIFETIME - 1;
        assert_eq!(cutoff(now), 0);
        let l = body(0, &[], &[tomb(ID2, 0, DEV_A)], "");
        let m = merge(&l, &l, now);
        assert_eq!(m.body.tombstones.len(), 1);
        assert_eq!(m.body.horizon, 0);
        let m = merge(&l, &l, u64::MAX);
        assert!(
            m.body.tombstones.is_empty(),
            "saturating arithmetic at the top too"
        );
    }

    #[test]
    fn expiry() {
        // A horizon is never later than `cutoff + DAY` after clamping.
        let horizon = cutoff(NOW) - 10 * DAY;
        let r = body(horizon, &[], &[], "");
        let stale = login(ID1, horizon - 1, DEV_A, "pw", &[]);
        let fresh = login(ID2, horizon, DEV_A, "pw", &[]);
        let l = body(0, &[stale.clone(), fresh], &[], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(m.expired.len(), 1);
        assert_eq!(m.expired[0].id, ID1);
        assert!(m.body.item(ID1).is_none());
        assert!(m.body.item(ID2).is_some());
        // A remote-only item older than the local horizon expires too.
        let m = merge(&r, &body(0, std::slice::from_ref(&stale), &[], ""), NOW);
        assert_eq!(m.expired.len(), 1);
        // The other side's horizon decides, not the item's own side.
        let m = merge(
            &body(0, &[], &[], ""),
            &body(horizon, std::slice::from_ref(&stale), &[], ""),
            NOW,
        );
        assert!(m.expired.is_empty());
        // An item paired with a tombstone on the other side never expires; the stamp decides.
        let r = body(horizon, &[], &[tomb(ID1, horizon - 5, DEV_B)], "");
        let m = merge(&body(0, &[stale], &[], ""), &r, NOW);
        assert!(m.expired.is_empty());
        assert_eq!(m.body.items.len(), 1);
    }

    #[test]
    fn purge_raises_the_horizon_only_when_a_tombstone_is_dropped() {
        let c = cutoff(NOW);
        let l = body(5, &[], &[tomb(ID1, c - 1, DEV_A), tomb(ID2, c, DEV_A)], "");
        let r = body(7, &[], &[], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(m.body.tombstones.len(), 1);
        assert_eq!(m.body.tombstones[0].id, ID2);
        assert_eq!(m.body.horizon, c);
        let l = body(5, &[], &[tomb(ID2, c, DEV_A)], "");
        let m = merge(&l, &r, NOW);
        assert_eq!(m.body.horizon, 7, "the greater of the two horizons");
    }

    #[test]
    fn unknown_item_type_merges_whole() {
        let card = |m: u64, n: u64| {
            format!(
                r#"{{"id":"{ID1}","type":"card","modified":{m},"modified_by":"{DEV_A}","number":{n},"password_history":[{{"retired":{}}}]}}"#,
                NOW + 5 * DAY
            )
        };
        let l = body(0, &[card(100, 1)], &[], "");
        let r = body(0, &[card(200, 2)], &[], "");
        let m = merge(&l, &r, NOW);
        let v = m.body.item(ID1).unwrap().to_value();
        let Value::Object(o) = &v else { panic!() };
        assert!(o["number"] == Value::Number(2));
        // Its contents are not clamped; only `modified` is.
        let text = String::from_utf8(json::to_vec(&o["password_history"]).to_vec()).unwrap();
        assert_eq!(text, format!(r#"[{{"retired":{}}}]"#, NOW + 5 * DAY));
        let l = body(0, &[card(NOW + 2 * DAY, 1)], &[], "");
        let m = merge(&l, &r, NOW);
        let i = m.body.item(ID1).unwrap();
        assert_eq!(i.modified, NOW);
        // An unknown type keeps `review` in its own map.
        let v = i.to_value();
        let Value::Object(o) = &v else { panic!() };
        assert!(o["review"] == Value::String("clamped".into()));
        assert!(m.body.to_checked_json().is_ok());
        // A non-string `review` on an unknown type is kept unchecked, and replaced when clamped.
        let odd = format!(
            r#"{{"id":"{ID1}","type":"card","modified":{},"modified_by":"{DEV_A}","review":[1]}}"#,
            NOW + 2 * DAY
        );
        let m = merge(&body(0, &[odd], &[], ""), &body(0, &[], &[], ""), NOW);
        let v = m.body.item(ID1).unwrap().to_value();
        let Value::Object(o) = &v else { panic!() };
        assert!(o["review"] == Value::String("clamped".into()));
    }

    #[test]
    fn unknown_top_level_fields() {
        let l = body(0, &[], &[], r#","a":1,"only_local":{"x":[]}"#);
        let r = body(0, &[], &[], r#","a":2,"only_remote":true"#);
        let m = merge(&l, &r, NOW);
        let keys: Vec<&str> = m.body.extra.keys().map(String::as_str).collect();
        assert_eq!(keys, ["a", "only_local", "only_remote"]);
        assert!(m.body.extra["a"] == Value::Number(2));
    }

    #[test]
    fn equal_bodies_merge_to_the_same_content() {
        let b = body(
            3,
            &[
                login(ID1, NOW - 1, DEV_A, "pw", &[("old", 5)]),
                format!(r#"{{"id":"{ID2}","type":"card","modified":9,"modified_by":"{DEV_A}"}}"#),
            ],
            &[tomb(
                "00000000-0000-4000-8000-000000000003",
                NOW - DAY,
                DEV_B,
            )],
            r#","z":[1]"#,
        );
        let m = merge(&b, &b, NOW);
        assert!(same_content(&m.body, &b));
        assert!(m.expired.is_empty());
    }

    #[test]
    fn adopt_test() {
        let a = body(
            0,
            &[login(ID1, 1, DEV_A, "pw", &[])],
            &[tomb(ID2, 1, DEV_A)],
            r#","k":1"#,
        );
        let mut b = a.clone();
        b.items.reverse();
        assert!(same_content(&a, &b));
        assert!(same_content(&a, &b));
        b.v = 2;
        assert!(!same_content(&a, &b), "v is compared");
        let mut c = a.clone();
        c.extra.insert("k".into(), Value::Number(2));
        assert!(!same_content(&a, &c), "unknown top-level key differs");
        let mut c = a.clone();
        c.extra.clear();
        assert!(!same_content(&a, &c));
        let mut c = a.clone();
        c.horizon = 1;
        assert!(!same_content(&a, &c));
        let mut c = a.clone();
        c.items[0].review = Some("clamped".into());
        assert!(!same_content(&a, &c));
        // An id moved from items to tombstones is a difference even with equal counts.
        let x = body(0, &[login(ID1, 1, DEV_A, "pw", &[])], &[], "");
        let y = body(0, &[], &[tomb(ID1, 1, DEV_A)], "");
        assert!(!same_content(&x, &y));
    }
}
