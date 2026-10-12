//! Local edits: adding, changing, deleting, importing, and restoring items, each stamped with the
//! local time and the device ID.

use crate::body::{
    Body, HistoryEntry, Item, ItemData, ItemFields, TYPE_LOGIN, TYPE_NOTE, Tombstone, id_text,
    new_item_id,
};
use crate::error::{InputKind, Result, input};
use crate::json::Map;
use crate::rng::Rng;

/// Stamps a local change: `modified = now`, `modified_by` the device ID, and `review` removed. The
/// history of a login or a note is normalised, as every edit requires.
fn stamp(item: &mut Item, now: u64, device_id: &[u8; 16]) {
    item.modified = now;
    item.modified_by = id_text(device_id);
    item.clear_review();
    if let ItemData::Known(f) = &mut item.data {
        f.normalise_history();
    }
}

fn new_item(
    body: &mut Body,
    rng: &mut dyn Rng,
    item_type: &str,
    fields: ItemFields,
    now: u64,
    device_id: &[u8; 16],
) -> Result<String> {
    if item_type != TYPE_LOGIN && item_type != TYPE_NOTE {
        return input(InputKind::UnsupportedItem);
    }
    let id = new_item_id(rng)?;
    let mut item = Item {
        id: id.clone(),
        item_type: item_type.to_owned(),
        modified: 0,
        modified_by: String::new(),
        review: None,
        data: ItemData::Known(Box::new(fields)),
    };
    stamp(&mut item, now, device_id);
    body.items.push(item);
    Ok(id)
}

/// Adds a new login or note with a random version 4 UUID and `created = now`, and returns its
/// `id`. Draws 16 bytes.
pub fn add_item(
    body: &mut Body,
    rng: &mut dyn Rng,
    item_type: &str,
    mut fields: ItemFields,
    now: u64,
    device_id: &[u8; 16],
) -> Result<String> {
    fields.created = now;
    new_item(body, rng, item_type, fields, now, device_id)
}

/// Adds an imported login or note with a random version 4 UUID, `modified = now`, and the
/// source's creation time kept in `fields.created`, and returns its `id`. Draws 16 bytes.
pub fn import_item(
    body: &mut Body,
    rng: &mut dyn Rng,
    item_type: &str,
    fields: ItemFields,
    now: u64,
    device_id: &[u8; 16],
) -> Result<String> {
    new_item(body, rng, item_type, fields, now, device_id)
}

/// Replaces the fields of the item `id` with `fields` and stamps it. When the login password
/// changes, the previous password joins `password_history` with `retired = now`; the history is
/// then normalised. An item of unknown `type` is never edited.
pub fn update_item(
    body: &mut Body,
    id: &str,
    mut fields: ItemFields,
    now: u64,
    device_id: &[u8; 16],
) -> Result<()> {
    let Some(item) = body.items.iter_mut().find(|i| i.id == id) else {
        return input(InputKind::NotFound);
    };
    let Some(old) = item.fields() else {
        return input(InputKind::UnsupportedItem);
    };
    if let (Some(old_login), Some(new_login)) = (&old.login, &mut fields.login)
        && old_login.password != new_login.password
    {
        fields.password_history.push(HistoryEntry {
            password: old_login.password.clone(),
            retired: now,
            extra: Map::new(),
        });
    }
    item.data = ItemData::Known(Box::new(fields));
    stamp(item, now, device_id);
    Ok(())
}

/// Replaces the item `id`, of any `type`, with a tombstone stamped `now` and the device ID.
pub fn delete_item(body: &mut Body, id: &str, now: u64, device_id: &[u8; 16]) -> Result<()> {
    let Some(pos) = body.items.iter().position(|i| i.id == id) else {
        return input(InputKind::NotFound);
    };
    body.items.remove(pos);
    body.tombstones.push(Tombstone {
        id: id.to_owned(),
        modified: now,
        modified_by: id_text(device_id),
        extra: Map::new(),
    });
    Ok(())
}

/// Restores one item from an older revision: a copy of `old`, stamped, replaces the item or
/// tombstone with its `id`. When the item exists, the restored item's history is the union of
/// `old`'s history, the existing item's history, and the existing item's login password with
/// `retired = now` when it differs from the restored one. Stamping normalises the history, which
/// drops the restored password itself.
pub fn restore_item(body: &mut Body, old: &Item, now: u64, device_id: &[u8; 16]) {
    let mut item = old.clone();
    let restored = item.login().map(|l| l.password.clone());
    if let Some(existing) = body.item(&old.id).and_then(Item::fields)
        && let ItemData::Known(f) = &mut item.data
    {
        // The revision's entries come first, so on equal `retired` they are kept.
        f.password_history
            .extend(existing.password_history.iter().cloned());
        if let Some(current) = existing.login.as_ref().map(|l| &l.password)
            && Some(current) != restored.as_ref()
        {
            f.password_history.push(HistoryEntry {
                password: current.clone(),
                retired: now,
                extra: Map::new(),
            });
        }
    }
    body.items.retain(|i| i.id != old.id);
    body.tombstones.retain(|t| t.id != old.id);
    stamp(&mut item, now, device_id);
    body.items.push(item);
}

/// Restores a whole vault from an older revision: every item of `old` is restored as by
/// [`restore_item`]. Items and tombstones that `old` does not hold are left as they are.
pub fn restore_all(body: &mut Body, old: &Body, now: u64, device_id: &[u8; 16]) {
    for item in &old.items {
        restore_item(body, item, now, device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::tests::{DEV_A, ID1, login_json};
    use crate::error::Error;
    use crate::rng::BufferRng;

    const DEV: [u8; 16] = [0xbb; 16];

    fn body() -> Body {
        let j = format!(
            r#"{{"v":1,"horizon":0,"items":[{}],"tombstones":[]}}"#,
            login_json(ID1, 5, DEV_A, "pw0")
        );
        Body::from_json(j.as_bytes()).unwrap()
    }

    fn with_password(b: &Body, pw: &str) -> ItemFields {
        let mut f = b.items[0].fields().unwrap().clone();
        f.login.as_mut().unwrap().password = pw.into();
        f
    }

    #[test]
    fn edit_stamps_and_removes_review() {
        let mut b = body();
        b.items[0].review = Some("clamped".into());
        let mut f = b.items[0].fields().unwrap().clone();
        f.name = "renamed".into();
        update_item(&mut b, ID1, f, 1000, &DEV).unwrap();
        let i = &b.items[0];
        assert_eq!(i.modified, 1000);
        assert_eq!(i.modified_by, "bb".repeat(16));
        assert_eq!(i.review, None);
        assert_eq!(i.fields().unwrap().name, "renamed");
        assert!(
            i.fields().unwrap().password_history.is_empty(),
            "same password"
        );
        assert!(b.to_checked_json().is_ok());
    }

    #[test]
    fn password_change_adds_history_in_order_and_keeps_ten() {
        let mut b = body();
        for n in 1..=12u64 {
            let f = with_password(&b, &format!("pw{n}"));
            update_item(&mut b, ID1, f, 100 + n, &DEV).unwrap();
        }
        let f = b.items[0].fields().unwrap();
        assert_eq!(f.login.as_ref().unwrap().password, "pw12");
        let h: Vec<(&str, u64)> = f
            .password_history
            .iter()
            .map(|e| (e.password.as_str(), e.retired))
            .collect();
        assert_eq!(h.len(), 10);
        assert_eq!(h[0], ("pw11", 112));
        assert_eq!(h[9], ("pw2", 103));
        assert!(b.to_checked_json().is_ok());
        // Same retired time: password bytes ascending.
        let mut b = body();
        let f = with_password(&b, "b");
        update_item(&mut b, ID1, f, 7, &DEV).unwrap();
        let mut f = with_password(&b, "c");
        f.password_history[0].password = "z".into();
        update_item(&mut b, ID1, f, 7, &DEV).unwrap();
        let order: Vec<&str> = b.items[0]
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|e| e.password.as_str())
            .collect();
        assert_eq!(order, ["b", "z"]);
    }

    #[test]
    fn a_to_b_to_a_leaves_no_a_in_history_and_merges_unchanged() {
        // The item starts at A = "pw0".
        let mut b = body();
        for (pw, now) in [("B", 10), ("pw0", 20)] {
            let f = with_password(&b, pw);
            update_item(&mut b, ID1, f, now, &DEV).unwrap();
        }
        let h: Vec<(&str, u64)> = b.items[0]
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|e| (e.password.as_str(), e.retired))
            .collect();
        assert_eq!(
            h,
            [("B", 20)],
            "the current password A is not in its own history"
        );
        let m = crate::merge::merge(&b, &b, 40);
        assert!(crate::merge::same_content(&m.body, &b));
    }

    #[test]
    fn edits_normalise_the_history() {
        let mut b = body();
        let mut f = with_password(&b, "");
        f.password_history = vec![
            HistoryEntry {
                password: "x".into(),
                retired: 1,
                extra: Map::new(),
            },
            HistoryEntry {
                password: "".into(),
                retired: 9,
                extra: Map::new(),
            },
            HistoryEntry {
                password: "x".into(),
                retired: 3,
                extra: Map::new(),
            },
        ];
        update_item(&mut b, ID1, f, 50, &DEV).unwrap();
        let f = with_password(&b, "next");
        update_item(&mut b, ID1, f, 60, &DEV).unwrap();
        let h: Vec<(&str, u64)> = b.items[0]
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|e| (e.password.as_str(), e.retired))
            .collect();
        assert_eq!(
            h,
            [("pw0", 50), ("x", 3)],
            "the empty password is never kept"
        );
    }

    #[test]
    fn edits_keep_origin() {
        let mut b = body();
        let mut origin = Map::new();
        origin.insert("bitwarden".into(), crate::json::Value::Number(7));
        let mut f = b.items[0].fields().unwrap().clone();
        f.origin = Some(origin.clone());
        update_item(&mut b, ID1, f, 10, &DEV).unwrap();
        let f = with_password(&b, "new");
        update_item(&mut b, ID1, f, 20, &DEV).unwrap();
        assert!(b.items[0].fields().unwrap().origin.as_ref() == Some(&origin));
        assert!(b.to_checked_json().is_ok());
    }

    #[test]
    fn unknown_types_are_never_edited_but_may_be_deleted() {
        let j = format!(
            r#"{{"v":1,"horizon":0,"items":[{{"id":"{ID1}","type":"card","modified":1,"modified_by":"{DEV_A}"}}],"tombstones":[]}}"#
        );
        let mut b = Body::from_json(j.as_bytes()).unwrap();
        let f = body().items[0].fields().unwrap().clone();
        assert_eq!(
            update_item(&mut b, ID1, f, 9, &DEV).err(),
            Some(Error::InvalidInput(InputKind::UnsupportedItem))
        );
        delete_item(&mut b, ID1, 9, &DEV).unwrap();
        assert!(b.items.is_empty());
        assert_eq!(b.tombstones[0].id, ID1);
        assert_eq!(b.tombstones[0].modified, 9);
        assert_eq!(b.tombstones[0].modified_by, "bb".repeat(16));
    }

    #[test]
    fn missing_items() {
        let mut b = body();
        let f = b.items[0].fields().unwrap().clone();
        let other = "00000000-0000-4000-8000-0000000000ff";
        assert_eq!(
            update_item(&mut b, other, f, 9, &DEV).err(),
            Some(Error::InvalidInput(InputKind::NotFound))
        );
        assert_eq!(
            delete_item(&mut b, other, 9, &DEV).err(),
            Some(Error::InvalidInput(InputKind::NotFound))
        );
    }

    #[test]
    fn add_and_import_stamps() {
        let mut b = Body::default();
        let mut f = body().items[0].fields().unwrap().clone();
        f.created = 42;
        let mut rng = BufferRng::new(&[&[1; 16], &[2; 16]]);
        let added = add_item(&mut b, &mut rng, TYPE_LOGIN, f.clone(), 500, &DEV).unwrap();
        let imported = import_item(&mut b, &mut rng, TYPE_LOGIN, f.clone(), 600, &DEV).unwrap();
        rng.assert_consumed();
        assert_eq!(added, "01010101-0101-4101-8101-010101010101");
        let a = b.item(&added).unwrap();
        assert_eq!((a.modified, a.fields().unwrap().created), (500, 500));
        let i = b.item(&imported).unwrap();
        assert_eq!((i.modified, i.fields().unwrap().created), (600, 42));
        assert_eq!(i.modified_by, "bb".repeat(16));
        assert!(b.to_checked_json().is_ok());
        assert_eq!(
            add_item(&mut b, &mut rng, "card", f, 1, &DEV).err(),
            Some(Error::InvalidInput(InputKind::UnsupportedItem))
        );
    }

    #[test]
    fn restore_keeps_the_current_password_in_history() {
        let old = body();
        let mut b = body();
        let f = with_password(&b, "B");
        update_item(&mut b, ID1, f, 40, &DEV).unwrap();
        restore_item(&mut b, &old.items[0], 60, &DEV);
        let i = &b.items[0];
        assert_eq!(i.login().unwrap().password, "pw0");
        let h: Vec<(&str, u64)> = i
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|e| (e.password.as_str(), e.retired))
            .collect();
        assert_eq!(h, [("B", 60)]);
        // Restoring the same password adds nothing.
        let mut same = body();
        restore_item(&mut same, &old.items[0], 60, &DEV);
        assert!(same.items[0].fields().unwrap().password_history.is_empty());
    }

    #[test]
    fn restore_merges_password_histories() {
        let entry = |p: &str, r: u64| HistoryEntry {
            password: p.into(),
            retired: r,
            extra: Map::new(),
        };
        // Local: p3 current, history [p2, p1]. Revision: p1 current, empty history.
        let mut b = body();
        let mut f = with_password(&b, "p3");
        f.password_history = vec![entry("p2", 20), entry("p1", 10)];
        b.items[0].data = ItemData::Known(Box::new(f));
        let mut old = body().items[0].clone();
        let mut of = with_password(&body(), "p1");
        of.password_history = vec![entry("p0", 5)];
        old.data = ItemData::Known(Box::new(of));
        restore_item(&mut b, &old, 60, &DEV);
        let i = &b.items[0];
        assert_eq!(i.login().unwrap().password, "p1");
        let h: Vec<(&str, u64)> = i
            .fields()
            .unwrap()
            .password_history
            .iter()
            .map(|e| (e.password.as_str(), e.retired))
            .collect();
        assert_eq!(
            h,
            [("p3", 60), ("p2", 20), ("p0", 5)],
            "p1 is dropped as the current one"
        );
    }

    #[test]
    fn restore_replaces_item_or_tombstone() {
        let old = body();
        let mut b = body();
        delete_item(&mut b, ID1, 50, &DEV).unwrap();
        restore_item(&mut b, &old.items[0], 60, &DEV);
        assert!(b.tombstones.is_empty());
        assert_eq!(b.items.len(), 1);
        assert_eq!(b.items[0].modified, 60);
        assert_eq!(b.items[0].modified_by, "bb".repeat(16));
        assert_eq!(b.items[0].login().unwrap().password, "pw0");
        let mut whole = Body::default();
        restore_all(&mut whole, &old, 70, &DEV);
        assert_eq!(whole.items.len(), 1);
        assert_eq!(whole.items[0].modified, 70);
        assert!(whole.to_checked_json().is_ok());
    }
}
