//! Items as a client lists and edits them: folder membership, search, the listing order
//! (requirement CORE-4), and merging a user's edit onto an item that changed meanwhile.

use vault_core::body::{Item, ItemFields};

/// Whether `item` is in `folder` or a folder under it. Slashes at either end of `folder` are
/// ignored, and `""` is the top level: only items without a folder. Items of unknown `type` are
/// in no folder.
pub fn in_folder(item: &Item, folder: &str) -> bool {
    let folder = folder.trim_matches('/');
    item.fields().is_some_and(|f| {
        f.folder == folder
            || (f.folder.len() > folder.len()
                && f.folder.starts_with(folder)
                && f.folder.as_bytes()[folder.len()] == b'/')
    })
}

/// Whether `text` occurs, without regard to case, in the item's name, folder, username, or URIs.
/// Passwords, notes, custom fields, and TOTP secrets are not searched. Items of unknown `type`
/// never match.
pub fn matches_text(item: &Item, text: &str) -> bool {
    let q = text.to_lowercase();
    let has = |s: &str| s.to_lowercase().contains(&q);
    let Some(f) = item.fields() else {
        return false;
    };
    has(&f.name)
        || has(&f.folder)
        || item
            .login()
            .is_some_and(|l| has(&l.username) || l.uris.iter().any(|u| has(&u.uri)))
}

/// Items in listing order: by folder, then name, without regard to case, then by `id`, so
/// names that differ only in case order the same on every client; items of unknown `type` last,
/// by `id`.
pub fn sorted(items: Vec<&Item>) -> Vec<&Item> {
    let mut items = items;
    items.sort_by_cached_key(|i| match i.fields() {
        Some(f) => (
            0,
            f.folder.to_lowercase(),
            f.name.to_lowercase(),
            i.id.clone(),
        ),
        None => (1, String::new(), String::new(), i.id.clone()),
    });
    items
}

/// The fields of `current` with the keys the user changed from `base` to `edited`, so a change
/// that reached `current` while the user edited (a sync, or another command) is kept wherever
/// the user did not touch the same key.
///
/// The keys are `name`, `folder`, `favourite`, `notes`, the custom fields as one list, and on a
/// login `username`, `password`, `totp`, and the URIs as one list. Everything else (password
/// history, app bindings, passkeys, `origin`, and unknown fields) comes from `current`.
pub fn apply_changes(base: &ItemFields, edited: &ItemFields, current: &ItemFields) -> ItemFields {
    fn pick<T: Clone + PartialEq>(base: &T, edited: &T, current: &T) -> T {
        if edited == base {
            current.clone()
        } else {
            edited.clone()
        }
    }
    let mut out = current.clone();
    out.name = pick(&base.name, &edited.name, &current.name);
    out.folder = pick(&base.folder, &edited.folder, &current.folder);
    out.favourite = pick(&base.favourite, &edited.favourite, &current.favourite);
    out.notes = pick(&base.notes, &edited.notes, &current.notes);
    out.fields = pick(&base.fields, &edited.fields, &current.fields);
    if let (Some(b), Some(e), Some(c)) = (&base.login, &edited.login, &mut out.login) {
        c.username = pick(&b.username, &e.username, &c.username);
        c.password = pick(&b.password, &e.password, &c.password);
        c.totp = pick(&b.totp, &e.totp, &c.totp);
        c.uris = pick(&b.uris, &e.uris, &c.uris);
    }
    out
}
