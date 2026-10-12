//! Items as the commands see them: selection by ID, name, or part of a name; the TOML text form
//! of `show` and `edit`; and the JSON forms of `show`, `ls`, and `find`.

use crate::error::{CliError, Exit, Result};
use crate::output::{format_time, obj, s};
use std::fmt::Write as _;
use toml::{Table, Value as Toml};
use vault_core::body::{
    Body, CustomField, Item, ItemData, ItemFields, Login, LoginUri, TYPE_LOGIN, TYPE_NOTE,
};
use vault_core::json::{Map, Value};
use zeroize::Zeroizing;

/// The shortest ID prefix that selects an item.
pub const MIN_ID_PREFIX: usize = 8;
/// What `show` prints in place of a secret without `--reveal`.
pub const MASK: &str = "********";

/// The display name of an item: its name, or its ID for an item of unknown `type`.
pub fn display_name(item: &Item) -> &str {
    item.fields().map_or(&item.id, |f| &f.name)
}

/// `folder/name`, or the name alone.
pub fn full_name(item: &Item) -> String {
    match item.fields() {
        Some(f) if !f.folder.is_empty() => format!("{}/{}", f.folder, f.name),
        Some(f) => f.name.clone(),
        None => item.id.clone(),
    }
}

/// Selects one item of `body`: by ID or an ID prefix of at least 8 characters, then by name
/// (or `folder/name`) without regard to case, then by part of a name. The first step that
/// matches exactly one item selects it; a step that matches several ends with exit code 3.
pub fn select<'a>(body: &'a Body, query: &str) -> Result<&'a Item> {
    let q = query.to_lowercase();
    let steps: [&dyn Fn(&Item) -> bool; 3] = [
        &|i| i.id == q || (q.len() >= MIN_ID_PREFIX && i.id.starts_with(&q)),
        &|i| match i.fields() {
            Some(f) => {
                let name = f.name.to_lowercase();
                name == q
                    || (!f.folder.is_empty()
                        && format!("{}/{}", f.folder.to_lowercase(), name) == q)
            }
            None => false,
        },
        &|i| {
            !q.is_empty()
                && i.fields()
                    .is_some_and(|f| f.name.to_lowercase().contains(&q))
        },
    ];
    for step in steps {
        let found: Vec<&Item> = body.items.iter().filter(|i| step(i)).collect();
        match found.len() {
            0 => continue,
            1 => return Ok(found[0]),
            _ => {
                let mut msg = format!("{} items match {query:?}:", found.len());
                for i in found {
                    let _ = write!(msg, "\n  {}  {}", &i.id[..MIN_ID_PREFIX], full_name(i));
                }
                return Err(CliError::new(Exit::Item, "item.ambiguous", msg));
            }
        }
    }
    Err(CliError::new(
        Exit::Item,
        "item.not_found",
        format!("no item matches {query:?}"),
    ))
}

/// A TOML basic string.
fn basic(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML multi-line basic string, starting on the line after the opening quotes.
fn multiline(text: &str) -> String {
    let mut out = String::from("\"\"\"\n");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\t' => out.push(c),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push_str("\"\"\"");
    out
}

const HEAD: [&str; 5] = [
    "# vault item",
    "# Lines that start with \"#\" are ignored.",
    "# Save and quit to apply the changes; quit without saving to cancel.",
    "#",
    "#",
];
const TAIL: [&str; 5] = ["#", "#", "#", "#", "# end of item"];

/// The text form of an item. Secrets are masked unless `reveal`. `error` goes in comments after
/// the fixed head lines, for the editor's second round.
pub fn text_form(item: &Item, reveal: bool, error: Option<&str>) -> Zeroizing<String> {
    let mut t = Zeroizing::new(String::with_capacity(text_form_capacity(item, error)));
    for l in HEAD {
        t.push_str(l);
        t.push('\n');
    }
    if let Some(e) = error {
        for l in e.lines() {
            let _ = writeln!(t, "# error: {l}");
        }
        t.push_str("#\n");
    }
    let _ = writeln!(t, "# id: {}", item.id);
    let _ = writeln!(t, "# type: {}", comment_safe(&item.item_type));
    let _ = writeln!(t, "# modified: {}", format_time(item.modified));
    let Some(f) = item.fields() else {
        t.push_str("# This item's type is not supported by this client.\n");
        for l in TAIL {
            t.push_str(l);
            t.push('\n');
        }
        return t;
    };
    let _ = writeln!(
        t,
        "# password history: {} entries",
        f.password_history.len()
    );
    if let Some(r) = &item.review {
        let _ = writeln!(t, "# review: {}", comment_safe(r));
    }
    let secret = |v: &str| {
        if reveal || v.is_empty() {
            basic(v)
        } else {
            basic(MASK)
        }
    };
    let _ = writeln!(t, "name = {}", basic(&f.name));
    let _ = writeln!(t, "folder = {}", basic(&f.folder));
    let _ = writeln!(t, "favourite = {}", f.favourite);
    if let Some(l) = item.login() {
        let _ = writeln!(t, "username = {}", basic(&l.username));
        let _ = writeln!(t, "password = {}", secret(&l.password));
        let _ = writeln!(t, "totp = {}", secret(l.totp.as_deref().unwrap_or("")));
        if l.uris.is_empty() {
            t.push_str("uris = []\n");
        } else {
            t.push_str("uris = [\n");
            for u in &l.uris {
                let _ = writeln!(
                    t,
                    "  {{ uri = {}, match = {} }},",
                    basic(&u.uri),
                    basic(&u.match_value)
                );
            }
            t.push_str("]\n");
        }
    }
    let _ = writeln!(t, "notes = {}", multiline(&f.notes));
    for field in &f.fields {
        t.push_str("\n[[fields]]\n");
        let _ = writeln!(t, "name = {}", basic(&field.name));
        let v = if field.hidden {
            secret(&field.value)
        } else {
            basic(&field.value)
        };
        let _ = writeln!(t, "value = {v}");
        let _ = writeln!(t, "hidden = {}", field.hidden);
    }
    t.push('\n');
    for l in TAIL {
        t.push_str(l);
        t.push('\n');
    }
    t
}

/// An upper bound on the length of [`text_form`], so its buffer never reallocates and leaves no
/// copy of item content behind: every content byte at most six times (a `\uXXXX` escape), plus
/// the fixed lines and the per-entry syntax.
fn text_form_capacity(item: &Item, error: Option<&str>) -> usize {
    let mut content =
        item.id.len() + item.item_type.len() + item.review.as_ref().map_or(0, String::len);
    let mut entries = 0;
    if let Some(f) = item.fields() {
        content += f.name.len() + f.folder.len() + f.notes.len();
        for c in &f.fields {
            content += c.name.len() + c.value.len();
        }
        entries += f.fields.len();
        if let Some(l) = item.login() {
            content += l.username.len() + l.password.len() + l.totp.as_ref().map_or(0, String::len);
            for u in &l.uris {
                content += u.uri.len() + u.match_value.len();
            }
            entries += l.uris.len();
        }
    }
    let error = error.map_or(0, |e| e.len() + 16 * (e.lines().count() + 1));
    6 * content + 64 * entries + error + 1024
}

/// A value for a comment line: no line breaks.
fn comment_safe(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

/// Parses an edited text form into the item's new fields. Everything the form does not show
/// (password history, app bindings, passkeys, `origin`, and unknown fields) is kept from `item`.
pub fn parse_text_form(item: &Item, text: &str) -> std::result::Result<ItemFields, String> {
    let old = item.fields().ok_or("the item's type is not supported")?;
    let mut table: Table = text.parse::<Table>().map_err(|e| e.message().to_owned())?;
    let mut f = old.clone();
    f.name = take_string(&mut table, "name")?;
    if f.name.is_empty() {
        return Err("name is empty".into());
    }
    f.folder = take_string(&mut table, "folder")?;
    f.favourite = match table.remove("favourite") {
        Some(Toml::Boolean(b)) => b,
        Some(_) => return Err("favourite must be true or false".into()),
        None => return Err("favourite is missing".into()),
    };
    f.notes = take_string(&mut table, "notes")?;
    f.fields = match table.remove("fields") {
        None => Vec::new(),
        Some(Toml::Array(a)) => a
            .into_iter()
            .enumerate()
            .map({
                let mut used = vec![false; old.fields.len()];
                move |(n, v)| custom_field(v, &old.fields, &mut used, n)
            })
            .collect::<std::result::Result<_, _>>()?,
        Some(_) => return Err("fields must be [[fields]] tables".into()),
    };
    if item.item_type == TYPE_LOGIN {
        let ol = old.login.as_ref().ok_or("the login has no login data")?;
        let mut l = ol.clone();
        l.username = take_string(&mut table, "username")?;
        l.password = take_string(&mut table, "password")?;
        let totp = take_string(&mut table, "totp")?;
        l.totp = if totp.is_empty() && ol.totp.is_none() {
            None
        } else {
            Some(totp)
        };
        l.uris = match table.remove("uris") {
            Some(Toml::Array(a)) => a
                .into_iter()
                .enumerate()
                .map({
                    let mut used = vec![false; ol.uris.len()];
                    move |(n, v)| login_uri(v, &ol.uris, &mut used, n)
                })
                .collect::<std::result::Result<_, _>>()?,
            Some(_) => return Err("uris must be an array".into()),
            None => return Err("uris is missing".into()),
        };
        f.login = Some(l);
    } else if item.item_type != TYPE_NOTE {
        return Err("the item's type is not supported".into());
    }
    if let Some(k) = table.keys().next() {
        return Err(format!("{k} is not a key of this item"));
    }
    Ok(f)
}

fn take_string(t: &mut Table, key: &str) -> std::result::Result<String, String> {
    match t.remove(key) {
        Some(Toml::String(s)) => Ok(s),
        Some(_) => Err(format!("{key} must be a string")),
        None => Err(format!("{key} is missing")),
    }
}

/// The unknown fields of the first entry of `old` not yet `used` that `same` accepts, which it
/// marks used; none when no entry matches.
fn take_extra<T>(
    old: &[T],
    used: &mut [bool],
    same: impl Fn(&T) -> bool,
    extra: impl Fn(&T) -> &Map,
) -> Map {
    match (0..old.len()).find(|&i| !used[i] && same(&old[i])) {
        Some(i) => {
            used[i] = true;
            extra(&old[i]).clone()
        }
        None => Map::new(),
    }
}

fn custom_field(
    v: Toml,
    old: &[CustomField],
    used: &mut [bool],
    n: usize,
) -> std::result::Result<CustomField, String> {
    let Toml::Table(mut t) = v else {
        return Err(format!("field {} must be a table", n + 1));
    };
    let name = take_string(&mut t, "name").map_err(|e| format!("field {}: {e}", n + 1))?;
    let value = take_string(&mut t, "value").map_err(|e| format!("field {}: {e}", n + 1))?;
    let hidden = match t.remove("hidden") {
        Some(Toml::Boolean(b)) => b,
        None => false,
        Some(_) => return Err(format!("field {}: hidden must be true or false", n + 1)),
    };
    if let Some(k) = t.keys().next() {
        return Err(format!("field {}: {k} is not a key of a field", n + 1));
    }
    let extra = take_extra(old, used, |o| o.name == name, |o| &o.extra);
    Ok(CustomField {
        name,
        value,
        hidden,
        extra,
    })
}

fn login_uri(
    v: Toml,
    old: &[LoginUri],
    used: &mut [bool],
    n: usize,
) -> std::result::Result<LoginUri, String> {
    let Toml::Table(mut t) = v else {
        return Err(format!(
            "URI {} must be {{ uri = \"...\", match = \"...\" }}",
            n + 1
        ));
    };
    let uri = take_string(&mut t, "uri").map_err(|e| format!("URI {}: {e}", n + 1))?;
    let match_value = match t.remove("match") {
        None => "base_domain".to_owned(),
        Some(Toml::String(m)) => m,
        Some(_) => return Err(format!("URI {}: match must be a string", n + 1)),
    };
    if let Some(k) = t.keys().next() {
        return Err(format!("URI {}: {k} is not a key of a URI", n + 1));
    }
    let extra = take_extra(old, used, |o| o.uri == uri, |o| &o.extra);
    Ok(LoginUri {
        uri,
        match_value,
        extra,
    })
}

/// The fields of `current` with the keys of the text form that the user changed from `base` to
/// `edited`, so a change that reached `current` while the editor was open (a sync, or another
/// command) is kept wherever the user did not touch the same key. Lists (custom fields and URIs)
/// count as one key each.
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

/// The fields of a new login or note.
pub fn new_fields(name: &str, folder: &str, login: Option<Login>) -> ItemFields {
    ItemFields {
        name: name.to_owned(),
        folder: folder.to_owned(),
        favourite: false,
        notes: String::new(),
        fields: Vec::new(),
        password_history: Vec::new(),
        created: 0,
        login,
        origin: None,
        extra: Map::new(),
    }
}

/// A login with a username, a password, and URIs matched by base domain.
pub fn new_login(username: &str, password: &str, uris: &[String]) -> Login {
    Login {
        username: username.to_owned(),
        password: password.to_owned(),
        uris: uris
            .iter()
            .map(|u| LoginUri {
                uri: u.clone(),
                match_value: "base_domain".into(),
                extra: Map::new(),
            })
            .collect(),
        apps: Vec::new(),
        totp: None,
        passkeys: Vec::new(),
        extra: Map::new(),
    }
}

/// The value `show --field` prints: `username`, `password`, `totp`, `notes`, `uri` (the first
/// URI), or a custom field's value.
pub fn field_value<'a>(item: &'a Item, name: &str) -> Result<&'a str> {
    let f = item.fields().ok_or_else(unsupported)?;
    let login = item.login();
    let v = match name {
        "username" => login.map(|l| l.username.as_str()),
        "password" => login.map(|l| l.password.as_str()),
        "totp" => login.map(|l| l.totp.as_deref().unwrap_or("")),
        "notes" => Some(f.notes.as_str()),
        "uri" => login.and_then(|l| l.uris.first()).map(|u| u.uri.as_str()),
        _ => None,
    };
    v.or_else(|| {
        f.fields
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value.as_str())
    })
    .ok_or_else(|| {
        CliError::new(
            Exit::Item,
            "item.no_field",
            format!("{} has no field {name:?}", display_name(item)),
        )
    })
}

/// The error for an item of unknown `type`.
pub fn unsupported() -> CliError {
    CliError::other(
        "input.unsupported_item",
        "the item's type is not supported by this client",
    )
}

/// The item as the body schema defines it, for `show --json`. Without `reveal`, the password,
/// the TOTP secret, hidden field values, the password history, and passkeys are `null`.
pub fn item_json(item: &Item, reveal: bool) -> Value {
    let mut v = item.to_value();
    if reveal || item.fields().is_none() {
        return v;
    }
    if let Value::Object(m) = &mut v {
        m.insert("password_history".into(), Value::Null);
        if let Some(Value::Array(fields)) = m.get_mut("fields") {
            for f in fields {
                if let Value::Object(fm) = f
                    && matches!(fm.get("hidden"), Some(Value::Bool(true)))
                {
                    fm.insert("value".into(), Value::Null);
                }
            }
        }
        if item.item_type == TYPE_LOGIN
            && let Some(Value::Object(l)) = m.get_mut("login")
        {
            for k in ["password", "totp", "passkeys"] {
                l.insert(k.into(), Value::Null);
            }
        }
    }
    v
}

/// The summary `ls` and `find` list.
pub fn summary_json(item: &Item) -> Value {
    let f = item.fields();
    obj([
        ("id", s(&item.id)),
        ("type", s(&item.item_type)),
        ("name", f.map_or(Value::Null, |f| s(&f.name))),
        ("folder", f.map_or(Value::Null, |f| s(&f.folder))),
        (
            "username",
            item.login().map_or(Value::Null, |l| s(&l.username)),
        ),
        (
            "favourite",
            f.map_or(Value::Null, |f| Value::Bool(f.favourite)),
        ),
        ("review", item.review.as_deref().map_or(Value::Null, s)),
    ])
}

/// Whether `item` is in `folder` or a folder under it.
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

/// Items sorted for listing: by folder, then name, without regard to case; unknown types last.
pub fn sorted(items: Vec<&Item>) -> Vec<&Item> {
    let mut items = items;
    items.sort_by_cached_key(|i| match i.fields() {
        Some(f) => (0, f.folder.to_lowercase(), f.name.to_lowercase()),
        None => (1, String::new(), i.id.clone()),
    });
    items
}

/// One line of `ls` and `find`: ID prefix, type marker, `folder/name`, and the username.
pub fn summary_line(item: &Item) -> String {
    let user = item.login().map_or("", |l| l.username.as_str());
    let kind = match (&item.data, item.item_type.as_str()) {
        (ItemData::Unknown(_), t) => format!("[unsupported: {t}]"),
        (_, TYPE_NOTE) => "[note]".to_owned(),
        _ => String::new(),
    };
    let review = if item.review.is_some() {
        " [review]"
    } else {
        ""
    };
    let mut line = format!("{}  {}", &item.id[..MIN_ID_PREFIX], full_name(item));
    if !kind.is_empty() {
        let _ = write!(line, " {kind}");
    }
    line.push_str(review);
    if !user.is_empty() {
        let _ = write!(line, "  ({user})");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err<T, E>(r: std::result::Result<T, E>) -> E {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    const DEV: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn body() -> Body {
        let item = |id: &str, name: &str, folder: &str| {
            format!(
                r#"{{"id":"{id}","type":"login","name":"{name}","folder":"{folder}","favourite":false,
                "notes":"line one\nsays \"hi\"","fields":[{{"name":"code","value":"s3cret","hidden":true,"x":1}}],
                "password_history":[],"created":1,"modified":2,"modified_by":"{DEV}",
                "login":{{"username":"ned","password":"pw","uris":[{{"uri":"https://a.example","match":"host"}}],
                "apps":[],"totp":null,"passkeys":[{{"k":1}}]}},"origin":{{"bitwarden":{{"id":"x"}}}},"zz":true}}"#
            )
        };
        let j = format!(
            r#"{{"v":1,"horizon":0,"items":[{},{},{},
            {{"id":"44444444-0000-4000-8000-000000000000","type":"card","modified":1,"modified_by":"{DEV}"}}],"tombstones":[]}}"#,
            item("11111111-0000-4000-8000-000000000000", "GitHub", "Work"),
            item("22222222-0000-4000-8000-000000000000", "GitHub", "Home"),
            item("33333333-0000-4000-8000-000000000000", "GitLab", ""),
        );
        Body::from_json(j.as_bytes()).unwrap()
    }

    #[test]
    fn selection_order() {
        let b = body();
        assert_eq!(select(&b, "33333333").unwrap().id[..8], *"33333333");
        assert_eq!(
            select(&b, "33333333-0000-4000-8000-000000000000")
                .unwrap()
                .id[..8],
            *"33333333"
        );
        assert_eq!(select(&b, "work/github").unwrap().id[..8], *"11111111");
        assert_eq!(select(&b, "gitlab").unwrap().id[..8], *"33333333");
        assert_eq!(select(&b, "lab").unwrap().id[..8], *"33333333");
        let e = err(select(&b, "github"));
        assert_eq!((e.exit(), e.code()), (Exit::Item, "item.ambiguous"));
        assert!(e.message().contains("11111111") && e.message().contains("22222222"));
        let e = err(select(&b, "git"));
        assert_eq!(e.code(), "item.ambiguous");
        let e = err(select(&b, "nothing"));
        assert_eq!((e.exit(), e.code()), (Exit::Item, "item.not_found"));
        // A prefix shorter than eight characters is not an ID.
        assert_eq!(err(select(&b, "3333")).code(), "item.not_found");
        assert_eq!(select(&b, "44444444").unwrap().item_type, "card");
    }

    #[test]
    fn text_form_round_trip_keeps_hidden_data() {
        let b = body();
        let item = &b.items[0];
        let t = text_form(item, true, None);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[..5], HEAD);
        assert_eq!(lines[lines.len() - 5..], TAIL);
        let f = parse_text_form(item, &t).unwrap();
        assert!(f == *item.fields().unwrap(), "unchanged:\n{}", t.as_str());
        let edited = t.replace("password = \"pw\"", "password = \"new\"");
        let f = parse_text_form(item, &edited).unwrap();
        let l = f.login.as_ref().unwrap();
        assert_eq!(l.password, "new");
        assert_eq!(l.passkeys.len(), 1, "passkeys kept");
        assert!(f.origin.is_some() && f.extra.contains_key("zz"));
        assert!(f.fields[0].extra.contains_key("x"));
    }

    #[test]
    fn extras_follow_entries_that_moved() {
        let mut b = body();
        let f = match &mut b.items[0].data {
            ItemData::Known(f) => f,
            ItemData::Unknown(_) => unreachable!(),
        };
        let mut second = f.fields[0].clone();
        second.name = "other".into();
        second.extra = Map::new();
        f.fields.push(second);
        let item = &b.items[0];
        let t = text_form(item, true, None);
        // Swap the two [[fields]] tables: the unknown key goes with the "code" field.
        let first = "[[fields]]\nname = \"code\"\nvalue = \"s3cret\"\nhidden = true\n";
        let other = "[[fields]]\nname = \"other\"\nvalue = \"s3cret\"\nhidden = true\n";
        assert!(t.contains(first) && t.contains(other), "{}", t.as_str());
        let swapped = t
            .replace(first, "@@")
            .replace(other, first)
            .replace("@@", other);
        let parsed = parse_text_form(item, &swapped).unwrap();
        assert_eq!(parsed.fields[0].name, "other");
        assert!(parsed.fields[0].extra.is_empty());
        assert_eq!(parsed.fields[1].name, "code");
        assert!(parsed.fields[1].extra.contains_key("x"));
    }

    #[test]
    fn changes_apply_onto_the_current_item() {
        let b = body();
        let base = b.items[0].fields().unwrap().clone();
        // Meanwhile, a sync moved the item, changed its username, and retired a password.
        let mut current = base.clone();
        current.folder = "Moved".into();
        current.login.as_mut().unwrap().username = "synced".into();
        current
            .password_history
            .push(vault_core::body::HistoryEntry {
                password: "older".into(),
                retired: 9,
                extra: Map::new(),
            });
        // The user changed only the password and the notes.
        let mut edited = base.clone();
        edited.login.as_mut().unwrap().password = "typed".into();
        edited.notes = "new notes".into();
        let out = apply_changes(&base, &edited, &current);
        assert_eq!(out.folder, "Moved");
        assert_eq!(out.notes, "new notes");
        let l = out.login.as_ref().unwrap();
        assert_eq!(
            (l.username.as_str(), l.password.as_str()),
            ("synced", "typed")
        );
        assert_eq!(l.passkeys.len(), 1);
        assert_eq!(
            out.password_history.len(),
            1,
            "history from the current item"
        );
        // No change from the user: the current item stays as it is.
        assert!(apply_changes(&base, &base, &current) == current);
    }

    #[test]
    fn the_text_form_buffer_never_grows() {
        let mut b = body();
        if let ItemData::Known(f) = &mut b.items[0].data {
            f.notes = "\u{1}".repeat(500);
            f.name = "\"".repeat(100);
        }
        for item in &b.items {
            for reveal in [true, false] {
                let cap = text_form_capacity(item, Some("an error\nover two lines"));
                let t = text_form(item, reveal, Some("an error\nover two lines"));
                assert!(t.len() <= cap && t.capacity() == cap, "{} {}", t.len(), cap);
            }
        }
    }

    #[test]
    fn masked_form_and_errors() {
        let b = body();
        let item = &b.items[0];
        let t = text_form(item, false, Some("bad"));
        assert!(!t.contains("s3cret") && !t.contains("\"pw\""));
        assert!(t.contains("# error: bad"));
        let reveal = text_form(item, true, None);
        for (from, to, want) in [
            ("name = \"GitHub\"", "name = \"\"", "name is empty"),
            ("favourite = false", "favourite = 1", "favourite must be"),
            (
                "favourite = false",
                "favourite = false\ncolour = 1",
                "colour is not a key",
            ),
            ("username = \"ned\"\n", "", "username is missing"),
        ] {
            let e = err(parse_text_form(item, &reveal.replace(from, to)));
            assert!(e.contains(want), "{e}");
        }
        assert!(parse_text_form(item, "name = ").is_err());
    }

    #[test]
    fn json_masks_without_reveal() {
        let b = body();
        let v = item_json(&b.items[0], false);
        let text = String::from_utf8(vault_core::json::to_vec(&v).to_vec()).unwrap();
        assert!(
            !text.contains("s3cret") && !text.contains("\"pw\""),
            "{text}"
        );
        assert!(text.contains("\"password\":null") && text.contains("\"password_history\":null"));
        let text =
            String::from_utf8(vault_core::json::to_vec(&item_json(&b.items[0], true)).to_vec())
                .unwrap();
        assert!(text.contains("s3cret"));
    }

    #[test]
    fn folders_and_text() {
        let b = body();
        assert!(in_folder(&b.items[0], "Work"));
        assert!(!in_folder(&b.items[0], "Wor"));
        assert!(matches_text(&b.items[0], "A.EXAMPLE"));
        assert!(!matches_text(&b.items[3], "card"));
        assert_eq!(field_value(&b.items[0], "code").unwrap(), "s3cret");
        assert_eq!(
            field_value(&b.items[0], "uri").unwrap(),
            "https://a.example"
        );
        assert_eq!(err(field_value(&b.items[0], "nope")).exit(), Exit::Item);
    }
}
