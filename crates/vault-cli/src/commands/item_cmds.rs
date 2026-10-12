//! The item commands: `ls`, `find`, `show`, `add`, `edit`, `rm`, and `mv`.

use super::AddArgs;
use crate::error::{CliError, Exit, Result};
use crate::items::{self, display_name, select};
use crate::output::{JsonResult, obj, s};
use crate::session::{self, Ctx, OsRng, Session};
use crate::sys::{clip, editor, prompt};
use vault_core::body::{Item, ItemData, ItemFields, TYPE_LOGIN, TYPE_NOTE};
use vault_core::edit::{add_item, delete_item, update_item};
use vault_core::json::Value;
use vault_core::secret::SecretString;

fn list(ctx: &Ctx, session: &Session, keep: impl Fn(&Item) -> bool) -> JsonResult {
    let found = items::sorted(session.body.items.iter().filter(|i| keep(i)).collect());
    for i in &found {
        ctx.out.line(&items::summary_line(i));
    }
    obj([(
        "items",
        Value::Array(found.iter().map(|i| items::summary_json(i)).collect()),
    )])
    .into()
}

/// `vault ls [<folder>] [--review]`.
pub fn ls(ctx: &Ctx, folder: Option<&str>, review: bool) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    Ok(list(ctx, &session, |i| {
        folder.is_none_or(|f| items::in_folder(i, f)) && (!review || i.review.is_some())
    }))
}

/// `vault find <text>`.
pub fn find(ctx: &Ctx, text: &str) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    Ok(list(ctx, &session, |i| items::matches_text(i, text)))
}

/// `vault show <item>`.
pub fn show(
    ctx: &Ctx,
    query: &str,
    reveal: bool,
    field: Option<&str>,
    copy: bool,
) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    let item = select(&session.body, query)?;
    if let ItemData::Unknown(_) = item.data {
        ctx.out
            .line(&format!("id: {}\ntype: {}", item.id, item.item_type));
        // An unsupported item's other keys may hold secrets this client cannot tell apart.
        if reveal {
            return Ok(items::item_json(item, true).into());
        }
        return Ok(obj([("id", s(&item.id)), ("type", s(&item.item_type))]).into());
    }
    let wanted = match (field, copy) {
        (Some(f), _) => Some(items::field_value(item, f)?),
        (None, true) => Some(
            item.login()
                .map(|l| l.password.as_str())
                .ok_or_else(|| CliError::usage("a note has no password; name a --field"))?,
        ),
        (None, false) => None,
    };
    match wanted {
        Some(v) if copy => {
            clip::copy(v, ctx.settings.clear_after)?;
            Ok(obj([("id", s(&item.id)), ("copied", Value::Bool(true))]).into())
        }
        Some(v) => {
            ctx.out.line(v);
            Ok(obj([("id", s(&item.id)), ("value", s(v))]).into())
        }
        None => {
            if !ctx.out.json {
                let text = items::text_form(item, reveal, None);
                ctx.out.line(text.trim_end_matches('\n'));
            }
            Ok(items::item_json(item, reveal).into())
        }
    }
}

/// The result of a write command.
fn written(ctx: &Ctx, session: &Session, id: &str, changed: bool) -> JsonResult {
    let synced = changed && session::sync_after_write(ctx, session);
    obj([("id", s(id)), ("synced", Value::Bool(synced))]).into()
}

/// Reads a new item's password: twice without echo on a terminal, or one line of standard input.
fn read_item_password() -> Result<SecretString> {
    if !prompt::stdin_is_terminal() {
        return prompt::hidden_line("Password: ");
    }
    loop {
        let pw = prompt::hidden_line("Password: ")?;
        let again = prompt::hidden_line("Repeat the password: ")?;
        if *pw == *again {
            return Ok(pw);
        }
        prompt::say("The two entries differ.");
    }
}

/// `vault add <name>`.
pub fn add(ctx: &Ctx, args: &AddArgs) -> Result<JsonResult> {
    if args.name.is_empty() {
        return Err(CliError::usage("the name is empty"));
    }
    let session = session::open(ctx)?;
    let (item_type, login) = if args.note {
        (TYPE_NOTE, None)
    } else {
        let password = if args.generate {
            args.gen_args.generate()?.0
        } else {
            read_item_password()?
        };
        (
            TYPE_LOGIN,
            Some(items::new_login(&args.username, &password, &args.uri)),
        )
    };
    let mut fields = items::new_fields(&args.name, args.folder.trim_matches('/'), login);
    if args.edit {
        let draft = Item {
            id: "(new item)".into(),
            item_type: item_type.into(),
            modified: session::now_ms(),
            modified_by: String::new(),
            review: None,
            data: ItemData::Known(Box::new(fields.clone())),
        };
        match edit_loop(&draft)? {
            Some(f) => fields = f,
            None => {
                ctx.out.err("Nothing was saved.");
                return Ok(obj([("id", Value::Null), ("synced", Value::Bool(false))]).into());
            }
        }
    }
    let name = fields.name.clone();
    let (id, changed) = session::write(ctx, &session, |body, now, device| {
        Ok(add_item(body, &mut OsRng, item_type, fields, now, device)?)
    })?;
    ctx.out
        .err(&format!("Added {name} ({}).", &id[..items::MIN_ID_PREFIX]));
    Ok(written(ctx, &session, &id, changed))
}

/// Opens the editor on `item` until the text parses; `None` when the file is saved unchanged
/// or the editor quits without saving.
fn edit_loop(item: &Item) -> Result<Option<ItemFields>> {
    let mut text = items::text_form(item, true, None);
    loop {
        let edited = editor::edit(text.as_bytes())?;
        if *edited == *text.as_bytes() {
            return Ok(None);
        }
        let edited = String::from_utf8(edited.to_vec())
            .map_err(|_| CliError::other("editor.not_utf8", "the edited file is not UTF-8"))?;
        let edited = zeroize::Zeroizing::new(edited);
        match items::parse_text_form(item, &edited) {
            Ok(f) => return Ok(Some(f)),
            Err(e) => text = with_error(&edited, &e),
        }
    }
}

const ERROR_PREFIX: &str = "# error: ";

/// The edited text with `error` as comments after the five fixed head lines. Error comments of
/// an earlier round are removed from there only, so item text that looks like one is kept.
fn with_error(text: &str, error: &str) -> zeroize::Zeroizing<String> {
    let lines: Vec<&str> = text.lines().collect();
    let split = lines.len().min(5);
    let rest = lines[split..]
        .iter()
        .position(|l| !l.starts_with(ERROR_PREFIX))
        .map_or(lines.len(), |p| split + p);
    let mut out = zeroize::Zeroizing::new(String::with_capacity(text.len() + error.len() + 64));
    for l in &lines[..split] {
        out.push_str(l);
        out.push('\n');
    }
    for l in error.lines() {
        out.push_str(ERROR_PREFIX);
        out.push_str(l);
        out.push('\n');
    }
    for l in &lines[rest..] {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Applies the user's changes from `base` to `edited` onto the item `id` as it is now, under the
/// write lock. An item deleted meanwhile is reported and nothing is saved.
fn update_changed(
    body: &mut vault_core::body::Body,
    id: &str,
    base: &ItemFields,
    edited: &ItemFields,
    now: u64,
    device: &[u8; 16],
) -> Result<()> {
    let current = body.item(id).and_then(Item::fields).ok_or_else(|| {
        CliError::new(
            Exit::Item,
            "item.not_found",
            "the item was deleted while it was being changed; nothing was saved",
        )
    })?;
    let fields = items::apply_changes(base, edited, current);
    if fields != *current {
        update_item(body, id, fields, now, device)?;
    }
    Ok(())
}

/// `vault edit <item>`.
pub fn edit(ctx: &Ctx, query: &str) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    let item = select(&session.body, query)?;
    if item.fields().is_none() {
        return Err(items::unsupported());
    }
    let id = item.id.clone();
    let Some(fields) = edit_loop(item)? else {
        ctx.out.err("No changes.");
        return Ok(written(ctx, &session, &id, false));
    };
    if Some(&fields) == item.fields() {
        ctx.out.err("No changes.");
        return Ok(written(ctx, &session, &id, false));
    }
    let base = item.fields().expect("checked above");
    let ((), changed) = session::write(ctx, &session, |body, now, device| {
        update_changed(body, &id, base, &fields, now, device)
    })?;
    ctx.out.err(&format!("Saved {}.", display_name(item)));
    Ok(written(ctx, &session, &id, changed))
}

/// `vault rm <item>`.
pub fn rm(ctx: &Ctx, query: &str) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    let item = select(&session.body, query)?;
    let id = item.id.clone();
    let ((), changed) = session::write(ctx, &session, |body, now, device| {
        Ok(delete_item(body, &id, now, device)?)
    })?;
    ctx.out.err(&format!("Deleted {}.", display_name(item)));
    Ok(written(ctx, &session, &id, changed))
}

/// `vault mv <item> <folder>`.
pub fn mv(ctx: &Ctx, query: &str, folder: &str) -> Result<JsonResult> {
    let session = session::open(ctx)?;
    let item = select(&session.body, query)?;
    let Some(old) = item.fields() else {
        return Err(items::unsupported());
    };
    let id = item.id.clone();
    let folder = folder.trim_matches('/');
    let mut fields = old.clone();
    fields.folder = folder.to_owned();
    let changed = if fields == *old {
        false
    } else {
        session::write(ctx, &session, |body, now, device| {
            update_changed(body, &id, old, &fields, now, device)
        })?
        .1
    };
    let to = if folder.is_empty() {
        "no folder"
    } else {
        folder
    };
    ctx.out
        .err(&format!("Moved {} to {to}.", display_name(item)));
    Ok(written(ctx, &session, &id, changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_comments_replace_only_the_header_ones() {
        let text =
            "h1\nh2\nh3\nh4\nh5\n# error: old\nname = \"x\"\nnotes = \"\"\"\n# error: x\n\"\"\"\n";
        let out = with_error(text, "new\nsecond");
        assert_eq!(
            out.as_str(),
            "h1\nh2\nh3\nh4\nh5\n# error: new\n# error: second\nname = \"x\"\nnotes = \"\"\"\n# error: x\n\"\"\"\n"
        );
    }
}
