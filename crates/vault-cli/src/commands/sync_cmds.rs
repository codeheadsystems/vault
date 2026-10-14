//! `vault unlock`, `lock`, `status`, `sync`, `passwd`, `history`, and `restore`.

use super::kdf_params;
use super::setup_cmds::show_kit;
use crate::error::{CliError, Exit, Result};
use crate::items::{self, select};
use crate::output::{JsonResult, format_time, n, obj, s};
use crate::session::{
    self, Ctx, OsRng, Session, ask, client_error, drive, finish, no_save, now_ms, sender,
};
use crate::store;
use crate::sys::{agent, prompt};
use vault_client::passwd::{PasswdChange, PasswdOptions};
use vault_client::restore::{RestoreScope, fetch_revision, restore_preview};
use vault_client::revisions::{RevisionInfo, parse_revisions};
use vault_client::sync::{Mode, SyncOutcome};
use vault_client::{ClientError, ClientState, Keys, Request, Save, StopReason};
use vault_core::json::Value;
use vault_core::secret::VaultKey;

/// The agent's key when it holds the key of `state`'s vault and that key opens its file.
fn agent_key(ctx: &Ctx, state: &ClientState) -> Option<VaultKey> {
    if !ctx.use_agent() {
        return None;
    }
    match agent::get_key(&ctx.paths) {
        Ok(Some((id, vk)))
            if id == state.vault_id && vault_core::file::open_file(&state.file, &vk).is_ok() =>
        {
            Some(vk)
        }
        _ => None,
    }
}

/// After a procedure that may have replaced the vault key: an agent holding the old key ends,
/// and a new one starts with the new key.
fn refresh_agent(ctx: &Ctx, vault_id: &[u8; 16], old: Option<&VaultKey>, new: Option<&VaultKey>) {
    let (Some(new), true) = (new, ctx.use_agent()) else {
        return;
    };
    if old.is_some_and(|o| o.expose() == new.expose()) {
        return;
    }
    let _ = agent::lock(&ctx.paths);
    if let Err(e) = agent::start(&ctx.paths, &ctx.settings, vault_id, new) {
        ctx.out.warn(&format!("the agent did not start: {e}"));
    }
}

/// `vault unlock`.
pub fn unlock(ctx: &Ctx) -> Result<JsonResult> {
    let state = store::require_state(&ctx.paths)?;
    if agent_key(ctx, &state).is_some() {
        ctx.out.err("Already unlocked.");
        return Ok(obj([("unlocked", Value::Bool(true))]).into());
    }
    let session = session::open(ctx)?;
    if session.agent {
        ctx.out.err("Unlocked.");
    } else {
        ctx.out.err(
            "Unlocked and synced; without an agent, later commands ask for the master password \
             again.",
        );
    }
    Ok(obj([("unlocked", Value::Bool(session.agent))]).into())
}

/// `vault lock`.
pub fn lock(ctx: &Ctx) -> Result<JsonResult> {
    let was = agent::lock(&ctx.paths)?;
    ctx.out.err(if was {
        "Locked."
    } else {
        "No agent was running."
    });
    Ok(obj([("locked", Value::Bool(was))]).into())
}

fn stop_reason(r: StopReason) -> &'static str {
    match r {
        StopReason::Integrity => "integrity",
        StopReason::Token => "token",
        StopReason::Credentials => "credentials",
    }
}

/// `vault status`.
pub fn status(ctx: &Ctx) -> Result<JsonResult> {
    let state = store::require_state(&ctx.paths)?;
    // An agent that refuses (one ending after `vault lock`) or cannot be reached safely is not
    // unlocked, as for any other command.
    let agent_status = if ctx.use_agent() {
        match agent::status(&ctx.paths) {
            Ok(s) => s,
            Err(e) if e.code() == "agent.refused" => None,
            Err(e) => {
                ctx.out.warn(&e.to_string());
                None
            }
        }
    } else {
        None
    };
    let unpushed = state.unpushed();
    ctx.out
        .line(&format!("Vault {}", hex::encode(state.vault_id)));
    match &agent_status {
        Some(a) => ctx.out.line(&format!(
            "Unlocked since {}, until {}",
            format_time(a.unlocked_at),
            format_time(a.locks_at)
        )),
        None => ctx.out.line("Locked"),
    }
    ctx.out.line(&format!(
        "Last sync: {}",
        state.last_sync.map_or("never".to_owned(), format_time)
    ));
    if let Some(e) = agent_status.as_ref().and_then(|a| a.last_error.as_ref()) {
        ctx.out.line(&format!(
            "Last background sync failed: {} ({})",
            e.message, e.code
        ));
    }
    ctx.out.line(&format!(
        "Unpushed changes: {}",
        if unpushed { "yes" } else { "no" }
    ));
    match &state.stopped {
        Some(st) => ctx.out.line(&format!(
            "Sync: stopped since {} ({}); run `{}`",
            format_time(st.at),
            st.code,
            session::repair_hint(st.reason)
        )),
        None => ctx.out.line("Sync: running"),
    }
    let stopped = state.stopped.as_ref().map_or(Value::Null, |st| {
        obj([
            ("reason", s(stop_reason(st.reason))),
            ("code", s(&st.code)),
            ("at", Value::Number(st.at)),
        ])
    });
    Ok(obj([
        ("unlocked", Value::Bool(agent_status.is_some())),
        ("last_sync", n(state.last_sync)),
        ("unpushed", Value::Bool(unpushed)),
        ("stopped", stopped),
        // Counting flagged items needs the vault key, and asking the agent for it would reset
        // its idle timer, so `status` leaves `review` null; `vault ls --review` lists them.
        ("review", Value::Null),
    ])
    .into())
}

/// `vault sync [--recover]`.
pub fn sync(ctx: &Ctx, recover: bool) -> Result<JsonResult> {
    let state = store::require_state(&ctx.paths)?;
    let mut t = Some(ctx.require_transport()?);
    let mut keys: Keys = session::load_keys(&ctx.paths, &state)?;
    let cached = agent_key(ctx, &state);
    keys.vault_key = cached.as_ref().map(VaultKey::clone_secret);
    let (outcome, generation, expired, vault_key) = if recover {
        let machine = vault_client::recover::recover(state.clone(), keys, OsRng);
        let f = drive(machine, &mut sender(&mut t), &mut ask, &mut no_save)?;
        session::commit(&ctx.paths, &state, &f, false, Some(&ctx.out))?;
        let r = finish(f.result, t.as_ref())?;
        if r.credentials_changed {
            ctx.out
                .err("Took over the credential change made on another device.");
        }
        session::report_pending(ctx, r.pending_secret_key);
        session::report_expired(ctx, &r.expired);
        (SyncOutcome::Pushed, r.generation, r.expired, f.vault_key)
    } else {
        let machine = vault_client::sync::sync(
            state.clone(),
            keys,
            Mode::Interactive { ask_again: true },
            OsRng,
        );
        let f = drive(machine, &mut sender(&mut t), &mut ask, &mut no_save)?;
        let c = session::commit(&ctx.paths, &state, &f, false, Some(&ctx.out))?;
        session::report_expired(ctx, &c.expired);
        if c.merged_local_changes {
            ctx.out
                .err("Changes made during the sync stay on this device until the next sync.");
        }
        let r = finish(f.result, t.as_ref())?;
        session::report_sync_extras(ctx, &r);
        (r.outcome, r.generation, r.expired, f.vault_key)
    };
    refresh_agent(ctx, &state.vault_id, cached.as_ref(), vault_key.as_ref());
    ctx.out.err(&match outcome {
        SyncOutcome::UpToDate => format!("Up to date at generation {generation}."),
        SyncOutcome::Adopted => format!("Took the server's vault at generation {generation}."),
        SyncOutcome::Pushed => format!("Pushed generation {generation}."),
    });
    Ok(obj([
        ("outcome", s(session::outcome_name(outcome))),
        ("generation", Value::Number(generation)),
        (
            "dropped",
            Value::Array(expired.into_iter().map(s).collect()),
        ),
    ])
    .into())
}

/// `vault passwd [--rekey | --new-secret-key [--keep-password]]`.
pub fn passwd(
    ctx: &Ctx,
    rekey: bool,
    new_secret_key: bool,
    keep_password: bool,
    kdf_memory: u32,
) -> Result<JsonResult> {
    let state = store::require_state(&ctx.paths)?;
    let server = store::require_server(&ctx.paths)?;
    let mut t = Some(ctx.require_transport()?);
    let (kdf, test_kdf) = kdf_params(kdf_memory)?;
    let change = if rekey {
        PasswdChange::Rekey
    } else if new_secret_key {
        PasswdChange::NewSecretKey {
            new_password: !keep_password,
        }
    } else {
        PasswdChange::NewPassword
    };
    let mut keys = session::load_keys(&ctx.paths, &state)?;
    keys.vault_key = agent_key(ctx, &state);
    let machine = vault_client::passwd::passwd(
        state.clone(),
        keys,
        PasswdOptions {
            change,
            kdf,
            test_kdf,
        },
        OsRng,
    );
    let mut started = state.clone();
    let f = {
        let mut save = |save: Save| -> Result<()> {
            show_kit(
                ctx,
                save.secret_key.key(),
                &server.url,
                &save.state.vault_id,
                None,
            )?;
            let lock = store::lock(&ctx.paths)?;
            let on_disk = store::require_state(&ctx.paths)?;
            session::apply_save(&ctx.paths, &lock, &save, &started, &on_disk)?;
            started = save.state;
            Ok(())
        };
        drive(machine, &mut sender(&mut t), &mut ask, &mut save)?
    };
    session::commit(&ctx.paths, &started, &f, false, Some(&ctx.out))?;
    let report = finish(f.result, t.as_ref())?;
    let _ = agent::lock(&ctx.paths);
    ctx.out.err(&format!(
        "Changed the credentials at generation {}. Other devices ask for the new ones at their \
         next sync.",
        report.generation
    ));
    if new_secret_key {
        ctx.out
            .err("The new emergency kit is in effect; the old one no longer opens the vault.");
    }
    Ok(obj([
        ("generation", Value::Number(report.generation)),
        ("retired_revision", n(report.retired_revision)),
    ])
    .into())
}

/// Lists the server's revisions.
fn list_revisions(ctx: &Ctx, t: &mut crate::http::Transport) -> Result<Vec<RevisionInfo>> {
    let resp = t
        .send(&Request::ListRevisions)
        .ok_or_else(|| client_error(ClientError::Unreachable, Some(t)))?;
    match resp.status {
        200 => Ok(parse_revisions(&resp.body)?),
        401 => {
            let _ = record_token_stop(ctx);
            Err(ClientError::Token.into())
        }
        st => Err(ClientError::Status(st).into()),
    }
}

/// Records that the server refused the token, as a sync does, unless sync is already stopped for
/// another reason, which keeps its own repair.
fn record_token_stop(ctx: &Ctx) -> Result<()> {
    let lock = store::lock(&ctx.paths)?;
    let mut st = store::require_state(&ctx.paths)?;
    if st.stopped.is_some() {
        return Ok(());
    }
    st.stopped = Some(vault_client::Stopped {
        reason: StopReason::Token,
        code: ClientError::Token.code().to_owned(),
        at: now_ms(),
    });
    store::write_state(&ctx.paths, &lock, &st)
}

/// `vault history`.
pub fn history(ctx: &Ctx) -> Result<JsonResult> {
    store::require_state(&ctx.paths)?;
    let mut t = ctx.require_transport()?;
    let mut list = list_revisions(ctx, &mut t)?;
    list.sort_by_key(|r| std::cmp::Reverse(r.id));
    // The server's current revision is its newest one.
    let current = list.first().map(|r| r.id);
    ctx.out.line(&format!(
        "  {:>8}  {:<20}  {:<32}  {:>10}",
        "ID", "CREATED", "TOKEN", "SIZE"
    ));
    for r in &list {
        let mark = if Some(r.id) == current { '*' } else { ' ' };
        ctx.out.line(&format!(
            "{mark} {:>8}  {:<20}  {:<32}  {:>10}",
            r.id, r.created, r.token, r.size
        ));
    }
    let revisions = list
        .iter()
        .map(|r| {
            obj([
                ("id", Value::Number(r.id)),
                ("etag", s(&r.etag)),
                ("size", Value::Number(r.size)),
                ("created", s(&r.created)),
                ("token", s(&r.token)),
            ])
        })
        .collect();
    Ok(obj([("revisions", Value::Array(revisions))]).into())
}

/// `vault restore <revision> [--item <item>] [-y]`.
pub fn restore(ctx: &Ctx, id: u64, item: Option<&str>, yes: bool) -> Result<JsonResult> {
    let session: Session = session::open(ctx)?;
    let state = &session.state;
    let mut t = Some(ctx.require_transport()?);
    let mut keys = session::load_keys(&ctx.paths, state)?;
    keys.vault_key = Some(session.vault_key.clone_secret());
    let machine = fetch_revision(state.clone(), keys, id, OsRng);
    let f = drive(machine, &mut sender(&mut t), &mut ask, &mut no_save)?;
    session::commit(&ctx.paths, state, &f, false, Some(&ctx.out))?;
    let revision = finish(f.result, t.as_ref())?;
    let item_id = match item {
        Some(q) => Some(select(&revision.body, q)?.id.clone()),
        None => None,
    };
    let scope = match &item_id {
        Some(i) => RestoreScope::Item(i),
        None => RestoreScope::All,
    };
    let preview = restore_preview(&session.body, &revision, scope)?;
    let token = t
        .as_mut()
        .and_then(|t| list_revisions(ctx, t).ok())
        .and_then(|l| l.into_iter().find(|r| r.id == id))
        .map_or_else(|| "unknown".to_owned(), |r| r.token);
    let what = match &item_id {
        Some(i) => format!(
            "item {}",
            revision
                .body
                .item(i)
                .map_or(i.as_str(), items::display_name)
        ),
        None => "the whole vault".to_owned(),
    };
    ctx.out.err(&format!(
        "Revision {id} (generation {}), pushed by token {token}: restoring {what} adds {} \
         item(s), changes {}, and removes {}.",
        revision.generation, preview.added, preview.changed, preview.removed
    ));
    if !yes && !prompt::confirm("Restore?")? {
        return Err(CliError::new(
            Exit::Other,
            "cancelled",
            "nothing was restored",
        ));
    }
    let device = store::read_device_id(&ctx.paths)?;
    let summary = {
        let lock = store::lock(&ctx.paths)?;
        let on_disk = store::require_state(&ctx.paths)?;
        let (next, summary) = vault_client::restore::restore(
            &on_disk,
            &session.vault_key,
            &revision,
            scope,
            &device,
            now_ms(),
            &mut OsRng,
        )?;
        store::write_state(&ctx.paths, &lock, &next)?;
        summary
    };
    let synced = session::sync_after_write(ctx, &session);
    ctx.out.err(&format!(
        "Restored: {} added, {} changed, {} removed.",
        summary.added, summary.changed, summary.removed
    ));
    Ok(obj([
        ("added", Value::Number(summary.added as u64)),
        ("changed", Value::Number(summary.changed as u64)),
        ("removed", Value::Number(summary.removed as u64)),
        ("synced", Value::Bool(synced)),
    ])
    .into())
}
