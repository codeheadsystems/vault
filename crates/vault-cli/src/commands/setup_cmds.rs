//! `vault init`, `vault setup`, and `vault key show`, with the emergency kit.

use super::kdf_params;
use crate::error::{CliError, Exit, Result};
use crate::output::{JsonResult, obj, s};
use crate::session::{self, Ctx, OsRng, ask, drive, finish, no_save, sender};
use crate::store::{self, ServerConfig};
use crate::sys::{agent, prompt, secrets};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use vault_client::{ClientError, ClientState, InitRefusal, Save, SecretKeyChange};
use vault_core::secret::{SecretKey, SecretString};
use vault_core::secret_key_text;
use zeroize::Zeroizing;

/// The QR code of `text` in Unicode half blocks.
pub fn qr(text: &str) -> Result<Zeroizing<String>> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| CliError::other("qr", format!("making the QR code: {e}")))?;
    Ok(Zeroizing::new(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    ))
}

/// The emergency kit: the secret key text form and its QR code, the server URL, and the vault
/// ID. It holds no token and no master password.
fn kit_text(sk_text: &str, url: &str, vault_id: &[u8; 16]) -> Result<Zeroizing<String>> {
    let code = qr(sk_text)?;
    // Sized once, so the secret key is never left in a reallocated buffer.
    let mut t = Zeroizing::new(String::with_capacity(
        code.len() + sk_text.len() + url.len() + 512,
    ));
    t.push_str("vault emergency kit\n\nSecret key:  ");
    t.push_str(sk_text);
    t.push_str("\nServer URL:  ");
    t.push_str(url);
    t.push_str("\nVault ID:    ");
    t.push_str(&hex::encode(vault_id));
    t.push_str("\n\n");
    t.push_str(&code);
    t.push_str(
        "\nKeep this kit, and the master password, somewhere safe. A new device needs both.\n",
    );
    Ok(t)
}

/// Prints the kit (on standard error with `--json`), writes it to `kit_file` when given, and
/// asks for the secret key's last group until it is typed correctly.
pub(super) fn show_kit(
    ctx: &Ctx,
    sk: &SecretKey,
    url: &str,
    vault_id: &[u8; 16],
    kit_file: Option<&Path>,
) -> Result<()> {
    let sk_text = secret_key_text::encode(sk);
    let kit = kit_text(&sk_text, url, vault_id)?;
    if ctx.out.json {
        eprintln!("{}", kit.as_str());
    } else {
        println!("{}", kit.as_str());
    }
    if let Some(p) = kit_file {
        write_new_private(p, kit.as_bytes())?;
        ctx.out
            .err(&format!("Wrote the emergency kit to {}.", p.display()));
    }
    let last = sk_text.rsplit('-').next().unwrap_or_default().to_owned();
    for _ in 0..3 {
        let typed =
            prompt::line("To confirm the kit was kept, type the last group of the secret key: ")?;
        if kit_group(&typed) == last {
            return Ok(());
        }
        prompt::say("That is not the last group.");
    }
    Err(CliError::other(
        "cancelled",
        "the emergency kit was not confirmed; nothing was saved",
    ))
}

/// A typed group of the secret key, read as the secret key decoder reads it: case and spaces are
/// ignored, and `O` is `0` and `I` and `L` are `1`.
fn kit_group(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

/// Writes a new file with mode `0600`, refusing an existing one.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::io(path.display(), e))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| CliError::io(path.display(), e))
}

/// Reads and parses setup text, reporting a failure without echoing it.
fn read_setup_text() -> Result<ServerConfig> {
    let text: SecretString = prompt::hidden_line("Setup text from `vault serve token add`: ")?;
    vault_core::setup::parse_setup(&text)
        .map(ServerConfig::from_setup)
        .map_err(|e| {
            CliError::new(
                Exit::Usage,
                e.code(),
                "the setup text does not parse: it is `vault://setup?url=...&token=...`, with an \
                 https URL, or http to localhost, 127.0.0.1, or [::1]",
            )
        })
}

/// `vault init`.
pub fn init(ctx: &Ctx, kdf_memory: u32, kit: Option<&Path>) -> Result<JsonResult> {
    if ctx.offline {
        return Err(CliError::usage(
            "vault init needs the server; drop --offline",
        ));
    }
    if store::read_state(&ctx.paths)?.is_some() {
        return Err(CliError::other(
            "state.exists",
            "this device already has a vault",
        ));
    }
    if let Some(p) = kit
        && p.exists()
    {
        return Err(CliError::usage(format!("{} exists", p.display())));
    }
    let (kdf, test_kdf) = kdf_params(kdf_memory)?;
    let server = read_setup_text()?;
    let mut t = Some(session::transport(&server)?);
    ctx.paths.ensure_data()?;
    let kind = session::choose_store(ctx);
    let machine = vault_client::setup::init(kdf, test_kdf, kind, OsRng);
    let mut started: Option<ClientState> = None;
    let f = {
        let mut save = |save: Save| -> Result<()> {
            show_kit(
                ctx,
                save.secret_key.key(),
                &server.url,
                &save.state.vault_id,
                kit,
            )?;
            let id = save.state.vault_id;
            let lock = store::lock(&ctx.paths)?;
            secrets::store(
                &ctx.paths,
                kind,
                &id,
                secrets::Slot::Current,
                save.secret_key.key(),
            )?;
            store::create_device_id(&ctx.paths)?;
            store::write_server(&ctx.paths, &server)?;
            store::write_state(&ctx.paths, &lock, &save.state)?;
            started = Some(save.state);
            Ok(())
        };
        drive(machine, &mut sender(&mut t), &mut ask, &mut save)?
    };
    if let Some(started) = &started {
        session::commit(&ctx.paths, started, &f, false, Some(&ctx.out))?;
    }
    let report = match f.result {
        Ok(r) => r,
        Err(ClientError::UndoSave(refusal)) => {
            if let Some(started) = &started {
                undo_init(ctx, started)?;
            }
            return Err(init_refused(refusal));
        }
        Err(e) => {
            if started.is_some() {
                ctx.out.warn(
                    "the vault is stored on this device but did not reach the server; the next \
                     `vault sync` pushes it",
                );
            }
            return Err(session::client_error(e, t.as_ref()));
        }
    };
    ctx.out
        .err("Created the vault and pushed it to the server.");
    if ctx.use_agent()
        && let Some(vk) = &f.vault_key
        && let Err(e) = agent::start(&ctx.paths, &ctx.settings, &report.vault_id, vk)
    {
        ctx.out.warn(&format!("the agent did not start: {e}"));
    }
    Ok(obj([("vault_id", s(hex::encode(report.vault_id)))]).into())
}

/// Removes what `vault init` saved before the server refused its push: `local.json`, the secret
/// key, `server.json`, and `device-id`.
fn undo_init(ctx: &Ctx, saved: &ClientState) -> Result<()> {
    let _lock = store::lock(&ctx.paths)?;
    secrets::remove(
        &ctx.paths,
        saved.secret_key_store,
        &saved.vault_id,
        secrets::Slot::Current,
    )?;
    for p in [
        ctx.paths.local_json(),
        ctx.paths.server_json(),
        ctx.paths.device_id(),
    ] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CliError::io(p.display(), e)),
        }
    }
    Ok(())
}

/// The error for a refused first push; nothing of the new vault is kept.
fn init_refused(refusal: InitRefusal) -> CliError {
    let code = ClientError::UndoSave(refusal).code();
    match refusal {
        InitRefusal::VaultExists => CliError::new(
            Exit::Other,
            code,
            "the server already holds a vault, pushed by another device meanwhile; nothing was \
             kept; run `vault setup` to add this device to it",
        ),
        InitRefusal::Token => CliError::new(
            Exit::Token,
            code,
            "the server refused the token; nothing was kept; run `vault init` with new setup text",
        ),
        InitRefusal::Status(st) => CliError::new(
            Exit::Server,
            code,
            format!("the server answered the first push with status {st}; nothing was kept"),
        ),
    }
}

/// `vault setup`: adds this device to the vault, or, on a device that has it, replaces the
/// server settings after checking that the server holds the same vault.
pub fn setup(ctx: &Ctx) -> Result<JsonResult> {
    if ctx.offline {
        return Err(CliError::usage(
            "vault setup needs the server; drop --offline",
        ));
    }
    let server = read_setup_text()?;
    let mut t = Some(session::transport(&server)?);
    if let Some(state) = store::read_state(&ctx.paths)? {
        let machine = vault_client::setup::repair_token(state.clone(), OsRng);
        let f = drive(machine, &mut sender(&mut t), &mut ask, &mut no_save)?;
        finish(f.result, t.as_ref())?;
        store::write_server(&ctx.paths, &server)?;
        session::commit(&ctx.paths, &state, &f, false, Some(&ctx.out))?;
        ctx.out
            .err("Replaced the server URL, token, and fingerprint.");
        return Ok(obj([("vault_id", s(hex::encode(state.vault_id)))]).into());
    }
    ctx.paths.ensure_data()?;
    let kind = session::choose_store(ctx);
    let machine = vault_client::setup::setup(kind, OsRng);
    let f = drive(machine, &mut sender(&mut t), &mut ask, &mut no_save)?;
    finish(f.result, t.as_ref())?;
    let state = f
        .state
        .ok_or_else(|| CliError::other("state.invalid", "setup returned no state"))?;
    let sk = match &f.secret_key {
        Some(SecretKeyChange::Replace(sk) | SecretKeyChange::ReplaceAndDiscardPending(sk)) => sk,
        Some(SecretKeyChange::PromotePending | SecretKeyChange::DiscardPending) | None => {
            return Err(CliError::other(
                "state.invalid",
                "setup returned no secret key to store",
            ));
        }
    };
    {
        let lock = store::lock(&ctx.paths)?;
        secrets::store(
            &ctx.paths,
            kind,
            &state.vault_id,
            secrets::Slot::Current,
            sk,
        )?;
        store::create_device_id(&ctx.paths)?;
        store::write_server(&ctx.paths, &server)?;
        store::write_state(&ctx.paths, &lock, &state)?;
    }
    ctx.out.err("This device is set up.");
    if ctx.use_agent()
        && let Some(vk) = &f.vault_key
        && let Err(e) = agent::start(&ctx.paths, &ctx.settings, &state.vault_id, vk)
    {
        ctx.out.warn(&format!("the agent did not start: {e}"));
    }
    Ok(obj([("vault_id", s(hex::encode(state.vault_id)))]).into())
}

/// `vault key show [--qr]`: asks for the master password every time, also while the agent is
/// unlocked.
pub fn key_show(ctx: &Ctx, with_qr: bool) -> Result<JsonResult> {
    let state = store::require_state(&ctx.paths)?;
    let keys = session::load_keys(&ctx.paths, &state)?;
    let sk = keys.secret_key.ok_or_else(session::missing_secret_key)?;
    let mut opened = false;
    for failed in 0..3 {
        if failed > 0 {
            prompt::say("Wrong master password.");
        }
        let pw = prompt::password("Master password: ")?;
        match vault_core::file::unlock(&state.file, &pw, &sk) {
            Ok(_) => {
                opened = true;
                break;
            }
            Err(vault_core::Error::WrongCredentials) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if !opened {
        return Err(vault_core::Error::WrongCredentials.into());
    }
    let text = secret_key_text::encode(&sk);
    ctx.out.line(&text);
    if with_qr {
        ctx.out.line(&qr(&text)?);
    }
    Ok(obj([("secret_key", s(text.as_str()))]).into())
}

#[cfg(test)]
mod tests {
    use super::kit_group;

    #[test]
    fn kit_groups_read_like_the_secret_key_decoder() {
        assert_eq!(kit_group(" c5la \n"), "C51A");
        assert_eq!(kit_group("o0Ii"), "0011");
        assert_eq!(kit_group("C5-1A"), "C51A");
        assert_ne!(kit_group("C51B"), "C51A");
    }
}
