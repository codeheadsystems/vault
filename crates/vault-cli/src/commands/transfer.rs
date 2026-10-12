//! `vault import bitwarden` and `vault export`.

use super::ExportFormat;
use super::setup_cmds::write_new_private;
use crate::error::{CliError, Exit, Result};
use crate::output::{JsonResult, obj, s};
use crate::session::{self, Ctx, OsRng};
use crate::store;
use crate::sys::prompt;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use vault_core::json::Value;
use vault_interop::{Export, ImportOptions, ImportReport, MAX_EXPORT_SIZE};
use zeroize::Zeroizing;

/// Reads at most `MAX_EXPORT_SIZE` bytes of the export file, plus one to detect a larger one.
fn read_export(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let f = std::fs::File::open(path).map_err(|e| CliError::io(path.display(), e))?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.take(MAX_EXPORT_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::io(path.display(), e))?;
    Ok(bytes)
}

/// `vault import bitwarden <file>`.
pub fn import(ctx: &Ctx, file: &Path, folder: &str, dry_run: bool) -> Result<JsonResult> {
    let bytes = read_export(file)?;
    let plain = match vault_interop::parse(&bytes)? {
        Export::Plain(p) => p,
        Export::Protected(p) => {
            let mut opened = None;
            for failed in 0..3 {
                if failed > 0 {
                    prompt::say("Wrong export password.");
                }
                let pw = prompt::hidden_line("Bitwarden export password: ")?;
                match p.decrypt(&pw) {
                    Ok(x) => {
                        opened = Some(x);
                        break;
                    }
                    Err(vault_interop::Error::WrongPassword) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            opened.ok_or_else(|| CliError::from(vault_interop::Error::WrongPassword))?
        }
    };
    drop(bytes);
    let session = session::open(ctx)?;
    let options = ImportOptions {
        folder: folder.to_owned(),
    };
    let run = |body: &mut vault_core::body::Body, now: u64, device: &[u8; 16]| {
        vault_interop::import(body, &plain, &options, now, device, &mut OsRng)
            .map_err(CliError::from)
    };
    let (report, synced): (ImportReport, bool) = if dry_run {
        let mut body = session.body.clone();
        let device = store::read_device_id(&ctx.paths)?;
        (run(&mut body, session::now_ms(), &device)?, false)
    } else {
        let (report, changed) = session::write(ctx, &session, run)?;
        let synced = changed && session::sync_after_write(ctx, &session);
        (report, synced)
    };
    let verb = if dry_run { "Would import" } else { "Imported" };
    ctx.out.err(&format!(
        "{verb}: {} added, {} updated, {} unchanged, {} skipped.",
        report.added,
        report.updated,
        report.unchanged,
        report.skipped.len()
    ));
    for sk in &report.skipped {
        ctx.out
            .err(&format!("  skipped {} ({})", sk.name, sk.reason.code()));
    }
    if report.deleted_in_source > 0 {
        ctx.out.err(&format!(
            "{} item(s) from an earlier import are gone from the export and were kept.",
            report.deleted_in_source
        ));
    }
    if report.collections > 0 {
        ctx.out.err(&format!(
            "{} collection(s) are not imported.",
            report.collections
        ));
    }
    if !dry_run {
        ctx.out.err(&format!(
            "The export file is not encrypted by vault; delete {} now.",
            file.display()
        ));
    }
    Ok(obj([
        ("added", Value::Number(report.added as u64)),
        ("updated", Value::Number(report.updated as u64)),
        ("unchanged", Value::Number(report.unchanged as u64)),
        ("skipped", Value::Number(report.skipped.len() as u64)),
        ("synced", Value::Bool(synced)),
    ])
    .into())
}

/// `vault export --format <format> [--plaintext] [-o <file>]`.
pub fn export(
    ctx: &Ctx,
    format: ExportFormat,
    plaintext: bool,
    output: Option<&Path>,
) -> Result<JsonResult> {
    if format != ExportFormat::Vault && !plaintext {
        return Err(CliError::usage(
            "the bitwarden and json formats are not encrypted; add --plaintext",
        ));
    }
    if format == ExportFormat::Vault && output.is_none() && std::io::stdout().is_terminal() {
        return Err(CliError::usage(
            "the vault format is binary; redirect standard output or give a file with -o",
        ));
    }
    if ctx.out.json && output.is_none() {
        return Err(CliError::usage("with --json, give the export file with -o"));
    }
    if let Some(p) = output
        && std::fs::symlink_metadata(p).is_ok()
    {
        return Err(CliError::new(
            Exit::Other,
            "io",
            format!("{} exists; give a new file", p.display()),
        ));
    }
    let bytes: Zeroizing<Vec<u8>> = match format {
        ExportFormat::Vault => Zeroizing::new(store::require_state(&ctx.paths)?.file),
        ExportFormat::Bitwarden => {
            let session = session::open(ctx)?;
            vault_interop::export_bitwarden(&session.body, &mut OsRng)?.json
        }
        ExportFormat::Json => session::open(ctx)?.body.to_json(),
    };
    if format != ExportFormat::Vault {
        ctx.out
            .warn("this export is not encrypted; anyone who reads it sees every password");
    }
    match output {
        Some(p) => {
            write_new_private(p, &bytes)?;
            ctx.out.err(&format!("Wrote {}.", p.display()));
        }
        None => {
            let mut o = std::io::stdout().lock();
            o.write_all(&bytes)
                .and_then(|()| o.flush())
                .map_err(|e| CliError::io("standard output", e))?;
        }
    }
    Ok(obj([(
        "file",
        output.map_or(Value::Null, |p| s(p.display().to_string())),
    )])
    .into())
}
