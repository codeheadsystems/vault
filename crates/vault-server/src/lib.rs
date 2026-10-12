//! `vault serve`: the server that stores the vault file for every client, its data directory,
//! and its commands. `docs/serve.md` describes them, and the spec Server API section is
//! normative for requests and responses.
//!
//! The server stores bytes, revision metadata, and token hashes. It calls only the token, setup
//! text, and `ETag` functions of `vault-core`, and never opens a vault.
//!
//! [`ServeCommand`] is the clap form of the commands, which the `vault` binary embeds as
//! `vault serve`; [`run`] carries one out. The library functions underneath ([`init`],
//! [`token_add`], [`Server`], and the rest) return values instead of printing them.

mod commands;
mod config;
mod datadir;
mod error;
mod revisions;
mod server;
mod time;
mod tls;
mod tokens;

pub use commands::{
    InitArgs, InitReport, TokenAddArgs, TokenAdded, init, token_add, token_list, token_remove,
};
pub use config::{Config, HttpConfig, HttpsConfig};
pub use datadir::DataDir;
pub use error::{Error, Result};
pub use revisions::remove_by_token as revisions_remove;
pub use revisions::{Revision, list as revisions_list, prune as revisions_prune};
pub use server::{Server, Tuning, shutdown_signal};
pub use tls::{fingerprint_colons, fingerprint_hex};
pub use tokens::{TokenInfo, valid_name};

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// `vault serve`: runs the server, or with a subcommand, edits its data directory.
#[derive(Debug, Clone, Args)]
pub struct ServeCommand {
    /// The data directory [default: $VAULT_SERVE_DATA, then $XDG_DATA_HOME/vault-serve, then
    /// ~/.local/share/vault-serve]
    #[arg(long, value_name = "DIR", global = true)]
    pub data: Option<PathBuf>,
    /// Without a subcommand, the server runs in the foreground.
    #[command(subcommand)]
    pub command: Option<ServeSubcommand>,
}

/// The subcommands of `vault serve`.
#[derive(Debug, Clone, Subcommand)]
pub enum ServeSubcommand {
    /// Creates the data directory, serve.toml, and a self-signed certificate
    Init(InitArgs),
    /// Creates, lists, and revokes tokens
    #[command(subcommand)]
    Token(TokenCommand),
    /// Lists and deletes retained revisions
    #[command(subcommand)]
    Revisions(RevisionsCommand),
}

/// `vault serve token`.
#[derive(Debug, Clone, Subcommand)]
pub enum TokenCommand {
    /// Creates a token and prints the setup text and its QR code
    Add(TokenAddArgs),
    /// Lists token names, creation times, and each token's last retained push
    Ls,
    /// Revokes a token
    Rm {
        /// The token's name
        name: String,
    },
}

/// `vault serve revisions`.
#[derive(Debug, Clone, Subcommand)]
pub enum RevisionsCommand {
    /// Lists retained revisions, newest first
    Ls,
    /// Deletes every revision with a lower ID, except the current one
    Prune {
        /// The lowest revision ID to keep
        #[arg(long, value_name = "ID")]
        before: u64,
    },
    /// Deletes the revisions a token pushed, except the current one
    Rm {
        /// The token's name
        #[arg(long, value_name = "NAME")]
        token: String,
        /// Deletes only the revisions with a higher ID
        #[arg(long, value_name = "ID")]
        after: Option<u64>,
    },
}

/// Carries out a `vault serve` command, printing its output to standard output. The server logs
/// to standard error.
pub fn run(cmd: ServeCommand) -> Result<()> {
    let data = DataDir::new(match cmd.data {
        Some(d) => d,
        None => DataDir::default_path()?,
    });
    match cmd.command {
        None => serve(&data),
        Some(ServeSubcommand::Init(args)) => {
            let report = init(&data, &args)?;
            for w in &report.warnings {
                eprintln!("{w}");
            }
            println!("Created {}", data.root().display());
            if let Some(fp) = report.fingerprint {
                print_fingerprint(&fp);
            }
            Ok(())
        }
        Some(ServeSubcommand::Token(TokenCommand::Add(args))) => {
            let added = token_add(&data, &args)?;
            let qr = commands::qr(&added.setup_text)?;
            println!("{}\n\n{}", added.setup_text.as_str(), qr.as_str());
            if let Some(fp) = added.fingerprint {
                print_fingerprint(&fp);
            }
            Ok(())
        }
        Some(ServeSubcommand::Token(TokenCommand::Ls)) => {
            println!("{:<32}  {:<20}  LAST PUSH", "NAME", "CREATED");
            for t in token_list(&data)? {
                let last = t.last_push.map_or_else(
                    || "-".to_owned(),
                    |(id, at)| format!("{at} (revision {id})"),
                );
                println!("{:<32}  {:<20}  {last}", t.name, t.created);
            }
            Ok(())
        }
        Some(ServeSubcommand::Token(TokenCommand::Rm { name })) => {
            token_remove(&data, &name)?;
            println!("Revoked {name}");
            Ok(())
        }
        Some(ServeSubcommand::Revisions(RevisionsCommand::Ls)) => {
            println!(
                "{:>8}  {:<20}  {:>10}  {:<32}  ETAG",
                "ID", "CREATED", "SIZE", "TOKEN"
            );
            for r in revisions_list(&data)? {
                println!(
                    "{:>8}  {:<20}  {:>10}  {:<32}  {}",
                    r.id,
                    r.created(),
                    r.size,
                    r.token,
                    r.etag
                );
            }
            Ok(())
        }
        Some(ServeSubcommand::Revisions(RevisionsCommand::Prune { before })) => {
            print_deleted(&revisions_prune(&data, before)?);
            Ok(())
        }
        Some(ServeSubcommand::Revisions(RevisionsCommand::Rm { token, after })) => {
            print_deleted(&revisions_remove(&data, &token, after)?);
            Ok(())
        }
    }
}

fn serve(data: &DataDir) -> Result<()> {
    if let Some(w) = commands::client_warning() {
        eprintln!("{w}");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| Error::Io {
            context: "starting the runtime".into(),
            source,
        })?;
    rt.block_on(async {
        let server = Server::bind(data).await?;
        if let Some(a) = server.https_addr() {
            eprintln!("listening on https://{a}");
        }
        if let Some(a) = server.http_addr() {
            eprintln!("listening on http://{a}");
        }
        server.run(shutdown_signal()).await
    })
}

fn print_fingerprint(fp: &[u8; 32]) {
    println!("Certificate SHA-256: {}", fingerprint_hex(fp));
    println!("                     {}", fingerprint_colons(fp));
}

fn print_deleted(ids: &[u64]) {
    let list: Vec<String> = ids.iter().map(u64::to_string).collect();
    match ids.len() {
        0 => println!("Deleted no revisions"),
        1 => println!("Deleted revision {}", list[0]),
        n => println!("Deleted {n} revisions: {}", list.join(", ")),
    }
}
