//! The `vault` command: the client commands of `docs/cli.md`, and `vault serve`.

#[cfg(feature = "client")]
mod agent;
#[cfg(feature = "client")]
mod clip;
#[cfg(feature = "client")]
mod commands;
#[cfg(feature = "client")]
mod editor;
#[cfg(feature = "client")]
mod error;
#[cfg(feature = "client")]
mod harden;
#[cfg(feature = "client")]
mod http;
#[cfg(feature = "client")]
mod items;
#[cfg(feature = "client")]
mod output;
#[cfg(feature = "client")]
mod paths;
#[cfg(feature = "client")]
mod prompt;
#[cfg(feature = "client")]
mod secrets;
#[cfg(feature = "client")]
mod session;
#[cfg(feature = "client")]
mod settings;
#[cfg(feature = "client")]
mod signals;
#[cfg(feature = "client")]
mod store;
#[cfg(feature = "client")]
mod sys;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// vault: a single-user, zero-knowledge password manager
#[derive(Debug, Parser)]
#[command(name = "vault", version)]
struct Cli {
    #[cfg(feature = "client")]
    #[command(flatten)]
    global: commands::Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[cfg(feature = "client")]
    #[command(flatten)]
    Client(commands::ClientCommand),
    /// Runs the server, or manages its data directory
    #[cfg(feature = "serve")]
    Serve(vault_server::ServeCommand),
}

fn main() -> ExitCode {
    #[cfg(feature = "client")]
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => return commands::usage_error(e),
    };
    #[cfg(not(feature = "client"))]
    let cli = Cli::parse();
    match cli.command {
        #[cfg(feature = "client")]
        Command::Client(cmd) => commands::run(cli.global, cmd),
        #[cfg(feature = "serve")]
        Command::Serve(cmd) => match vault_server::run(cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vault: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// The clap command tree, for `vault completions`.
#[cfg(feature = "client")]
fn command_tree() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}
