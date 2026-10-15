//! The client commands: the clap tree, the options every command takes, and the dispatch that
//! prints the JSON result or the error and picks the exit code.

mod gen_cmd;
mod item_cmds;
mod setup_cmds;
mod sync_cmds;
mod transfer;

use crate::error::{CliError, Result};
use crate::output::{self, JsonResult, Out};
use crate::paths::Paths;
use crate::session::{self, Ctx};
use crate::settings::Settings;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

pub use gen_cmd::GenArgs;

/// Options for every command.
#[derive(Debug, Args)]
pub struct Global {
    /// Prints one JSON object on standard output
    #[arg(long, global = true)]
    pub json: bool,
    /// Contacts no server; writes stay local until a later sync
    #[arg(long, global = true)]
    pub offline: bool,
    /// Reads the master password from this file descriptor, for scripts
    #[arg(long, value_name = "N", global = true)]
    pub password_fd: Option<i32>,
}

/// The client commands.
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Creates a vault, prints the emergency kit, and pushes the vault to the server
    Init {
        /// Argon2id memory in MiB: 64, 128, or 256
        #[arg(long, value_name = "MIB", default_value_t = 64)]
        kdf_memory: u32,
        /// Also writes the emergency kit to this new file
        #[arg(long, value_name = "FILE")]
        kit: Option<PathBuf>,
    },
    /// Adds this device to an existing vault, or replaces its server token
    Setup,
    /// Shows the secret key
    #[command(subcommand)]
    Key(KeyCommand),
    /// Unlocks the vault and starts the agent
    Unlock,
    /// Ends the agent
    Lock,
    /// Lock state, last sync, unpushed changes, and sync problems
    Status,
    /// Lists items
    Ls {
        /// Only items in this folder and the folders under it
        folder: Option<String>,
        /// Only items a merge flagged for review
        #[arg(long)]
        review: bool,
    },
    /// Searches names, folders, usernames, and URIs
    Find {
        /// The text to search for
        text: String,
    },
    /// Prints an item
    Show {
        /// An item ID, ID prefix, name, folder/name, or part of a name
        item: String,
        /// Prints passwords, TOTP secrets, and hidden fields
        #[arg(long)]
        reveal: bool,
        /// Prints one value: username, password, totp, notes, uri, or a custom field name
        #[arg(long, value_name = "NAME")]
        field: Option<String>,
        /// Copies the password, or the --field value, to the clipboard
        #[arg(short = 'c', long = "copy")]
        copy: bool,
    },
    /// Chooses an item in a launcher menu and copies its password
    Pick {
        /// Copies this value instead: username, password, totp, notes, uri, or a custom field
        #[arg(long, value_name = "NAME", default_value = "password")]
        field: String,
        /// Prints the value instead of copying it, for a typing tool such as wtype or xdotool
        #[arg(long)]
        print: bool,
        /// The launcher; without it, the first of fuzzel (Wayland only), rofi, and dmenu found
        #[arg(long, value_enum)]
        launcher: Option<PickLauncher>,
    },
    /// Adds a login, or a note with --note
    Add(AddArgs),
    /// Edits an item in the editor
    Edit {
        /// The item
        item: String,
    },
    /// Deletes an item
    Rm {
        /// The item
        item: String,
    },
    /// Moves an item to a folder; "" for none
    Mv {
        /// The item
        item: String,
        /// The folder
        folder: String,
    },
    /// Generates a password or passphrase
    Gen {
        #[command(flatten)]
        gen_args: GenArgs,
        /// Copies the value to the clipboard instead of printing it
        #[arg(short = 'c', long = "copy")]
        copy: bool,
    },
    /// Syncs now
    Sync {
        /// Repairs sync after an integrity error
        #[arg(long)]
        recover: bool,
    },
    /// Changes the master password, the vault key, or the secret key
    Passwd {
        /// Replaces only the vault key
        #[arg(long, conflicts_with = "new_secret_key")]
        rekey: bool,
        /// Replaces the secret key and prints a new emergency kit
        #[arg(long)]
        new_secret_key: bool,
        /// With --new-secret-key, keeps the master password
        #[arg(long, requires = "new_secret_key")]
        keep_password: bool,
        /// Argon2id memory in MiB for the new wrap: 64, 128, or 256
        #[arg(long, value_name = "MIB", default_value_t = 64)]
        kdf_memory: u32,
    },
    /// Imports items
    #[command(subcommand)]
    Import(ImportCommand),
    /// Exports the vault
    Export {
        /// vault, bitwarden, or json
        #[arg(long, value_enum)]
        format: ExportFormat,
        /// Allows an unencrypted export
        #[arg(long)]
        plaintext: bool,
        /// Writes to this new file instead of standard output
        #[arg(short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Lists the server's revisions
    History,
    /// Restores the vault, or one item, from a revision
    Restore {
        /// The revision ID
        revision: u64,
        /// Restores only this item, selected in the revision
        #[arg(long, value_name = "ITEM")]
        item: Option<String>,
        /// Restores without asking
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
    /// Prints a completion script
    Completions {
        /// The shell
        #[arg(value_enum)]
        shell: Shell,
    },
    /// The agent daemon
    #[command(hide = true)]
    Agent,
    /// The clipboard helper
    #[command(hide = true)]
    Clip,
}

/// `vault key`.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Prints the secret key text form
    Show {
        /// Also prints its QR code
        #[arg(long)]
        qr: bool,
    },
}

/// `vault import`.
#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Imports a Bitwarden JSON export
    Bitwarden {
        /// The export file
        file: PathBuf,
        /// A folder the imported folders go under
        #[arg(long, value_name = "PREFIX", default_value = "")]
        folder: String,
        /// Prints the counts without saving
        #[arg(long)]
        dry_run: bool,
    },
}

/// `vault add`.
#[derive(Debug, Args)]
pub struct AddArgs {
    /// The item's name
    pub name: String,
    /// Adds a note instead of a login
    #[arg(long, conflicts_with_all = ["username", "uri", "generate"])]
    pub note: bool,
    /// The folder
    #[arg(long, default_value = "")]
    pub folder: String,
    /// The username
    #[arg(long, default_value = "")]
    pub username: String,
    /// A URI; repeatable
    #[arg(long)]
    pub uri: Vec<String>,
    /// Generates the password
    #[arg(long)]
    pub generate: bool,
    #[command(flatten)]
    pub gen_args: GenArgs,
    /// Opens the editor on the item before saving
    #[arg(short = 'e', long = "edit")]
    pub edit: bool,
}

/// The formats of `vault export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// The local vault file
    Vault,
    /// A plain Bitwarden JSON export
    Bitwarden,
    /// The vault body as the spec defines it
    Json,
}

/// The launchers of `vault pick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PickLauncher {
    /// rofi
    Rofi,
    /// fuzzel
    Fuzzel,
    /// dmenu, which needs an unlocked agent
    Dmenu,
}

impl From<PickLauncher> for crate::launcher::Launcher {
    fn from(l: PickLauncher) -> Self {
        match l {
            PickLauncher::Rofi => Self::Rofi,
            PickLauncher::Fuzzel => Self::Fuzzel,
            PickLauncher::Dmenu => Self::Dmenu,
        }
    }
}

/// The shells of `vault completions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// Bash
    Bash,
    /// Zsh
    Zsh,
    /// Fish
    Fish,
}

/// Reports a command line that does not parse: help and version go to standard output with
/// exit code 0; anything else is a usage error, as JSON with `--json`.
pub fn usage_error(e: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion)
        || !std::env::args().any(|a| a == "--json")
    {
        e.exit();
    }
    let msg = e
        .kind()
        .as_str()
        .unwrap_or("the command line does not parse");
    output::print_error(&CliError::usage(msg));
    ExitCode::from(2)
}

/// Runs a client command and reports its outcome.
pub fn run(global: Global, cmd: ClientCommand) -> ExitCode {
    match cmd {
        ClientCommand::Agent => return crate::sys::agent::daemon(),
        ClientCommand::Clip => return crate::sys::clip::helper(),
        ClientCommand::Completions { shell } => {
            let shell = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
            };
            clap_complete::generate(
                shell,
                &mut crate::command_tree(),
                "vault",
                &mut std::io::stdout(),
            );
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let out = Out::new(global.json);
    let result = setup_ctx(&global, out).and_then(|ctx| {
        let r = dispatch(&ctx, cmd);
        if r.is_ok() {
            session::status_line(&ctx);
        }
        r
    });
    match result {
        Ok(r) => {
            if out.json {
                output::print_result(&r);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if out.json {
                output::print_error(&e);
            } else {
                out.err(&format!("vault: {e}"));
            }
            ExitCode::from(e.exit() as u8)
        }
    }
}

fn setup_ctx(global: &Global, out: Out) -> Result<Ctx> {
    crate::harden::harden_process();
    crate::sys::prompt::init(global.password_fd)?;
    let paths = Paths::from_env()?;
    paths.check_data()?;
    let settings = Settings::load(&paths)?;
    Ok(Ctx {
        paths,
        settings,
        out,
        offline: global.offline,
        review: Default::default(),
    })
}

fn dispatch(ctx: &Ctx, cmd: ClientCommand) -> Result<JsonResult> {
    use ClientCommand as C;
    match cmd {
        C::Init { kdf_memory, kit } => setup_cmds::init(ctx, kdf_memory, kit.as_deref()),
        C::Setup => setup_cmds::setup(ctx),
        C::Key(KeyCommand::Show { qr }) => setup_cmds::key_show(ctx, qr),
        C::Unlock => sync_cmds::unlock(ctx),
        C::Lock => sync_cmds::lock(ctx),
        C::Status => sync_cmds::status(ctx),
        C::Ls { folder, review } => item_cmds::ls(ctx, folder.as_deref(), review),
        C::Find { text } => item_cmds::find(ctx, &text),
        C::Show {
            item,
            reveal,
            field,
            copy,
        } => item_cmds::show(ctx, &item, reveal, field.as_deref(), copy),
        C::Pick {
            field,
            print,
            launcher,
        } => item_cmds::pick(ctx, &field, print, launcher.map(Into::into)),
        C::Add(args) => item_cmds::add(ctx, &args),
        C::Edit { item } => item_cmds::edit(ctx, &item),
        C::Rm { item } => item_cmds::rm(ctx, &item),
        C::Mv { item, folder } => item_cmds::mv(ctx, &item, &folder),
        C::Gen { gen_args, copy } => gen_cmd::gen_cmd(ctx, &gen_args, copy),
        C::Sync { recover } => sync_cmds::sync(ctx, recover),
        C::Passwd {
            rekey,
            new_secret_key,
            keep_password,
            kdf_memory,
        } => sync_cmds::passwd(ctx, rekey, new_secret_key, keep_password, kdf_memory),
        C::Import(ImportCommand::Bitwarden {
            file,
            folder,
            dry_run,
        }) => transfer::import(ctx, &file, &folder, dry_run),
        C::Export {
            format,
            plaintext,
            output,
        } => transfer::export(ctx, format, plaintext, output.as_deref()),
        C::History => sync_cmds::history(ctx),
        C::Restore {
            revision,
            item,
            yes,
        } => sync_cmds::restore(ctx, revision, item.as_deref(), yes),
        C::Completions { .. } | C::Agent | C::Clip => unreachable!("handled in run"),
    }
}

/// The KDF parameters for `--kdf-memory`. A test build with `VAULT_TEST_KDF=1` uses the test
/// parameters instead, so the integration tests unlock quickly.
pub fn kdf_params(mib: u32) -> Result<(vault_core::kdf::KdfParams, bool)> {
    #[cfg(feature = "insecure-test-kdf")]
    if std::env::var_os("VAULT_TEST_KDF").is_some_and(|v| v == "1") {
        return Ok((vault_core::kdf::TEST, true));
    }
    vault_core::kdf::KdfParams::with_memory_mib(mib)
        .map(|k| (k, false))
        .map_err(|_| CliError::usage("--kdf-memory is 64, 128, or 256"))
}
