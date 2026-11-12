//! `vault`: command-line client for the password manager.

mod clipboard;
mod commands;
mod prompt;
mod session;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "vault",
    version,
    about = "Local-first, zero-knowledge password manager"
)]
struct Cli {
    /// Vault file. Defaults to `<local data dir>/vault/default.vault`.
    #[arg(long, global = true, env = "VAULT_FILE", value_name = "PATH")]
    vault: Option<PathBuf>,

    /// Read every prompt (master password, confirmations, …) from stdin, one line each.
    /// Meant for scripts and tests; interactive use should type at the hidden prompt instead.
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Open the vault even if it is older than a version this device has already seen.
    #[arg(long, global = true)]
    allow_rollback: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new vault and print its emergency kit.
    Init(InitArgs),
    /// Show public information about the vault file (no unlock needed).
    Info,
    /// List items.
    #[command(alias = "ls")]
    List {
        /// Only items whose title, username or URL contains this text.
        search: Option<String>,
    },
    /// Add an item.
    Add(AddArgs),
    /// Show an item (password hidden unless --reveal).
    Show(ShowArgs),
    /// Change fields of an item.
    Edit(EditArgs),
    /// Delete an item.
    #[command(alias = "remove")]
    Rm {
        /// Item id (prefix) or title.
        item: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Generate a random password (no vault needed).
    Generate(GenerateArgs),
    /// Show the current TOTP code of an item.
    Totp {
        item: String,
        /// Copy the code to the clipboard instead of printing it.
        #[arg(long)]
        copy: bool,
    },
    /// Change the master password.
    Passwd,
    /// Lost your master password or Secret Key? Unlock with the Recovery Key and set new ones.
    Recover,
    /// Print the emergency kit again (Secret Key); optionally issue a new Recovery Key.
    Kit {
        /// Replace the Recovery Key with a new one and print it.
        #[arg(long)]
        new_recovery_key: bool,
    },
    /// Remove this vault's Secret Key from this device's credential store.
    Forget,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Do not create a Recovery Key (losing the password or Secret Key then means losing the vault).
    #[arg(long)]
    no_recovery_key: bool,
    /// Target unlock time used to calibrate Argon2id.
    #[arg(long, default_value_t = 1000, value_name = "MS")]
    kdf_target_ms: u64,
    /// Argon2id memory cost.
    #[arg(long, default_value_t = 256, value_name = "MIB")]
    kdf_memory_mib: u32,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum KindArg {
    Login,
    Card,
    Note,
    Passkey,
}

#[derive(Debug, Args)]
struct AddArgs {
    /// Item title.
    title: String,
    #[arg(long, value_enum, default_value_t = KindArg::Login)]
    kind: KindArg,
    #[arg(short, long)]
    username: Option<String>,
    /// Website address (repeat for several).
    #[arg(long)]
    url: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    /// TOTP secret (Base32) or otpauth:// URI.
    #[arg(long)]
    totp: Option<String>,
    #[arg(long)]
    favorite: bool,
    /// Generate the password instead of typing it.
    #[arg(short, long)]
    generate: bool,
    /// Length of the generated password.
    #[arg(long, default_value_t = 24)]
    length: usize,
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// Item id (prefix) or title.
    item: String,
    /// Print the password in clear text.
    #[arg(long)]
    reveal: bool,
    /// Copy the password to the clipboard (cleared after 20 s).
    #[arg(short, long)]
    copy: bool,
}

#[derive(Debug, Args)]
struct EditArgs {
    /// Item id (prefix) or title.
    item: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(short, long)]
    username: Option<String>,
    /// Replace all URLs (repeat for several).
    #[arg(long)]
    url: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    /// New TOTP secret or URI; pass an empty string to remove it.
    #[arg(long)]
    totp: Option<String>,
    #[arg(long)]
    favorite: Option<bool>,
    /// Type a new password.
    #[arg(long, conflicts_with = "generate")]
    password: bool,
    /// Generate a new password.
    #[arg(short, long)]
    generate: bool,
    #[arg(long, default_value_t = 24)]
    length: usize,
}

#[derive(Debug, Args)]
struct GenerateArgs {
    #[arg(short, long, default_value_t = 24)]
    length: usize,
    #[arg(long)]
    no_lowercase: bool,
    #[arg(long)]
    no_uppercase: bool,
    #[arg(long)]
    no_digits: bool,
    #[arg(long)]
    no_symbols: bool,
    /// Leave out look-alike characters (I l 1 O 0 o).
    #[arg(long)]
    avoid_ambiguous: bool,
    /// Copy instead of printing.
    #[arg(short, long)]
    copy: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(path) => path,
        None => session::default_vault_path()?,
    };
    let mut prompter = prompt::Prompter::new(cli.password_stdin)?;
    let ctx = commands::Context {
        path,
        allow_rollback: cli.allow_rollback,
    };
    match cli.command {
        Command::Init(args) => commands::init(
            &ctx,
            &mut prompter,
            args.no_recovery_key,
            args.kdf_target_ms,
            args.kdf_memory_mib,
        ),
        Command::Info => commands::info(&ctx),
        Command::List { search } => commands::list(&ctx, &mut prompter, search.as_deref()),
        Command::Add(args) => commands::add(
            &ctx,
            &mut prompter,
            commands::NewItem {
                title: args.title,
                kind: args.kind.into(),
                username: args.username,
                urls: args.url,
                notes: args.notes,
                totp: args.totp,
                favorite: args.favorite,
                generate: args.generate.then_some(args.length),
            },
        ),
        Command::Show(args) => {
            commands::show(&ctx, &mut prompter, &args.item, args.reveal, args.copy)
        }
        Command::Edit(args) => commands::edit(
            &ctx,
            &mut prompter,
            commands::ItemChanges {
                item: args.item,
                title: args.title,
                username: args.username,
                urls: args.url,
                notes: args.notes,
                totp: args.totp,
                favorite: args.favorite,
                new_password: args.password,
                generate: args.generate.then_some(args.length),
            },
        ),
        Command::Rm { item, yes } => commands::remove(&ctx, &mut prompter, &item, yes),
        Command::Generate(args) => commands::generate(
            &vault_core::generator::PasswordOptions {
                length: args.length,
                lowercase: !args.no_lowercase,
                uppercase: !args.no_uppercase,
                digits: !args.no_digits,
                symbols: !args.no_symbols,
                avoid_ambiguous: args.avoid_ambiguous,
            },
            args.copy,
        ),
        Command::Totp { item, copy } => commands::totp(&ctx, &mut prompter, &item, copy),
        Command::Passwd => commands::passwd(&ctx, &mut prompter),
        Command::Recover => commands::recover(&ctx, &mut prompter),
        Command::Kit { new_recovery_key } => commands::kit(&ctx, &mut prompter, new_recovery_key),
        Command::Forget => commands::forget(&ctx),
    }
}

impl From<KindArg> for vault_core::ItemKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Login => Self::Login,
            KindArg::Card => Self::Card,
            KindArg::Note => Self::SecureNote,
            KindArg::Passkey => Self::Passkey,
        }
    }
}
