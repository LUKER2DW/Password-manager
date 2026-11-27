//! `vault`: command-line client for the password manager.

mod clipboard;
mod commands;
mod prompt;
mod session;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use vault_core::generator;

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

    /// The vault's keyfile, when it uses one. Remembered per device after it works once.
    #[arg(long, global = true, env = "VAULT_KEYFILE", value_name = "PATH")]
    vault_keyfile: Option<PathBuf>,

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
    /// Show an item (password, notes, hidden fields and one-time code hidden unless --reveal).
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
    /// Renew the vault key: a new vault key, Secret Key and emergency kit, the master password
    /// kept. An older copy of the file (a backup, an old kit) no longer opens newer ones; every
    /// other device asks once for the new Secret Key (`vault sync --take-new-key`).
    RenewKey {
        /// Don't ask to confirm.
        #[arg(long)]
        yes: bool,
    },
    /// Forgot your master password? Unlock with all three recovery parts (or the Recovery Key
    /// of an older kit) and set a new password and Secret Key.
    Recover,
    /// Print the emergency kit again (Secret Key); optionally issue new recovery parts.
    Kit {
        /// Issue new recovery parts (the old ones, or an older kit's Recovery Key, stop working)
        /// and print them.
        #[arg(long, alias = "new-recovery-key")]
        new_parts: bool,
    },
    /// Hide a recovery part inside a picture of your own, saved as a PNG that looks the same.
    PartPicture {
        /// The picture to hide it in (PNG, JPEG, WebP, BMP or GIF).
        cover: PathBuf,
        /// Where to save the PNG.
        out: PathBuf,
    },
    /// Remove this vault's Secret Key from this device's credential store.
    Forget,
    /// Add, replace or remove the keyfile: a file needed together with the master password.
    Keyfile {
        #[command(subcommand)]
        action: KeyfileCommand,
    },
    /// Import an export from another password manager or a browser (JSON, CSV or KDBX).
    Import(ImportArgs),
    /// Sync this vault with your other devices: through a folder they all see (OneDrive,
    /// Google Drive, Dropbox, Syncthing, a network share), your own vault-server, or a
    /// WebDAV folder (Nextcloud, a NAS). Each device writes only its own sealed copy there;
    /// the others' copies are merged in. The place is remembered after the first time.
    Sync(SyncArgs),
}

#[derive(Debug, clap::Args)]
struct SyncArgs {
    /// Sync through this folder.
    #[arg(conflicts_with_all = ["server", "join", "webdav"])]
    folder: Option<PathBuf>,
    /// Sync through your own vault-server at this address (https://, or http:// on
    /// Tailscale). The first time needs --invite.
    #[arg(long, conflicts_with_all = ["join", "webdav"])]
    server: Option<String>,
    /// The one-time invite made by `vault-server invite` or by a device already in.
    #[arg(long, requires = "server")]
    invite: Option<String>,
    /// Join with the invite text another device showed (vaultsync:1?...).
    #[arg(long, conflicts_with = "webdav")]
    join: Option<String>,
    /// Sync through a WebDAV folder at this address (asks for the password once).
    #[arg(long, requires = "user")]
    webdav: Option<String>,
    /// The WebDAV user name.
    #[arg(long, requires = "webdav")]
    user: Option<String>,
    /// Print an invite another device joins the server with (good for an hour).
    #[arg(long, conflicts_with_all = ["devices", "remove", "stop"])]
    add_device: bool,
    /// List the devices that sync this vault.
    #[arg(long, conflicts_with_all = ["remove", "stop"])]
    devices: bool,
    /// Remove a device from this vault (its id, or the first characters of it): it gets
    /// nothing new from then on.
    #[arg(long, conflicts_with = "stop")]
    remove: Option<String>,
    /// Stop syncing this vault on this device (the copies there are left).
    #[arg(long, conflicts_with_all = ["folder", "server", "join", "webdav"])]
    stop: bool,
    /// The vault key was renewed on another device: ask for the new Secret Key (from the new
    /// emergency kit) and take the new key.
    #[arg(long, conflicts_with = "stop")]
    take_new_key: bool,
}

#[derive(Debug, Subcommand)]
enum KeyfileCommand {
    /// Write a new random keyfile to PATH and require it from now on.
    Create { path: PathBuf },
    /// Require an existing file from now on (it must never change).
    Use { path: PathBuf },
    /// Stop requiring a keyfile.
    Remove,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImportFormat {
    Auto,
    Json,
    Csv,
    Kdbx,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// The export file.
    file: PathBuf,
    #[arg(long, value_enum, default_value_t = ImportFormat::Auto)]
    format: ImportFormat,
    /// KeePass key file, if the database uses one.
    #[arg(long, value_name = "PATH")]
    keyfile: Option<PathBuf>,
    /// Show what would be imported without changing the vault.
    #[arg(long)]
    dry_run: bool,
    /// After a successful import, overwrite the (plain-text) export file and delete it.
    #[arg(long)]
    delete_source: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Do not create recovery parts (losing the password then means losing the vault).
    #[arg(long = "no-recovery", alias = "no-recovery-key")]
    no_recovery_key: bool,
    /// Target unlock time used to calibrate Argon2id.
    #[arg(long, default_value_t = 1000, value_name = "MS")]
    kdf_target_ms: u64,
    /// Argon2id memory cost.
    #[arg(long, default_value_t = 256, value_name = "MIB")]
    kdf_memory_mib: u32,
    /// How the master password is hashed. Argon2id is the recommendation; scrypt and
    /// PBKDF2-SHA-256 are weaker against guessing on graphics cards.
    #[arg(long, value_enum, default_value_t = HashArg::Argon2id)]
    hash: HashArg,
    /// Cost level for scrypt and PBKDF2-SHA-256 (Argon2id is calibrated instead).
    #[arg(long, value_enum, default_value_t = LevelArg::Standard)]
    hash_level: LevelArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HashArg {
    Argon2id,
    Scrypt,
    #[value(name = "pbkdf2-sha256")]
    Pbkdf2Sha256,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LevelArg {
    Light,
    Standard,
    Strong,
    Maximum,
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
    /// TOTP secret (Base32) or otpauth:// URI; `-` asks for it without showing it (a value
    /// typed here stays in the shell's history).
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
    /// With --generate: make a passphrase of this many words instead.
    #[arg(long, requires = "generate")]
    words: Option<usize>,
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// Item id (prefix) or title.
    item: String,
    /// Print the password, notes, hidden fields and the current one-time code in clear text.
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
    /// New TOTP secret or URI (`-` asks for it without showing it); an empty string removes
    /// it.
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
    /// With --generate: make a passphrase of this many words instead.
    #[arg(long, requires = "generate")]
    words: Option<usize>,
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// Make a passphrase of this many words (EFF word list) instead of a random-character password.
    #[arg(short, long)]
    words: Option<usize>,
    /// Passphrase: text between words.
    #[arg(long, default_value = "-", requires = "words")]
    separator: String,
    /// Passphrase: capitalize every word.
    #[arg(long, requires = "words")]
    capitalize: bool,
    /// Passphrase: add one digit.
    #[arg(long, requires = "words")]
    number: bool,
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
    // Before anything loads a DLL by name: System32 only, never next to the exe.
    vault_platform::process::restrict_dll_search();
    // Other programs of this user can't read, write or steer the process (release builds: a
    // debugger can't attach afterwards), and the mitigation policies that keep it working.
    if !cfg!(debug_assertions) {
        vault_platform::process::protect_memory();
    }
    vault_platform::process::apply_mitigations();
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
        keyfile: cli.vault_keyfile,
    };
    match cli.command {
        Command::Init(args) => commands::init(
            &ctx,
            &mut prompter,
            args.no_recovery_key,
            args.kdf_target_ms,
            args.kdf_memory_mib,
            {
                use vault_core::{KdfMethod, KdfStrength};
                let level = match args.hash_level {
                    LevelArg::Light => KdfStrength::Light,
                    LevelArg::Standard => KdfStrength::Standard,
                    LevelArg::Strong => KdfStrength::Strong,
                    LevelArg::Maximum => KdfStrength::Maximum,
                };
                match args.hash {
                    HashArg::Argon2id => None,
                    HashArg::Scrypt => Some((KdfMethod::Scrypt, level)),
                    HashArg::Pbkdf2Sha256 => Some((KdfMethod::Pbkdf2Sha256, level)),
                }
            },
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
                generate: args
                    .generate
                    .then(|| commands::Recipe::new(args.length, args.words)),
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
                generate: args
                    .generate
                    .then(|| commands::Recipe::new(args.length, args.words)),
            },
        ),
        Command::Rm { item, yes } => commands::remove(&ctx, &mut prompter, &item, yes),
        Command::Generate(args) => {
            let recipe = match args.words {
                Some(words) => commands::Recipe::Passphrase(generator::PassphraseOptions {
                    words,
                    separator: args.separator,
                    case: if args.capitalize {
                        generator::WordCase::Title
                    } else {
                        generator::WordCase::Lower
                    },
                    include_number: args.number,
                    wordlist: None,
                }),
                None => commands::Recipe::Password(generator::PasswordOptions {
                    length: args.length,
                    lowercase: !args.no_lowercase,
                    uppercase: !args.no_uppercase,
                    digits: !args.no_digits,
                    symbols: !args.no_symbols,
                    avoid_ambiguous: args.avoid_ambiguous,
                    ..generator::PasswordOptions::default()
                }),
            };
            commands::generate(&recipe, args.copy)
        }
        Command::Totp { item, copy } => commands::totp(&ctx, &mut prompter, &item, copy),
        Command::Passwd => commands::passwd(&ctx, &mut prompter),
        Command::RenewKey { yes } => commands::renew_key(&ctx, &mut prompter, yes),
        Command::Recover => commands::recover(&ctx, &mut prompter),
        Command::Kit { new_parts } => commands::kit(&ctx, &mut prompter, new_parts),
        Command::PartPicture { cover, out } => {
            let part = prompter.secret("Recovery part to hide (A0-, B0- or C0-…)")?;
            commands::part_picture(&part, &cover, &out)
        }
        Command::Forget => commands::forget(&ctx),
        Command::Keyfile { action } => commands::keyfile(
            &ctx,
            &mut prompter,
            match action {
                KeyfileCommand::Create { path } => commands::KeyfileAction::Create(path),
                KeyfileCommand::Use { path } => commands::KeyfileAction::Use(path),
                KeyfileCommand::Remove => commands::KeyfileAction::Remove,
            },
        ),
        Command::Sync(args) => commands::sync(
            &ctx,
            &mut prompter,
            commands::SyncRequest {
                folder: args.folder,
                server: args.server,
                invite: args.invite,
                join: args.join,
                webdav: args.webdav.zip(args.user),
                add_device: args.add_device,
                devices: args.devices,
                remove: args.remove,
                stop: args.stop,
                take_new_key: args.take_new_key,
            },
        ),
        Command::Import(args) => commands::import(
            &ctx,
            &mut prompter,
            commands::ImportRequest {
                file: args.file,
                format: match args.format {
                    ImportFormat::Auto => None,
                    ImportFormat::Json => Some(vault_import::Format::Json),
                    ImportFormat::Csv => Some(vault_import::Format::Csv),
                    ImportFormat::Kdbx => Some(vault_import::Format::Kdbx),
                },
                keyfile: args.keyfile,
                dry_run: args.dry_run,
                delete_source: args.delete_source,
            },
        ),
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
