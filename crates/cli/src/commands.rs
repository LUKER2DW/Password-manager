//! Implementation of each subcommand.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, bail};
use vault_core::{
    ItemData, ItemId, ItemKind, KdfMethod, KdfParams, KdfStrength, PasswordKdf, RecoveryKey,
    SecretKey, Unlock, Vault,
    generator::{self, PassphraseOptions, PasswordOptions},
    storage,
    totp::Totp,
};
use zeroize::Zeroizing;

use crate::{
    clipboard,
    prompt::Prompter,
    session::{self, Session, explain},
};

const MIN_MASTER_PASSWORD_CHARS: usize = 12;

pub struct Context {
    pub path: PathBuf,
    pub allow_rollback: bool,
    /// `--keyfile`: where the vault's keyfile is, when it uses one.
    pub keyfile: Option<PathBuf>,
}

impl Context {
    fn unlock(&self, prompter: &mut Prompter) -> Result<Session> {
        Session::unlock(
            &self.path,
            prompter,
            self.allow_rollback,
            self.keyfile.as_deref(),
        )
    }
}

/// What `vault keyfile` does.
pub enum KeyfileAction {
    /// Write a new random keyfile there and require it from now on.
    Create(PathBuf),
    /// Require an existing file from now on.
    Use(PathBuf),
    /// Stop requiring a keyfile.
    Remove,
}

pub fn keyfile(ctx: &Context, prompter: &mut Prompter, action: KeyfileAction) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let (new, path) = match &action {
        KeyfileAction::Create(path) => (Some(vault_platform::keyfile::create(path)?), Some(path)),
        KeyfileAction::Use(path) => (Some(vault_platform::keyfile::read(path)?), Some(path)),
        KeyfileAction::Remove => (None, None),
    };
    let kdf = session.vault.kdf_params().clone();
    session
        .vault
        .change_password(&session.password, &session.secret_key, new.as_ref(), &kdf)
        .map_err(explain)?;
    session.save()?;
    vault_platform::keyfile::remember_path(&session.vault.id_hex(), path.map(PathBuf::as_path))?;
    match action {
        KeyfileAction::Create(path) => {
            println!("Keyfile written to {}.", path.display());
            println!(
                "From now on the vault needs it together with your master password. Keep a \
                 copy somewhere safe and apart from the vault: without the file (or your \
                 Recovery Key) the vault can't be opened."
            );
        }
        KeyfileAction::Use(path) => println!(
            "The vault now needs {} together with your master password. The file must never \
             change, not even by one byte.",
            path.display()
        ),
        KeyfileAction::Remove => println!("The vault no longer needs a keyfile."),
    }
    Ok(())
}

pub struct NewItem {
    pub title: String,
    pub kind: ItemKind,
    pub username: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub favorite: bool,
    /// Generate the password with this recipe instead of prompting.
    pub generate: Option<Recipe>,
}

pub struct ItemChanges {
    pub item: String,
    pub title: Option<String>,
    pub username: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub favorite: Option<bool>,
    pub new_password: bool,
    pub generate: Option<Recipe>,
}

// ---------------------------------------------------------------------------------------------

pub fn init(
    ctx: &Context,
    prompter: &mut Prompter,
    no_recovery_key: bool,
    kdf_target_ms: u64,
    kdf_memory_mib: u32,
    other_hash: Option<(KdfMethod, KdfStrength)>,
) -> Result<()> {
    if ctx.path.exists() {
        bail!(
            "{} already exists; refusing to overwrite it",
            ctx.path.display()
        );
    }
    let password = new_master_password(prompter)?;

    let kdf: PasswordKdf = match other_hash {
        Some((method, level)) => {
            eprintln!(
                "Note: Argon2id (the default) resists password guessing on graphics cards \
                 better than scrypt, and far better than PBKDF2."
            );
            PasswordKdf::preset(method, level).map_err(explain)?
        }
        None => {
            eprintln!("Calibrating Argon2id for this computer…");
            KdfParams::calibrate(
                kdf_memory_mib.saturating_mul(1024),
                KdfParams::default_parallelism(),
                Duration::from_millis(kdf_target_ms),
            )
            .map_err(explain)?
            .into()
        }
    };

    let secret_key = SecretKey::generate().map_err(explain)?;
    let recovery_key = if no_recovery_key {
        None
    } else {
        Some(RecoveryKey::generate().map_err(explain)?)
    };
    let mut vault =
        Vault::create(&password, &secret_key, recovery_key.as_ref(), kdf).map_err(explain)?;

    if let Some(parent) = ctx.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let bytes = vault.to_bytes().map_err(explain)?;
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;
    session::store_secret_key(&vault.id_hex(), &secret_key)?;
    session::record_new_vault(&vault)?;

    eprintln!(
        "Vault created: {} ({})",
        ctx.path.display(),
        describe_kdf(vault.kdf_params())
    );
    print_kit(
        &vault.id_hex(),
        &ctx.path,
        &secret_key,
        recovery_key.as_ref(),
    );
    Ok(())
}

/// "Argon2id, 256 MiB, 3 iterations, 4 lanes" and the like.
fn describe_kdf(kdf: &PasswordKdf) -> String {
    match kdf {
        PasswordKdf::Argon2id(params) => format!(
            "Argon2id, {} MiB, {} iterations, {} lanes",
            params.memory_kib() / 1024,
            params.iterations(),
            params.parallelism()
        ),
        PasswordKdf::Scrypt { .. } => format!("scrypt, {} MiB", kdf.memory_mib()),
        PasswordKdf::Pbkdf2Sha256 { iterations, .. } => {
            format!("PBKDF2-SHA-256, {iterations} iterations")
        }
    }
}

pub fn info(ctx: &Context) -> Result<()> {
    let bytes = session::read_vault_file(&ctx.path)?;
    let info = Vault::inspect(&bytes).map_err(explain)?;
    let known = session::load_secret_key(&info.id_hex)?.is_some();
    println!("File:           {}", ctx.path.display());
    println!("Size:           {} bytes", bytes.len());
    println!("Vault ID:       {}", info.id_hex);
    println!("Password hash:  {}", describe_kdf(&info.kdf));
    println!(
        "Recovery Key:   {}",
        if info.has_recovery_key { "yes" } else { "no" }
    );
    println!(
        "Keyfile:        {}",
        if info.needs_keyfile {
            "needed"
        } else {
            "not used"
        }
    );
    println!(
        "This device:    {}",
        if known {
            "has the Secret Key"
        } else {
            "does not have the Secret Key"
        }
    );
    Ok(())
}

pub fn list(ctx: &Context, prompter: &mut Prompter, search: Option<&str>) -> Result<()> {
    let session = ctx.unlock(prompter)?;
    let mut summaries = session.vault.summaries().map_err(explain)?;
    if let Some(query) = search.map(str::to_lowercase) {
        summaries.retain(|s| {
            [&s.title, &s.username, &s.url]
                .iter()
                .any(|field| field.to_lowercase().contains(&query))
        });
    }
    summaries.sort_by_key(|s| s.title.to_lowercase());
    if summaries.is_empty() {
        println!("(no items)");
        return Ok(());
    }
    for s in &summaries {
        println!(
            "{}  {}{:<28}  {:<28}  {}",
            &s.id.to_hex()[..8],
            if s.favorite { "★ " } else { "  " },
            truncate(&s.title, 28),
            truncate(&s.username, 28),
            s.url
        );
    }
    println!("{} item(s)", summaries.len());
    Ok(())
}

pub fn add(ctx: &Context, prompter: &mut Prompter, new: NewItem) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let mut item = ItemData::new(new.kind, &new.title);
    item.username = new.username.unwrap_or_default();
    item.urls = new.urls;
    item.notes = new.notes.unwrap_or_default();
    item.favorite = new.favorite;
    if let Some(totp) = new.totp {
        Totp::parse(&totp).map_err(explain)?;
        item.totp = totp;
    }
    let generated = match &new.generate {
        Some(recipe) => {
            item.password = recipe.make()?.to_string();
            true
        }
        None if new.kind == ItemKind::Login => {
            item.password = prompter
                .secret("Password for the item (empty for none)")?
                .to_string();
            false
        }
        None => false,
    };
    // No item lock check to add: the new item is sealed the next time the lock opens.
    let id = session.vault.add_item(&item).map_err(explain)?;
    session.save()?;
    println!("Added {} ({})", item.title, &id.to_hex()[..8]);
    if generated {
        println!(
            "A {}-character password was generated; use `vault show {} --copy` to use it.",
            item.password.chars().count(),
            &id.to_hex()[..8]
        );
    }
    Ok(())
}

pub fn show(
    ctx: &Context,
    prompter: &mut Prompter,
    query: &str,
    reveal: bool,
    copy: bool,
) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, query)?;
    let item = session.open_item(&id, prompter)?;

    println!("{}{}", item.title, if item.favorite { "  ★" } else { "" });
    println!("  id:        {}", id.to_hex());
    println!("  kind:      {:?}", item.kind);
    if !item.username.is_empty() {
        println!("  username:  {}", item.username);
    }
    if !item.password.is_empty() {
        let shown = if reveal {
            item.password.clone()
        } else {
            "•".repeat(12)
        };
        println!("  password:  {shown}");
    }
    for url in &item.urls {
        println!("  url:       {url}");
    }
    if !item.totp.is_empty() {
        let totp = Totp::parse(&item.totp).map_err(explain)?;
        let (code, remaining) = totp.now();
        println!("  totp:      {} ({remaining} s left)", code.as_str());
    }
    for field in &item.custom_fields {
        let value = if field.sensitive && !reveal {
            "•".repeat(8)
        } else {
            field.value.clone()
        };
        println!("  {}: {value}", field.name);
    }
    if !item.notes.is_empty() {
        if reveal {
            println!("  notes:\n    {}", item.notes.replace('\n', "\n    "));
        } else {
            println!("  notes:     (hidden; use --reveal)");
        }
    }
    if copy {
        if item.password.is_empty() {
            bail!("this item has no password to copy");
        }
        clipboard::copy_and_clear(&item.password, "Password")?;
    }
    Ok(())
}

pub fn edit(ctx: &Context, prompter: &mut Prompter, changes: ItemChanges) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, &changes.item)?;
    let mut item = session.open_item(&id, prompter)?;

    if let Some(title) = changes.title {
        item.title = title;
    }
    if let Some(username) = changes.username {
        item.username = username;
    }
    if !changes.urls.is_empty() {
        item.urls = changes.urls;
    }
    if let Some(notes) = changes.notes {
        item.notes = notes;
    }
    if let Some(totp) = changes.totp {
        if !totp.is_empty() {
            Totp::parse(&totp).map_err(explain)?;
        }
        item.totp = totp;
    }
    if let Some(favorite) = changes.favorite {
        item.favorite = favorite;
    }
    if let Some(recipe) = &changes.generate {
        item.password = recipe.make()?.to_string();
    } else if changes.new_password {
        item.password = prompter
            .new_secret("New password for the item")?
            .to_string();
    }
    item.touch();
    session.vault.update_item(&id, &item).map_err(explain)?;
    session.save()?;
    println!("Updated {}", item.title);
    Ok(())
}

pub fn remove(ctx: &Context, prompter: &mut Prompter, query: &str, yes: bool) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, query)?;
    let item = session.vault.get_item(&id).map_err(explain)?;
    if !yes {
        let answer = prompter.line(&format!("Type the title \"{}\" to delete it", item.title))?;
        if answer != item.title {
            bail!("not deleted (title did not match)");
        }
    }
    session.vault.remove_item(&id).map_err(explain)?;
    session.save()?;
    println!(
        "Deleted {}. The previous file is kept as {}.",
        item.title,
        storage::backup_path(&session.path).display()
    );
    Ok(())
}

pub fn generate(recipe: &Recipe, copy: bool) -> Result<()> {
    let password = recipe.make()?;
    eprintln!("~{:.0} bits of entropy", recipe.entropy_bits());
    if copy {
        clipboard::copy_and_clear(&password, "Password")
    } else {
        println!("{}", password.as_str());
        Ok(())
    }
}

pub fn totp(ctx: &Context, prompter: &mut Prompter, query: &str, copy: bool) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, query)?;
    let item = session.open_item(&id, prompter)?;
    if item.totp.is_empty() {
        bail!("{} has no TOTP secret", item.title);
    }
    let (code, remaining) = Totp::parse(&item.totp).map_err(explain)?.now();
    if copy {
        clipboard::copy_and_clear(&code, "Code")
    } else {
        println!("{}  ({remaining} s left)", code.as_str());
        Ok(())
    }
}

pub fn passwd(ctx: &Context, prompter: &mut Prompter) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let password = new_master_password(prompter)?;
    let kdf = session.vault.kdf_params().clone();
    // So the item lock's reset copy of its key follows the new master password.
    session
        .vault
        .unlock_secrets_with_master(&session.password)
        .map_err(explain)?;
    session
        .vault
        .change_password(
            &password,
            &session.secret_key,
            session.keyfile.as_ref(),
            &kdf,
        )
        .map_err(explain)?;
    session.save()?;
    println!("Master password changed.");
    Ok(())
}

pub fn recover(ctx: &Context, prompter: &mut Prompter) -> Result<()> {
    let bytes = session::read_vault_file(&ctx.path)?;
    let text = prompter.secret("Recovery Key (R0-…)")?;
    let recovery_key = RecoveryKey::parse(&text).map_err(explain)?;
    let mut vault = Vault::open(&bytes, Unlock::Recovery(&recovery_key)).map_err(explain)?;
    eprintln!("Unlocked with the Recovery Key. Choose a new master password.");

    let password = new_master_password(prompter)?;
    // The old Secret Key may be lost or exposed, so always issue a new one.
    let secret_key = SecretKey::generate().map_err(explain)?;
    let kdf = vault.kdf_params().clone();
    // The keyfile may be what was lost: the new lock is the password and Secret Key only.
    let had_keyfile = vault.needs_keyfile();
    vault
        .change_password(&password, &secret_key, None, &kdf)
        .map_err(explain)?;
    let bytes = vault.to_bytes().map_err(explain)?;
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;
    session::store_secret_key(&vault.id_hex(), &secret_key)?;
    session::record_new_vault(&vault)?;

    println!("New master password and Secret Key set. Your Recovery Key still works.");
    if had_keyfile {
        let _ = vault_platform::keyfile::remember_path(&vault.id_hex(), None);
        println!("The keyfile is no longer needed; add one again with `vault keyfile create`.");
    }
    print_kit(&vault.id_hex(), &ctx.path, &secret_key, None);
    Ok(())
}

pub fn kit(ctx: &Context, prompter: &mut Prompter, new_recovery_key: bool) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let recovery_key = if new_recovery_key {
        let key = RecoveryKey::generate().map_err(explain)?;
        session
            .vault
            .set_recovery_key(Some(&key))
            .map_err(explain)?;
        session.save()?;
        eprintln!("A new Recovery Key was issued; the old one no longer works.");
        Some(key)
    } else {
        None
    };
    print_kit(
        &session.vault.id_hex(),
        &session.path,
        &session.secret_key,
        recovery_key.as_ref(),
    );
    if !new_recovery_key && session.vault.has_recovery_key() {
        println!(
            "(The Recovery Key is never stored, so it cannot be shown again. Use --new-recovery-key to replace it.)"
        );
    }
    Ok(())
}

pub fn forget(ctx: &Context) -> Result<()> {
    let bytes = session::read_vault_file(&ctx.path)?;
    let info = Vault::inspect(&bytes).map_err(explain)?;
    if session::forget_secret_key(&info.id_hex)? {
        println!(
            "Secret Key removed from this device. You will need the emergency kit to unlock here again."
        );
    } else {
        println!("This device did not have the Secret Key stored.");
    }
    Ok(())
}

pub struct ImportRequest {
    pub file: PathBuf,
    /// `None` = detect from the contents.
    pub format: Option<vault_import::Format>,
    pub keyfile: Option<PathBuf>,
    pub dry_run: bool,
    pub delete_source: bool,
}

pub fn import(ctx: &Context, prompter: &mut Prompter, request: ImportRequest) -> Result<()> {
    use vault_import::Format;

    let source = Zeroizing::new(
        std::fs::read(&request.file)
            .with_context(|| format!("reading {}", request.file.display()))?,
    );
    let format = request
        .format
        .unwrap_or_else(|| vault_import::detect_format(&source));
    let mut session = ctx.unlock(prompter)?;

    let (password, keyfile) = if format == Format::Sealed {
        (prompter.secret("Password of the export")?, None)
    } else if format == Format::Kdbx {
        let keyfile = match &request.keyfile {
            Some(path) => Some(Zeroizing::new(
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
            )),
            None => None,
        };
        (prompter.secret("Database password")?, keyfile)
    } else {
        (Zeroizing::new(String::new()), None)
    };
    let report = vault_import::import(
        &source,
        format,
        &password,
        keyfile.as_deref().map(Vec::as_slice),
    )?;

    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    // Duplicates are found by comparing passwords, and locked items must be stored sealed.
    if !request.dry_run {
        session.open_secrets(prompter)?;
    }
    // Entries that already exist (same title, username, password and first URL) are skipped.
    if request.dry_run {
        let outcome = report.preview(&session.vault).map_err(explain)?;
        for title in &outcome.titles {
            println!("  would import: {title}");
        }
        println!(
            "Dry run: {} item(s) would be imported into {} new folder(s), {} duplicate(s) skipped. \
             Nothing was changed.",
            outcome.added, outcome.new_folders, outcome.duplicates
        );
        return Ok(());
    }
    let outcome = report.add_to_vault(&mut session.vault).map_err(explain)?;
    session.save()?;
    println!(
        "Imported {} item(s) ({format:?}), {} new folder(s); skipped {} duplicate(s).",
        outcome.added, outcome.new_folders, outcome.duplicates
    );

    if !format.needs_password() {
        if request.delete_source {
            wipe_file(&request.file)?;
            println!("The export file was overwritten and deleted.");
        } else {
            println!(
                "IMPORTANT: {} holds your passwords in PLAIN TEXT. Delete it now (and empty the \
                 recycle bin), or re-run with --delete-source.",
                request.file.display()
            );
        }
    }
    Ok(())
}

/// Best-effort wipe: overwrite with zeros, flush, delete. (On SSDs and copy-on-write file systems
/// old blocks may survive; full-disk encryption is the real protection there.)
fn wipe_file(path: &std::path::Path) -> Result<()> {
    use std::io::Write as _;
    let len = std::fs::metadata(path)?.len();
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; 64 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..chunk])?;
            remaining -= chunk as u64;
        }
        file.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------

fn new_master_password(prompter: &mut Prompter) -> Result<Zeroizing<String>> {
    let password = prompter.new_secret("New master password")?;
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        bail!(
            "the master password must have at least {MIN_MASTER_PASSWORD_CHARS} characters (a few random words work well)"
        );
    }
    Ok(password)
}

/// How to generate a secret: random characters or EFF-word passphrase.
pub enum Recipe {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

impl Recipe {
    /// `words` set → passphrase with default options; otherwise a password of `length`.
    pub fn new(length: usize, words: Option<usize>) -> Self {
        match words {
            Some(words) => Self::Passphrase(PassphraseOptions {
                words,
                ..PassphraseOptions::default()
            }),
            None => Self::Password(PasswordOptions {
                length,
                ..PasswordOptions::default()
            }),
        }
    }

    fn make(&self) -> Result<Zeroizing<String>> {
        match self {
            Self::Password(options) => generator::generate_password(options),
            Self::Passphrase(options) => generator::generate_passphrase(options),
        }
        .map_err(explain)
    }

    fn entropy_bits(&self) -> f64 {
        match self {
            Self::Password(options) => options.entropy_bits(),
            Self::Passphrase(options) => options.entropy_bits(),
        }
    }
}

/// Finds an item by id prefix (≥ 4 hex chars) or by title (exact, then substring),
/// case-insensitively. Ambiguous matches are an error listing the candidates.
fn resolve(vault: &Vault, query: &str) -> Result<ItemId> {
    let needle = query.to_lowercase();
    if needle.len() >= 4 && needle.chars().all(|c| c.is_ascii_hexdigit()) {
        let matches: Vec<ItemId> = vault
            .item_ids()
            .filter(|id| id.to_hex().starts_with(&needle))
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0]);
        }
    }
    let summaries = vault.summaries().map_err(explain)?;
    let exact: Vec<_> = summaries
        .iter()
        .filter(|s| s.title.to_lowercase() == needle)
        .collect();
    let candidates = if exact.is_empty() {
        summaries
            .iter()
            .filter(|s| s.title.to_lowercase().contains(&needle))
            .collect()
    } else {
        exact
    };
    match candidates.as_slice() {
        [single] => Ok(single.id),
        [] => bail!("no item matches \"{query}\""),
        many => {
            let list: Vec<String> = many
                .iter()
                .map(|s| format!("  {}  {}", &s.id.to_hex()[..8], s.title))
                .collect();
            bail!(
                "\"{query}\" matches several items; use the id:\n{}",
                list.join("\n")
            )
        }
    }
}

fn print_kit(
    vault_id: &str,
    path: &std::path::Path,
    secret_key: &SecretKey,
    recovery_key: Option<&RecoveryKey>,
) {
    println!();
    println!("================ EMERGENCY KIT ================");
    println!("Write this down or print it. Keep it offline and safe.");
    println!();
    println!("  Vault ID:      {vault_id}");
    println!("  Vault file:    {}", path.display());
    println!(
        "  Secret Key:    {}",
        secret_key.to_display_string().as_str()
    );
    if let Some(key) = recovery_key {
        println!("  Recovery Key:  {}", key.to_display_string().as_str());
        println!();
        println!(
            "  The Recovery Key opens the vault ON ITS OWN. Store it apart from your devices."
        );
    }
    println!("  Master password: ____________________________ (write by hand)");
    println!("===============================================");
    println!();
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let cut: String = text.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}
