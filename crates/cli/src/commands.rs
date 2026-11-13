//! Implementation of each subcommand.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, bail};
use vault_core::{
    ItemData, ItemId, ItemKind, KdfParams, RecoveryKey, SecretKey, Unlock, Vault,
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
}

impl Context {
    fn unlock(&self, prompter: &mut Prompter) -> Result<Session> {
        Session::unlock(&self.path, prompter, self.allow_rollback)
    }
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
) -> Result<()> {
    if ctx.path.exists() {
        bail!(
            "{} already exists; refusing to overwrite it",
            ctx.path.display()
        );
    }
    let password = new_master_password(prompter)?;

    eprintln!("Calibrating Argon2id for this computer…");
    let kdf = KdfParams::calibrate(
        kdf_memory_mib.saturating_mul(1024),
        KdfParams::default_parallelism(),
        Duration::from_millis(kdf_target_ms),
    )
    .map_err(explain)?;

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

    let params = vault.kdf_params();
    eprintln!(
        "Vault created: {} (Argon2id {} MiB, {} iterations, {} lanes)",
        ctx.path.display(),
        params.memory_kib() / 1024,
        params.iterations(),
        params.parallelism()
    );
    print_kit(
        &vault.id_hex(),
        &ctx.path,
        &secret_key,
        recovery_key.as_ref(),
    );
    Ok(())
}

pub fn info(ctx: &Context) -> Result<()> {
    let bytes = session::read_vault_file(&ctx.path)?;
    let info = Vault::inspect(&bytes).map_err(explain)?;
    let known = session::load_secret_key(&info.id_hex)?.is_some();
    println!("File:           {}", ctx.path.display());
    println!("Size:           {} bytes", bytes.len());
    println!("Vault ID:       {}", info.id_hex);
    println!(
        "Argon2id:       {} MiB, {} iterations, {} lanes",
        info.kdf.memory_kib() / 1024,
        info.kdf.iterations(),
        info.kdf.parallelism()
    );
    println!(
        "Recovery Key:   {}",
        if info.has_recovery_key { "yes" } else { "no" }
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
    let session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, query)?;
    let item = session.vault.get_item(&id).map_err(explain)?;

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
    let mut item = session.vault.get_item(&id).map_err(explain)?;

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
    let session = ctx.unlock(prompter)?;
    let id = resolve(&session.vault, query)?;
    let item = session.vault.get_item(&id).map_err(explain)?;
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
    session
        .vault
        .change_password(&password, &session.secret_key, &kdf)
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
    vault
        .change_password(&password, &secret_key, &kdf)
        .map_err(explain)?;
    let bytes = vault.to_bytes().map_err(explain)?;
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;
    session::store_secret_key(&vault.id_hex(), &secret_key)?;
    session::record_new_vault(&vault)?;

    println!("New master password and Secret Key set. Your Recovery Key still works.");
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

    let report = match format {
        Format::BitwardenJson => vault_import::import_bitwarden_json(&source)?,
        Format::Csv => vault_import::import_csv(&source)?,
        Format::Kdbx => {
            let keyfile = match &request.keyfile {
                Some(path) => Some(Zeroizing::new(
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
                )),
                None => None,
            };
            let password = prompter.secret("KeePass database password")?;
            vault_import::import_kdbx(&source, &password, keyfile.as_deref().map(Vec::as_slice))?
        }
    };

    // Skip entries that already exist (same title, username, password and first URL).
    let fingerprint = |item: &ItemData| {
        Zeroizing::new(format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            item.title.to_lowercase(),
            item.username,
            item.password,
            item.urls.first().map(String::as_str).unwrap_or_default()
        ))
    };
    let mut known: Vec<Zeroizing<String>> =
        Vec::with_capacity(session.vault.len() + report.items.len());
    for id in session.vault.item_ids().collect::<Vec<_>>() {
        known.push(fingerprint(&session.vault.get_item(&id).map_err(explain)?));
    }

    let mut imported = 0usize;
    let mut duplicates = 0usize;
    for item in &report.items {
        let key = fingerprint(item);
        if known.contains(&key) {
            duplicates += 1;
            continue;
        }
        known.push(key);
        if request.dry_run {
            println!("  would import: {} ({:?})", item.title, item.kind);
        } else {
            session.vault.add_item(item).map_err(explain)?;
        }
        imported += 1;
    }

    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    if request.dry_run {
        println!(
            "Dry run: {imported} item(s) would be imported, {duplicates} duplicate(s) skipped. Nothing was changed."
        );
        return Ok(());
    }
    session.save()?;
    println!("Imported {imported} item(s) ({format:?}); skipped {duplicates} duplicate(s).");

    if format != Format::Kdbx {
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
