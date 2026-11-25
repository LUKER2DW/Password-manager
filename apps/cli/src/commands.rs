//! Implementation of each subcommand.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, anyhow, bail};
use vault_core::{
    ItemData, ItemId, ItemKind, KdfMethod, KdfParams, KdfStrength, PartLabel, PasswordKdf,
    RecoveryKey, RecoveryPart, RecoveryParts, SecretKey, Unlock, Vault,
    generator::{self, PassphraseOptions, PasswordOptions},
    storage,
    totp::Totp,
};
use zeroize::Zeroizing;

use crate::{
    clipboard,
    prompt::Prompter,
    session::{self, NotKept, Session, explain},
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
    init_with(
        ctx,
        prompter,
        no_recovery_key,
        kdf_target_ms,
        kdf_memory_mib,
        other_hash,
        session::store_secret_key,
    )
}

/// [`init`], with `keep` keeping the new vault's Secret Key on this device.
fn init_with(
    ctx: &Context,
    prompter: &mut Prompter,
    no_recovery_key: bool,
    kdf_target_ms: u64,
    kdf_memory_mib: u32,
    other_hash: Option<(KdfMethod, KdfStrength)>,
    keep: impl FnOnce(&str, &SecretKey) -> Result<()>,
) -> Result<()> {
    refuse_to_overwrite(&ctx.path)?;
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
    let parts = if no_recovery_key {
        None
    } else {
        Some(RecoveryParts::generate().map_err(explain)?)
    };
    let mut vault = Vault::create(&password, &secret_key, None, kdf).map_err(explain)?;
    if let Some(parts) = &parts {
        vault
            .set_recovery_parts(parts, &secret_key)
            .map_err(explain)?;
    }

    if let Some(parent) = ctx.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let bytes = vault.to_bytes().map_err(explain)?;
    // Again now: while the password was typed and the hash calibrated, the app or a sync
    // client may have put a vault here, which is not written over.
    refuse_to_overwrite(&ctx.path)?;
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;

    // From here on the file is only opened with this kit: it is shown whatever fails next.
    eprintln!(
        "Vault created: {} ({})",
        ctx.path.display(),
        describe_kdf(vault.kdf_params())
    );
    print_kit(&vault.id_hex(), &ctx.path, &secret_key, parts.as_ref());
    keep(&vault.id_hex(), &secret_key).context(
        "the vault was created, but this device didn't keep its Secret Key: write down the kit \
         above, the Secret Key is asked for when the vault is opened here",
    )?;
    session::record_new_vault(&vault)?;
    Ok(())
}

/// Refuses to make a vault at `path` when anything is there, also a link to nowhere (which
/// `exists` would not see).
fn refuse_to_overwrite(path: &std::path::Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        );
    }
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
        "Recovery:       {}",
        if info.has_recovery_parts {
            "three recovery parts"
        } else if info.has_recovery_key {
            "Recovery Key of an older kit (`vault kit --new-parts` replaces it)"
        } else {
            "none"
        }
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
        let mut totp = typed_totp(prompter, totp)?;
        Totp::parse(&totp).map_err(explain)?;
        item.totp = std::mem::take(&mut *totp);
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
        // The current code opens the account as the password does: hidden the same way.
        if reveal {
            let totp = Totp::parse(&item.totp).map_err(explain)?;
            let (code, remaining) = totp.now();
            println!("  totp:      {} ({remaining} s left)", code.as_str());
        } else {
            println!("  totp:      (hidden; use --reveal, or `vault totp`)");
        }
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

/// `--totp -`: the secret is typed at a prompt that doesn't show it. A value given on the
/// command line stays in the shell's history (and in the list of running processes while the
/// command runs), and the secret makes every code from now on.
///
/// Nothing typed there is refused: Enter pressed to back out (or an empty line in a script)
/// must not remove the secret an item has. `--totp ""` is how that is asked for.
fn typed_totp(prompter: &mut Prompter, given: String) -> Result<Zeroizing<String>> {
    if given != "-" {
        return Ok(Zeroizing::new(given));
    }
    let typed = prompter.secret("TOTP secret (Base32) or otpauth:// URI")?;
    let typed = Zeroizing::new(typed.trim().to_owned());
    if typed.is_empty() {
        bail!(
            "nothing was typed for the TOTP secret, so nothing was changed (to remove one, pass \
             --totp \"\")"
        );
    }
    Ok(typed)
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
        let mut totp = typed_totp(prompter, totp)?;
        if !totp.is_empty() {
            Totp::parse(&totp).map_err(explain)?;
        }
        item.totp = std::mem::take(&mut *totp);
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
    // Behind the item lock, deleting asks for its PIN or password like showing does: the
    // deletion goes to every device the vault syncs with. Nothing is changed before it passes.
    let item = session.open_item(&id, prompter)?;
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

/// The desktop app's files for vault `id` that hold more than one sealed piece (the drop box
/// of logins saved while locked, the index for filling while locked): the app seals them again
/// itself when it renews or takes a key, this command can't. Named as in
/// apps/desktop/src/controller/drop_box.rs and locked_fill.rs.
fn app_files_held(id: &str) -> Vec<PathBuf> {
    let Ok(dir) = vault_platform::paths::app_dir() else {
        return Vec::new();
    };
    [
        format!("browser-drop-{id}.bin"),
        format!("browser-locked-v2-{id}.bin"),
    ]
    .into_iter()
    .map(|name| dir.join(name))
    .filter(|path| path.exists())
    .collect()
}

/// Refuses a renewal (or a renewed key taken) here while the desktop app keeps files only it
/// can seal again: the logins it holds for the next unlock would be lost.
fn refuse_while_app_files(id: &str) -> Result<()> {
    let held = app_files_held(id);
    if !held.is_empty() {
        bail!(
            "the desktop app keeps files for this vault that only it can seal again under a new \
             key ({}): do this in the app (Emergency kit → Renew the vault key, or Settings → \
             Sync). Nothing was changed.",
            held.iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// After the vault key changed here: what the desktop app sealed whole with the former key
/// (generator history, the extension's connection key, website icons, the leak watch) is sealed
/// again, and Windows Hello, whose copy of the key opens nothing any more, is turned off. Named
/// as in the desktop app's controller modules. `true` when Windows Hello was on.
fn reseal_app_files(vault: &Vault, former: &vault_core::FormerKey) -> bool {
    use vault_platform::{files, quick_unlock};
    let id = vault.id_hex();
    if let Ok(dir) = vault_platform::paths::app_dir() {
        for (name, purpose) in [
            (format!("generated-{id}.bin"), "generated-history"),
            (format!("browser-pairing-{id}.bin"), "browser-pairing"),
            (format!("icons-{id}.cache"), "icons"),
            (
                format!("leak-watch-{id}.bin"),
                vault_platform::leak_check::WATCH_PURPOSE,
            ),
        ] {
            files::reseal(&dir.join(name), vault, former, purpose);
        }
    }
    let _ = quick_unlock::record_password_unlock(vault);
    let hello = quick_unlock::is_enrolled(&id);
    quick_unlock::forget(&id);
    hello
}

/// Renews the vault key (`Vault::renew_key`): a new vault key, Secret Key and kit, with the
/// master password just typed. Written only over the file this session read, and kept only
/// together with the new Secret Key (as `recover` does); then the new kit is printed.
pub fn renew_key(ctx: &Context, prompter: &mut Prompter, yes: bool) -> Result<()> {
    use vault_platform::DeviceState;

    let mut session = ctx.unlock(prompter)?;
    refuse_while_app_files(&session.vault.id_hex())?;
    if !yes {
        eprintln!(
            "Renewing the vault key makes a new Secret Key and a new emergency kit. The old kit \
             and the old Secret Key stop working, and every other device asks once for the new \
             Secret Key."
        );
        if prompter.line("Type RENEW to go on")? != "RENEW" {
            bail!("nothing was changed");
        }
    }
    let read = storage::read(&session.path).map_err(explain)?;
    if storage::fingerprint(&read) != session.file_hash() {
        bail!(
            "{} was changed while this command was running: nothing was renewed. Run it again.",
            session.path.display()
        );
    }
    let before = session.vault.unlock_id();
    let password = session.password.clone();
    let renewed = session
        .vault
        .renew_key(&password, &session.secret_key, session.keyfile.as_ref())
        .map_err(explain)?;
    let id = session.vault.id_hex();
    let written = session.vault.to_bytes().map_err(explain)?;
    match session::replace_then_keep(&session.path, &read, &written, || {
        session::store_secret_key(&id, &renewed.secret_key)
    }) {
        Ok(hash) => session.wrote(hash),
        Err(NotKept::NotWritten(err)) => return Err(err.context("nothing was renewed")),
        Err(NotKept::PutBack(err)) => {
            return Err(err.context(
                "this device didn't keep the new Secret Key, so the vault was left as it was",
            ));
        }
        Err(NotKept::Replaced { error, back }) => {
            print_kit(
                &id,
                &session.path,
                &renewed.secret_key,
                Some(&renewed.parts),
            );
            return Err(error.context(format!(
                "this device didn't keep the new Secret Key, and putting the vault back as it \
                 was failed ({back:#}): only the new emergency kit above opens it now, write it \
                 down"
            )));
        }
    }
    let mut state = DeviceState::load()?;
    state.retire_unlock(&id, &before);
    state.record_revision(&id, session.vault.revision());
    state.save()?;
    if reseal_app_files(&session.vault, &renewed.former) {
        println!("Windows Hello was turned off for this vault: turn it on again in the app.");
    }
    println!(
        "The vault key was renewed. The old Secret Key and the old kit no longer open this vault \
         or any copy made from now on."
    );
    print_kit(
        &id,
        &session.path,
        &renewed.secret_key,
        Some(&renewed.parts),
    );
    println!(
        "Next: `vault sync` to send the renewed copy. Each other device asks once for the new \
         Secret Key and the master password (`vault sync --take-new-key`, or the app's Sync \
         settings)."
    );
    Ok(())
}

pub fn recover(ctx: &Context, prompter: &mut Prompter) -> Result<()> {
    recover_with(ctx, prompter, session::store_secret_key)
}

/// [`recover`], with `keep` keeping the new Secret Key on this device.
fn recover_with(
    ctx: &Context,
    prompter: &mut Prompter,
    keep: impl FnOnce(&str, &SecretKey) -> Result<()>,
) -> Result<()> {
    let bytes = session::read_vault_file(&ctx.path)?;
    let info = Vault::inspect(&bytes).map_err(explain)?;
    let mut vault = if info.has_recovery_key {
        let text = prompter.secret("Recovery Key (R0-…)")?;
        let recovery_key = RecoveryKey::parse(&text).map_err(explain)?;
        Vault::open(&bytes, Unlock::Recovery(&recovery_key)).map_err(explain)?
    } else {
        let mut parts = Vec::with_capacity(3);
        for which in ["first", "second", "third"] {
            let text = prompter.secret(&format!(
                "Recovery part, {which} of three (A0-, B0- or C0-…)"
            ))?;
            parts.push(RecoveryPart::parse(&text).map_err(explain)?);
        }
        Vault::open(&bytes, Unlock::Parts([&parts[0], &parts[1], &parts[2]])).map_err(explain)?
    };
    eprintln!("Unlocked with the emergency kit. Choose a new master password.");

    let password = new_master_password(prompter)?;
    // The old Secret Key may be lost or exposed, so always issue a new one.
    let secret_key = SecretKey::generate().map_err(explain)?;
    let kdf = vault.kdf_params().clone();
    // The keyfile may be what was lost: the new lock is the password and Secret Key only.
    let had_keyfile = vault.needs_keyfile();
    vault
        .change_password(&password, &secret_key, None, &kdf)
        .map_err(explain)?;
    // Recovery parts work once: the ones just typed are replaced by a new set.
    let new_parts = if info.has_recovery_key {
        None
    } else {
        let parts = RecoveryParts::generate().map_err(explain)?;
        vault
            .set_recovery_parts(&parts, &secret_key)
            .map_err(explain)?;
        Some(parts)
    };
    // Written only over the file the kit was checked against, and kept only together with the
    // new Secret Key: once written, nothing but the new kit opens the vault.
    let id = vault.id_hex();
    let written = vault.to_bytes().map_err(explain)?;
    match session::replace_then_keep(&ctx.path, &bytes, &written, || keep(&id, &secret_key)) {
        Ok(_) => {}
        Err(NotKept::NotWritten(err)) => return Err(err),
        Err(NotKept::PutBack(err)) => {
            return Err(err.context(
                "this device didn't keep the new Secret Key, so the vault was left as it was: \
                 the emergency kit you typed still opens it",
            ));
        }
        Err(NotKept::Replaced { error, back }) => {
            print_kit(&id, &ctx.path, &secret_key, new_parts.as_ref());
            return Err(error.context(format!(
                "this device didn't keep the new Secret Key, and putting the vault back as it \
                 was failed ({back:#}): only the new emergency kit above opens it now, write it \
                 down"
            )));
        }
    }

    println!(
        "{}",
        if info.has_recovery_key {
            "New master password and Secret Key set. Your Recovery Key still works."
        } else {
            "New master password and Secret Key set. The recovery parts you typed no longer \
             work: here are new ones."
        }
    );
    if had_keyfile {
        let _ = vault_platform::keyfile::remember_path(&vault.id_hex(), None);
        println!("The keyfile is no longer needed; add one again with `vault keyfile create`.");
    }
    print_kit(&id, &ctx.path, &secret_key, new_parts.as_ref());
    // After the kit: what is noted here only helps tell an old copy of the file later.
    session::record_new_vault(&vault)
        .context("the vault was recovered (its new kit is above), but this device didn't note it")
}

pub fn kit(ctx: &Context, prompter: &mut Prompter, new_parts: bool) -> Result<()> {
    let mut session = ctx.unlock(prompter)?;
    let parts = if new_parts {
        let parts = RecoveryParts::generate().map_err(explain)?;
        let secret_key = &session.secret_key;
        session
            .vault
            .set_recovery_parts(&parts, secret_key)
            .map_err(explain)?;
        session.save()?;
        eprintln!("New recovery parts were issued; the old ones (or Recovery Key) no longer work.");
        Some(parts)
    } else {
        None
    };
    print_kit(
        &session.vault.id_hex(),
        &session.path,
        &session.secret_key,
        parts.as_ref(),
    );
    if !new_parts {
        if session.vault.has_recovery_parts() {
            println!(
                "(Recovery parts are never stored, so they cannot be shown again. Use --new-parts to replace them.)"
            );
        } else if session.vault.has_recovery_key() {
            println!(
                "(This vault still uses the Recovery Key of an older kit. Use --new-parts to replace it with recovery parts.)"
            );
        }
    }
    Ok(())
}

/// Saves a recovery part inside a picture of the person's own (`cover`) as a PNG at `out`,
/// then reads the file back to check it.
pub fn part_picture(part_text: &str, cover: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let part = RecoveryPart::parse(part_text).map_err(explain)?;
    let cover_bytes =
        std::fs::read(cover).with_context(|| format!("reading {}", cover.display()))?;
    let picture = vault_platform::part_picture::make(&part, Some(&cover_bytes))?;
    if out.exists() {
        bail!("{} already exists; refusing to overwrite it", out.display());
    }
    std::fs::write(out, &*picture).with_context(|| format!("writing {}", out.display()))?;
    let back = vault_platform::part_picture::read(&std::fs::read(out)?)?;
    if back != part {
        let _ = std::fs::remove_file(out);
        bail!("the saved picture gives back another part");
    }
    println!(
        "Part {} is in {}. Keep that file as it is: a resized or converted copy loses the part.",
        part.label().letter(),
        out.display()
    );
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

/// What `vault sync` was asked to do.
#[derive(Debug, Default)]
pub struct SyncRequest {
    pub folder: Option<PathBuf>,
    pub server: Option<String>,
    pub invite: Option<String>,
    pub join: Option<String>,
    /// Address and user name.
    pub webdav: Option<(String, String)>,
    pub add_device: bool,
    pub devices: bool,
    pub remove: Option<String>,
    pub stop: bool,
    /// Ask for the new Secret Key of a vault key renewed on another device, and take the key.
    pub take_new_key: bool,
}

pub fn sync(ctx: &Context, prompter: &mut Prompter, request: SyncRequest) -> Result<()> {
    use vault_platform::{
        DeviceState, SyncTo, secret_store,
        sync::{self, ServerTarget},
    };

    let bytes = session::read_vault_file(&ctx.path)?;
    let id = Vault::inspect(&bytes).map_err(explain)?.id_hex;
    let mut state = DeviceState::load()?;
    let device = state.device_id_for(&id).map_err(explain)?;
    state.save()?;
    if request.stop {
        state.set_sync_to(&id, None);
        state.save()?;
        let _ = secret_store::forget_sync_key(&id, &device.to_hex());
        let _ = secret_store::forget_webdav_password(&id);
        println!("This vault no longer syncs on this device. The copies there were left.");
        return Ok(());
    }
    let place = state.sync_place(&id);

    // Where to sync: what was asked, else what was used last time.
    let to = if let Some(folder) = request.folder {
        if !folder.is_dir() {
            bail!("{} is not a folder", folder.display());
        }
        SyncTo::Folder { path: folder }
    } else if let Some(text) = request.join {
        let link = vault_sync_wire::InviteLink::parse(&text)
            .context("that isn't an invite: it starts with vaultsync:1?")?;
        if !link.fits(&id) {
            bail!("that invite is for another vault");
        }
        join_server(&id, device, &link.server, &link.invite)?
    } else if let Some(address) = request.server {
        let url = sync::check_address(&address)?;
        match request.invite {
            Some(invite) => join_server(&id, device, &url, &invite)?,
            None if matches!(&place, Some(p) if p.to == SyncTo::Server { url: url.clone() }) => {
                SyncTo::Server { url }
            }
            None => bail!(
                "the first time on a server needs --invite (from `vault-server invite` or another device)"
            ),
        }
    } else if let Some((address, user)) = request.webdav {
        let url = sync::check_webdav_address(&address)?;
        let password = prompter.secret("WebDAV password")?;
        // Checked before it is kept: the folder must answer with these credentials.
        let target = sync::WebDavTarget::new(&url, &id, &user, &password)?;
        sync::Target::list(&target)?;
        secret_store::store_webdav_password(&id, &password)?;
        SyncTo::Webdav { url, user }
    } else if let Some(place) = &place {
        place.to.clone()
    } else {
        bail!(
            "this vault doesn't sync yet: run `vault sync <folder>`, `vault sync --server <address> --invite <invite>` or `vault sync --webdav <address> --user <name>` once"
        );
    };
    let (mut seen, published) = match place.filter(|p| p.to == to) {
        Some(place) => (place.seen, place.published),
        None => match DeviceState::load()?.sync_place(&id) {
            // Moved to another place: what was seen still holds there.
            Some(place) => (place.seen, 0),
            None => Default::default(),
        },
    };
    let target = sync::open_target(&id, device, &to)?;

    if request.add_device {
        let SyncTo::Server { url } = &to else {
            bail!(
                "an invite is for a server; with a folder or WebDAV, set the same place on the other device"
            );
        };
        let seed = secret_store::load_sync_key(&id, &device.to_hex())?
            .context("this device has no key for the server: join it again")?;
        let server = ServerTarget::new(
            url,
            &id,
            device,
            vault_sync_wire::DeviceKey::from_seed(&seed),
        )?;
        let invite = server.invite()?;
        println!("{}", *server.invite_link(&invite).to_text());
        eprintln!(
            "On the other device: vault sync --join \"<the line above>\" (or scan it in the app). \
             Good once, for an hour. It doesn't open the vault: that still needs the master \
             password and the Secret Key."
        );
        state = DeviceState::load()?;
        state.set_sync_to(&id, Some(to));
        state.save()?;
        return Ok(());
    }

    let mut session = ctx.unlock(prompter)?;
    let joined = sync::join(&mut session.vault, device, &sync::device_name()).map_err(explain)?;

    if request.devices {
        let enrolled = match &to {
            SyncTo::Server { url } => {
                let seed = secret_store::load_sync_key(&id, &device.to_hex())?;
                seed.and_then(|seed| {
                    ServerTarget::new(
                        url,
                        &id,
                        device,
                        vault_sync_wire::DeviceKey::from_seed(&seed),
                    )
                    .ok()
                })
                .and_then(|server| server.enrolled().ok())
            }
            _ => None,
        };
        println!("Syncs through {}", to.describe());
        for other in session.vault.sync_devices() {
            let mark = if other.id == device {
                "  (this device)"
            } else {
                ""
            };
            let seen_at = enrolled
                .as_ref()
                .and_then(|list| list.iter().find(|e| e.device == other.id.to_hex()))
                .map(|e| format!("  last seen on the server at {}", e.seen_at))
                .unwrap_or_default();
            println!("  {}  {}{mark}{seen_at}", short(&other.id), other.name);
        }
        if joined {
            session.save()?;
        }
        return Ok(());
    }

    if let Some(prefix) = &request.remove {
        let prefix = prefix.trim().to_ascii_lowercase();
        let matches: Vec<_> = session
            .vault
            .sync_devices()
            .iter()
            .filter(|d| !prefix.is_empty() && d.id.to_hex().starts_with(&prefix))
            .map(|d| (d.id, d.name.clone()))
            .collect();
        let [(other, name)] = matches.as_slice() else {
            bail!(
                "{} devices start with that id: `vault sync --devices` lists them",
                matches.len()
            );
        };
        if *other == device {
            bail!("this is this device: use `vault sync --stop` here instead");
        }
        session.vault.remove_sync_device(other).map_err(explain)?;
        session.save()?;
        if let Err(err) = target.remove(*other) {
            eprintln!("Its copy couldn't be deleted there ({err:#}); it is refused anyway.");
        }
        println!("Removed {name}: the other devices refuse its copies from their next sync.");
    }

    let fetched = sync::fetch(&*target, device, &sync::Tags::new())?;
    for (other, why) in &fetched.unreadable {
        eprintln!("Couldn't read the copy of device {}: {why}", short(other));
    }
    let mut round = sync::merge_all(&mut session.vault, &fetched, &mut seen);
    // Copies the key held here can't open: from a device yet to take a key renewed here, or
    // sealed under a key renewed on that device.
    let mismatch = sync::key_mismatch_in(&id, &fetched.copies, &round, &DeviceState::load()?);
    if request.take_new_key {
        if mismatch.renewed.is_empty() {
            bail!("no copy there was sealed under a renewed vault key: nothing to take");
        }
        refuse_while_app_files(&id)?;
        let typed = prompter.secret("New Secret Key (S0-..., from the new emergency kit)")?;
        let new_secret_key = SecretKey::parse(&typed).map_err(explain)?;
        let read = storage::read(&session.path).map_err(explain)?;
        if storage::fingerprint(&read) != session.file_hash() {
            bail!(
                "{} was changed while this command was running: run it again",
                session.path.display()
            );
        }
        let mut state = DeviceState::load()?;
        let password = session.password.clone();
        let taken = sync::take_renewed_key(
            &mut session.vault,
            &mismatch.renewed,
            &password,
            &new_secret_key,
            session.keyfile.as_ref(),
            &mut state,
        )
        .map_err(|err| match err {
            vault_core::Error::DecryptionFailed => anyhow!(
                "that Secret Key (with this master password) opens none of the renewed copies"
            ),
            other => explain(other),
        })?;
        if let Some(former) = &taken {
            let written = session.vault.to_bytes().map_err(explain)?;
            match session::replace_then_keep(&session.path, &read, &written, || {
                session::store_secret_key(&id, &new_secret_key)
            }) {
                Ok(hash) => session.wrote(hash),
                Err(NotKept::NotWritten(err)) | Err(NotKept::PutBack(err)) => {
                    return Err(err.context("the new key was not taken: the vault is as it was"));
                }
                Err(NotKept::Replaced { error, back }) => {
                    return Err(error.context(format!(
                        "the vault now opens with the new Secret Key only, but this device \
                         didn't keep it, and putting the vault back failed ({back:#}): keep \
                         the new emergency kit at hand"
                    )));
                }
            }
            session.secret_key = new_secret_key;
            state.save()?;
            if reseal_app_files(&session.vault, former) {
                println!(
                    "Windows Hello was turned off for this vault: turn it on again in the app."
                );
            }
            println!("This device took the renewed vault key.");
        }
        round = sync::merge_all(&mut session.vault, &fetched, &mut seen);
    } else if !mismatch.renewed.is_empty() {
        println!(
            "{} copy(ies) there can't be opened with this vault's key. If the vault key was \
             renewed on another device, run `vault sync --take-new-key` with its new Secret Key.",
            mismatch.renewed.len()
        );
    }
    if !mismatch.behind.is_empty() {
        println!(
            "{} device(s) still use the vault's former key: their copies are used once they \
             take the new one.",
            mismatch.behind.len()
        );
    }
    if round.removed_here {
        state = DeviceState::load()?;
        state.set_sync_to(&id, None);
        state.save()?;
        bail!("this device was removed from the vault on another device: sync is off here");
    }
    if round.waiting_for_lock() > 0 {
        // Edits made on two devices to items behind the item lock: opened, they are folded.
        println!(
            "{} item(s) were changed on two devices and are behind the item lock.",
            round.waiting_for_lock()
        );
        session.open_secrets(prompter)?;
        round = sync::merge_all(&mut session.vault, &fetched, &mut seen);
    }
    if round.changed() || joined {
        session.save()?;
    }
    let changed = round.changed() || joined || request.remove.is_some();
    let mut published_now = published;
    if changed || session.vault.revision() > published {
        let saved = storage::read(&session.path).map_err(explain)?;
        target.put(device, &saved)?;
        published_now = session.vault.revision();
    }
    // Read again: saving the vault recorded its revision in the same file.
    let mut state = DeviceState::load()?;
    state.set_sync_to(&id, Some(to.clone()));
    state.record_sync(&id, &seen, unix_now(), published_now);
    state.save()?;

    let others = fetched.copies.len();
    let (mut added, mut updated, mut removed) = (0, 0, 0);
    for report in &round.reports {
        added += report.added;
        updated += report.updated;
        removed += report.removed;
    }
    println!(
        "Synced with {others} other device(s) in {}: {added} added, {updated} updated, \
         {removed} removed here.",
        to.describe()
    );
    if round.conflicts() > 0 {
        println!(
            "{} item(s) were changed on two devices: the newer version was kept, and the \
             other password is in the item's history.",
            round.conflicts()
        );
    }
    if round.waiting_for_lock() > 0 {
        println!(
            "{} item(s) still wait for the item lock: each device keeps its own version.",
            round.waiting_for_lock()
        );
    }
    if round.unlock_changed() {
        println!(
            "The master password, keyfile or Recovery Key was changed on another device: \
             use that one from now on."
        );
    }
    for (other, err) in round.refused {
        // Said above: copies under another vault key.
        if matches!(err, vault_core::Error::DecryptionFailed) {
            continue;
        }
        eprintln!(
            "Not used: the copy of device {}: {}",
            short(&other),
            explain(err)
        );
    }
    Ok(())
}

/// Enrolls this device on a server with a one-time invite and keeps its new key.
fn join_server(
    vault_id: &str,
    device: vault_core::sync::DeviceId,
    address: &str,
    invite: &str,
) -> Result<vault_platform::SyncTo> {
    use vault_platform::{secret_store, sync};
    let url = sync::check_address(address)?;
    let server = sync::ServerTarget::join(&url, vault_id, device, &sync::device_name(), invite)?;
    secret_store::store_sync_key(vault_id, &device.to_hex(), &server.key_seed())?;
    println!("This device joined the server at {url}.");
    Ok(vault_platform::SyncTo::Server { url })
}

fn short(device: &vault_core::sync::DeviceId) -> String {
    device.to_hex()[..8].to_owned()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
    // Only duplicates: the vault is as it was, so the file (and its .bak) stays untouched.
    if outcome.added > 0 || outcome.new_folders > 0 {
        session.save()?;
    }
    println!(
        "Imported {} item(s) ({format:?}), {} new folder(s); skipped {} duplicate(s).",
        outcome.added, outcome.new_folders, outcome.duplicates
    );

    if !format.needs_password() {
        if request.delete_source {
            wipe_file(&request.file, &source)?;
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
/// Only the export that was read: a link is refused (writing through it would zero the file it
/// points at, and deleting only the link would leave the plain-text export where it is), and so
/// is a file put in its place since it was read (in a shared or synced folder, say), which may
/// be someone else's.
fn wipe_file(path: &std::path::Path, read: &[u8]) -> Result<()> {
    use vault_platform::files;
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("{} is gone: nothing was wiped", path.display()))?;
    if files::is_link(&meta) {
        bail!(
            "{} is a link, not the export itself: nothing was wiped. Delete the file it points \
             to yourself.",
            path.display()
        );
    }
    files::wipe_if_same(path, read)
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
    parts: Option<&RecoveryParts>,
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
    if let Some(parts) = parts {
        for label in PartLabel::ALL {
            println!(
                "  Part {}:        {}",
                label.letter(),
                parts.part(label).to_display_string().as_str()
            );
        }
        println!();
        println!("  Keep each part in a different place, apart from your devices. Any two bring");
        println!("  back the Secret Key; all three let you set a new master password.");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `--delete-source` wipes the export that was read, never a file put in its place since.
    #[test]
    fn only_the_export_that_was_read_is_wiped() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join("test-export.csv");
        let read = b"name,url,username,password\nShop,https://shop.example,me,test-pw\n";
        std::fs::write(&export, read).unwrap();

        // Someone else's file, put in its place after the import read it.
        std::fs::write(&export, b"someone else's file").unwrap();
        let refused = format!("{:#}", wipe_file(&export, read).unwrap_err());
        assert!(refused.contains("nothing was wiped"), "{refused}");
        assert_eq!(std::fs::read(&export).unwrap(), b"someone else's file");

        // The export as read: wiped.
        std::fs::write(&export, read).unwrap();
        wipe_file(&export, read).unwrap();
        assert!(!export.exists());
        // Gone already: said so, not reported as wiped.
        assert!(wipe_file(&export, read).is_err());
    }

    /// A link where the export was is refused, and the message reads as one sentence.
    #[test]
    fn a_link_is_not_wiped_through() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join("test-export.csv");
        let link = dir.path().join("link.csv");
        let read = b"name,password\nShop,test-pw\n";
        std::fs::write(&export, read).unwrap();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&export, &link).is_ok();
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&export, &link).is_ok();
        if !linked {
            // Making links needs a right this account may not have (Windows without
            // developer mode).
            return;
        }
        let refused = format!("{:#}", wipe_file(&link, read).unwrap_err());
        assert!(
            refused.contains("nothing was wiped. Delete the file it points to yourself."),
            "{refused}"
        );
        assert_eq!(std::fs::read(&export).unwrap(), read);
    }

    /// `--totp -` with nothing typed (Enter to back out) changes nothing; a secret given on the
    /// command line is taken as it is, and `--totp ""` still removes one.
    #[test]
    fn nothing_typed_for_a_totp_secret_is_refused() {
        for nothing in ["", "   ", "\t"] {
            let mut prompter = Prompter::scripted(&[nothing], |_| {});
            let refused = typed_totp(&mut prompter, "-".into())
                .unwrap_err()
                .to_string();
            assert!(refused.contains("nothing was changed"), "{refused}");
        }
        let mut prompter = Prompter::scripted(&["  JBSWY3DPEHPK3PXP \t"], |_| {});
        let typed = typed_totp(&mut prompter, "-".into()).unwrap();
        assert_eq!(typed.as_str(), "JBSWY3DPEHPK3PXP");
        let mut prompter = Prompter::scripted(&[], |label| panic!("asked for {label}"));
        assert_eq!(
            typed_totp(&mut prompter, String::new()).unwrap().as_str(),
            ""
        );
        let given = typed_totp(&mut prompter, "GEZDGNBVGY3TQOJQ".into()).unwrap();
        assert_eq!(given.as_str(), "GEZDGNBVGY3TQOJQ");
    }

    const PASSWORD: &str = "unit test master passphrase";
    const NEW_PASSWORD: &str = "unit test new passphrase";

    fn context(path: &std::path::Path) -> Context {
        Context {
            path: path.to_owned(),
            allow_rollback: false,
            keyfile: None,
        }
    }

    /// A test vault with recovery parts written at `path`: its bytes, and the parts as typed.
    fn vault_with_parts(path: &std::path::Path) -> (Vec<u8>, Vec<String>) {
        let secret_key = SecretKey::generate().unwrap();
        let kdf = KdfParams::minimum().unwrap();
        let mut vault = Vault::create(PASSWORD, &secret_key, None, kdf).unwrap();
        let parts = RecoveryParts::generate().unwrap();
        vault.set_recovery_parts(&parts, &secret_key).unwrap();
        let bytes = vault.to_bytes().unwrap();
        storage::write_atomic(path, &bytes).unwrap();
        let typed = PartLabel::ALL
            .map(|label| parts.part(label).to_display_string().as_str().to_owned())
            .to_vec();
        (bytes, typed)
    }

    /// The prompts of `vault recover`: the three parts, then the new master password.
    fn recovery_answers(parts: &[String]) -> Vec<&str> {
        let mut answers: Vec<&str> = parts.iter().map(String::as_str).collect();
        answers.push(NEW_PASSWORD);
        answers
    }

    /// PM-14: a recovery whose new Secret Key this device can't keep leaves the vault as it
    /// was, so the kit just typed still opens it (and nothing opens it that was never shown).
    #[test]
    fn a_recovery_whose_secret_key_cant_be_kept_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (before, parts) = vault_with_parts(&path);
        let mut prompter = Prompter::scripted(&recovery_answers(&parts), |_| {});
        let failed = recover_with(&context(&path), &mut prompter, |_, _| {
            bail!("no credential store here")
        })
        .unwrap_err();
        let message = format!("{failed:#}");
        assert!(
            message.contains("no credential store here") && message.contains("still opens it"),
            "{message}"
        );
        assert_eq!(storage::read(&path).unwrap(), before);
    }

    /// Kept only once written, and written only over the file the kit was checked against.
    #[test]
    fn a_recovery_is_not_written_over_another_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (_, parts) = vault_with_parts(&path);
        let at = path.clone();
        let mut prompter = Prompter::scripted(&recovery_answers(&parts), move |label| {
            if label == "New master password" {
                storage::write_atomic(&at, b"saved meanwhile").unwrap();
            }
        });
        let failed = recover_with(&context(&path), &mut prompter, |_, _| {
            panic!("the Secret Key was kept, but the vault not written")
        })
        .unwrap_err();
        let message = format!("{failed:#}");
        assert!(
            message.contains("changed while this command was running"),
            "{message}"
        );
        assert_eq!(storage::read(&path).unwrap(), b"saved meanwhile");

        // Nothing in the way: the new Secret Key is kept for the file written.
        let (_, parts) = vault_with_parts(&path);
        let mut prompter = Prompter::scripted(&recovery_answers(&parts), |_| {});
        let mut kept = None;
        let recovered = recover_with(&context(&path), &mut prompter, |_, secret_key| {
            let bytes = storage::read(&path).unwrap();
            let unlock = Unlock::Password {
                password: NEW_PASSWORD,
                secret_key,
            };
            kept = Some(Vault::open(&bytes, unlock).is_ok());
            bail!("stopped here, before this device's state is noted")
        });
        assert!(recovered.is_err());
        assert_eq!(kept, Some(true), "the new key opens the file written");
    }

    /// When the vault can't be put back either, the new kit is all that opens it: the command
    /// says so (and shows it) instead of ending without it.
    #[test]
    fn a_recovery_that_cant_be_put_back_says_the_new_kit_is_needed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (_, parts) = vault_with_parts(&path);
        let mut prompter = Prompter::scripted(&recovery_answers(&parts), |_| {});
        let failed = recover_with(&context(&path), &mut prompter, |_, _| {
            storage::write_atomic(&path, b"saved meanwhile").unwrap();
            bail!("no credential store here")
        })
        .unwrap_err();
        let message = format!("{failed:#}");
        assert!(
            message.contains("only the new emergency kit above opens it now"),
            "{message}"
        );
    }

    /// `vault init` checks again right before it writes: a vault put at that place while the
    /// password was typed (by the app, or a sync client) is not written over.
    #[test]
    fn a_vault_put_in_place_during_init_is_not_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let at = path.clone();
        let mut prompter = Prompter::scripted(&[PASSWORD], move |_| {
            std::fs::write(&at, b"someone else's vault").unwrap();
        });
        let refused = init_with(
            &context(&path),
            &mut prompter,
            true,
            50,
            64,
            None,
            |_, _| panic!("a Secret Key kept for a vault not written"),
        )
        .unwrap_err();
        assert!(refused.to_string().contains("already exists"), "{refused}");
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's vault");
        assert!(!storage::backup_path(&path).exists());
    }

    /// Once the new vault is written, only its kit opens it: a Secret Key this device can't
    /// keep comes after the kit is shown, and the file stays.
    #[test]
    fn an_init_whose_secret_key_cant_be_kept_keeps_the_vault_and_its_kit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let mut prompter = Prompter::scripted(&[PASSWORD], |_| {});
        let mut made = None;
        let failed = init_with(
            &context(&path),
            &mut prompter,
            true,
            50,
            64,
            None,
            |_, secret_key| {
                made = Some(secret_key.to_display_string().as_str().to_owned());
                bail!("no credential store here")
            },
        )
        .unwrap_err();
        let message = format!("{failed:#}");
        assert!(
            message.contains("no credential store here") && message.contains("kit above"),
            "{message}"
        );
        let secret_key = SecretKey::parse(&made.unwrap()).unwrap();
        let bytes = storage::read(&path).unwrap();
        let unlock = Unlock::Password {
            password: PASSWORD,
            secret_key: &secret_key,
        };
        assert!(Vault::open(&bytes, unlock).is_ok());
    }
}
