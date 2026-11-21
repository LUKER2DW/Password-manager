//! Implementation of each subcommand.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, bail};
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
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;
    session::store_secret_key(&vault.id_hex(), &secret_key)?;
    session::record_new_vault(&vault)?;

    eprintln!(
        "Vault created: {} ({})",
        ctx.path.display(),
        describe_kdf(vault.kdf_params())
    );
    print_kit(&vault.id_hex(), &ctx.path, &secret_key, parts.as_ref());
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
    session::ensure_unchanged(&ctx.path, &storage::fingerprint(&bytes))?;
    let bytes = vault.to_bytes().map_err(explain)?;
    storage::write_atomic(&ctx.path, &bytes).map_err(explain)?;
    session::store_secret_key(&vault.id_hex(), &secret_key)?;
    session::record_new_vault(&vault)?;

    println!(
        "New master password and Secret Key set. Your {} still work{}.",
        if info.has_recovery_key {
            "Recovery Key"
        } else {
            "recovery parts"
        },
        if info.has_recovery_key { "s" } else { "" }
    );
    if had_keyfile {
        let _ = vault_platform::keyfile::remember_path(&vault.id_hex(), None);
        println!("The keyfile is no longer needed; add one again with `vault keyfile create`.");
    }
    print_kit(&vault.id_hex(), &ctx.path, &secret_key, None);
    Ok(())
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
}

pub fn sync(ctx: &Context, prompter: &mut Prompter, request: SyncRequest) -> Result<()> {
    use vault_platform::{
        DeviceState, SyncTo, secret_store,
        sync::{self, ServerTarget},
    };

    let bytes = session::read_vault_file(&ctx.path)?;
    let id = Vault::inspect(&bytes).map_err(explain)?.id_hex;
    let mut state = DeviceState::load()?;
    let device = state.device_id().map_err(explain)?;
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
        if link.vault != id {
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
        let url = sync::check_address(&address)?;
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
/// A link is refused: writing through it would zero the file it points at, and deleting only
/// the link would leave the plain-text export where it is.
fn wipe_file(path: &std::path::Path) -> Result<()> {
    use vault_platform::files;
    let meta = std::fs::symlink_metadata(path)?;
    if files::is_link(&meta) {
        bail!(
            "{} is a link, not the export itself: nothing was wiped. Delete the file it points \
             to yourself.",
            path.display()
        );
    }
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        files::overwrite_with_zeros(&mut file, meta.len())?;
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
