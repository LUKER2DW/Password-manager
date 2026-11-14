//! Filling from the browser while the vault is locked (see `vault_core::locked_fill` for the
//! keys and `vault_browser::locked` for what may be answered).
//!
//! Kept next to the app's other files, one per vault, as `browser-locked-<vault id>.bin`:
//! - the blob's key, wrapped for Windows Hello and sealed with the vault key;
//! - the passwords, encrypted under that key;
//! - each login's name, username and websites, protected for the Windows user (DPAPI) so the
//!   locked app can list them.
//!
//! It exists only while Settings → Browser extension → "Fill with Windows Hello while the vault
//! is locked" is on and the item lock opens with Windows Hello. Making it asks Windows Hello
//! once; keeping it current (after each save, unlock or opening of the item lock) asks nothing.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vault_browser::locked::{LockedGate, LockedLogin};
use vault_core::{
    ItemKind, Vault,
    locked_fill::{LockedFillKey, LockedPasswords},
    storage,
};
use vault_platform::{dpapi, paths, quick_unlock};
use zeroize::Zeroizing;

use super::{Controller, JobResult, Runner, error, notice};

const PURPOSE: &str = "browser-locked-fill";

#[derive(Serialize, Deserialize)]
pub(super) struct IndexFile {
    key_by_device: Vec<u8>,
    key_by_vault: Vec<u8>,
    passwords: Vec<u8>,
    /// DPAPI-protected postcard of `Vec<StoredLogin>`.
    logins: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredLogin {
    id: String,
    title: String,
    username: String,
    urls: Vec<String>,
    fillable: bool,
}

fn index_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-locked-{vault_id}.bin")),
    )
}

pub(super) fn read_index(vault_id: &str) -> Option<IndexFile> {
    let bytes = std::fs::read(index_path(vault_id)?).ok()?;
    postcard::from_bytes(&bytes).ok()
}

pub(super) fn remove_index(vault_id: &str) {
    if let Some(path) = index_path(vault_id) {
        let _ = std::fs::remove_file(storage::backup_path(&path));
        let _ = std::fs::remove_file(path);
    }
}

/// Writes the index from an open vault. The passwords readable now are taken; for a login
/// whose secrets are behind the closed item lock, the one kept before stays.
pub(super) fn build(
    vault: &Vault,
    key: &LockedFillKey,
    key_by_device: Vec<u8>,
    previous: Option<&LockedPasswords>,
) -> Option<()> {
    let id = vault.id_hex();
    let mut passwords = LockedPasswords::default();
    let mut logins = Vec::new();
    for item_id in vault.item_ids() {
        let Ok(item) = vault.get_item(&item_id) else {
            continue;
        };
        if item.kind != ItemKind::Login {
            continue;
        }
        let hex = item_id.to_hex();
        let password = Zeroizing::new(if item.is_locked() {
            previous
                .and_then(|kept| kept.get(&hex))
                .unwrap_or_default()
                .to_owned()
        } else {
            item.password.clone()
        });
        passwords.set(&hex, &password);
        logins.push(StoredLogin {
            id: hex,
            title: item.title.clone(),
            username: item.username.clone(),
            urls: item.urls.clone(),
            fillable: !password.is_empty(),
        });
    }
    let file = IndexFile {
        key_by_device,
        key_by_vault: vault.seal_local(PURPOSE, key.as_bytes()).ok()?,
        passwords: key.seal_passwords(&id, &passwords).ok()?,
        logins: dpapi::protect(&postcard::to_allocvec(&logins).ok()?)?,
    };
    let path = index_path(&id)?;
    std::fs::create_dir_all(path.parent()?).ok()?;
    storage::write_atomic(&path, &postcard::to_allocvec(&file).ok()?).ok()
}

/// Makes the index anew for an open vault whose item lock key is open, with the secret
/// Windows Hello just produced (when the item lock is saved with Windows Hello).
pub(super) fn create(vault: &Vault, device_secret: &[u8]) -> Option<()> {
    let key = LockedFillKey::generate().ok()?;
    let key_by_device = key.wrap_for_device(device_secret, &vault.id_hex()).ok()?;
    build(vault, &key, key_by_device, None)
}

/// The logins the locked app may list.
pub(super) fn logins(file: &IndexFile) -> Vec<LockedLogin> {
    dpapi::unprotect(&file.logins)
        .and_then(|plain| postcard::from_bytes::<Vec<StoredLogin>>(&plain).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|login| LockedLogin {
            id: login.id,
            title: login.title,
            username: login.username,
            urls: login.urls,
            fillable: login.fillable,
        })
        .collect()
}

/// Opens one kept password with what Windows Hello produced for this request.
pub(super) struct HelloGate<'a> {
    pub(super) file: &'a IndexFile,
    pub(super) vault_id: String,
    pub(super) device: Option<Zeroizing<Vec<u8>>>,
}

impl LockedGate for HelloGate<'_> {
    fn password(&mut self, id: &str) -> Option<Zeroizing<String>> {
        let device = self.device.take()?;
        let key =
            LockedFillKey::unwrap_for_device(&device, &self.vault_id, &self.file.key_by_device)
                .ok()?;
        let passwords = key
            .open_passwords(&self.vault_id, &self.file.passwords)
            .ok()?;
        passwords
            .get(id)
            .map(|password| Zeroizing::new(password.to_owned()))
    }
}

impl Controller {
    /// Whether filling while locked is wanted and possible for this vault.
    fn locked_fill_wanted(&self, vault_id: &str) -> bool {
        let settings = &self.state.borrow().settings;
        settings.browser_extension
            && settings.browser_locked_fill
            && quick_unlock::item_lock_enrolled(vault_id)
    }

    /// Keeps the index current after a save, an unlock or the item lock opened. Asks nothing:
    /// the key comes from its copy sealed with the vault key.
    pub(super) fn refresh_locked_fill(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        if !self.locked_fill_wanted(&id) {
            remove_index(&id);
            return;
        }
        // Made with Windows Hello, in Settings or when the item lock was saved.
        let Some(file) = read_index(&id) else {
            return;
        };
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return;
        };
        let Some(key) = session
            .vault
            .open_local(PURPOSE, &file.key_by_vault)
            .ok()
            .and_then(|raw| LockedFillKey::from_bytes(&raw).ok())
        else {
            return;
        };
        let previous = key.open_passwords(&id, &file.passwords).ok();
        let _ = build(&session.vault, &key, file.key_by_device, previous.as_ref());
    }

    /// Settings: turned on. Windows Hello is asked once, off the UI thread, to wrap the key.
    pub(super) fn enable_locked_fill(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        if !self.locked_fill_wanted(&id) {
            if !quick_unlock::item_lock_enrolled(&id) {
                self.set_error(error::LOCKED_FILL_NEEDS_HELLO, "");
            }
            return;
        }
        let Some(verifier) = self.state.borrow().verifier.clone() else {
            return;
        };
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        self.run_job(move || {
            let mut session = session;
            let made = verifier
                .secret(&quick_unlock::item_lock_key_id(&id))
                .ok()
                .and_then(|secret| {
                    // The same Windows Hello answer opens the item lock for a moment, so the
                    // passwords of locked logins are kept too; then it is closed again.
                    let was_open = session.vault.secrets_open();
                    if !was_open && let Some(sealed) = quick_unlock::item_lock_load(&id) {
                        let _ = session.vault.unlock_secrets_with_device(&secret, &sealed);
                    }
                    let made = create(&session.vault, &secret);
                    if !was_open {
                        session.vault.lock_secrets();
                    }
                    made
                });
            JobResult::Returned {
                session,
                notice: if made.is_some() {
                    notice::LOCKED_FILL_ON
                } else {
                    0
                },
            }
        });
    }
}
