//! Filling from the browser while the vault is locked (see `vault_core::locked_fill` for the
//! keys and `vault_browser::locked` for what may be answered).
//!
//! Kept next to the app's other files, one per vault, as `browser-locked-v2-<vault id>.bin`:
//! - the passwords of logins outside the item lock, encrypted under a key wrapped for Windows
//!   Hello and sealed with the vault key (the vault key reads those logins anyway);
//! - the passwords of logins behind the item lock, each sealed to a key pair whose private
//!   half is wrapped for Windows Hello only: the vault key alone never reads them, and the
//!   open app adds them with the public half, asking nothing;
//! - each login's name, username and websites, protected for the Windows user (DPAPI) so the
//!   locked app can list them, with the stamp of the version of the login they were taken
//!   from (`Vault::item_stamp`). A locked login's password is kept only for that version:
//!   changed meanwhile (on another device, say), it is not filled until the item lock opens
//!   here again, never with the old password on the new website.
//!
//! It exists only while Settings → Browser extension → "Fill with Windows Hello while the vault
//! is locked" is on and the item lock opens with Windows Hello. Making it asks Windows Hello
//! once; keeping it current (after each save, unlock or opening of the item lock) asks nothing.
//! The file of earlier versions (`browser-locked-<vault id>.bin`, whose vault-key copy opened
//! every password) is deleted with its backup wherever this one is read or written.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vault_browser::locked::{LockedGate, LockedLogin};
use vault_core::{
    ItemKind, Vault,
    locked_fill::{
        GUARDED_PUBLIC_KEY_LEN, GuardedFillKey, LockedFillKey, LockedPasswords, seal_guarded,
    },
    storage,
};
use vault_platform::{dpapi, paths, quick_unlock};
use zeroize::Zeroizing;

use super::{Controller, JobResult, Runner, error, notice};

const PURPOSE: &str = "browser-locked-fill";
/// The public half of the locked logins' key, sealed with the vault key so it can't be
/// swapped for another while the vault is open.
const PUBLIC_PURPOSE: &str = "browser-locked-fill-public";

#[derive(Serialize, Deserialize)]
pub(super) struct IndexFile {
    key_by_device: Vec<u8>,
    key_by_vault: Vec<u8>,
    /// The passwords of logins outside the item lock.
    passwords: Vec<u8>,
    /// The private half of the locked logins' key, wrapped for Windows Hello only.
    guarded_key_by_device: Vec<u8>,
    /// Its public half, sealed with the vault key.
    guarded_public_by_vault: Vec<u8>,
    /// The passwords of logins behind the item lock, one by one.
    guarded: Vec<GuardedEntry>,
    /// DPAPI-protected postcard of `Vec<StoredLogin>`.
    logins: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct GuardedEntry {
    id: String,
    stamp: [u8; 32],
    sealed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredLogin {
    id: String,
    title: String,
    username: String,
    urls: Vec<String>,
    fillable: bool,
    /// The version of the login this was taken from (`Vault::item_stamp`).
    stamp: [u8; 32],
}

fn index_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-locked-v2-{vault_id}.bin")),
    )
}

/// The file of earlier versions: its passwords opened with the vault key alone.
fn legacy_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-locked-{vault_id}.bin")),
    )
}

fn remove_with_backup(path: Option<PathBuf>) {
    if let Some(path) = path {
        let _ = std::fs::remove_file(storage::backup_path(&path));
        let _ = std::fs::remove_file(path);
    }
}

pub(super) fn read_index(vault_id: &str) -> Option<IndexFile> {
    remove_with_backup(legacy_path(vault_id));
    let bytes = std::fs::read(index_path(vault_id)?).ok()?;
    postcard::from_bytes(&bytes).ok()
}

/// Removes the file of an earlier version, if there is one: whether there was.
fn remove_legacy(vault_id: &str) -> bool {
    let Some(path) = legacy_path(vault_id) else {
        return false;
    };
    let found = path.exists() || storage::backup_path(&path).exists();
    remove_with_backup(Some(path));
    found
}

/// Whether this vault has an index to fill from while locked (of this version).
fn has_index(vault_id: &str) -> bool {
    index_path(vault_id).is_some_and(|path| path.exists())
}

/// After a renewal of the vault key: the index's copies of its keys for the vault sealed
/// again under the new key (those for Windows Hello stay as they are).
pub(super) fn reseal(vault: &Vault, former: &vault_core::FormerKey) {
    let id = vault.id_hex();
    let Some(mut file) = read_index(&id) else {
        return;
    };
    let (Ok(key), Ok(public)) = (
        vault.reseal_local(former, PURPOSE, &file.key_by_vault),
        vault.reseal_local(former, PUBLIC_PURPOSE, &file.guarded_public_by_vault),
    ) else {
        return;
    };
    file.key_by_vault = key;
    file.guarded_public_by_vault = public;
    let Some(path) = index_path(&id) else {
        return;
    };
    if let Ok(bytes) = postcard::to_allocvec(&file)
        && storage::write_atomic(&path, &bytes).is_ok()
    {
        let _ = std::fs::remove_file(storage::backup_path(&path));
    }
}

pub(super) fn remove_index(vault_id: &str) {
    remove_with_backup(legacy_path(vault_id));
    remove_with_backup(index_path(vault_id));
}

/// The keys of an index: the blob key and the locked logins' public half (and their copies
/// for Windows Hello, which the open app can't make and keeps as they are).
pub(super) struct IndexKeys {
    pub(super) key: LockedFillKey,
    pub(super) key_by_device: Vec<u8>,
    pub(super) guarded_public: [u8; GUARDED_PUBLIC_KEY_LEN],
    pub(super) guarded_key_by_device: Vec<u8>,
}

/// Writes the index from an open vault. The passwords readable now are taken. For a login
/// whose secrets are behind the closed item lock, the one kept before stays, but only while
/// the login is the version it was kept for.
pub(super) fn build(vault: &Vault, keys: &IndexKeys, previous: &[GuardedEntry]) -> Option<()> {
    let file = make(vault, keys, previous)?;
    let id = vault.id_hex();
    let path = index_path(&id)?;
    std::fs::create_dir_all(path.parent()?).ok()?;
    remove_with_backup(legacy_path(&id));
    storage::write_atomic(&path, &postcard::to_allocvec(&file).ok()?).ok()
}

/// The index of an open vault (see [`build`]), not written yet.
fn make(vault: &Vault, keys: &IndexKeys, previous: &[GuardedEntry]) -> Option<IndexFile> {
    let id = vault.id_hex();
    let guard_encrypts = vault.item_guard().encrypts();
    let mut passwords = LockedPasswords::default();
    let mut guarded = Vec::new();
    let mut logins = Vec::new();
    for item_id in vault.item_ids() {
        let Ok(item) = vault.get_item(&item_id) else {
            continue;
        };
        if item.kind != ItemKind::Login {
            continue;
        }
        let Some(stamp) = vault.item_stamp(&item_id) else {
            continue;
        };
        let hex = item_id.to_hex();
        let fillable = if guard_encrypts && vault.guards(&item) {
            // Behind the item lock: sealed to the public half, or kept as it was for this
            // very version of the login.
            let entry = if item.is_locked() {
                previous
                    .iter()
                    .find(|kept| kept.id == hex && kept.stamp == stamp)
                    .cloned()
            } else if item.password.is_empty() {
                None
            } else {
                Some(GuardedEntry {
                    id: hex.clone(),
                    stamp,
                    sealed: seal_guarded(&keys.guarded_public, &id, &hex, &stamp, &item.password)
                        .ok()?,
                })
            };
            let fillable = entry.is_some();
            guarded.extend(entry);
            fillable
        } else {
            passwords.set(&hex, &item.password);
            !item.password.is_empty()
        };
        logins.push(StoredLogin {
            id: hex,
            title: item.title.clone(),
            username: item.username.clone(),
            urls: item.urls.clone(),
            fillable,
            stamp,
        });
    }
    Some(IndexFile {
        key_by_device: keys.key_by_device.clone(),
        key_by_vault: vault.seal_local(PURPOSE, keys.key.as_bytes()).ok()?,
        passwords: keys.key.seal_passwords(&id, &passwords).ok()?,
        guarded_key_by_device: keys.guarded_key_by_device.clone(),
        guarded_public_by_vault: vault
            .seal_local(PUBLIC_PURPOSE, &keys.guarded_public)
            .ok()?,
        guarded,
        logins: dpapi::protect(&postcard::to_allocvec(&logins).ok()?)?,
    })
}

/// Makes the index anew for an open vault whose item lock key is open, with the secret
/// Windows Hello just produced (when the item lock is saved with Windows Hello).
pub(super) fn create(vault: &Vault, device_secret: &[u8]) -> Option<()> {
    let id = vault.id_hex();
    let key = LockedFillKey::generate().ok()?;
    let guarded = GuardedFillKey::generate().ok()?;
    let keys = IndexKeys {
        key_by_device: key.wrap_for_device(device_secret, &id).ok()?,
        guarded_public: guarded.public_key(),
        guarded_key_by_device: guarded.wrap_for_device(device_secret, &id).ok()?,
        key,
    };
    build(vault, &keys, &[])
}

/// The keys and the locked logins' kept passwords of an index, opened with the open vault
/// (nothing is asked). `None` when the file is not this vault's.
fn open_index(vault: &Vault, file: IndexFile) -> Option<(IndexKeys, Vec<GuardedEntry>)> {
    let key = vault
        .open_local(PURPOSE, &file.key_by_vault)
        .ok()
        .and_then(|raw| LockedFillKey::from_bytes(&raw).ok())?;
    let guarded_public: [u8; GUARDED_PUBLIC_KEY_LEN] = vault
        .open_local(PUBLIC_PURPOSE, &file.guarded_public_by_vault)
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    Some((
        IndexKeys {
            key,
            key_by_device: file.key_by_device,
            guarded_public,
            guarded_key_by_device: file.guarded_key_by_device,
        },
        file.guarded,
    ))
}

/// The logins the locked app may list.
pub(super) fn logins(file: &IndexFile) -> Vec<LockedLogin> {
    stored_logins(file)
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

fn stored_logins(file: &IndexFile) -> Vec<StoredLogin> {
    dpapi::unprotect(&file.logins)
        .and_then(|plain| postcard::from_bytes::<Vec<StoredLogin>>(&plain).ok())
        .unwrap_or_default()
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
        // A login behind the item lock: its own entry, for the version listed.
        if let Some(entry) = self.file.guarded.iter().find(|entry| entry.id == id) {
            let listed = stored_logins(self.file)
                .into_iter()
                .find(|login| login.id == id)?;
            if listed.stamp != entry.stamp {
                return None;
            }
            let key = GuardedFillKey::unwrap_for_device(
                &device,
                &self.vault_id,
                &self.file.guarded_key_by_device,
            )
            .ok()?;
            return key
                .open_guarded(&self.vault_id, id, &entry.stamp, &entry.sealed)
                .ok();
        }
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

    /// Whether filling while locked is wanted but has no index yet: the next answer of
    /// Windows Hello for the item lock (in the app or for the extension) makes it.
    pub(super) fn locked_fill_missing(&self, vault_id: &str) -> bool {
        self.locked_fill_wanted(vault_id) && !has_index(vault_id)
    }

    /// Keeps the index current after a save, an unlock or the item lock opened. Asks nothing:
    /// the key comes from its copy sealed with the vault key.
    ///
    /// The file of an earlier version is removed (its copy for the vault key opened every
    /// password); the index that replaces it needs Windows Hello once, so the person is told,
    /// once, that filling while locked waits for that.
    pub(super) fn refresh_locked_fill(&self) {
        let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        let legacy = remove_legacy(&id);
        if !self.locked_fill_wanted(&id) {
            remove_index(&id);
            return;
        }
        // Made with Windows Hello, in Settings or when the item lock was saved or opened.
        let Some(file) = read_index(&id) else {
            if legacy {
                self.notify_long(notice::LOCKED_FILL_AGAIN, "");
            }
            return;
        };
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return;
        };
        let Some((keys, previous)) = open_index(&session.vault, file) else {
            return;
        };
        let _ = build(&session.vault, &keys, &previous);
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

#[cfg(test)]
mod tests {
    use vault_browser::locked::LockedGate;
    use vault_core::{
        GuardCheck, ItemData, KdfParams, SecretKey, Vault, locked_fill::LockedFillKey,
    };
    use zeroize::Zeroizing;

    use super::{GuardedFillKey, HelloGate, IndexKeys, PURPOSE, logins, make, open_index};

    const DEVICE: [u8; 32] = [9; 32];

    fn keys(vault: &Vault) -> IndexKeys {
        let id = vault.id_hex();
        let key = LockedFillKey::generate().unwrap();
        let guarded = GuardedFillKey::generate().unwrap();
        IndexKeys {
            key_by_device: key.wrap_for_device(&DEVICE, &id).unwrap(),
            guarded_public: guarded.public_key(),
            guarded_key_by_device: guarded.wrap_for_device(&DEVICE, &id).unwrap(),
            key,
        }
    }

    fn fill(file: &super::IndexFile, vault_id: &str, id: &str) -> Option<String> {
        let mut gate = HelloGate {
            file,
            vault_id: vault_id.to_owned(),
            device: Some(Zeroizing::new(DEVICE.to_vec())),
        };
        gate.password(id)
            .map(|password| password.as_str().to_owned())
    }

    /// A vault with a PIN lock on one login only, and a login outside it.
    fn vault() -> (Vault, String, String) {
        let mut vault = Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let mut locked = ItemData::login("Bank", "me", "bank-secret", "https://bank.example");
        locked.reprompt = true;
        let locked = vault.add_item(&locked).unwrap();
        let open = vault
            .add_item(&ItemData::login(
                "Forum",
                "me",
                "forum-pw",
                "https://forum.example",
            ))
            .unwrap();
        vault
            .set_item_guard(false, GuardCheck::Pin, Some("4821"), Some("pw"))
            .unwrap();
        (vault, locked.to_hex(), open.to_hex())
    }

    #[test]
    fn the_vault_key_alone_never_opens_a_locked_logins_password() {
        let (mut vault, locked, open) = vault();
        let id = vault.id_hex();
        let keys = keys(&vault);
        let file = make(&vault, &keys, &[]).unwrap();
        vault.lock_secrets();
        // Windows Hello opens both, as before.
        assert_eq!(fill(&file, &id, &locked).as_deref(), Some("bank-secret"));
        assert_eq!(fill(&file, &id, &open).as_deref(), Some("forum-pw"));
        // What the vault key opens (the blob key) holds the password outside the lock only.
        let blob = vault
            .open_local(PURPOSE, &file.key_by_vault)
            .map(|raw| LockedFillKey::from_bytes(&raw).unwrap())
            .unwrap();
        let readable = blob.open_passwords(&id, &file.passwords).unwrap();
        assert_eq!(readable.get(&open), Some("forum-pw"));
        assert_eq!(readable.get(&locked), None, "behind the item lock");
        assert_eq!(readable.len(), 1);
        // And the locked one's entry needs the private half, kept for Windows Hello only.
        assert!(
            GuardedFillKey::unwrap_for_device(&[1; 32], &id, &file.guarded_key_by_device).is_err()
        );
    }

    #[test]
    fn a_kept_password_never_follows_its_login_to_another_website() {
        let (mut vault, locked, _) = vault();
        let id = vault.id_hex();
        let keys = keys(&vault);
        let file = make(&vault, &keys, &[]).unwrap();
        // The lock closed; kept passwords stay while the login is the same.
        vault.lock_secrets();
        let (keys, previous) = open_index(&vault, file).unwrap();
        let file = make(&vault, &keys, &previous).unwrap();
        assert_eq!(fill(&file, &id, &locked).as_deref(), Some("bank-secret"));
        // The login moves to another website (as a sync from another device would bring it),
        // with the lock still closed here: its old password is not kept for the new site.
        let item_id = vault.item_ids().find(|i| i.to_hex() == locked).unwrap();
        let mut moved = vault.get_item(&item_id).unwrap();
        assert!(moved.is_locked());
        moved.urls = vec!["https://elsewhere.example".into()];
        moved.touch();
        assert!(vault.unlock_secrets("4821").unwrap());
        let mut full = vault.get_item(&item_id).unwrap();
        full.urls = moved.urls.clone();
        full.password = "new-bank-secret".into();
        full.touch();
        vault.update_item(&item_id, &full).unwrap();
        vault.lock_secrets();
        let (keys, previous) = open_index(&vault, file).unwrap();
        let file = make(&vault, &keys, &previous).unwrap();
        let listed = logins(&file);
        let entry = listed.iter().find(|login| login.id == locked).unwrap();
        assert_eq!(entry.urls, ["https://elsewhere.example"]);
        assert!(
            !entry.fillable,
            "not fillable until the item lock opens here"
        );
        assert_eq!(fill(&file, &id, &locked), None);
        // Opened again: the new password, for the new website.
        assert!(vault.unlock_secrets("4821").unwrap());
        let (keys, previous) = open_index(&vault, file).unwrap();
        let file = make(&vault, &keys, &previous).unwrap();
        assert!(
            logins(&file)
                .iter()
                .any(|login| login.id == locked && login.fillable)
        );
        assert_eq!(
            fill(&file, &id, &locked).as_deref(),
            Some("new-bank-secret")
        );
    }
}
