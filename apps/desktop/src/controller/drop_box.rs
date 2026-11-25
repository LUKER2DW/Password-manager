//! Logins saved from the browser while the vault is locked (see `vault_core::drop_box` for
//! the keys and `vault_browser::locked::answer_locked_save` for what is accepted).
//!
//! One file per vault next to the app's other files, `browser-drop-<vault id>.bin`: the drop
//! box's public key, its private key sealed with the vault key, and the logins sealed to the
//! public key since the last unlock. The locked app only appends; the next unlock opens the
//! entries, adds them as items and empties the list.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vault_browser::{
    locked::QueuedLogin,
    origin::{Origin, item_matches},
};
use vault_core::{
    ItemData, ItemKind, Vault,
    drop_box::{self, DropBoxKey, PUBLIC_KEY_LEN},
    storage,
};
use vault_platform::paths;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{Controller, notice};

/// Entries kept at most while locked; later saves are refused as locked.
const MAX_ENTRIES: usize = 200;

#[derive(Serialize, Deserialize)]
struct DropFile {
    public_key: [u8; PUBLIC_KEY_LEN],
    sealed_key: Vec<u8>,
    entries: Vec<Vec<u8>>,
}

/// One login, as sealed in an entry.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Dropped {
    url: String,
    title: String,
    username: String,
    password: String,
}

fn path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-drop-{vault_id}.bin")),
    )
}

fn read(vault_id: &str) -> Option<DropFile> {
    let bytes = std::fs::read(path(vault_id)?).ok()?;
    postcard::from_bytes(&bytes).ok()
}

fn write(vault_id: &str, file: &DropFile) -> Option<()> {
    let path = path(vault_id)?;
    std::fs::create_dir_all(path.parent()?).ok()?;
    let bytes = postcard::to_allocvec(file).ok()?;
    storage::write_atomic(&path, &bytes).ok()
}

pub(super) fn remove(vault_id: &str) {
    if let Some(path) = path(vault_id) {
        let _ = std::fs::remove_file(storage::backup_path(&path));
        let _ = std::fs::remove_file(path);
    }
}

/// Seals a login saved while vault `vault_id` is locked and keeps it for the next unlock.
/// `false` when there is no drop box for that vault (it is made at an unlock with the browser
/// extension on) or it is full.
pub(super) fn keep(vault_id: &str, login: QueuedLogin) -> bool {
    let Some(mut file) = read(vault_id) else {
        return false;
    };
    if file.entries.len() >= MAX_ENTRIES {
        return false;
    }
    let dropped = Dropped {
        url: login.url,
        title: login.title,
        username: login.username,
        password: login.password.as_str().to_owned(),
    };
    let Ok(plain) = postcard::to_allocvec(&dropped).map(Zeroizing::new) else {
        return false;
    };
    let Ok(entry) = drop_box::seal_entry(&file.public_key, vault_id, &plain) else {
        return false;
    };
    file.entries.push(entry);
    write(vault_id, &file).is_some()
}

impl Controller {
    /// At unlock, and again when the item lock opens: stores the logins the browser saved
    /// while the vault was locked, and makes the drop box when the browser extension is on
    /// and there is none yet.
    ///
    /// The browser was told each of them is kept, so none is dropped unread: the drop file
    /// keeps every entry that is not in the saved vault yet (one whose login is behind the
    /// closed item lock, or one this copy can't read), and loses only those stored now or
    /// already there with the same password.
    pub(super) fn open_drop_box(&self) {
        let wanted = self.state.borrow().settings.browser_extension;
        // The drop file is emptied only once its logins are safe in the saved vault: emptied
        // before a save that then fails, they would live only in memory.
        let mut left: Option<DropFile> = None;
        let id;
        let outcome = {
            let mut state = self.state.borrow_mut();
            let lock_open = state.secrets_open;
            let Some(session) = state.session.as_mut() else {
                return;
            };
            let vault = &mut session.vault;
            id = vault.id_hex();
            match read(&id) {
                Some(file) => match DropBoxKey::open_with(vault, &file.sealed_key) {
                    Ok(key) => {
                        let outcome = add_entries(vault, &key, &file.entries, lock_open);
                        if outcome.kept.len() != file.entries.len() {
                            left = Some(DropFile {
                                entries: outcome.kept.clone(),
                                ..file
                            });
                        }
                        outcome
                    }
                    // Another vault's key under this id, or a damaged file: start over.
                    Err(_) => {
                        remove(&id);
                        if wanted {
                            create(vault);
                        }
                        Added::default()
                    }
                },
                None => {
                    if wanted {
                        create(vault);
                    }
                    Added::default()
                }
            }
        };
        if outcome.stored > 0 {
            self.state.borrow_mut().summaries_stale = true;
            if !self.save_vault() {
                // Kept in the drop file: the next unlock stores them again (what is there by
                // then with the same password is skipped, so nothing is doubled).
                return;
            }
            self.refresh_list();
            self.notify_long(notice::BROWSER_DROPPED, &outcome.stored.to_string());
        }
        if let Some(left) = left {
            let _ = write(&id, &left);
        }
        if outcome.behind_lock > 0 {
            self.notify_long(
                notice::BROWSER_DROPPED_WAITING,
                &outcome.behind_lock.to_string(),
            );
        }
    }
}

/// What the drop box's entries became.
#[derive(Default)]
struct Added {
    /// Logins added, or updated with a new password (the old one in their history).
    stored: usize,
    /// Entries for a login behind the closed item lock: they wait for it to open.
    behind_lock: usize,
    /// The entries to keep in the drop file: every one not in the vault now.
    kept: Vec<Vec<u8>>,
}

fn create(vault: &Vault) {
    let Ok(key) = DropBoxKey::generate() else {
        return;
    };
    let Ok(sealed_key) = key.seal_with(vault) else {
        return;
    };
    let file = DropFile {
        public_key: key.public_key(),
        sealed_key,
        entries: Vec::new(),
    };
    let _ = write(&vault.id_hex(), &file);
}

/// What one entry became.
enum Entry {
    /// Added as a login, or a login's new password (the old one in its history).
    Stored,
    /// The vault has it already: a login for that site and username with that password.
    Same,
    /// A login for that site and username is behind the closed item lock: whether its
    /// password is this one is known once the lock opens.
    BehindLock,
    /// Not readable or not storable here.
    Unread,
}

/// Stores each entry: a login of its own, or the new password of the login for that site and
/// username (the old one goes into its history). Nothing a person saved is lost by being
/// "already known": only the very same password is. A login behind the item lock changes
/// only while the lock is open here (`lock_open`), as when the browser changes it.
fn add_entries(vault: &mut Vault, key: &DropBoxKey, entries: &[Vec<u8>], lock_open: bool) -> Added {
    let mut added = Added::default();
    for entry in entries {
        match add_entry(vault, key, entry, lock_open) {
            Entry::Stored => added.stored += 1,
            Entry::Same => {}
            Entry::BehindLock => {
                added.behind_lock += 1;
                added.kept.push(entry.clone());
            }
            Entry::Unread => added.kept.push(entry.clone()),
        }
    }
    added
}

fn add_entry(vault: &mut Vault, key: &DropBoxKey, entry: &[u8], lock_open: bool) -> Entry {
    let Ok(plain) = key.open_entry(vault, entry) else {
        return Entry::Unread;
    };
    let Ok(dropped) = postcard::from_bytes::<Dropped>(&plain) else {
        return Entry::Unread;
    };
    let Ok(origin) = Origin::of_page(&dropped.url) else {
        return Entry::Unread;
    };
    let matching: Vec<(vault_core::ItemId, ItemData)> = vault
        .item_ids()
        .filter_map(|id| Some((id, vault.get_item(&id).ok()?)))
        .filter(|(_, item)| {
            item.kind == ItemKind::Login
                && item.username == dropped.username
                && item_matches(&item.urls, &origin)
        })
        .collect();
    if matching
        .iter()
        .any(|(_, item)| !item.is_locked() && item.password == dropped.password)
    {
        return Entry::Same;
    }
    // A login for it takes the new password; one behind the closed item lock might already
    // have it (and changes only with the lock open), so the entry waits for the lock rather
    // than add a second login.
    let may_change = |item: &ItemData| !item.is_locked() && (lock_open || !vault.guards(item));
    if let Some((id, item)) = matching.iter().find(|(_, item)| may_change(item)) {
        let mut item = item.clone();
        item.password.clone_from(&dropped.password);
        item.touch();
        return match vault.update_item(id, &item) {
            Ok(()) => Entry::Stored,
            Err(vault_core::Error::SecretsLocked) => Entry::BehindLock,
            Err(_) => Entry::Unread,
        };
    }
    if !matching.is_empty() {
        return Entry::BehindLock;
    }
    let item = ItemData::login(
        &dropped.title,
        &dropped.username,
        &dropped.password,
        &dropped.url,
    );
    match vault.add_item(&item) {
        Ok(_) => Entry::Stored,
        Err(_) => Entry::Unread,
    }
}

#[cfg(test)]
mod tests {
    use vault_core::{GuardCheck, KdfParams, SecretKey};

    use super::*;

    fn vault() -> Vault {
        Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap()
    }

    fn seal(key: &DropBoxKey, vault: &Vault, url: &str, username: &str, password: &str) -> Vec<u8> {
        let dropped = Dropped {
            url: url.into(),
            title: "Shop".into(),
            username: username.into(),
            password: password.into(),
        };
        drop_box::seal_entry(
            &key.public_key(),
            &vault.id_hex(),
            &postcard::to_allocvec(&dropped).unwrap(),
        )
        .unwrap()
    }

    fn find(vault: &Vault, title: &str) -> ItemData {
        vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|item| item.title == title)
            .unwrap()
    }

    #[test]
    fn dropped_logins_join_the_vault_once() {
        let mut vault = vault();
        vault
            .add_item(&ItemData::login(
                "GitHub",
                "octocat",
                "new-secret",
                "https://github.com",
            ))
            .unwrap();
        let key = DropBoxKey::generate().unwrap();
        let entries = vec![
            seal(&key, &vault, "https://shop.example", "me", "new-secret"),
            seal(&key, &vault, "https://github.com", "octocat", "new-secret"),
            vec![1, 2, 3],
        ];
        let added = add_entries(&mut vault, &key, &entries, false);
        assert_eq!(
            added.stored, 1,
            "the same login with the same password is there"
        );
        let shop = find(&vault, "Shop");
        assert_eq!(
            (shop.username.as_str(), shop.password.as_str()),
            ("me", "new-secret")
        );
        // What couldn't be read is kept, never dropped unseen.
        assert_eq!(added.kept, [vec![1, 2, 3]]);
        let again = add_entries(&mut vault, &key, &entries, false);
        assert_eq!(again.stored, 0, "already there");
        assert_eq!(vault.item_ids().count(), 2);
    }

    #[test]
    fn a_new_password_for_a_known_login_is_never_lost() {
        let mut vault = vault();
        vault
            .add_item(&ItemData::login(
                "GitHub",
                "octocat",
                "old",
                "https://github.com",
            ))
            .unwrap();
        let key = DropBoxKey::generate().unwrap();
        let entries = vec![seal(
            &key,
            &vault,
            "https://github.com",
            "octocat",
            "changed",
        )];
        let added = add_entries(&mut vault, &key, &entries, false);
        assert_eq!(added.stored, 1);
        assert!(added.kept.is_empty());
        let github = find(&vault, "GitHub");
        assert_eq!(github.password, "changed", "the browser's new password");
        assert_eq!(github.password_history.len(), 1);
        assert_eq!(
            github.password_history[0].password, "old",
            "kept in its history"
        );
        assert_eq!(vault.item_ids().count(), 1, "no second login");
    }

    #[test]
    fn a_new_password_for_a_locked_login_waits_for_the_item_lock() {
        let mut vault = vault();
        vault
            .add_item(&ItemData::login(
                "Bank",
                "me",
                "old",
                "https://bank.example",
            ))
            .unwrap();
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("4821"), Some("pw"))
            .unwrap();
        vault.lock_secrets();
        let key = DropBoxKey::generate().unwrap();
        let entries = vec![seal(&key, &vault, "https://bank.example", "me", "changed")];
        // Closed: kept for later, nothing changed, no second login.
        let added = add_entries(&mut vault, &key, &entries, false);
        assert_eq!((added.stored, added.behind_lock), (0, 1));
        assert_eq!(added.kept, entries);
        assert_eq!(vault.item_ids().count(), 1);
        // Opened: the login takes it.
        assert!(vault.unlock_secrets("4821").unwrap());
        let added = add_entries(&mut vault, &key, &entries, true);
        assert_eq!((added.stored, added.behind_lock), (1, 0));
        assert!(added.kept.is_empty());
        let bank = find(&vault, "Bank");
        assert_eq!(bank.password, "changed");
        assert_eq!(bank.password_history[0].password, "old");
    }
}
