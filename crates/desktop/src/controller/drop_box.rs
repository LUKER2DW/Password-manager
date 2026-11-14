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
    /// At unlock: adds the logins the browser saved while the vault was locked, and makes the
    /// drop box when the browser extension is on and there is none yet. Returns how many
    /// logins were added.
    pub(super) fn open_drop_box(&self) {
        let wanted = self.state.borrow().settings.browser_extension;
        let added = {
            let mut state = self.state.borrow_mut();
            let Some(session) = state.session.as_mut() else {
                return;
            };
            let vault = &mut session.vault;
            let id = vault.id_hex();
            match read(&id) {
                Some(file) => match DropBoxKey::open_with(vault, &file.sealed_key) {
                    Ok(key) => {
                        let added = add_entries(vault, &key, &file.entries);
                        if !file.entries.is_empty() {
                            let emptied = DropFile {
                                entries: Vec::new(),
                                ..file
                            };
                            let _ = write(&id, &emptied);
                        }
                        added
                    }
                    // Another vault's key under this id, or a damaged file: start over.
                    Err(_) => {
                        remove(&id);
                        if wanted {
                            create(vault);
                        }
                        0
                    }
                },
                None => {
                    if wanted {
                        create(vault);
                    }
                    0
                }
            }
        };
        if added > 0 {
            self.state.borrow_mut().summaries_stale = true;
            if self.save_vault() {
                self.refresh_list();
                self.notify_long(notice::BROWSER_DROPPED, &added.to_string());
            }
        }
    }
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

/// Adds each readable entry as a login, unless the vault has one for that site and username
/// already. Returns how many were added.
fn add_entries(vault: &mut Vault, key: &DropBoxKey, entries: &[Vec<u8>]) -> usize {
    let mut added = 0;
    for entry in entries {
        let Ok(plain) = key.open_entry(vault, entry) else {
            continue;
        };
        let Ok(dropped) = postcard::from_bytes::<Dropped>(&plain) else {
            continue;
        };
        let Ok(origin) = Origin::of_page(&dropped.url) else {
            continue;
        };
        let known = vault.item_ids().any(|id| {
            vault.get_item(&id).is_ok_and(|item| {
                item.kind == ItemKind::Login
                    && item.username == dropped.username
                    && item_matches(&item.urls, &origin)
            })
        });
        if known {
            continue;
        }
        let item = ItemData::login(
            &dropped.title,
            &dropped.username,
            &dropped.password,
            &dropped.url,
        );
        if vault.add_item(&item).is_ok() {
            added += 1;
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use vault_core::{KdfParams, SecretKey};

    use super::*;

    #[test]
    fn dropped_logins_join_the_vault_once() {
        let mut vault = Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        vault
            .add_item(&ItemData::login(
                "GitHub",
                "octocat",
                "old",
                "https://github.com",
            ))
            .unwrap();
        let key = DropBoxKey::generate().unwrap();
        let id = vault.id_hex();
        let seal = |url: &str, username: &str| {
            let dropped = Dropped {
                url: url.into(),
                title: "Shop".into(),
                username: username.into(),
                password: "new-secret".into(),
            };
            drop_box::seal_entry(
                &key.public_key(),
                &id,
                &postcard::to_allocvec(&dropped).unwrap(),
            )
            .unwrap()
        };
        let entries = vec![
            seal("https://shop.example", "me"),
            seal("https://github.com", "octocat"),
            vec![1, 2, 3],
        ];
        assert_eq!(add_entries(&mut vault, &key, &entries), 1);
        let shop = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|item| item.title == "Shop")
            .unwrap();
        assert_eq!(
            (shop.username.as_str(), shop.password.as_str()),
            ("me", "new-secret")
        );
        assert_eq!(add_entries(&mut vault, &key, &entries), 0, "already there");
    }
}
