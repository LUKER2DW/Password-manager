//! Android autofill's questions, answered from the vault. The Java side
//! (`apps/mobile-android/java/…/VaultAutofillService.java`, `AutofillActivity.java`) finds a
//! form's fields and where it is: a website's domain in a browser, else the app's package.
//!
//! - Which logins belong there: the website's exact domain (or everything under a saved
//!   `*.example.com`), or an app by the `androidapp://<package>` address saved in the login.
//!   A login behind the item lock is never offered.
//! - Before anything is filled, the person confirms with a fingerprint or the phone's own lock
//!   (the Java side asks). With the vault locked, fingerprint unlock opens the vault file here
//!   just long enough to read the logins for that place.
//! - A login saved from another app while the vault is locked is sealed to the vault's drop box
//!   (CRYPTO.md §3.5: only the open vault reads it) and added at the next unlock.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_core::{
    ItemData, ItemId, ItemKind, Vault,
    drop_box::{self, DropBoxKey, PUBLIC_KEY_LEN},
    generator::{PasswordOptions, generate_password},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{bio, platform::files, prefs};

/// A login offered to a form.
#[derive(Clone)]
pub struct Login {
    /// The item's id (hex).
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

/// A saved address's host, lower case, without scheme, user, port or path; `None` for an app's
/// address or nothing usable.
fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = match url.split_once("://") {
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("androidapp") => return None,
        Some((_, rest)) => rest,
        None => url,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether a login's saved address `url` is the website `domain`: the same host, or `domain`
/// is under a saved `*.example.com`.
pub fn site_matches(url: &str, domain: &str) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    match host.strip_prefix("*.") {
        Some(rest) => domain == rest || domain.ends_with(&format!(".{rest}")),
        None => host == domain,
    }
}

/// Whether a login's saved address `url` is the app `package` (`androidapp://<package>`).
pub fn app_matches(url: &str, package: &str) -> bool {
    let url = url.trim();
    url.len() > "androidapp://".len()
        && url[.."androidapp://".len()].eq_ignore_ascii_case("androidapp://")
        && url["androidapp://".len()..].trim_end_matches('/') == package
}

/// Whether `item` belongs to the place asking: `domain` in a browser, else the app `app`.
fn fits(item: &ItemData, domain: Option<&str>, app: &str) -> bool {
    match domain.filter(|d| !d.is_empty()) {
        Some(domain) => item.urls.iter().any(|url| site_matches(url, domain)),
        None => !app.is_empty() && item.urls.iter().any(|url| app_matches(url, app)),
    }
}

/// The logins of `vault` for the place asking, by title. None behind the item lock.
pub fn logins_for(vault: &Vault, domain: Option<&str>, app: &str) -> Vec<Login> {
    let mut found: Vec<Login> = vault
        .item_ids()
        .filter_map(|id| {
            let item = vault.get_item(&id).ok()?;
            let usable = item.kind == ItemKind::Login
                && !item.is_locked()
                && !vault.guards(&item)
                && !(item.password.is_empty() && item.username.is_empty())
                && fits(&item, domain, app);
            usable.then(|| Login {
                id: id.to_hex(),
                title: item.title.clone(),
                username: item.username.clone(),
                password: Zeroizing::new(item.password.clone()),
            })
        })
        .collect();
    found.sort_by_key(|login| login.title.to_lowercase());
    found
}

/// One login of `vault` by its id, only if it still belongs to the place asking.
pub fn login_by_id(vault: &Vault, id: &str, domain: Option<&str>, app: &str) -> Option<Login> {
    let id = ItemId::from_hex(id)?;
    logins_for(vault, domain, app)
        .into_iter()
        .find(|login| ItemId::from_hex(&login.id) == Some(id))
}

/// A strong password for a new-password field (the generator's defaults: 20 characters of
/// every kind).
pub fn suggest() -> Option<Zeroizing<String>> {
    generate_password(&PasswordOptions::default()).ok()
}

// ---- the locked app ----

/// The phone's vault file in `home` that the app opened last.
fn current_vault(home: &Path) -> PathBuf {
    let prefs = prefs::Prefs::load(&prefs::path_for(&home.join(prefs::FIRST_VAULT)));
    let file = if prefs::is_vault_file(&prefs.current) {
        prefs.current
    } else {
        prefs::FIRST_VAULT.to_owned()
    };
    home.join(file)
}

/// The vault the app opened last, when fingerprint unlock is on for it and the master password
/// isn't due: its id and its device secret as the secure hardware sealed it.
pub fn locked_unlock(home: &Path, now: i64) -> Option<(String, Vec<u8>)> {
    let bytes = files::read(&current_vault(home)).ok()?;
    let id = Vault::inspect(&bytes).ok()?.id_hex;
    let unlock = bio::read(home, &id).filter(|b| b.fresh(now))?;
    Some((id, unlock.hardware))
}

/// Opens that vault with the device secret the fingerprint released and reads the logins for
/// the place asking. The vault leaves memory when this returns.
pub fn open_with_secret(
    home: &Path,
    secret: &[u8],
    domain: Option<&str>,
    app: &str,
    now: i64,
) -> Option<Vec<Login>> {
    let bytes = files::read(&current_vault(home)).ok()?;
    let id = Vault::inspect(&bytes).ok()?.id_hex;
    let unlock = bio::read(home, &id).filter(|b| b.fresh(now))?;
    let vault = Vault::open_with_device(&bytes, secret, &unlock.sealed_key).ok()?;
    Some(logins_for(&vault, domain, app))
}

// ---- the drop box: logins saved while the vault is locked ----

/// Entries kept at most while locked; later saves are refused.
const MAX_ENTRIES: usize = 200;

/// `autofill-drop-<vault id>.json` next to the vault: the drop box's public key, its private key
/// sealed with the vault key, and the logins sealed to the public key since the last unlock.
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

fn drop_path(folder: &Path, vault_id: &str) -> PathBuf {
    folder.join(format!("autofill-drop-{vault_id}.json"))
}

fn read_drop(folder: &Path, vault_id: &str) -> Option<DropFile> {
    let bytes = files::read_any(&drop_path(folder, vault_id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_drop(folder: &Path, vault_id: &str, file: &DropFile) -> bool {
    serde_json::to_vec(file)
        .ok()
        .is_some_and(|bytes| files::write_atomic(&drop_path(folder, vault_id), &bytes).is_ok())
}

/// The title and address a login saved from `domain` (a browser) or the app `app` gets.
pub fn place_of(domain: Option<&str>, app: &str) -> (String, String) {
    match domain.filter(|d| !d.trim().is_empty()) {
        Some(domain) => {
            let domain = domain.trim().to_ascii_lowercase();
            let title = domain.strip_prefix("www.").unwrap_or(&domain).to_owned();
            (title, format!("https://{domain}"))
        }
        None => (app.to_owned(), format!("androidapp://{app}")),
    }
}

/// Seals a login saved from another app while the vault the app opened last is locked, for
/// the next unlock. `false` when that vault has no drop box yet (it is made at an unlock) or
/// it is full.
pub fn keep_locked(
    home: &Path,
    domain: Option<&str>,
    app: &str,
    username: &str,
    password: &str,
) -> bool {
    let Ok(bytes) = files::read(&current_vault(home)) else {
        return false;
    };
    let Ok(info) = Vault::inspect(&bytes) else {
        return false;
    };
    let Some(mut file) = read_drop(home, &info.id_hex) else {
        return false;
    };
    if file.entries.len() >= MAX_ENTRIES {
        return false;
    }
    let (title, url) = place_of(domain, app);
    let dropped = Dropped {
        url,
        title,
        username: username.to_owned(),
        password: password.to_owned(),
    };
    let Ok(plain) = serde_json::to_vec(&dropped).map(Zeroizing::new) else {
        return false;
    };
    let Ok(entry) = drop_box::seal_entry(&file.public_key, &info.id_hex, &plain) else {
        return false;
    };
    file.entries.push(entry);
    write_drop(home, &info.id_hex, &file)
}

/// At unlock: the logins saved while the vault was locked, as items to add (the drop box is
/// made when there is none). Call [`empty_drop_box`] once they are safely saved.
pub(crate) fn dropped_logins(folder: &Path, vault: &Vault) -> Vec<ItemData> {
    let id = vault.id_hex();
    let Some(file) = read_drop(folder, &id) else {
        make_drop_box(folder, vault);
        return Vec::new();
    };
    let Ok(key) = DropBoxKey::open_with(vault, &file.sealed_key) else {
        // Another vault's key under this id, or a damaged file: start over.
        make_drop_box(folder, vault);
        return Vec::new();
    };
    file.entries
        .iter()
        .filter_map(|entry| {
            let plain = key.open_entry(vault, entry).ok()?;
            let dropped: Dropped = serde_json::from_slice(&plain).ok()?;
            let mut item = ItemData::new(ItemKind::Login, &dropped.title);
            item.username.clone_from(&dropped.username);
            item.password.clone_from(&dropped.password);
            item.urls = vec![dropped.url.clone()];
            Some(item)
        })
        .collect()
}

/// Empties the drop box once its logins are in the saved vault.
pub(crate) fn empty_drop_box(folder: &Path, vault_id: &str) {
    if let Some(file) = read_drop(folder, vault_id)
        && !file.entries.is_empty()
    {
        write_drop(
            folder,
            vault_id,
            &DropFile {
                entries: Vec::new(),
                ..file
            },
        );
    }
}

fn make_drop_box(folder: &Path, vault: &Vault) {
    let Ok(key) = DropBoxKey::generate() else {
        return;
    };
    let Ok(sealed_key) = key.seal_with(vault) else {
        return;
    };
    write_drop(
        folder,
        &vault.id_hex(),
        &DropFile {
            public_key: key.public_key(),
            sealed_key,
            entries: Vec::new(),
        },
    );
}

/// Adds a login saved from another app to the open `vault`: the password of a login already
/// saved there for the same place and username changes (the old one goes into its history),
/// else a new login is made. Returns whether anything changed.
pub(crate) fn save_into(
    vault: &mut Vault,
    domain: Option<&str>,
    app: &str,
    username: &str,
    password: &str,
) -> vault_core::Result<bool> {
    if password.is_empty() {
        return Ok(false);
    }
    let same = vault
        .item_ids()
        .filter_map(|id| Some((id, vault.get_item(&id).ok()?)))
        .find(|(_, item)| {
            item.kind == ItemKind::Login
                && !item.is_locked()
                && item.username == username
                && fits(item, domain, app)
        });
    match same {
        Some((_, item)) if item.password == password => Ok(false),
        Some((id, mut item)) => {
            item.password = password.to_owned();
            vault.update_item(&id, &item)?;
            Ok(true)
        }
        None => {
            let (title, url) = place_of(domain, app);
            let mut item = ItemData::new(ItemKind::Login, &title);
            item.username = username.to_owned();
            item.password = password.to_owned();
            item.urls = vec![url];
            vault.add_item(&item)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_match_exactly_or_under_a_wildcard() {
        assert!(site_matches("https://github.com/login", "github.com"));
        assert!(site_matches("github.com", "GitHub.com"));
        assert!(site_matches(
            "https://user@accounts.example.com:8443/",
            "accounts.example.com"
        ));
        assert!(!site_matches("https://github.com", "evilgithub.com"));
        assert!(!site_matches("https://github.com", "github.com.evil.net"));
        assert!(
            !site_matches("https://www.github.com", "github.com"),
            "exact host only"
        );
        assert!(site_matches("*.example.com", "example.com"));
        assert!(site_matches("https://*.example.com", "mail.example.com"));
        assert!(!site_matches("*.example.com", "badexample.com"));
        assert!(!site_matches("androidapp://com.example", "com.example"));
        assert!(app_matches(
            "androidapp://com.example.app",
            "com.example.app"
        ));
        assert!(app_matches(
            "AndroidApp://com.example.app/",
            "com.example.app"
        ));
        assert!(!app_matches(
            "androidapp://com.example.app",
            "com.example.app2"
        ));
        assert!(!app_matches("https://com.example.app", "com.example.app"));
        assert_eq!(
            place_of(Some("www.Example.com"), "com.android.chrome"),
            (
                "example.com".to_owned(),
                "https://www.example.com".to_owned()
            )
        );
        assert_eq!(
            place_of(None, "com.example.app"),
            (
                "com.example.app".to_owned(),
                "androidapp://com.example.app".to_owned()
            )
        );
    }

    #[test]
    fn logins_saved_while_locked_come_in_at_the_next_unlock() {
        use vault_core::{KdfParams, SecretKey};
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join(prefs::FIRST_VAULT),
            vault.to_bytes().unwrap(),
        )
        .unwrap();
        assert!(
            !keep_locked(
                dir.path(),
                Some("example.com"),
                "com.android.chrome",
                "me",
                "pw1"
            ),
            "no drop box before an unlock"
        );
        assert!(dropped_logins(dir.path(), &vault).is_empty());
        assert!(keep_locked(
            dir.path(),
            Some("example.com"),
            "com.android.chrome",
            "me",
            "pw1"
        ));
        assert!(keep_locked(
            dir.path(),
            None,
            "com.example.app",
            "you",
            "pw2"
        ));
        let items = dropped_logins(dir.path(), &vault);
        assert_eq!(items.len(), 2);
        for item in &items {
            vault.add_item(item).unwrap();
        }
        empty_drop_box(dir.path(), &vault.id_hex());
        assert!(dropped_logins(dir.path(), &vault).is_empty());
        let found = logins_for(&vault, Some("example.com"), "com.android.chrome");
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].username.as_str(), found[0].password.as_str()),
            ("me", "pw1")
        );
        assert_eq!(logins_for(&vault, None, "com.example.app").len(), 1);
        assert!(logins_for(&vault, None, "com.android.chrome").is_empty());
        // Saving again: the same login gets the new password, another username a new login.
        assert!(save_into(&mut vault, Some("example.com"), "x", "me", "pw3").unwrap());
        assert!(!save_into(&mut vault, Some("example.com"), "x", "me", "pw3").unwrap());
        assert!(save_into(&mut vault, Some("example.com"), "x", "other", "pw4").unwrap());
        let found = logins_for(&vault, Some("example.com"), "x");
        assert_eq!(found.len(), 2);
        let me = found.iter().find(|l| l.username == "me").unwrap();
        assert_eq!(me.password.as_str(), "pw3");
        assert!(login_by_id(&vault, &me.id, Some("example.com"), "x").is_some());
        assert!(
            login_by_id(&vault, &me.id, Some("evil.com"), "x").is_none(),
            "only for its place"
        );
        assert!(suggest().is_some_and(|p| p.chars().count() >= 20));
    }
}
