//! The phone's own settings, kept next to its copies of the vaults (`settings.json`): how it
//! looks, when it locks, what it fetches, which vaults it keeps. Nothing secret is in them,
//! and nothing of a vault but its name. A file that can't be read gives the defaults (the app
//! works the same, as if new).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::platform::files;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub dark_theme: bool,
    /// 0: 1 minute, 1: 5 minutes, 2: 15 minutes (`LOCK_CHOICES`).
    pub lock_choice: u8,
    /// Seconds a copied secret stays on the clipboard.
    pub clipboard_seconds: u32,
    /// The doodle texture behind the open vault.
    pub backdrop: bool,
    /// Website icons: each saved site is asked for its icon once. Off until turned on, since
    /// someone watching the network can see which sites were asked (AGENTS.md §4.1, rule 5).
    pub website_icons: bool,
    /// How the generator was last set up (never what it made).
    pub generator: Generator,
    /// Lock at once whenever the app leaves the screen, not only after `lock_choice`.
    pub lock_on_leave: bool,
    /// Screenshots, screen recordings and the recent apps view may show the app.
    pub allow_capture: bool,
    /// Every time a password, a one-time code, a card's number or code, a secure note or an
    /// attached file is shown or copied (or an item opened for editing), the phone's own check
    /// asks first: a fingerprint, a face or the screen lock (`System::check_person`), with
    /// nothing remembered between two uses. On until turned off.
    pub ask_each_use: bool,
    /// The app's language: "" follows the phone, else a catalogue's tag ("en", "pt-BR").
    pub language: String,
    /// The vaults this phone keeps, each a file next to this one, in the order they came.
    pub vaults: Vec<KnownVault>,
    /// The file of the vault opened last ("" = the first one, `vault.vault`).
    pub current: String,
    /// The leak watch: every login's password checked once a day while the vault is open (it
    /// uses the network on its own, so it is off until turned on).
    pub leak_watch: bool,
    /// The order the person gave the Codes page, per vault (its id): item ids (hex), first
    /// to last. Codes not listed come after them, by title. Kept on this phone only.
    pub code_order: std::collections::BTreeMap<String, Vec<String>>,
    /// When the master password was last typed here and checked against the vault, per vault
    /// (its id), in Unix seconds. Fingerprint unlock asks for it again 14 days after that
    /// (`crate::bio`); turning fingerprint unlock on starts from this time, not from now.
    pub password_typed_at: std::collections::BTreeMap<String, i64>,
    /// Where the app's updates come from: [`UPDATES_FROM_GITHUB`] (the project's releases,
    /// the default) or [`UPDATES_FROM_SERVER`] (the servers the open vault syncs through).
    pub update_source: u8,
    /// Updates are looked for by themselves while a vault is open (on until turned off), not
    /// only with Check for updates.
    pub update_checks: bool,
    /// When GitHub was last asked for an update without the person pressing the button (Unix
    /// seconds, 0 never): it is asked again only some hours later, not at every unlock.
    pub github_asked_at: i64,
}

/// Updates from the project's releases on GitHub.
pub const UPDATES_FROM_GITHUB: u8 = 0;
/// Updates from the vault's own sync server, where its owner (or the server itself, following
/// the releases) put them.
pub const UPDATES_FROM_SERVER: u8 = 1;

/// A vault this phone keeps: its file (a bare name, next to `settings.json`) and the name it
/// had when it was last open (shown in the vault chooser; the file itself tells nothing
/// before it is unlocked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownVault {
    pub file: String,
    pub name: String,
    /// The vault's id (it is in the file's plain header too), for where it syncs.
    #[serde(default)]
    pub id: String,
    /// The icon chosen for it on this phone (a line icon's name; "" = its initial).
    #[serde(default)]
    pub icon: String,
}

/// The first vault's file, kept where the phone has always kept its one vault.
pub const FIRST_VAULT: &str = "vault.vault";

/// Whether `file` is a plain vault file name, next to `settings.json`: no folder, nothing
/// that could point elsewhere (`vault.vault`, `vault-2.vault`, a copy's own name).
pub fn is_vault_file(file: &str) -> bool {
    file.len() <= 64
        && file.len() > ".vault".len()
        && file.ends_with(".vault")
        && !file.starts_with('.')
        && !file.contains(['/', '\\', ':'])
        && !file.contains("..")
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            dark_theme: true,
            lock_choice: 1,
            clipboard_seconds: 30,
            backdrop: true,
            website_icons: false,
            generator: Generator::default(),
            lock_on_leave: false,
            allow_capture: false,
            ask_each_use: true,
            language: String::new(),
            vaults: Vec::new(),
            current: String::new(),
            leak_watch: false,
            code_order: std::collections::BTreeMap::new(),
            password_typed_at: std::collections::BTreeMap::new(),
            update_source: UPDATES_FROM_GITHUB,
            update_checks: true,
            github_asked_at: 0,
        }
    }
}

/// The generator's options, as on screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Generator {
    /// 0 characters, 1 words.
    pub mode: u8,
    pub length: u32,
    pub words: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    pub also_use: String,
    pub never_use: String,
    pub min_uppercase: u32,
    pub min_lowercase: u32,
    pub min_digits: u32,
    pub min_symbols: u32,
    /// 0 lower, 1 Title, 2 UPPER, 3 mixed.
    pub word_case: u8,
    /// 0 `-`, 1 `.`, 2 `_`, 3 a space.
    pub separator: u8,
    pub add_digit: bool,
}

impl Default for Generator {
    fn default() -> Self {
        Self {
            mode: 0,
            length: 20,
            words: 6,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            also_use: String::new(),
            never_use: String::new(),
            min_uppercase: 0,
            min_lowercase: 0,
            min_digits: 0,
            min_symbols: 0,
            word_case: 0,
            separator: 0,
            add_digit: false,
        }
    }
}

/// Where the settings of the phone whose vault copy is `vault` live.
pub fn path_for(vault: &Path) -> PathBuf {
    vault.with_file_name("settings.json")
}

impl Prefs {
    /// Notes that the vault in `file` is called `name` and has the id `id`, adding it to the
    /// list if it is new.
    pub fn remember_vault(&mut self, file: &str, id: &str, name: &str) {
        match self.vaults.iter_mut().find(|v| v.file == file) {
            Some(known) => {
                known.name = name.to_owned();
                known.id = id.to_owned();
            }
            None => self.vaults.push(KnownVault {
                file: file.to_owned(),
                name: name.to_owned(),
                id: id.to_owned(),
                icon: String::new(),
            }),
        }
    }

    /// A file name for one more vault, not used by any vault this phone knows or keeps in
    /// `folder`.
    pub fn free_file(&self, folder: &Path) -> String {
        (2..10_000)
            .map(|n| format!("vault-{n}.vault"))
            .find(|name| {
                !self.vaults.iter().any(|v| v.file == *name) && !folder.join(name).exists()
            })
            .unwrap_or_else(|| FIRST_VAULT.to_owned())
    }

    pub fn load(path: &Path) -> Self {
        files::read_any(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            if let Some(parent) = path.parent() {
                let _ = files::create_dir_all(parent);
            }
            let _ = files::write_atomic(path, &bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_partial_files_give_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(&dir.path().join("vault.vault"));
        assert_eq!(Prefs::load(&path), Prefs::default());
        std::fs::write(&path, br#"{"website_icons": true}"#).unwrap();
        let loaded = Prefs::load(&path);
        assert!(loaded.website_icons && loaded.backdrop && loaded.dark_theme);
        assert!(
            loaded.ask_each_use,
            "a phone that never chose asks for the fingerprint or screen lock every time"
        );
        assert_eq!(
            loaded.update_source, UPDATES_FROM_GITHUB,
            "a phone that never chose takes its updates from GitHub"
        );
        let changed = Prefs {
            dark_theme: false,
            ..loaded
        };
        changed.save(&path);
        assert_eq!(Prefs::load(&path), changed);
    }

    #[test]
    fn only_plain_vault_names_are_opened() {
        for good in ["vault.vault", "vault-2.vault", "phone-test.vault"] {
            assert!(is_vault_file(good), "{good}");
        }
        for bad in [
            "",
            ".vault",
            "../vault.vault",
            "a/b.vault",
            "a\\b.vault",
            "C:x.vault",
            "vault.txt",
            "a..b.vault",
        ] {
            assert!(!is_vault_file(bad), "{bad}");
        }
        let mut prefs = Prefs::default();
        assert!(!is_vault_file("../../elsewhere.vault"));
        let dir = tempfile::tempdir().unwrap();
        prefs.remember_vault(FIRST_VAULT, "ab", "Personal");
        assert_eq!(prefs.free_file(dir.path()), "vault-2.vault");
        std::fs::write(dir.path().join("vault-2.vault"), b"x").unwrap();
        assert_eq!(prefs.free_file(dir.path()), "vault-3.vault");
        prefs.remember_vault("vault-3.vault", "cd", "Work");
        prefs.remember_vault(FIRST_VAULT, "ab", "Home");
        assert_eq!(prefs.vaults.len(), 2);
        assert_eq!(prefs.vaults[0].name, "Home");
    }
}
