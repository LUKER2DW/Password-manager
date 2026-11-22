//! The phone's own settings, kept next to its copy of the vault (`settings.json`): how it
//! looks, when it locks, what it fetches. Nothing secret is in them, and nothing of the vault.
//! A file that can't be read gives the defaults (the app works the same, as if new).

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
        let changed = Prefs {
            dark_theme: false,
            ..loaded
        };
        changed.save(&path);
        assert_eq!(Prefs::load(&path), changed);
    }
}
