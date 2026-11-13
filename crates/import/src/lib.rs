//! Importers from other password managers.
//!
//! Supported:
//! - **Bitwarden** unencrypted JSON export (`.json`)
//! - **KeePass / KeePassXC** databases (`.kdbx`, KDBX 3 and 4) — opened with their password
//! - **CSV** exports from Chrome, Edge, Firefox, Bitwarden and similar (header-detected)
//!
//! Importers only produce [`ItemData`]; they never touch the vault or its keys.

mod bitwarden;
mod csv_import;
mod dates;
mod export;
mod kdbx;

pub use bitwarden::import_bitwarden_json;
pub use csv_import::import_csv;
pub use export::{export_bitwarden_json, export_csv};
pub use kdbx::import_kdbx;

use vault_core::{ItemData, Vault};
use zeroize::Zeroizing;

/// File formats the importer understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    BitwardenJson,
    Csv,
    Kdbx,
}

/// Guesses the format from the file contents.
pub fn detect_format(bytes: &[u8]) -> Format {
    // KDBX signature: 0x9AA2D903 (little-endian).
    if bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]) {
        return Format::Kdbx;
    }
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match text.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') => Format::BitwardenJson,
        _ => Format::Csv,
    }
}

/// Result of an import: the items plus notes about anything that could not be carried over.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub items: Vec<ItemData>,
    /// Folder name for each item (same order as `items`); nested folders as `Parent/Child`.
    pub folders: Vec<Option<String>>,
    /// Human-readable warnings (skipped rows, unsupported data such as passkeys).
    pub warnings: Vec<String>,
}

impl ImportReport {
    pub(crate) fn push(&mut self, item: ItemData, folder: Option<String>) {
        self.items.push(item);
        self.folders.push(folder.filter(|f| !f.trim().is_empty()));
    }

    /// What [`ImportReport::add_to_vault`] would do, without changing the vault.
    pub fn preview(&self, vault: &Vault) -> Result<ImportOutcome, vault_core::Error> {
        let mut known = known_fingerprints(vault)?;
        let mut outcome = ImportOutcome::default();
        let mut new_folders: Vec<String> = Vec::new();
        for (item, folder) in self.items.iter().zip(&self.folders) {
            if !known.insert(fingerprint(item)) {
                outcome.duplicates += 1;
                continue;
            }
            if let Some(name) = folder {
                let lower = name.trim().to_lowercase();
                if find_folder(vault, &lower).is_none() && !new_folders.contains(&lower) {
                    new_folders.push(lower);
                }
            }
            outcome.titles.push(item.title.clone());
            outcome.added += 1;
        }
        outcome.new_folders = new_folders.len();
        Ok(outcome)
    }

    /// Adds the items to `vault`, skipping ones it already has (same title, username, password
    /// and first URL) and creating missing folders (an existing folder with the same name,
    /// ignoring case, is reused).
    pub fn add_to_vault(self, vault: &mut Vault) -> Result<ImportOutcome, vault_core::Error> {
        let mut known = known_fingerprints(vault)?;
        let mut outcome = ImportOutcome::default();
        for (mut item, folder) in self.items.into_iter().zip(self.folders) {
            if !known.insert(fingerprint(&item)) {
                outcome.duplicates += 1;
                continue;
            }
            if let Some(name) = folder {
                let name = name.trim();
                item.folder = Some(match find_folder(vault, &name.to_lowercase()) {
                    Some(id) => id,
                    None => {
                        outcome.new_folders += 1;
                        vault.add_folder(name)?
                    }
                });
            }
            vault.add_item(&item)?;
            outcome.titles.push(item.title.clone());
            outcome.added += 1;
        }
        Ok(outcome)
    }
}

/// Counts from adding an import to a vault.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub added: usize,
    pub duplicates: usize,
    pub new_folders: usize,
    /// Titles of the items added (or that would be added), in order.
    pub titles: Vec<String>,
}

fn find_folder(vault: &Vault, lowercase_name: &str) -> Option<vault_core::FolderId> {
    vault
        .folders()
        .iter()
        .find(|f| f.name.to_lowercase() == lowercase_name)
        .map(|f| f.id)
}

/// Identity of an item for duplicate detection: a SHA-256 digest, so the set of known items
/// holds no copy of any password.
fn fingerprint(item: &ItemData) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let text = Zeroizing::new(format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        item.title.to_lowercase(),
        item.username,
        item.password,
        item.urls.first().map(String::as_str).unwrap_or_default()
    ));
    Sha256::digest(text.as_bytes()).into()
}

fn known_fingerprints(
    vault: &Vault,
) -> Result<std::collections::HashSet<[u8; 32]>, vault_core::Error> {
    vault
        .item_ids()
        .map(|id| vault.get_item(&id).map(|item| fingerprint(&item)))
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("this export is encrypted; export again choosing the unencrypted JSON format")]
    EncryptedExport,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid CSV: {0}")]
    Csv(#[from] csv::Error),
    #[error(
        "the CSV has no recognizable columns (need at least a password, username or URL column)"
    )]
    UnknownCsvLayout,
    #[error("could not open the KeePass database (wrong password or key file?): {0}")]
    Kdbx(String),
}

/// Title fallback for entries without one: the host part of a URL.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format(&[0x03, 0xd9, 0xa2, 0x9a, 0x67]), Format::Kdbx);
        assert_eq!(
            detect_format(b"\xEF\xBB\xBF  {\"items\": []}"),
            Format::BitwardenJson
        );
        assert_eq!(detect_format(b"name,url,username,password\n"), Format::Csv);
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://www.github.com/login?x=1").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host_of("http://user@host.example:8080/").as_deref(),
            Some("host.example")
        );
        assert_eq!(
            host_of("android://hash@com.example.app/").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(host_of("").as_deref(), None);
    }
}
