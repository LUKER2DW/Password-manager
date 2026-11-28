//! Password health's warnings the person chose to ignore: which item and which warning, kept
//! for each vault on this computer in a file sealed with the vault's key (that an item's
//! password is weak or reused is for the open vault only, as the leak watch keeps its leaks).
//! An ignored warning stays so until Don't ignore, or until its item is gone.

use std::{collections::BTreeSet, path::PathBuf};

use vault_core::{FormerKey, ItemId, Vault, storage};
use vault_platform::paths;

const PURPOSE: &str = "health-ignored";

/// An item and the group of its warning (the health page's: 0 leaked, 1 weak, 2 reused, 3 old,
/// 4 expiring, 5 saved without HTTPS, 6 one-time codes offered, 7 passkeys offered).
pub(super) type Ignored = BTreeSet<(ItemId, i32)>;

fn path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("health-ignored-{vault_id}.bin")),
    )
}

/// What this computer keeps for `vault`: nothing when there is no file, or one that doesn't open
/// (damaged, another vault's).
pub(super) fn load(vault: &Vault) -> Ignored {
    let Some(sealed) = path(&vault.id_hex()).and_then(|path| std::fs::read(path).ok()) else {
        return Ignored::new();
    };
    vault
        .open_local(PURPOSE, &sealed)
        .ok()
        .and_then(|plain| postcard::from_bytes::<Vec<(ItemId, i32)>>(&plain).ok())
        .map(|list| list.into_iter().collect())
        .unwrap_or_default()
}

pub(super) fn save(vault: &Vault, ignored: &Ignored) -> anyhow::Result<()> {
    let path = path(&vault.id_hex()).ok_or_else(|| anyhow::anyhow!("no app folder"))?;
    let list: Vec<(ItemId, i32)> = ignored.iter().copied().collect();
    let sealed = vault.seal_local(PURPOSE, &postcard::to_allocvec(&list)?)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    storage::write_atomic(&path, &sealed)?;
    Ok(())
}

/// After a renewal of the vault key: sealed again under the new key.
pub(super) fn reseal(vault: &Vault, former: &FormerKey) {
    if let Some(path) = path(&vault.id_hex()) {
        vault_platform::files::reseal(&path, vault, former, PURPOSE);
    }
}
