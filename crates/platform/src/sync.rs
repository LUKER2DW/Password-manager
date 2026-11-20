//! Sync targets (spec: SYNC.md §5) and one sync round, shared by the CLI and the desktop app.
//!
//! A target holds one sealed copy of the vault per device and nothing else. This device
//! writes only its own copy and reads the others; [`vault_core::Vault::merge`] decides what
//! they change here. Targets: a folder (here), our own server ([`server`]) and WebDAV
//! ([`webdav`]).

mod http;
pub mod server;
pub mod webdav;

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use vault_core::{
    Vault,
    sync::{DeviceId, MergeReport, SeenRevisions},
};

pub use http::check_address;
pub use server::ServerTarget;
pub use webdav::WebDavTarget;

use crate::{SyncTo, secret_store};

/// Copies bigger than this are not read: a vault is kilobytes to a few MB (pictures stay in
/// each device's cache), and a target is not trusted to hand over something sane.
pub const MAX_COPY_BYTES: u64 = 64 * 1024 * 1024;

/// Where copies are kept. Every call may be slow (a network share, a cloud drive fetching a
/// file on demand): run them off the UI thread.
pub trait Target: Send + Sync {
    /// The devices that have a copy there, each with a tag that changes when its copy does
    /// (`None`: unknown, always read it).
    fn list(&self) -> Result<Vec<Listed>>;
    fn get(&self, device: DeviceId) -> Result<Vec<u8>>;
    /// Replaces this device's own copy, whole: readers never see half of it.
    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()>;
    /// Deletes a device's copy (a device removed from the vault).
    fn remove(&self, device: DeviceId) -> Result<()>;
    /// Waits up to `seconds` for a change after `after` (a counter the target hands out) and
    /// returns where the counter stands. `None`: this target can't tell, look again later.
    fn wait(&self, _after: u64, _seconds: u64) -> Option<Result<u64>> {
        None
    }
}

/// One copy found on a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub device: DeviceId,
    pub tag: Option<String>,
}

/// The tags of the copies already folded in, so an unchanged copy isn't read again. Kept in
/// memory only: the first round after an unlock reads everything.
pub type Tags = HashMap<DeviceId, String>;

/// A folder another program keeps the same on every computer (OneDrive, Google Drive for
/// desktop, Dropbox, Syncthing, a network share): `<folder>/<vault id>/devices/<device>.vault`.
#[derive(Debug, Clone)]
pub struct FolderTarget {
    devices: PathBuf,
}

impl FolderTarget {
    /// The target for vault `vault_id` (hex) under `folder`, the one the person chose.
    pub fn new(folder: &Path, vault_id: &str) -> Result<Self> {
        if vault_id.len() != 32 || !vault_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("not a vault id");
        }
        Ok(Self {
            devices: folder.join(vault_id).join("devices"),
        })
    }

    fn path(&self, device: DeviceId) -> PathBuf {
        self.devices.join(format!("{}.vault", device.to_hex()))
    }
}

impl Target for FolderTarget {
    fn list(&self) -> Result<Vec<Listed>> {
        let entries = match fs::read_dir(&self.devices) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).context("reading the sync folder"),
        };
        let mut devices = Vec::new();
        for entry in entries {
            let entry = entry.context("reading the sync folder")?;
            // Only `<32 hex>.vault`: a cloud drive's "conflicted copy", a temporary file or
            // anything else someone put there is not a device's copy.
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".vault")) else {
                continue;
            };
            if let Some(device) = DeviceId::from_hex(stem)
                && let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos());
                devices.push(Listed {
                    device,
                    tag: Some(format!("{}-{modified}", meta.len())),
                });
            }
        }
        devices.sort_by_key(|l| l.device);
        Ok(devices)
    }

    fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
        let path = self.path(device);
        let file = fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_COPY_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_COPY_BYTES {
            bail!("{} is too big to be a vault", path.display());
        }
        Ok(bytes)
    }

    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.devices).context("creating the sync folder")?;
        let path = self.path(own);
        // Written beside it under a name `list` ignores, then renamed over it.
        let temp = self.devices.join(format!(".{}.vault.tmp", own.to_hex()));
        {
            use std::io::Write;
            let mut file = fs::File::create(&temp).context("writing to the sync folder")?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temp, &path).inspect_err(|_| {
            let _ = fs::remove_file(&temp);
        })?;
        Ok(())
    }

    fn remove(&self, device: DeviceId) -> Result<()> {
        match fs::remove_file(self.path(device)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
            _ => Ok(()),
        }
    }
}

/// The other devices' copies, read in one go (off the UI thread), and what couldn't be read.
#[derive(Debug, Default)]
pub struct Fetched {
    pub copies: Vec<(DeviceId, Vec<u8>)>,
    pub unreadable: Vec<(DeviceId, String)>,
    /// The tags of the copies read or known, to pass as `known` next time once merged.
    pub tags: Tags,
    /// Copies left unread because their tag was known.
    pub unchanged: usize,
}

/// Reads every copy but this device's own whose tag isn't in `known` (pass an empty map to
/// read them all). An unreachable target is an error; one copy that can't be read is listed
/// and the others are still read.
pub fn fetch(target: &dyn Target, own: DeviceId, known: &Tags) -> Result<Fetched> {
    let mut fetched = Fetched::default();
    for listed in target.list()? {
        if listed.device == own {
            continue;
        }
        if let Some(tag) = &listed.tag
            && known.get(&listed.device) == Some(tag)
        {
            fetched.unchanged += 1;
            fetched.tags.insert(listed.device, tag.clone());
            continue;
        }
        match target.get(listed.device) {
            Ok(bytes) => {
                if let Some(tag) = listed.tag {
                    fetched.tags.insert(listed.device, tag);
                }
                fetched.copies.push((listed.device, bytes));
            }
            Err(err) => fetched.unreadable.push((listed.device, format!("{err:#}"))),
        }
    }
    Ok(fetched)
}

/// The target for vault `vault_id` synced by `device` through `to`, with what it needs from
/// the OS credential store.
pub fn open_target(vault_id: &str, device: DeviceId, to: &SyncTo) -> Result<Box<dyn Target>> {
    Ok(match to {
        SyncTo::Folder { path } => Box::new(FolderTarget::new(path, vault_id)?),
        SyncTo::Server { url } => {
            let seed = secret_store::load_sync_key(vault_id, &device.to_hex())?
                .context("this device has no key for the sync server: join it again")?;
            Box::new(ServerTarget::new(
                url,
                vault_id,
                device,
                vault_sync_wire::DeviceKey::from_seed(&seed),
            )?)
        }
        SyncTo::Webdav { url, user } => {
            let password = secret_store::load_webdav_password(vault_id)?
                .context("the WebDAV password isn't saved on this device: set it again")?;
            Box::new(WebDavTarget::new(url, vault_id, user, &password)?)
        }
    })
}

/// What folding the fetched copies did.
#[derive(Debug, Default)]
pub struct Round {
    pub reports: Vec<MergeReport>,
    /// Copies refused (a replay, a fork, another vault, a removed device…), with why.
    pub refused: Vec<(DeviceId, vault_core::Error)>,
    /// This device was removed from the vault on another device: stop syncing.
    pub removed_here: bool,
}

impl Round {
    /// Whether the vault changed and must be saved (and then published).
    pub fn changed(&self) -> bool {
        self.reports.iter().any(MergeReport::changed)
    }

    pub fn conflicts(&self) -> usize {
        self.reports.iter().map(|r| r.conflicts.len()).sum()
    }

    pub fn waiting_for_lock(&self) -> usize {
        self.reports.iter().map(|r| r.waiting_for_lock).sum()
    }

    pub fn unlock_changed(&self) -> bool {
        self.reports.iter().any(|r| r.unlock_changed)
    }
}

/// Folds every fetched copy into `vault`. Runs where the vault is (the UI thread), and is
/// quick: no file or network access.
pub fn merge_all(vault: &mut Vault, fetched: &Fetched, seen: &mut SeenRevisions) -> Round {
    let mut round = Round::default();
    for (device, bytes) in &fetched.copies {
        match vault.merge(bytes, seen) {
            Ok(report) => round.reports.push(report),
            Err(vault_core::Error::RemovedHere) => round.removed_here = true,
            Err(err) => round.refused.push((*device, err)),
        }
    }
    round
}

/// Makes sure this vault writes as `device` and lists it among the devices that sync it.
/// Returns whether that changed the vault (save it).
pub fn join(vault: &mut Vault, device: DeviceId, name: &str) -> vault_core::Result<bool> {
    let mut changed = vault.device() != device;
    vault.set_device(device);
    if !vault.sync_devices().iter().any(|d| d.id == device) {
        vault.add_sync_device(vault_core::sync::SyncDevice {
            id: device,
            name: name.to_owned(),
            signing_key: None,
            added_at: unix_now(),
        })?;
        changed = true;
    }
    Ok(changed)
}

/// A name for this device in the vault's device list: the computer's name.
pub fn device_name() -> String {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(vault_core::sync::SyncDevice::MAX_NAME_CHARS)
        .collect();
    if name.is_empty() {
        "This computer".into()
    } else {
        name
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    #[test]
    fn a_folder_holds_one_copy_per_device_and_ignores_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let target = FolderTarget::new(dir.path(), id).unwrap();
        assert!(target.list().unwrap().is_empty(), "nothing there yet");
        let devices_of = |target: &FolderTarget| -> Vec<DeviceId> {
            target
                .list()
                .unwrap()
                .into_iter()
                .map(|l| l.device)
                .collect()
        };
        target.put(device(1), b"one").unwrap();
        target.put(device(2), b"two").unwrap();
        target.put(device(1), b"one, newer").unwrap();
        let devices = dir.path().join(id).join("devices");
        // What cloud drives and people leave next to the copies.
        fs::write(devices.join("conflicted copy.vault"), b"x").unwrap();
        fs::write(
            devices.join(format!("{} (1).vault", device(3).to_hex())),
            b"x",
        )
        .unwrap();
        fs::create_dir(devices.join(format!("{}.vault", device(4).to_hex()))).unwrap();
        assert_eq!(devices_of(&target), [device(1), device(2)]);
        assert_eq!(target.get(device(1)).unwrap(), b"one, newer");
        let fetched = fetch(&target, device(1), &Tags::new()).unwrap();
        assert_eq!(fetched.copies, [(device(2), b"two".to_vec())]);
        // Known and unchanged: not read again.
        let again = fetch(&target, device(1), &fetched.tags).unwrap();
        assert!(again.copies.is_empty());
        assert_eq!(again.unchanged, 1);
        target.remove(device(2)).unwrap();
        target.remove(device(2)).unwrap();
        assert_eq!(devices_of(&target), [device(1)]);
        assert!(FolderTarget::new(dir.path(), "../escape").is_err());
    }

    #[test]
    fn a_copy_too_big_to_be_a_vault_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = FolderTarget::new(dir.path(), &"a".repeat(32)).unwrap();
        target.put(device(1), b"small").unwrap();
        let file = fs::File::create(target.path(device(2))).unwrap();
        file.set_len(MAX_COPY_BYTES + 1).unwrap();
        let fetched = fetch(&target, device(9), &Tags::new()).unwrap();
        assert_eq!(fetched.copies.len(), 1);
        assert_eq!(fetched.unreadable.len(), 1);
    }
}
