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

pub use http::{check_address, split_pin};
pub use server::ServerTarget;
pub use webdav::WebDavTarget;

use crate::{SyncPlace, SyncTo, secret_store};

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

/// Watches the folder target of vault `vault_id` under `folder` until `stop` is set, and calls
/// `changed` (on this thread) when another device's copy appears, changes or goes: a second
/// after the last such event, so a copy written in pieces counts once. This device's own
/// copy and temporary files are ignored. Returns at once if the folder can't be watched
/// (some network shares): the regular rounds still run.
pub fn watch_folder(
    folder: &Path,
    vault_id: &str,
    own: DeviceId,
    stop: &std::sync::atomic::AtomicBool,
    changed: impl Fn(),
) {
    use std::{sync::atomic::Ordering, time::Duration};

    use notify::{RecursiveMode, Watcher};

    let Ok(target) = FolderTarget::new(folder, vault_id) else {
        return;
    };
    if fs::create_dir_all(&target.devices).is_err() {
        return;
    }
    let own_name = format!("{}.vault", own.to_hex());
    let (sender, events) = std::sync::mpsc::channel();
    let Ok(mut watcher) = notify::recommended_watcher(sender) else {
        return;
    };
    if watcher
        .watch(&target.devices, RecursiveMode::NonRecursive)
        .is_err()
    {
        return;
    }
    let concerns = |event: &notify::Event| {
        event.paths.iter().any(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".vault").map(|stem| (n, stem)))
                .is_some_and(|(name, stem)| name != own_name && DeviceId::from_hex(stem).is_some())
        })
    };
    let mut pending = false;
    while !stop.load(Ordering::Relaxed) {
        match events.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(event)) => pending |= concerns(&event),
            Ok(Err(_)) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if pending && !stop.load(Ordering::Relaxed) {
                    pending = false;
                    changed();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
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

/// Which of a vault's sync places.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Where the vault syncs.
    Main,
    /// A second place (a backup server) synced every round too: the vault keeps syncing
    /// through it while the main place can't be reached, and the main place catches up as
    /// soon as it answers again.
    Backup,
}

impl Role {
    /// Added to the names its credentials are kept under; the main place's keep the names
    /// they always had.
    fn suffix(self) -> &'static str {
        match self {
            Role::Main => "",
            Role::Backup => ":backup",
        }
    }
}

/// The name `device`'s key for the server in `role` is kept under (the `device` of
/// `secret_store::*_sync_key`).
pub fn sync_key_name(device: DeviceId, role: Role) -> String {
    format!("{}{}", device.to_hex(), role.suffix())
}

/// The name the WebDAV password for the place in `role` is kept under (the `vault_id` of
/// `secret_store::*_webdav_password`).
pub fn webdav_password_name(vault_id: &str, role: Role) -> String {
    format!("{vault_id}{}", role.suffix())
}

/// The target for vault `vault_id` synced by `device` through `to`, with what it needs from
/// the OS credential store.
pub fn open_target(vault_id: &str, device: DeviceId, to: &SyncTo) -> Result<Box<dyn Target>> {
    open_target_as(vault_id, device, to, Role::Main)
}

/// [`open_target`] for the place in `role`.
pub fn open_target_as(
    vault_id: &str,
    device: DeviceId,
    to: &SyncTo,
    role: Role,
) -> Result<Box<dyn Target>> {
    Ok(match to {
        SyncTo::Folder { path } => Box::new(FolderTarget::new(path, vault_id)?),
        SyncTo::Server { url } => {
            let seed = secret_store::load_sync_key(vault_id, &sync_key_name(device, role))?
                .context("this device has no key for the sync server: join it again")?;
            Box::new(ServerTarget::new(
                url,
                vault_id,
                device,
                vault_sync_wire::DeviceKey::from_seed(&seed),
            )?)
        }
        SyncTo::Webdav { url, user } => {
            let password =
                secret_store::load_webdav_password(&webdav_password_name(vault_id, role))?
                    .context("the WebDAV password isn't saved on this device: set it again")?;
            Box::new(WebDavTarget::new(url, vault_id, user, &password)?)
        }
    })
}

/// The tags of the copies already merged, per place.
#[derive(Debug, Default, Clone)]
pub struct KnownTags {
    pub main: Tags,
    pub backup: Tags,
}

/// One round's reading from every place the vault syncs through.
#[derive(Debug)]
pub struct Reading {
    pub main: Result<Fetched, String>,
    /// `None` when there is no backup place.
    pub backup: Option<Result<Fetched, String>>,
}

impl Reading {
    /// At least one place answered: the round goes on with what it read.
    pub fn reached(&self) -> bool {
        self.main.is_ok() || matches!(self.backup, Some(Ok(_)))
    }

    /// Why the main place couldn't be read, when it couldn't.
    pub fn main_down(&self) -> Option<&str> {
        self.main.as_ref().err().map(String::as_str)
    }

    /// Why the backup place couldn't be read, when there is one and it couldn't.
    pub fn backup_down(&self) -> Option<&str> {
        match &self.backup {
            Some(Err(why)) => Some(why),
            _ => None,
        }
    }

    /// The tags to pass as `known` next round, once what was read is merged: a place that
    /// didn't answer keeps what was known of it.
    pub fn tags(&self, before: &KnownTags) -> KnownTags {
        KnownTags {
            main: self
                .main
                .as_ref()
                .map_or_else(|_| before.main.clone(), |f| f.tags.clone()),
            backup: match &self.backup {
                Some(Ok(fetched)) => fetched.tags.clone(),
                _ => before.backup.clone(),
            },
        }
    }

    /// The places that answered, by role.
    fn answered(&self) -> impl Iterator<Item = (Role, &Fetched)> {
        let main = self.main.as_ref().ok().map(|f| (Role::Main, f));
        let backup = match &self.backup {
            Some(Ok(fetched)) => Some((Role::Backup, fetched)),
            _ => None,
        };
        main.into_iter().chain(backup)
    }
}

/// Reads every other device's copy from the main place and the backup place, if any, at the
/// same time (off the UI thread). A place that can't be reached is reported in the result;
/// the round goes on with the other.
pub fn read_all(vault_id: &str, device: DeviceId, place: &SyncPlace, known: &KnownTags) -> Reading {
    let read = |to: &SyncTo, role: Role, known: &Tags| {
        open_target_as(vault_id, device, to, role)
            .and_then(|target| fetch(&*target, device, known))
            .map_err(|err| format!("{err:#}"))
    };
    std::thread::scope(|scope| {
        let backup = place
            .backup
            .as_ref()
            .map(|to| scope.spawn(|| read(to, Role::Backup, &known.backup)));
        let main = read(&place.to, Role::Main, &known.main);
        Reading {
            main,
            backup: backup.map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("reading the backup place failed".to_owned()))
            }),
        }
    })
}

/// Folds what a round read into `vault`. With one place this is [`merge_all`]. With a backup
/// place, each other device's newest copy is taken from whichever place has it; a copy older
/// than one already merged from that device is left out without a warning, since a place
/// that was down holds older copies until it catches up (it is never merged either way).
pub fn merge_reading(vault: &mut Vault, reading: &Reading, seen: &mut SeenRevisions) -> Round {
    if reading.backup.is_none() {
        return match &reading.main {
            Ok(fetched) => merge_all(vault, fetched, seen),
            Err(_) => Round::default(),
        };
    }
    let mut chosen: Vec<(DeviceId, &[u8], Option<u64>)> = Vec::new();
    for (_, fetched) in reading.answered() {
        for (device, bytes) in &fetched.copies {
            let revision = vault.check_copy(bytes).ok();
            if let (Some(revision), Some(known)) = (revision, seen.revision(device))
                && revision < known
            {
                continue;
            }
            match chosen.iter_mut().find(|(id, _, _)| id == device) {
                None => chosen.push((*device, bytes, revision)),
                Some(slot) if revision > slot.2 => *slot = (*device, bytes, revision),
                Some(_) => {}
            }
        }
    }
    let fetched = Fetched {
        copies: chosen
            .into_iter()
            .map(|(device, bytes, _)| (device, bytes.to_vec()))
            .collect(),
        ..Fetched::default()
    };
    merge_all(vault, &fetched, seen)
}

/// The places this device's copy goes to after a round: those that answered and don't have
/// `revision` yet (all that answered when the round `changed` the vault).
pub fn to_publish(place: &SyncPlace, reading: &Reading, revision: u64, changed: bool) -> Vec<Role> {
    let mut roles = Vec::new();
    if reading.main.is_ok() && (changed || revision > place.published) {
        roles.push(Role::Main);
    }
    if matches!(reading.backup, Some(Ok(_))) && (changed || revision > place.published_backup) {
        roles.push(Role::Backup);
    }
    roles
}

/// What each place answered when this device's copy was put there.
pub type Published = Vec<(Role, Result<(), String>)>;

/// Puts this device's copy on each place in `roles` (off the UI thread); what each answered.
pub fn publish_all(
    vault_id: &str,
    device: DeviceId,
    place: &SyncPlace,
    bytes: &[u8],
    roles: &[Role],
) -> Published {
    roles
        .iter()
        .filter_map(|role| {
            let to = match role {
                Role::Main => &place.to,
                Role::Backup => place.backup.as_ref()?,
            };
            let put = open_target_as(vault_id, device, to, *role)
                .and_then(|target| target.put(device, bytes))
                .map_err(|err| format!("{err:#}"));
            Some((*role, put))
        })
        .collect()
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
    fn a_folder_watch_hears_other_devices_only() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let id = "c".repeat(32);
        let target = FolderTarget::new(dir.path(), &id).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let heard = Arc::new(AtomicUsize::new(0));
        let watching = {
            let (folder, id, stop, heard) = (
                dir.path().to_owned(),
                id.clone(),
                stop.clone(),
                heard.clone(),
            );
            std::thread::spawn(move || {
                watch_folder(&folder, &id, device(1), &stop, || {
                    heard.fetch_add(1, Ordering::SeqCst);
                });
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        target.put(device(1), b"own copy").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1800));
        assert_eq!(heard.load(Ordering::SeqCst), 0, "this device's own copy");
        target.put(device(2), b"another device").unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while heard.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(heard.load(Ordering::SeqCst), 1, "one change, heard once");
        stop.store(true, Ordering::SeqCst);
        watching.join().unwrap();
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
