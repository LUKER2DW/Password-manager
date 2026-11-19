//! What syncing between devices needs from the vault (spec: SYNC.md, format v7).
//!
//! Every device keeps a whole vault and writes only its own copy to the sync target. Copies
//! are folded together by [`crate::Vault::merge`]; this module holds the state that makes the
//! fold safe and the types the caller keeps between rounds.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{FolderId, ItemId, Result, random};

/// Random 128-bit identifier of one device that syncs a vault. Made once per device and kept
/// in its device state; never secret.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    pub fn generate() -> Result<Self> {
        random::array().map(Self)
    }

    /// The all-zero id of a vault that was never synced.
    pub fn is_none(&self) -> bool {
        self.0 == [0; 16]
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Lowercase hex form (32 characters), as used in a copy's file name.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses the hex form produced by [`DeviceId::to_hex`].
    pub fn from_hex(text: &str) -> Option<Self> {
        ItemId::from_hex(text).map(|id| Self(*id.as_bytes()))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.to_hex())
    }
}

/// A device allowed to write copies of this vault (format v7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDevice {
    pub id: DeviceId,
    /// Chosen by the person ("Desktop", "Phone"); at most 60 characters.
    pub name: String,
    /// Ed25519 public key with which it signs requests to a sync server.
    pub signing_key: Option<[u8; 32]>,
    /// Unix seconds.
    pub added_at: i64,
}

impl SyncDevice {
    pub const MAX_NAME_CHARS: usize = 60;
}

/// What a tombstone stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Gone {
    Item,
    Folder,
    Device,
}

/// Something deleted, kept so that a copy which still has it does not bring it back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Tombstone {
    pub(crate) id: [u8; 16],
    pub(crate) kind: Gone,
    pub(crate) deleted_at: i64,
}

/// Tombstones older than this are dropped (SYNC.md §4.2).
pub(crate) const TOMBSTONE_DAYS: i64 = 400;

/// The part of a v7 body that sync needs: who wrote it, what was deleted, and when each part
/// that is not an item last changed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SyncState {
    /// The device that wrote this copy (zero: never synced).
    pub(crate) writer: DeviceId,
    pub(crate) tombstones: Vec<Tombstone>,
    /// When each folder last changed (Unix seconds); a folder missing here counts as 0.
    pub(crate) folder_times: Vec<(FolderId, i64)>,
    /// When the folders were last put in another order.
    pub(crate) order_changed_at: i64,
    pub(crate) settings_changed_at: i64,
    /// +1 on every change to the key slots or the password hashing.
    pub(crate) unlock_revision: u64,
    /// +1 on every change to the item lock.
    pub(crate) guard_revision: u64,
    /// Which guard key sealed this copy's guarded items (see [`guard_key_id`]); zero for none.
    pub(crate) guard_key_id: [u8; 8],
    pub(crate) devices: Vec<SyncDevice>,
    /// For each item, the versions its current one was made from, newest first (see
    /// [`record_digest`]): a copy whose item is listed here is older, not a concurrent edit.
    pub(crate) lineage: Vec<(ItemId, Vec<[u8; 8]>)>,
}

/// How many earlier versions of an item are remembered.
pub(crate) const LINEAGE: usize = 8;

/// A short name for one stored version of an item (its record's ciphertext, which is new for
/// every version and copied unchanged between devices).
pub(crate) fn record_digest(data: &[u8]) -> [u8; 8] {
    let digest = Sha256::new()
        .chain_update(b"vault-v0/record")
        .chain_update(data)
        .finalize();
    let mut id = [0; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

impl SyncState {
    pub(crate) fn lineage(&self, id: &ItemId) -> &[[u8; 8]] {
        self.lineage
            .iter()
            .find(|(item, _)| item == id)
            .map_or(&[], |(_, versions)| versions.as_slice())
    }

    /// Item `id` was replaced by a new version: remember the one it was made from.
    pub(crate) fn descend(&mut self, id: ItemId, from: [u8; 8]) {
        let mut versions = vec![from];
        versions.extend(self.lineage(&id).iter().copied().filter(|v| *v != from));
        self.set_lineage(id, versions);
    }

    pub(crate) fn set_lineage(&mut self, id: ItemId, mut versions: Vec<[u8; 8]>) {
        versions.truncate(LINEAGE);
        self.lineage.retain(|(item, _)| *item != id);
        if !versions.is_empty() {
            self.lineage.push((id, versions));
        }
    }

    pub(crate) fn forget_item(&mut self, id: &ItemId) {
        self.lineage.retain(|(item, _)| item != id);
    }

    pub(crate) fn folder_time(&self, id: &FolderId) -> i64 {
        self.folder_times
            .iter()
            .find(|(folder, _)| folder == id)
            .map_or(0, |(_, at)| *at)
    }

    pub(crate) fn touch_folder(&mut self, id: FolderId, at: i64) {
        match self
            .folder_times
            .iter_mut()
            .find(|(folder, _)| *folder == id)
        {
            Some(entry) => entry.1 = entry.1.max(at),
            None => self.folder_times.push((id, at)),
        }
    }

    pub(crate) fn tombstone(&self, kind: Gone, id: &[u8; 16]) -> Option<i64> {
        self.tombstones
            .iter()
            .filter(|t| t.kind == kind && t.id == *id)
            .map(|t| t.deleted_at)
            .max()
    }

    pub(crate) fn bury(&mut self, kind: Gone, id: [u8; 16], at: i64) {
        match self
            .tombstones
            .iter_mut()
            .find(|t| t.kind == kind && t.id == id)
        {
            Some(t) => t.deleted_at = t.deleted_at.max(at),
            None => self.tombstones.push(Tombstone {
                id,
                kind,
                deleted_at: at,
            }),
        }
    }

    /// Drops tombstones older than [`TOMBSTONE_DAYS`] before `now`.
    pub(crate) fn prune(&mut self, now: i64) {
        let oldest = now.saturating_sub(TOMBSTONE_DAYS * 86_400);
        self.tombstones.retain(|t| t.deleted_at >= oldest);
    }
}

/// A short, non-secret name for a guard key: equal ids mean the same key.
pub(crate) fn guard_key_id(key: &[u8]) -> [u8; 8] {
    let digest = Sha256::new()
        .chain_update(b"vault-v0/guard-key-id")
        .chain_update(key)
        .finalize();
    let mut id = [0; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

/// What this device has already seen from each other device: the highest revision and the
/// hash of that copy. Kept in device state between rounds (it is not secret), and passed to
/// every [`crate::Vault::merge`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenRevisions(BTreeMap<DeviceId, (u64, [u8; 32])>);

impl SeenRevisions {
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest revision seen from `device`.
    pub fn revision(&self, device: &DeviceId) -> Option<u64> {
        self.0.get(device).map(|(revision, _)| *revision)
    }

    pub(crate) fn get(&self, device: &DeviceId) -> Option<&(u64, [u8; 32])> {
        self.0.get(device)
    }

    pub(crate) fn note(&mut self, device: DeviceId, revision: u64, hash: [u8; 32]) {
        self.0.insert(device, (revision, hash));
    }

    /// Forgets a device (removed from the vault, or added again after a reset).
    pub fn forget(&mut self, device: &DeviceId) {
        self.0.remove(device);
    }
}

/// What a merge changed here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// The device whose copy was folded in.
    pub writer: DeviceId,
    /// Items that came from the other copy, new or newer.
    pub added: usize,
    pub updated: usize,
    /// Items deleted on the other device.
    pub removed: usize,
    /// Items changed on both devices: the newer version was kept, and the other password
    /// went into its history. Their ids, to point the person at them.
    pub conflicts: Vec<ItemId>,
    /// Items changed on both devices that can't be folded while the item lock is closed: this
    /// copy keeps its own version until the lock is opened and the merge runs again.
    pub waiting_for_lock: usize,
    /// The other copy brought a newer master password, keyfile or Recovery Key: the next
    /// unlock needs what was set on that device.
    pub unlock_changed: bool,
    /// The other copy brought a newer item lock.
    pub guard_changed: bool,
    /// Folders, their order, the vault's settings or its devices changed.
    pub other_changed: bool,
}

impl MergeReport {
    /// Whether anything changed here, so the vault must be saved.
    pub fn changed(&self) -> bool {
        self.added + self.updated + self.removed > 0
            || !self.conflicts.is_empty()
            || self.unlock_changed
            || self.guard_changed
            || self.other_changed
    }
}
