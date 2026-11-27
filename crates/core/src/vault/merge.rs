//! Folding another device's copy of this vault into this one (SYNC.md §4).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{Vault, secrets_aad};
use crate::{
    Error, Folder, FolderId, GuardCheck, ItemData, ItemGuard, ItemId, Result, aead,
    format::{self, ItemRecord},
    guard::GuardSlot,
    item::PasswordChange,
    memory::ShieldedKey,
    padding,
    sync::{DeviceId, Gone, MergeReport, SeenRevisions, guard_key_id, record_digest},
};

/// The id of a guard key no copy has named: no lock, or one from before format v7.
const NO_KEY_ID: [u8; 8] = [0; 8];

/// A newer item lock from another device's copy, sealed under a key this copy doesn't have,
/// while this copy holds items sealed under its own. Taking it would leave those items with
/// no seal at all (only the vault key) until the new lock opens here, in this copy and in
/// every copy written meanwhile; so it waits here, in memory, until its key is open too: the
/// new lock's PIN or password, or the master password, typed on this device (the item
/// lock's own `unlock_guard*`). The next merge then moves the items from one key to the
/// other directly.
///
/// With several devices on several newer locks, the newest of them is the one that waits: the
/// others are older than the lock this copy will end up with.
#[derive(Clone)]
pub(crate) struct IncomingGuard {
    guard: ItemGuard,
    /// Its guard revision.
    pub(super) revision: u64,
    key_id: [u8; 8],
    /// The device whose copy brought it.
    writer: DeviceId,
    /// Its key, once opened here (encrypted between uses, as the guard key is).
    pub(crate) key: Option<ShieldedKey>,
}

/// Which of two item locks is newer: the revision, then the bytes (so every device picks the
/// same one of two set at the same time).
fn guard_rank(revision: u64, guard: &ItemGuard) -> Result<(u64, Vec<u8>)> {
    Ok((
        revision,
        postcard::to_allocvec(guard).map_err(|_| Error::Malformed)?,
    ))
}

impl Vault {
    /// The waiting item lock, while it is newer than this copy's own (which may have changed
    /// since it came).
    fn waiting_guard(&self) -> Option<&IncomingGuard> {
        let incoming = self.incoming_guard.as_ref()?;
        let newer = guard_rank(incoming.revision, &incoming.guard).ok()?;
        let own = guard_rank(self.sync.guard_revision, &self.guard).ok()?;
        (newer > own).then_some(incoming)
    }

    /// Tries `secret` on the waiting item lock (see [`IncomingGuard`]); whether it opened.
    pub(super) fn open_incoming_guard(&mut self, secret: &str, slot: GuardSlot) -> Result<bool> {
        let Some(incoming) = self.waiting_guard() else {
            return Ok(false);
        };
        let wrapped = incoming.guard.key.as_ref().and_then(|slots| match slot {
            GuardSlot::Check => Some(&slots.check),
            GuardSlot::Master => slots.master.as_ref(),
        });
        let key = wrapped
            .map(|wrapped| wrapped.unwrap(secret, &self.header.vault_id, slot))
            .transpose()?
            .flatten();
        // A lock from before format v7 says no key id: the key that opened it is its key.
        let named = incoming.key_id;
        let Some(key) = key.filter(|key| named == NO_KEY_ID || guard_key_id(key.as_ref()) == named)
        else {
            return Ok(false);
        };
        if let Some(incoming) = self.incoming_guard.as_mut() {
            incoming.key = Some(ShieldedKey::new(key));
        }
        Ok(true)
    }

    /// Whether a newer item lock from another device waits here for this copy's items to move
    /// to it: for its key (its PIN or password, or the master password), or for this copy's
    /// own lock to be open.
    pub fn guard_waiting(&self) -> bool {
        self.waiting_guard().is_some()
    }

    /// What opens the newer item lock that waits ([`Vault::guard_waiting`]): its PIN or its
    /// password. The master password when it encrypts nothing: the lock was turned off on
    /// another device, and only this copy's own lock is still to be opened.
    pub fn guard_waiting_check(&self) -> Option<GuardCheck> {
        self.waiting_guard().map(|incoming| incoming.guard.check)
    }

    /// Whether both locks are open: the next merge of the other device's copy moves the items.
    pub fn guard_move_ready(&self) -> bool {
        self.guard_key.is_some()
            && self
                .waiting_guard()
                .is_some_and(|incoming| incoming.key.is_some() || !incoming.guard.encrypts())
    }

    /// Remembers `theirs`' item lock as the newer one that waits. The same lock again keeps
    /// its key.
    fn note_incoming_guard(&mut self, theirs: &Vault) {
        let same = self.incoming_guard.as_ref().is_some_and(|known| {
            known.revision == theirs.sync.guard_revision && known.guard == theirs.guard
        });
        if !same {
            self.incoming_guard = Some(IncomingGuard {
                guard: theirs.guard.clone(),
                revision: theirs.sync.guard_revision,
                key_id: theirs.sync.guard_key_id,
                writer: theirs.sync.writer,
                key: None,
            });
        }
    }

    /// Copies from a removed device are refused: a lock that waits from one never comes.
    pub(super) fn drop_lock_of_removed_devices(&mut self) {
        let removed = self.incoming_guard.as_ref().is_some_and(|incoming| {
            let writer = incoming.writer.as_bytes();
            self.sync.tombstone(Gone::Device, writer).is_some()
        });
        if removed {
            self.incoming_guard = None;
        }
    }

    /// Whether both copies seal guarded items under the same key. Copies say which key is
    /// theirs, except for a lock from before format v7 that was not opened or changed since
    /// ([`NO_KEY_ID`]): then the key open here decides, and without one they count as different
    /// keys (the lock is opened first, as for any other key).
    fn same_guard_key(&self, theirs: &Vault) -> Result<bool> {
        let (ours, other) = match (&self.guard.key, &theirs.guard.key) {
            (None, None) => return Ok(true),
            (Some(ours), Some(other)) => (ours, other),
            _ => return Ok(false),
        };
        // The same wrapped copy of the key, by the PIN or by the master password.
        if ours.check == other.check || (ours.master.is_some() && ours.master == other.master) {
            return Ok(true);
        }
        let their_id = theirs.sync.guard_key_id;
        let our_id = match &self.guard_key {
            Some(key) => guard_key_id(key.open().as_ref()),
            None => self.sync.guard_key_id,
        };
        if our_id == their_id {
            return Ok(true);
        }
        if their_id == NO_KEY_ID
            && let Some(key) = &self.guard_key
        {
            for record in &theirs.items {
                if let Some(sealed) = &self.open_visible(record)?.sealed {
                    let aad = secrets_aad(&self.header.vault_id, &record.id);
                    return Ok(aead::open(&key.open(), &sealed.ciphertext, &aad).is_ok());
                }
            }
        }
        Ok(false)
    }
}

/// One side of an item while merging: its record and what can be read of it.
struct Side<'a> {
    record: &'a ItemRecord,
    /// In full, or without its secrets when they are sealed under a key not open here.
    data: ItemData,
    /// Stored with its secrets sealed under the item lock.
    sealed: bool,
    digest: [u8; 8],
    /// The versions this one was made from.
    lineage: Vec<[u8; 8]>,
}

impl Side<'_> {
    fn readable(&self) -> bool {
        self.data.sealed.is_none()
    }

    /// Which of two concurrent versions is newer: revision, then the time of the change, then
    /// the contents without the password history (so every device picks the same one, and a
    /// version that only gained history ranks as the one it came from).
    fn rank(&self) -> Result<(u64, i64, [u8; 32])> {
        let mut plain = self.data.clone();
        plain.password_history.clear();
        let bytes = format::encode_secret(&plain)?;
        Ok((
            self.record.revision,
            self.data.updated_at,
            Sha256::digest(bytes.as_slice()).into(),
        ))
    }
}

impl Vault {
    /// Folds another copy of this vault (a whole vault file written by another device) into
    /// this one. Nothing here is decided by the other copy alone: it is opened with this
    /// vault's own key, and must be newer than anything `seen` from the device that wrote it.
    ///
    /// - Items are matched by id. The newer of two versions wins; when both were changed, the
    ///   other password goes into the winner's history (see [`MergeReport::conflicts`]).
    /// - A deletion on either side is a tombstone: an item missing from one copy is never
    ///   taken as deleted, and an item changed after it was deleted elsewhere is kept.
    /// - The master password and the item lock follow the copy where they changed last.
    ///
    /// On error nothing here has changed (a newer item lock that came with
    /// [`Error::SecretsLocked`] is only remembered, see [`Vault::guard_waiting`]). On success
    /// `seen` records the copy; save the vault when [`MergeReport::changed`].
    ///
    /// # Errors
    /// [`Error::OtherVault`], [`Error::UnsupportedVersion`] for a copy written by another
    /// format version, [`Error::DecryptionFailed`] for a copy not sealed with this vault's
    /// key, [`Error::SyncRollback`] / [`Error::SyncFork`] for a replayed or forked copy,
    /// [`Error::DeviceRemoved`] for a copy from a removed device, [`Error::RemovedHere`] when
    /// the copy says this device was removed, [`Error::SecretsLocked`] when taking the other copy's item lock needs
    /// this one's open first.
    pub fn merge(&mut self, other: &[u8], seen: &mut SeenRevisions) -> Result<MergeReport> {
        let parsed = format::parse(other)?;
        if parsed.header.vault_id != self.header.vault_id {
            return Err(Error::OtherVault);
        }
        if parsed.version != format::FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(parsed.version));
        }
        let theirs = Vault::from_parsed(parsed, self.vault_key.duplicate())?;
        let writer = theirs.sync.writer;
        if writer.is_none() {
            return Err(Error::Malformed);
        }
        if writer == self.sync.writer {
            // This device's own copy, back from the target.
            return Ok(MergeReport {
                writer,
                ..MergeReport::default()
            });
        }
        if self
            .sync
            .tombstone(Gone::Device, writer.as_bytes())
            .is_some()
        {
            return Err(Error::DeviceRemoved);
        }
        let hash: [u8; 32] = Sha256::digest(other).into();
        if let Some((revision, known)) = seen.get(&writer) {
            if theirs.revision < *revision {
                return Err(Error::SyncRollback);
            }
            if theirs.revision == *revision && *known != hash {
                return Err(Error::SyncFork);
            }
        }

        let snapshot = (
            self.header.clone(),
            self.items.clone(),
            self.folders.clone(),
            self.settings.clone(),
            self.guard.clone(),
            self.guard_key.clone(),
            self.sync.clone(),
            self.incoming_guard.clone(),
        );
        match self.fold(&theirs) {
            Ok(mut report) => {
                report.writer = writer;
                seen.note(writer, theirs.revision, hash);
                Ok(report)
            }
            Err(err) => {
                // The newer lock that is why, so the person can be told what to type.
                let waiting = self.incoming_guard.take();
                (
                    self.header,
                    self.items,
                    self.folders,
                    self.settings,
                    self.guard,
                    self.guard_key,
                    self.sync,
                    self.incoming_guard,
                ) = snapshot;
                if matches!(err, Error::SecretsLocked) {
                    self.incoming_guard = waiting;
                }
                Err(err)
            }
        }
    }

    fn fold(&mut self, theirs: &Vault) -> Result<MergeReport> {
        let mut report = MergeReport::default();

        // Tombstones and devices first: they decide what the rest may bring back.
        let tombstones_before = self.sync.tombstones.len();
        for t in &theirs.sync.tombstones {
            self.sync.bury(t.kind, t.id, t.deleted_at);
        }
        if self
            .sync
            .tombstone(Gone::Device, self.sync.writer.as_bytes())
            .is_some()
            && !self.sync.writer.is_none()
        {
            // This device was removed on the other one: it takes nothing more from it.
            return Err(Error::RemovedHere);
        }
        let devices_before = self.sync.devices.clone();
        for device in &theirs.sync.devices {
            match self.sync.devices.iter_mut().find(|d| d.id == device.id) {
                Some(known) => {
                    if (device.added_at, &device.name) > (known.added_at, &known.name) {
                        *known = device.clone();
                    }
                }
                None => self.sync.devices.push(device.clone()),
            }
        }
        let sync = &self.sync;
        let removed: Vec<_> = sync
            .devices
            .iter()
            .filter(|d| sync.tombstone(Gone::Device, d.id.as_bytes()).is_some())
            .map(|d| d.id)
            .collect();
        self.sync.devices.retain(|d| !removed.contains(&d.id));
        self.drop_lock_of_removed_devices();
        report.other_changed |=
            self.sync.devices != devices_before || self.sync.tombstones.len() != tombstones_before;

        self.fold_unlock(theirs, &mut report)?;
        self.fold_guard(theirs, &mut report)?;
        self.fold_items(theirs, &mut report)?;
        self.fold_folders(theirs, &mut report)?;

        let theirs_settings = (
            theirs.sync.settings_changed_at,
            postcard::to_allocvec(&theirs.settings).map_err(|_| Error::Malformed)?,
        );
        let ours_settings = (
            self.sync.settings_changed_at,
            postcard::to_allocvec(&self.settings).map_err(|_| Error::Malformed)?,
        );
        if theirs_settings > ours_settings {
            self.settings = theirs.settings.clone();
            self.sync.settings_changed_at = theirs.sync.settings_changed_at;
            report.other_changed = true;
        }
        self.sync.prune(crate::item::unix_now());
        Ok(report)
    }

    /// The key slots and password hashing: the copy with the higher unlock revision wins.
    fn fold_unlock(&mut self, theirs: &Vault, report: &mut MergeReport) -> Result<()> {
        let ours = (
            self.sync.unlock_revision,
            format::encode_header(&self.header)?,
        );
        let other = (
            theirs.sync.unlock_revision,
            format::encode_header(&theirs.header)?,
        );
        if other > ours {
            self.header = theirs.header.clone();
            self.sync.unlock_revision = theirs.sync.unlock_revision;
            report.unlock_changed = true;
        }
        Ok(())
    }

    /// The item lock: the copy with the higher guard revision wins. When its key is another
    /// one, this copy's sealed items are opened with the key open here and sealed again under
    /// the new key, which must be open here too (see [`IncomingGuard`]). Until it is, the new
    /// lock waits and this copy keeps its own: a sealed item is never stored without its seal.
    ///
    /// A newer lock that encrypts nothing (turned off on another device, with the master
    /// password) has no key to wait for: with this copy's own lock open, it is taken at once.
    fn fold_guard(&mut self, theirs: &Vault, report: &mut MergeReport) -> Result<()> {
        // Not newer than this copy's own any more: its own was changed since.
        if self.waiting_guard().is_none() {
            self.incoming_guard = None;
        }
        let other = guard_rank(theirs.sync.guard_revision, &theirs.guard)?;
        if other <= guard_rank(self.sync.guard_revision, &self.guard)? {
            return Ok(());
        }
        // The lock that waits, when it is this one: its key, if it was opened here.
        let opened = self
            .incoming_guard
            .as_ref()
            .filter(|incoming| {
                incoming.revision == theirs.sync.guard_revision && incoming.guard == theirs.guard
            })
            .and_then(|incoming| incoming.key.clone());
        let key_id = |key: &ShieldedKey| guard_key_id(key.open().as_ref());
        let same_key = self.same_guard_key(theirs)?
            || (opened.is_some()
                && opened.as_ref().map(key_id) == self.guard_key.as_ref().map(key_id));
        let mut reopened = Vec::new();
        if !same_key {
            // An even newer lock waits: the items move to that one.
            if let Some(incoming) = &self.incoming_guard
                && guard_rank(incoming.revision, &incoming.guard)? > other
            {
                return Ok(());
            }
            for (index, record) in self.items.iter().enumerate() {
                if self.open_visible(record)?.sealed.is_none() {
                    continue;
                }
                let data = self.open_item(record)?;
                if data.sealed.is_some() {
                    self.note_incoming_guard(theirs);
                    return Err(Error::SecretsLocked);
                }
                reopened.push((index, data));
            }
        }
        if !reopened.is_empty() && theirs.guard.encrypts() && opened.is_none() {
            self.note_incoming_guard(theirs);
            report.waiting_for_lock += reopened.len();
            return Ok(());
        }
        let key = if same_key {
            self.guard_key.clone()
        } else {
            opened
        };
        self.guard = theirs.guard.clone();
        self.sync.guard_revision = theirs.sync.guard_revision;
        // The key's id when the other copy doesn't say it (see `same_guard_key`).
        self.sync.guard_key_id = match (&self.guard.key, theirs.sync.guard_key_id, &key) {
            (None, _, _) => NO_KEY_ID,
            (Some(_), NO_KEY_ID, Some(key)) => guard_key_id(key.open().as_ref()),
            (Some(_), NO_KEY_ID, None) if same_key => self.sync.guard_key_id,
            (Some(_), named, _) => named,
        };
        if self.waiting_guard().is_none() {
            self.incoming_guard = None;
        }
        if !same_key {
            self.guard_key = key;
            for (index, data) in reopened {
                let record = &self.items[index];
                let record = self.store_item(record.id, record.revision, &data)?;
                self.replace_record(index, record);
            }
        }
        report.guard_changed = true;
        Ok(())
    }

    fn fold_items(&mut self, theirs: &Vault, report: &mut MergeReport) -> Result<()> {
        // Their sealed items open here only under the same guard key.
        let foreign = !self.same_guard_key(theirs)?;
        // While a newer lock waits, what other devices store without a seal (a lock turned off,
        // or one that covers fewer items) doesn't replace a record sealed here: it arrives when
        // this copy takes that lock.
        let lock_waits = self.guard_waiting();
        let theirs_by_id: BTreeMap<ItemId, &ItemRecord> =
            theirs.items.iter().map(|r| (r.id, r)).collect();
        let mut ids: Vec<ItemId> = self.items.iter().map(|r| r.id).collect();
        ids.extend(
            theirs
                .items
                .iter()
                .map(|r| r.id)
                .filter(|id| self.position(id).is_none()),
        );

        let ours_records = std::mem::take(&mut self.items);
        let ours_by_id: BTreeMap<ItemId, &ItemRecord> =
            ours_records.iter().map(|r| (r.id, r)).collect();
        let mut merged = Vec::with_capacity(ids.len());
        for id in ids {
            let ours = ours_by_id
                .get(&id)
                .map(|record| self.side(record, false, self.sync.lineage(&id)))
                .transpose()?;
            let other = theirs_by_id
                .get(&id)
                .map(|record| self.side(record, foreign, theirs.sync.lineage(&id)))
                .transpose()?;
            let deleted = self.sync.tombstone(Gone::Item, id.as_bytes());
            let buried = |side: &Side<'_>| deleted.is_some_and(|at| side.data.updated_at <= at);
            let (ours, other) = match (ours, other) {
                (Some(ours), None) => {
                    if buried(&ours) {
                        self.sync.forget_item(&id);
                        report.removed += 1;
                    } else {
                        merged.push(ours.record.clone());
                    }
                    continue;
                }
                (None, Some(other)) => {
                    if buried(&other) {
                        continue;
                    }
                    if other.sealed && foreign {
                        // Sealed under a key this copy doesn't have: it arrives once the
                        // other device has taken this copy's item lock.
                        report.waiting_for_lock += 1;
                        continue;
                    }
                    self.sync.set_lineage(id, other.lineage.clone());
                    merged.push(other.record.clone());
                    report.added += 1;
                    continue;
                }
                (Some(ours), Some(other)) => (ours, other),
                (None, None) => continue,
            };
            if buried(&ours) && buried(&other) {
                self.sync.forget_item(&id);
                report.removed += 1;
                continue;
            }
            if ours.digest == other.digest {
                merged.push(ours.record.clone());
                continue;
            }
            let unseals = lock_waits && ours.sealed && !other.sealed;
            // One made from the other: the later one, as it is.
            let theirs_later = other.lineage.contains(&ours.digest);
            let ours_later = ours.lineage.contains(&other.digest);
            if theirs_later != ours_later {
                if theirs_later && ((other.sealed && foreign) || unseals) {
                    report.waiting_for_lock += 1;
                    merged.push(ours.record.clone());
                } else if theirs_later {
                    self.sync.set_lineage(id, other.lineage.clone());
                    merged.push(other.record.clone());
                    report.updated += 1;
                } else {
                    merged.push(ours.record.clone());
                }
                continue;
            }
            // Changed on both devices. Both versions are needed in full to keep both
            // passwords; without them this copy keeps its own until the item lock is open.
            if !(ours.readable() && other.readable()) || unseals {
                report.waiting_for_lock += 1;
                merged.push(ours.record.clone());
                continue;
            }
            let (winner, loser) = if ours.rank()? >= other.rank()? {
                (&ours, &other)
            } else {
                (&other, &ours)
            };
            let result = self
                .keep_both_passwords(&winner.data, &loser.data)
                .unwrap_or_else(|| winner.data.clone());
            let mut lineage = vec![ours.digest, other.digest];
            lineage.extend(ours.lineage.iter().chain(&other.lineage).copied());
            lineage.dedup();
            let same_as = |side: &Side<'_>| side.data == result;
            let record = match (same_as(&ours), same_as(&other)) {
                // Two versions with the same contents (each device folded the same edits
                // on its own): every device keeps the one with the smaller digest.
                (true, true) => {
                    if other.digest < ours.digest {
                        other.record.clone()
                    } else {
                        ours.record.clone()
                    }
                }
                (true, false) => ours.record.clone(),
                (false, true) => {
                    report.updated += 1;
                    other.record.clone()
                }
                (false, false) => {
                    report.conflicts.push(id);
                    // Ranked as the winner was, so a third device's edit compares with it
                    // as it would have with the winner.
                    self.restore(id, winner.record.revision, &result)?
                }
            };
            let kept = record_digest(&record.data);
            lineage.retain(|v| *v != kept);
            let mut seen = Vec::new();
            lineage.retain(|v| {
                let first = !seen.contains(v);
                seen.push(*v);
                first
            });
            self.sync.set_lineage(id, lineage);
            merged.push(record);
        }
        self.items = merged;
        Ok(())
    }

    fn side<'a>(
        &self,
        record: &'a ItemRecord,
        foreign: bool,
        lineage: &[[u8; 8]],
    ) -> Result<Side<'a>> {
        let stored = self.open_visible(record)?;
        let sealed = stored.sealed.is_some();
        let data = if foreign || !sealed {
            stored
        } else {
            self.open_item(record)?
        };
        Ok(Side {
            record,
            data,
            sealed,
            digest: record_digest(&record.data),
            lineage: lineage.to_vec(),
        })
    }

    /// The item as stored, its secrets left sealed. Checks the record like any open.
    fn open_visible(&self, record: &ItemRecord) -> Result<ItemData> {
        let padded = self.decrypt_item(record)?;
        format::decode_exact(padding::unpad(&padded)?)
    }

    /// The winner with the loser's password added to its history, when the loser had one the
    /// winner doesn't know. `None` when there is nothing to add.
    fn keep_both_passwords(&self, winner: &ItemData, loser: &ItemData) -> Option<ItemData> {
        let mut history: Vec<PasswordChange> = winner.password_history.clone();
        let known = |history: &[PasswordChange], password: &str| {
            password.is_empty()
                || password == winner.password
                || history.iter().any(|h| h.password == password)
        };
        for old in &loser.password_history {
            if !known(&history, &old.password) {
                history.push(old.clone());
            }
        }
        if !known(&history, &loser.password) {
            history.push(PasswordChange {
                password: loser.password.clone(),
                replaced_at: loser.password_changed_at.max(loser.updated_at),
            });
        }
        if history.len() == winner.password_history.len() {
            return None;
        }
        history.sort_by(|a, b| (a.replaced_at, &a.password).cmp(&(b.replaced_at, &b.password)));
        let limit = usize::from(self.settings.history_limit).max(1);
        let excess = history.len().saturating_sub(limit);
        history.drain(..excess);
        let mut folded = winner.clone();
        folded.password_history = history;
        Some(folded)
    }

    /// Stores an item read in full, sealed under the item lock when the lock covers it and its
    /// key is open, else waiting for it.
    fn restore(&self, id: ItemId, revision: u64, data: &ItemData) -> Result<ItemRecord> {
        if self.needs_unlock_to_store(data) {
            self.seal_item(id, revision, data)
        } else {
            self.store_item(id, revision, data)
        }
    }

    fn fold_folders(&mut self, theirs: &Vault, report: &mut MergeReport) -> Result<()> {
        let rank = |folder: &Folder, at: i64| -> Result<(i64, Vec<u8>)> {
            Ok((
                at,
                postcard::to_allocvec(folder).map_err(|_| Error::Malformed)?,
            ))
        };
        let mut kept: Vec<Folder> = Vec::new();
        let mut ids: Vec<FolderId> = self.folders.iter().map(|f| f.id).collect();
        for folder in &theirs.folders {
            if !ids.contains(&folder.id) {
                ids.push(folder.id);
            }
        }
        for id in &ids {
            let ours = self.folders.iter().find(|f| f.id == *id);
            let other = theirs.folders.iter().find(|f| f.id == *id);
            let ours_at = self.sync.folder_time(id);
            let other_at = theirs.sync.folder_time(id);
            let deleted = self.sync.tombstone(Gone::Folder, id.as_bytes());
            let newest = ours_at.max(other_at);
            if deleted.is_some_and(|at| newest <= at) {
                if ours.is_some() {
                    report.other_changed = true;
                }
                continue;
            }
            let pick = match (ours, other) {
                (Some(ours), Some(other)) => {
                    if rank(other, other_at)? > rank(ours, ours_at)? {
                        report.other_changed = true;
                        other
                    } else {
                        ours
                    }
                }
                (Some(ours), None) => ours,
                (None, Some(other)) => {
                    report.other_changed = true;
                    other
                }
                (None, None) => continue,
            };
            kept.push(pick.clone());
            if newest > 0 {
                self.sync.touch_folder(*id, newest);
            }
        }
        // The order: the copy where it changed last, then any folder it doesn't list.
        let theirs_order = theirs.sync.order_changed_at > self.sync.order_changed_at;
        let base: Vec<FolderId> = if theirs_order {
            report.other_changed = true;
            self.sync.order_changed_at = theirs.sync.order_changed_at;
            theirs.folders.iter().map(|f| f.id).collect()
        } else {
            self.folders.iter().map(|f| f.id).collect()
        };
        let position = |id: &FolderId| base.iter().position(|b| b == id).unwrap_or(usize::MAX);
        kept.sort_by_key(|folder| position(&folder.id));
        self.sync
            .folder_times
            .retain(|(id, _)| kept.iter().any(|f| f.id == *id));
        self.folders = kept;
        Ok(())
    }
}
