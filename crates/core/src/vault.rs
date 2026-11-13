//! The unlocked vault: open, modify, and serialize (spec: VAULT_FORMAT.md).

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Error, Folder, FolderId, ItemData, ItemId, ItemSummary, KdfParams, RecoveryKey, Result,
    SecretKey, VaultSettings, aead,
    format::{
        self, ItemRecord, KeySlot, SlotKind, VaultBody, VaultBodyV0, VaultBodyV1, VaultBodyV2,
        VaultHeader,
    },
    item::{FolderV1, ItemDataV0, ItemDataV1, ItemDataV2, PasswordChange},
    keys::{self, VaultKey},
    padding,
};

const SUBKEY_BODY: &[u8] = b"body";
const SUBKEY_ITEM_WRAP: &[u8] = b"item-wrap";

/// How to unlock a vault.
pub enum Unlock<'a> {
    /// Master password + Secret Key (normal use).
    Password {
        password: &'a str,
        secret_key: &'a SecretKey,
    },
    /// Recovery Key from the emergency kit.
    Recovery(&'a RecoveryKey),
}

impl fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unlock::Password { .. } => f.write_str("Unlock::Password(<redacted>)"),
            Unlock::Recovery(_) => f.write_str("Unlock::Recovery(<redacted>)"),
        }
    }
}

/// Public header information, readable without credentials (see [`Vault::inspect`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub id_hex: String,
    pub kdf: KdfParams,
    pub has_recovery_key: bool,
}

/// An unlocked vault. Items stay encrypted in memory; each one is decrypted only when asked for.
pub struct Vault {
    header: VaultHeader,
    vault_key: VaultKey,
    revision: u64,
    items: Vec<ItemRecord>,
    folders: Vec<Folder>,
    settings: VaultSettings,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &hex(&self.header.vault_id))
            .field("revision", &self.revision)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a new, empty vault protected by the master password + Secret Key, and optionally
    /// by a Recovery Key.
    pub fn create(
        password: &str,
        secret_key: &SecretKey,
        recovery_key: Option<&RecoveryKey>,
        kdf: KdfParams,
    ) -> Result<Self> {
        kdf.validate()?;
        let vault_id: [u8; 16] = crate::random::array()?;
        let vault_key = VaultKey::generate()?;
        let mut vault = Self {
            header: VaultHeader {
                vault_id,
                kdf,
                slots: Vec::new(),
            },
            vault_key,
            revision: 0,
            items: Vec::new(),
            folders: Vec::new(),
            settings: VaultSettings::default(),
        };
        let slot = vault.password_slot(password, secret_key, &vault.header.kdf)?;
        vault.header.slots.push(slot);
        if let Some(recovery_key) = recovery_key {
            let slot = vault.recovery_slot(recovery_key)?;
            vault.header.slots.push(slot);
        }
        Ok(vault)
    }

    /// Parses and decrypts a vault file.
    pub fn open(bytes: &[u8], unlock: Unlock<'_>) -> Result<Self> {
        let parsed = format::parse(bytes)?;
        let header = &parsed.header;
        let (kind, kek) = match unlock {
            Unlock::Password {
                password,
                secret_key,
            } => (
                SlotKind::Password,
                keys::password_kek(password, secret_key, &header.kdf, &header.vault_id)?,
            ),
            Unlock::Recovery(recovery_key) => (
                SlotKind::Recovery,
                keys::recovery_kek(recovery_key, &header.vault_id),
            ),
        };
        let slot = header.slot(kind).ok_or(Error::NoMatchingSlot)?;
        let key_bytes = aead::open(
            &kek,
            &slot.wrapped_vault_key,
            &slot_aad(&header.vault_id, kind),
        )?;
        Self::from_parsed(parsed, VaultKey::from_slice(&key_bytes)?)
    }

    /// Opens the vault with a device unlock made by [`Vault::seal_for_device`] on this device.
    ///
    /// Fails with [`Error::DecryptionFailed`] when the device secret is different or when the
    /// master password was changed since (here or on another device): the device unlock is
    /// bound to the current password slot, so changing the password revokes it.
    pub fn open_with_device(bytes: &[u8], device_secret: &[u8], sealed: &[u8]) -> Result<Self> {
        let parsed = format::parse(bytes)?;
        let kek = keys::device_kek(device_secret, &parsed.header.vault_id)?;
        let key_bytes = aead::open(&kek, sealed, &device_aad(&parsed.header)?)?;
        Self::from_parsed(parsed, VaultKey::from_slice(&key_bytes)?)
    }

    /// Wraps the vault key for quick unlock on this device (Windows Hello and similar).
    /// The result is kept on the device, never in the vault file, and is useless without
    /// `device_secret`, which only the device's secure hardware can produce again.
    pub fn seal_for_device(&self, device_secret: &[u8]) -> Result<Vec<u8>> {
        let kek = keys::device_kek(device_secret, &self.header.vault_id)?;
        aead::seal(&kek, self.vault_key.as_bytes(), &device_aad(&self.header)?)
    }

    fn from_parsed(parsed: format::ParsedFile<'_>, vault_key: VaultKey) -> Result<Self> {
        let header = &parsed.header;
        let body_key = vault_key.subkey(SUBKEY_BODY, &header.vault_id);
        let padded = aead::open(&body_key, parsed.body, &body_aad(parsed.header_bytes))?;
        let plain = padding::unpad(&padded)?;
        let body: VaultBody = match parsed.version {
            0 => {
                let old: VaultBodyV0 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: Vec::new(),
                    settings: VaultSettings::default(),
                }
            }
            1 => {
                let old: VaultBodyV1 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders.into_iter().map(FolderV1::upgrade).collect(),
                    settings: VaultSettings::default(),
                }
            }
            2 => {
                let old: VaultBodyV2 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders.into_iter().map(FolderV1::upgrade).collect(),
                    settings: old.settings,
                }
            }
            _ => format::decode_exact(plain)?,
        };

        let mut ids: Vec<ItemId> = body.items.iter().map(|record| record.id).collect();
        ids.sort_unstable();
        let mut folder_ids: Vec<FolderId> = body.folders.iter().map(|f| f.id).collect();
        folder_ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1])
            || folder_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(Error::Malformed);
        }

        let mut vault = Self {
            header: parsed.header,
            vault_key,
            revision: body.revision,
            items: body.items,
            folders: body.folders,
            settings: body.settings,
        };
        if parsed.version < format::FORMAT_VERSION {
            vault.upgrade_items(parsed.version)?;
        }
        Ok(vault)
    }

    /// Re-encrypts every item from an older layout into the current one, keeping ids and
    /// revisions. Runs in memory when an older file is opened; the next save writes the
    /// current format.
    fn upgrade_items(&mut self, version: u16) -> Result<()> {
        for index in 0..self.items.len() {
            let padded = self.decrypt_item(&self.items[index])?;
            let plain = padding::unpad(&padded)?;
            let item = match version {
                0 => format::decode_exact::<ItemDataV0>(plain)?.upgrade(),
                1 => format::decode_exact::<ItemDataV1>(plain)?.upgrade(),
                2 => format::decode_exact::<ItemDataV2>(plain)?.upgrade(),
                _ => return Err(Error::Malformed),
            };
            let (id, revision) = (self.items[index].id, self.items[index].revision);
            self.items[index] = self.seal_item(id, revision, &item)?;
        }
        Ok(())
    }

    // ---- settings ----

    /// Settings kept inside this vault.
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// Replaces the vault's settings. Lowering the history limit trims every item's history
    /// on its next change, not now.
    pub fn set_settings(&mut self, settings: VaultSettings) -> Result<()> {
        let name = settings.name.trim();
        if name.chars().count() > VaultSettings::MAX_NAME_CHARS
            || name.chars().any(char::is_control)
            || settings.history_limit > VaultSettings::MAX_HISTORY_LIMIT
        {
            return Err(Error::InvalidName);
        }
        self.settings = VaultSettings {
            name: name.to_owned(),
            ..settings
        };
        Ok(())
    }

    // ---- folders ----

    /// Folders, in the order they were created.
    pub fn folders(&self) -> &[Folder] {
        &self.folders
    }

    /// Creates a folder. Names are trimmed; empty names are refused.
    pub fn add_folder(&mut self, name: &str) -> Result<FolderId> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::InvalidName);
        }
        let id = loop {
            let candidate = FolderId::generate()?;
            if !self.folders.iter().any(|f| f.id == candidate) {
                break candidate;
            }
        };
        self.folders.push(Folder {
            id,
            name: name.to_owned(),
            icon: String::new(),
            color: 0,
        });
        Ok(id)
    }

    pub fn rename_folder(&mut self, id: &FolderId, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::InvalidName);
        }
        let folder = self
            .folders
            .iter_mut()
            .find(|f| f.id == *id)
            .ok_or(Error::FolderNotFound)?;
        folder.name = name.to_owned();
        Ok(())
    }

    /// Sets a folder's icon (an icon name, "" for the plain folder) and colour (0 = default).
    pub fn style_folder(&mut self, id: &FolderId, icon: &str, color: u8) -> Result<()> {
        if icon.chars().count() > Folder::MAX_ICON_CHARS
            || !icon.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || color > Folder::MAX_COLOR
        {
            return Err(Error::InvalidName);
        }
        let folder = self
            .folders
            .iter_mut()
            .find(|f| f.id == *id)
            .ok_or(Error::FolderNotFound)?;
        folder.icon = icon.to_owned();
        folder.color = color;
        Ok(())
    }

    /// Deletes a folder. Its items are kept and simply leave the folder.
    pub fn remove_folder(&mut self, id: &FolderId) -> Result<()> {
        let index = self
            .folders
            .iter()
            .position(|f| f.id == *id)
            .ok_or(Error::FolderNotFound)?;
        let ids: Vec<ItemId> = self.items.iter().map(|record| record.id).collect();
        for item_id in ids {
            let mut data = self.get_item(&item_id)?;
            if data.folder == Some(*id) {
                data.folder = None;
                self.update_item(&item_id, &data)?;
            }
        }
        self.folders.remove(index);
        Ok(())
    }

    /// Reads the public, unencrypted header information without unlocking.
    pub fn inspect(bytes: &[u8]) -> Result<VaultInfo> {
        let parsed = format::parse(bytes)?;
        Ok(VaultInfo {
            id_hex: hex(&parsed.header.vault_id),
            has_recovery_key: parsed.header.slot(SlotKind::Recovery).is_some(),
            kdf: parsed.header.kdf,
        })
    }

    /// Serializes the vault into file bytes. Increments the vault revision.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        let next_revision = self.revision.checked_add(1).ok_or(Error::Malformed)?;
        let header_bytes = format::encode_header(&self.header)?;
        let body = VaultBody {
            revision: next_revision,
            items: self.items.clone(),
            folders: self.folders.clone(),
            settings: self.settings.clone(),
        };
        let encoded = postcard::to_allocvec(&body).map_err(|_| Error::Malformed)?;
        let padded = padding::pad(&encoded, padding::body_bucket)?;
        let body_key = self.vault_key.subkey(SUBKEY_BODY, &self.header.vault_id);
        let sealed = aead::seal(&body_key, &padded, &body_aad(&header_bytes))?;
        let bytes = format::assemble(&header_bytes, &sealed)?;
        self.revision = next_revision;
        Ok(bytes)
    }

    /// Encrypts data that belongs to this vault but is kept outside the vault file on this
    /// device, such as a cache of website icons. Bound to this vault and to `purpose`.
    pub fn seal_local(&self, purpose: &str, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.local_key(purpose);
        aead::seal(&key, data, &local_aad(&self.header.vault_id, purpose))
    }

    /// Decrypts data produced by [`Vault::seal_local`] with the same `purpose`.
    pub fn open_local(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.local_key(purpose);
        aead::open(&key, sealed, &local_aad(&self.header.vault_id, purpose))
    }

    fn local_key(&self, purpose: &str) -> Zeroizing<aead::Key> {
        let label = [b"local/".as_slice(), purpose.as_bytes()].concat();
        self.vault_key.subkey(&label, &self.header.vault_id)
    }

    /// Random identifier of this vault, as hex.
    pub fn id_hex(&self) -> String {
        hex(&self.header.vault_id)
    }

    /// Incremented on every save; compare with the last value seen to detect rollbacks.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn kdf_params(&self) -> &KdfParams {
        &self.header.kdf
    }

    pub fn has_recovery_key(&self) -> bool {
        self.header.slot(SlotKind::Recovery).is_some()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn item_ids(&self) -> impl Iterator<Item = ItemId> + '_ {
        self.items.iter().map(|record| record.id)
    }

    /// Adds an item and returns its new id.
    pub fn add_item(&mut self, data: &ItemData) -> Result<ItemId> {
        let id = loop {
            let candidate = ItemId::generate()?;
            if self.position(&candidate).is_none() {
                break candidate;
            }
        };
        let mut data = data.clone();
        if data.password_changed_at == 0 && !data.password.is_empty() {
            data.password_changed_at = data.created_at;
        }
        let record = self.seal_item(id, 1, &data)?;
        self.items.push(record);
        Ok(id)
    }

    /// Decrypts one item.
    pub fn get_item(&self, id: &ItemId) -> Result<ItemData> {
        let record = &self.items[self.position(id).ok_or(Error::ItemNotFound)?];
        self.open_item(record)
    }

    /// Replaces an item's contents (new item key, revision + 1).
    ///
    /// When the password changes, the old one is added to the item's password history (up to
    /// the vault's history limit, oldest dropped first) and `password_changed_at` is set to
    /// now; the history passed in `data` is replaced by the stored one in that case.
    pub fn update_item(&mut self, id: &ItemId, data: &ItemData) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        let old = self.open_item(&self.items[index])?;
        let mut data = data.clone();
        if old.password != data.password {
            let mut history = old.password_history.clone();
            if !old.password.is_empty() {
                history.push(PasswordChange {
                    password: old.password.clone(),
                    replaced_at: crate::item::unix_now(),
                });
            }
            let limit = usize::from(self.settings.history_limit);
            let excess = history.len().saturating_sub(limit);
            history.drain(..excess);
            data.password_history = history;
            data.password_changed_at = crate::item::unix_now();
        }
        self.items[index] = self.seal_item(*id, revision, &data)?;
        Ok(())
    }

    /// Forgets an item's earlier passwords.
    pub fn clear_password_history(&mut self, id: &ItemId) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let mut item = self.open_item(&self.items[index])?;
        if item.password_history.is_empty() {
            return Ok(());
        }
        item.password_history.clear();
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        self.items[index] = self.seal_item(*id, revision, &item)?;
        Ok(())
    }

    pub fn remove_item(&mut self, id: &ItemId) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        self.items.remove(index);
        Ok(())
    }

    /// Decrypts every item into a non-secret summary (title, username, first URL).
    pub fn summaries(&self) -> Result<Vec<ItemSummary>> {
        self.items
            .iter()
            .map(|record| {
                let data = self.open_item(record)?;
                Ok(ItemSummary::from_data(record.id, &data))
            })
            .collect()
    }

    /// Re-protects the vault with a new master password and/or Secret Key and KDF cost.
    /// The vault key and items are unchanged; only the password slot is rewritten.
    pub fn change_password(
        &mut self,
        new_password: &str,
        secret_key: &SecretKey,
        kdf: &KdfParams,
    ) -> Result<()> {
        let kdf = kdf.with_fresh_salt()?;
        let slot = self.password_slot(new_password, secret_key, &kdf)?;
        self.header.kdf = kdf;
        self.header.slots.retain(|s| s.kind != SlotKind::Password);
        self.header.slots.insert(0, slot);
        Ok(())
    }

    /// Adds, replaces or (with `None`) removes the recovery slot.
    pub fn set_recovery_key(&mut self, recovery_key: Option<&RecoveryKey>) -> Result<()> {
        let slot = recovery_key
            .map(|key| self.recovery_slot(key))
            .transpose()?;
        self.header.slots.retain(|s| s.kind != SlotKind::Recovery);
        if let Some(slot) = slot {
            self.header.slots.push(slot);
        }
        Ok(())
    }

    fn position(&self, id: &ItemId) -> Option<usize> {
        self.items.iter().position(|record| record.id == *id)
    }

    fn password_slot(
        &self,
        password: &str,
        secret_key: &SecretKey,
        kdf: &KdfParams,
    ) -> Result<KeySlot> {
        let vault_id = &self.header.vault_id;
        let kek = keys::password_kek(password, secret_key, kdf, vault_id)?;
        self.wrap_vault_key(&kek, SlotKind::Password)
    }

    fn recovery_slot(&self, recovery_key: &RecoveryKey) -> Result<KeySlot> {
        let kek = keys::recovery_kek(recovery_key, &self.header.vault_id);
        self.wrap_vault_key(&kek, SlotKind::Recovery)
    }

    fn wrap_vault_key(&self, kek: &aead::Key, kind: SlotKind) -> Result<KeySlot> {
        let wrapped = aead::seal(
            kek,
            self.vault_key.as_bytes(),
            &slot_aad(&self.header.vault_id, kind),
        )?;
        Ok(KeySlot {
            kind,
            wrapped_vault_key: wrapped,
        })
    }

    fn seal_item(&self, id: ItemId, revision: u64, data: &ItemData) -> Result<ItemRecord> {
        let vault_id = &self.header.vault_id;
        let item_key = crate::random::secret_array::<{ aead::KEY_LEN }>()?;
        let wrap_key = self.vault_key.subkey(SUBKEY_ITEM_WRAP, vault_id);
        let wrapped_key = aead::seal(&wrap_key, item_key.as_ref(), &item_key_aad(vault_id, &id))?;

        let encoded = format::encode_secret(data)?;
        let padded = padding::pad(&encoded, padding::item_bucket)?;
        let sealed = aead::seal(&item_key, &padded, &item_aad(vault_id, &id, revision))?;
        Ok(ItemRecord {
            id,
            revision,
            wrapped_key,
            data: sealed,
        })
    }

    fn open_item(&self, record: &ItemRecord) -> Result<ItemData> {
        let padded = self.decrypt_item(record)?;
        format::decode_exact(padding::unpad(&padded)?)
    }

    /// The item's padded plaintext (still to be unpadded and decoded).
    fn decrypt_item(&self, record: &ItemRecord) -> Result<Zeroizing<Vec<u8>>> {
        let vault_id = &self.header.vault_id;
        let wrap_key = self.vault_key.subkey(SUBKEY_ITEM_WRAP, vault_id);
        let key_bytes = aead::open(
            &wrap_key,
            &record.wrapped_key,
            &item_key_aad(vault_id, &record.id),
        )?;
        let item_key: Zeroizing<aead::Key> = Zeroizing::new(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Malformed)?,
        );
        aead::open(
            &item_key,
            &record.data,
            &item_aad(vault_id, &record.id, record.revision),
        )
    }
}

fn slot_aad(vault_id: &[u8; 16], kind: SlotKind) -> Vec<u8> {
    [b"vault-v0/slot".as_slice(), vault_id, &[kind.aad_byte()]].concat()
}

fn body_aad(header_bytes: &[u8]) -> Vec<u8> {
    [b"vault-v0/body".as_slice(), header_bytes].concat()
}

fn item_key_aad(vault_id: &[u8; 16], id: &ItemId) -> Vec<u8> {
    [b"vault-v0/item-key".as_slice(), vault_id, id.as_bytes()].concat()
}

fn item_aad(vault_id: &[u8; 16], id: &ItemId, revision: u64) -> Vec<u8> {
    [
        b"vault-v0/item".as_slice(),
        vault_id,
        id.as_bytes(),
        &revision.to_le_bytes(),
    ]
    .concat()
}

/// Binds a device unlock to the vault and to the current password slot.
fn device_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let slot = header
        .slot(SlotKind::Password)
        .ok_or(Error::NoMatchingSlot)?;
    let slot_hash = Sha256::digest(&slot.wrapped_vault_key);
    Ok([
        b"vault-v0/device".as_slice(),
        &header.vault_id,
        slot_hash.as_slice(),
    ]
    .concat())
}

fn local_aad(vault_id: &[u8; 16], purpose: &str) -> Vec<u8> {
    [b"vault-v0/local".as_slice(), vault_id, purpose.as_bytes()].concat()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_vault() -> (Vault, RecoveryKey) {
        let secret_key = SecretKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let vault = Vault::create(
            "correct horse battery staple",
            &secret_key,
            Some(&recovery_key),
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        (vault, recovery_key)
    }

    /// Rebuilds a file with a modified header but the original body (an attacker's edit).
    fn with_header(bytes: &[u8], edit: impl FnOnce(&mut VaultHeader)) -> Vec<u8> {
        let parsed = format::parse(bytes).unwrap();
        let mut header = parsed.header.clone();
        edit(&mut header);
        let header_bytes = format::encode_header(&header).unwrap();
        format::assemble(&header_bytes, parsed.body).unwrap()
    }

    #[test]
    fn kdf_downgrade_is_rejected_before_any_work() {
        let (mut vault, recovery_key) = recovery_vault();
        let bytes = vault.to_bytes().unwrap();
        let downgraded = with_header(&bytes, |h| h.kdf.memory_kib = 1024);
        assert!(matches!(
            Vault::open(&downgraded, Unlock::Recovery(&recovery_key)),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn header_edits_break_the_body() {
        let (mut vault, recovery_key) = recovery_vault();
        let bytes = vault.to_bytes().unwrap();
        // A still-valid header (higher cost, new salt) must not open the old body: the body is
        // bound to the exact header bytes.
        let edited = with_header(&bytes, |h| h.kdf.iterations += 1);
        assert!(matches!(
            Vault::open(&edited, Unlock::Recovery(&recovery_key)),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn swapping_slots_between_kinds_fails() {
        let (mut vault, recovery_key) = recovery_vault();
        let bytes = vault.to_bytes().unwrap();
        // Relabel the recovery slot as the password slot and vice versa.
        let swapped = with_header(&bytes, |h| {
            for slot in &mut h.slots {
                slot.kind = match slot.kind {
                    SlotKind::Password => SlotKind::Recovery,
                    SlotKind::Recovery => SlotKind::Password,
                };
            }
        });
        assert!(Vault::open(&swapped, Unlock::Recovery(&recovery_key)).is_err());
    }

    #[test]
    fn duplicate_or_missing_password_slot_is_malformed() {
        let (mut vault, recovery_key) = recovery_vault();
        let bytes = vault.to_bytes().unwrap();
        let no_password = with_header(&bytes, |h| h.slots.retain(|s| s.kind != SlotKind::Password));
        assert!(matches!(
            Vault::open(&no_password, Unlock::Recovery(&recovery_key)),
            Err(Error::Malformed)
        ));
        let duplicated = with_header(&bytes, |h| {
            let slot = h.slots[0].clone();
            h.slots.push(slot);
        });
        assert!(matches!(
            Vault::open(&duplicated, Unlock::Recovery(&recovery_key)),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn item_records_cannot_be_swapped() {
        let (mut vault, _) = recovery_vault();
        let a = vault
            .add_item(&ItemData::login("A", "a", "pa", ""))
            .unwrap();
        let b = vault
            .add_item(&ItemData::login("B", "b", "pb", ""))
            .unwrap();
        // Swap the encrypted payloads of two items (keeping ids): both must fail to decrypt.
        let (ia, ib) = (vault.position(&a).unwrap(), vault.position(&b).unwrap());
        let data_a = vault.items[ia].data.clone();
        vault.items[ia].data = vault.items[ib].data.clone();
        vault.items[ib].data = data_a;
        assert!(vault.get_item(&a).is_err());
        assert!(vault.get_item(&b).is_err());
    }

    #[test]
    fn device_unlock_opens_and_is_revoked_by_a_password_change() {
        let secret_key = SecretKey::generate().unwrap();
        let mut vault = Vault::create(
            "device unlock test passphrase",
            &secret_key,
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let item = vault
            .add_item(&ItemData::login("Site", "me", "pw", "https://site.example"))
            .unwrap();
        let bytes = vault.to_bytes().unwrap();
        let device_secret = [7u8; 256];
        let sealed = vault.seal_for_device(&device_secret).unwrap();

        let opened = Vault::open_with_device(&bytes, &device_secret, &sealed).unwrap();
        assert_eq!(opened.get_item(&item).unwrap().title, "Site");

        let mut other_secret = device_secret;
        other_secret[0] ^= 1;
        assert!(matches!(
            Vault::open_with_device(&bytes, &other_secret, &sealed),
            Err(Error::DecryptionFailed)
        ));
        assert!(
            vault.seal_for_device(&[1u8; 16]).is_err(),
            "short device secrets are refused"
        );

        // Another vault cannot use it.
        let mut stranger = Vault::create(
            "device unlock test passphrase",
            &secret_key,
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let stranger_bytes = stranger.to_bytes().unwrap();
        assert!(Vault::open_with_device(&stranger_bytes, &device_secret, &sealed).is_err());

        // Changing the master password revokes every device unlock.
        let kdf = vault.kdf_params().clone();
        vault
            .change_password("a brand new passphrase", &secret_key, &kdf)
            .unwrap();
        let changed = vault.to_bytes().unwrap();
        assert!(matches!(
            Vault::open_with_device(&changed, &device_secret, &sealed),
            Err(Error::DecryptionFailed)
        ));
        let resealed = vault.seal_for_device(&device_secret).unwrap();
        assert!(Vault::open_with_device(&changed, &device_secret, &resealed).is_ok());
    }

    #[test]
    fn local_data_is_bound_to_vault_and_purpose() {
        let (vault, _) = recovery_vault();
        let (other, _) = recovery_vault();
        let sealed = vault.seal_local("icons", b"cache bytes").unwrap();
        assert_eq!(
            vault.open_local("icons", &sealed).unwrap().as_slice(),
            b"cache bytes"
        );
        assert!(vault.open_local("other-purpose", &sealed).is_err());
        assert!(other.open_local("icons", &sealed).is_err());
    }

    #[test]
    fn item_revision_rollback_is_detected() {
        let (mut vault, _) = recovery_vault();
        let id = vault
            .add_item(&ItemData::login("A", "a", "old", ""))
            .unwrap();
        let old_record = vault.items[0].clone();
        vault
            .update_item(&id, &ItemData::login("A", "a", "new", ""))
            .unwrap();
        // Replay the old ciphertext under the new revision number.
        vault.items[0].data = old_record.data;
        vault.items[0].wrapped_key = old_record.wrapped_key;
        assert!(vault.get_item(&id).is_err());
    }
}
