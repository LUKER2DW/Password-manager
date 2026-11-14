//! The unlocked vault: open, modify, and serialize (spec: VAULT_FORMAT.md).

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Error, Folder, FolderId, GuardCheck, ItemData, ItemGuard, ItemId, ItemSummary, PasswordKdf,
    RecoveryKey, Result, SecretKey, VaultSettings, aead,
    format::{
        self, ItemRecord, KeySlot, SlotKind, VaultBody, VaultBodyV0, VaultBodyV1, VaultBodyV2,
        VaultBodyV3, VaultBodyV4, VaultBodyV5, VaultHeader,
    },
    guard::{GuardKeySlots, GuardSlot, WrappedGuardKey},
    item::{
        FolderV1, FolderV3, ItemDataV0, ItemDataV1, ItemDataV2, ItemDataV3, ItemDataV5,
        ItemSecrets, PasswordChange, SealedSecrets,
    },
    keys::{self, Keyfile, VaultKey},
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
    /// Master password + Secret Key + keyfile, for vaults that use one.
    PasswordAndKeyfile {
        password: &'a str,
        secret_key: &'a SecretKey,
        keyfile: &'a Keyfile,
    },
    /// Recovery Key from the emergency kit. Opens the vault on its own, keyfile or not.
    Recovery(&'a RecoveryKey),
}

impl fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unlock::Password { .. } => f.write_str("Unlock::Password(<redacted>)"),
            Unlock::PasswordAndKeyfile { .. } => {
                f.write_str("Unlock::PasswordAndKeyfile(<redacted>)")
            }
            Unlock::Recovery(_) => f.write_str("Unlock::Recovery(<redacted>)"),
        }
    }
}

/// Public header information, readable without credentials (see [`Vault::inspect`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub id_hex: String,
    pub kdf: PasswordKdf,
    pub has_recovery_key: bool,
    /// The master password alone doesn't open it: a keyfile is needed too.
    pub needs_keyfile: bool,
}

/// An unlocked vault. Items stay encrypted in memory; each one is decrypted only when asked for.
pub struct Vault {
    header: VaultHeader,
    vault_key: VaultKey,
    revision: u64,
    items: Vec<ItemRecord>,
    folders: Vec<Folder>,
    settings: VaultSettings,
    guard: ItemGuard,
    /// The item guard key, while guarded secrets are open (see [`Vault::unlock_secrets`]).
    guard_key: Option<Zeroizing<aead::Key>>,
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
        kdf: impl Into<PasswordKdf>,
    ) -> Result<Self> {
        let kdf = kdf.into();
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
            guard: ItemGuard::default(),
            guard_key: None,
        };
        let slot = vault.password_slot(password, secret_key, None, &vault.header.kdf)?;
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
            } => {
                // Checked before the slow hash: the answer is in the (public) header.
                if header.slot(SlotKind::PasswordKeyfile).is_some() {
                    return Err(Error::KeyfileRequired);
                }
                (
                    SlotKind::Password,
                    keys::password_kek(password, secret_key, None, &header.kdf, &header.vault_id)?,
                )
            }
            Unlock::PasswordAndKeyfile {
                password,
                secret_key,
                keyfile,
            } => {
                // A vault without a keyfile opens with the password alone; the extra file
                // is simply not used.
                let (kind, keyfile) = if header.slot(SlotKind::PasswordKeyfile).is_some() {
                    (SlotKind::PasswordKeyfile, Some(keyfile))
                } else {
                    (SlotKind::Password, None)
                };
                (
                    kind,
                    keys::password_kek(
                        password,
                        secret_key,
                        keyfile,
                        &header.kdf,
                        &header.vault_id,
                    )?,
                )
            }
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
                    guard: ItemGuard::default(),
                }
            }
            1 => {
                let old: VaultBodyV1 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders.into_iter().map(FolderV1::upgrade).collect(),
                    settings: VaultSettings::default(),
                    guard: ItemGuard::default(),
                }
            }
            2 => {
                let old: VaultBodyV2 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders.into_iter().map(FolderV1::upgrade).collect(),
                    settings: old.settings,
                    guard: ItemGuard::default(),
                }
            }
            3 => {
                let old: VaultBodyV3 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders.into_iter().map(FolderV3::upgrade).collect(),
                    settings: old.settings,
                    guard: ItemGuard::default(),
                }
            }
            4 => {
                let old: VaultBodyV4 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders,
                    settings: old.settings,
                    guard: ItemGuard::default(),
                }
            }
            5 => {
                let old: VaultBodyV5 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders,
                    settings: old.settings,
                    guard: old.guard.upgrade(),
                }
            }
            _ => format::decode_exact(plain)?,
        };
        body.guard.validate()?;

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
            guard: body.guard,
            guard_key: None,
        };
        if parsed.version < format::ITEM_LAYOUT_VERSION {
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
                3 | 4 => format::decode_exact::<ItemDataV3>(plain)?.upgrade(),
                5 => format::decode_exact::<ItemDataV5>(plain)?.upgrade(),
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

    // ---- item guard ----

    /// The second check asked before guarded items show their secrets.
    pub fn item_guard(&self) -> &ItemGuard {
        &self.guard
    }

    /// Changes the item guard: which items it covers and what is typed to pass it.
    ///
    /// `secret` is the new PIN or password (`None` keeps the current one when the kind is
    /// unchanged). With a PIN or password, the secrets of guarded items are encrypted under a
    /// guard key that only that PIN or password unwraps; `master_password`, when given, wraps
    /// a second copy so a forgotten PIN can be replaced (the caller has checked that it is the
    /// vault's master password). With the master password as the check nothing extra is
    /// encrypted.
    ///
    /// When secrets are sealed and not open, `master_password` is used to open them; without
    /// it the call fails with [`Error::SecretsLocked`]. Afterwards the secrets are open.
    pub fn set_item_guard(
        &mut self,
        all_items: bool,
        check: GuardCheck,
        secret: Option<&str>,
        master_password: Option<&str>,
    ) -> Result<()> {
        if let Some(secret) = secret {
            ItemGuard::check_secret(check, secret)?;
        }
        if self.guard.encrypts()
            && self.guard_key.is_none()
            && !master_password
                .map(|master| self.unlock_secrets_with_master(master))
                .transpose()?
                .unwrap_or(false)
        {
            return Err(Error::SecretsLocked);
        }
        let vault_id = self.header.vault_id;
        let (slots, guard_key) = if check == GuardCheck::Master {
            (None, None)
        } else {
            let guard_key = match &self.guard_key {
                Some(key) => key.clone(),
                None => crate::random::secret_array::<{ aead::KEY_LEN }>()?,
            };
            let check_slot = match (secret, &self.guard.key) {
                (Some(secret), _) => {
                    WrappedGuardKey::wrap(secret, &guard_key, &vault_id, GuardSlot::Check)?
                }
                (None, Some(slots)) if self.guard.check == check => slots.check.clone(),
                _ => return Err(Error::InvalidGuardSecret),
            };
            let master = match master_password {
                Some(master) => Some(WrappedGuardKey::wrap(
                    master,
                    &guard_key,
                    &vault_id,
                    GuardSlot::Master,
                )?),
                None => self.guard.key.as_ref().and_then(|k| k.master.clone()),
            };
            (
                Some(GuardKeySlots {
                    check: check_slot,
                    master,
                }),
                Some(guard_key),
            )
        };

        // Every item in full, then stored again under the new rules.
        let items = self
            .items
            .iter()
            .map(|record| self.open_item(record))
            .collect::<Result<Vec<_>>>()?;
        let previous = (
            std::mem::replace(
                &mut self.guard,
                ItemGuard::with_key(all_items, check, slots),
            ),
            std::mem::replace(&mut self.guard_key, guard_key),
        );
        let records = self
            .items
            .iter()
            .zip(&items)
            .map(|(record, item)| self.store_item(record.id, record.revision, item))
            .collect::<Result<Vec<_>>>();
        match records {
            Ok(records) => {
                self.items = records;
                Ok(())
            }
            Err(err) => {
                (self.guard, self.guard_key) = previous;
                Err(err)
            }
        }
    }

    /// Opens guarded secrets with the guard's PIN or password. `false` when it is wrong (and
    /// always for a guard that checks the master password, which the client verifies against
    /// the file).
    ///
    /// The first time after an upgrade from format v5 this also encrypts the guarded secrets
    /// ([`ItemGuard::encrypts`] turns true): save the vault afterwards.
    pub fn unlock_secrets(&mut self, secret: &str) -> Result<bool> {
        if let Some(slots) = &self.guard.key {
            let key = slots
                .check
                .unwrap(secret, &self.header.vault_id, GuardSlot::Check)?;
            self.guard_key = key;
            return Ok(self.guard_key.is_some());
        }
        if !self.guard.verify_legacy(secret)? {
            return Ok(false);
        }
        let (all_items, check) = (self.guard.all_items, self.guard.check);
        self.set_item_guard(all_items, check, Some(secret), None)?;
        Ok(true)
    }

    /// Opens guarded secrets with the master password, when the guard kept a copy of its key
    /// for it ([`ItemGuard::master_can_reset`]). `false` when there is none or it is wrong.
    pub fn unlock_secrets_with_master(&mut self, master_password: &str) -> Result<bool> {
        let Some(slot) = self.guard.key.as_ref().and_then(|k| k.master.as_ref()) else {
            return Ok(false);
        };
        let key = slot.unwrap(master_password, &self.header.vault_id, GuardSlot::Master)?;
        let opened = key.is_some();
        if opened {
            self.guard_key = key;
        }
        Ok(opened)
    }

    /// Closes guarded secrets again: the guard key leaves memory.
    pub fn lock_secrets(&mut self) {
        self.guard_key = None;
    }

    /// Whether encrypted secrets are open right now.
    pub fn secrets_open(&self) -> bool {
        self.guard_key.is_some()
    }

    /// Whether storing this item needs open secrets first: the guard encrypts, covers the
    /// item, and its key is not in memory.
    pub fn needs_unlock_to_store(&self, item: &ItemData) -> bool {
        self.guard.encrypts() && self.guards(item) && self.guard_key.is_none()
    }

    /// Whether this item's secrets wait for the guard's check.
    pub fn guards(&self, item: &ItemData) -> bool {
        self.guard.all_items || item.reprompt
    }

    // ---- folders ----

    /// Folders, in the user's order (creation order unless moved).
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
            icon_url: String::new(),
        });
        Ok(id)
    }

    /// Moves a folder to position `index` (clamped to the end); the others keep their order.
    pub fn move_folder(&mut self, id: &FolderId, index: usize) -> Result<()> {
        let from = self
            .folders
            .iter()
            .position(|f| f.id == *id)
            .ok_or(Error::FolderNotFound)?;
        let folder = self.folders.remove(from);
        let to = index.min(self.folders.len());
        self.folders.insert(to, folder);
        Ok(())
    }

    /// Sets the website or image link whose picture stands for a folder ("" = none). Links are
    /// trimmed; whitespace inside or control characters are refused.
    pub fn set_folder_icon_url(&mut self, id: &FolderId, url: &str) -> Result<()> {
        let url = url.trim();
        if url.chars().count() > Folder::MAX_ICON_URL_CHARS
            || url.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Error::InvalidName);
        }
        let folder = self
            .folders
            .iter_mut()
            .find(|f| f.id == *id)
            .ok_or(Error::FolderNotFound)?;
        folder.icon_url = url.to_owned();
        Ok(())
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
            needs_keyfile: parsed.header.slot(SlotKind::PasswordKeyfile).is_some(),
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
            guard: self.guard.clone(),
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

    pub fn kdf_params(&self) -> &PasswordKdf {
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
        let record = self.store_item(id, 1, &data)?;
        self.items.push(record);
        Ok(id)
    }

    /// Decrypts one item. While its secrets are locked ([`ItemData::is_locked`]) the fields
    /// that hold them come back empty.
    pub fn get_item(&self, id: &ItemId) -> Result<ItemData> {
        let record = &self.items[self.position(id).ok_or(Error::ItemNotFound)?];
        self.open_item(record)
    }

    /// Replaces an item's contents (new item key, revision + 1).
    ///
    /// When the password changes, the old one is added to the item's password history (up to
    /// the vault's history limit, oldest dropped first) and `password_changed_at` is set to
    /// now; the history passed in `data` is replaced by the stored one in that case.
    ///
    /// A locked item can be written back as it was read (to change its title, folder or
    /// favourite mark): its sealed secrets are kept. Changing the secrets of a locked item
    /// fails with [`Error::SecretsLocked`].
    pub fn update_item(&mut self, id: &ItemId, data: &ItemData) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        let mut old = self.open_item(&self.items[index])?;
        let mut data = data.clone();
        if data.is_locked() {
            if old.is_locked() {
                data.sealed.clone_from(&old.sealed);
                self.items[index] = self.seal_item(*id, revision, &data)?;
                return Ok(());
            }
            // Read while locked, written after the secrets were opened: they are unchanged.
            data.sealed = None;
            data.put_secrets(old.take_secrets())?;
            self.items[index] = self.store_item(*id, revision, &data)?;
            return Ok(());
        }
        if old.is_locked() {
            return Err(Error::SecretsLocked);
        }
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
        self.items[index] = self.store_item(*id, revision, &data)?;
        Ok(())
    }

    /// Forgets an item's earlier passwords.
    pub fn clear_password_history(&mut self, id: &ItemId) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let mut item = self.open_item(&self.items[index])?;
        if item.is_locked() {
            return Err(Error::SecretsLocked);
        }
        if item.password_history.is_empty() {
            return Ok(());
        }
        item.password_history.clear();
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        self.items[index] = self.store_item(*id, revision, &item)?;
        Ok(())
    }

    pub fn remove_item(&mut self, id: &ItemId) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        self.items.remove(index);
        Ok(())
    }

    /// Decrypts every item into a non-secret summary (title, username, first URL). Works
    /// with locked secrets too.
    pub fn summaries(&self) -> Result<Vec<ItemSummary>> {
        self.items
            .iter()
            .map(|record| {
                let data = self.open_item(record)?;
                Ok(ItemSummary::from_data(record.id, &data))
            })
            .collect()
    }

    /// Re-protects the vault with a new master password and/or Secret Key, KDF cost and
    /// keyfile. The vault key and items are unchanged; only the password slot is rewritten.
    ///
    /// `keyfile` is what the vault needs from now on: `Some` makes (or keeps) it a third
    /// factor, `None` removes it. Callers that only change the password pass the keyfile the
    /// vault was opened with.
    ///
    /// The item guard's copy of its key for the master password follows the new password
    /// only while guarded secrets are open (after [`Vault::unlock_secrets_with_master`] with
    /// the current password, for instance).
    pub fn change_password(
        &mut self,
        new_password: &str,
        secret_key: &SecretKey,
        keyfile: Option<&Keyfile>,
        kdf: impl Into<PasswordKdf>,
    ) -> Result<()> {
        let kdf = kdf.into().with_fresh_salt()?;
        let slot = self.password_slot(new_password, secret_key, keyfile, &kdf)?;
        if let (Some(key), true) = (&self.guard_key, self.guard.encrypts()) {
            let master =
                WrappedGuardKey::wrap(new_password, key, &self.header.vault_id, GuardSlot::Master)?;
            if let Some(slots) = &mut self.guard.key {
                slots.master = Some(master);
            }
        }
        self.header.kdf = kdf;
        self.header
            .slots
            .retain(|s| !matches!(s.kind, SlotKind::Password | SlotKind::PasswordKeyfile));
        self.header.slots.insert(0, slot);
        Ok(())
    }

    /// Whether the master password needs a keyfile next to it.
    pub fn needs_keyfile(&self) -> bool {
        self.header.slot(SlotKind::PasswordKeyfile).is_some()
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
        keyfile: Option<&Keyfile>,
        kdf: &PasswordKdf,
    ) -> Result<KeySlot> {
        let vault_id = &self.header.vault_id;
        let kek = keys::password_kek(password, secret_key, keyfile, kdf, vault_id)?;
        let kind = if keyfile.is_some() {
            SlotKind::PasswordKeyfile
        } else {
            SlotKind::Password
        };
        self.wrap_vault_key(&kek, kind)
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

    /// Encrypts an item for the vault. When the guard encrypts and covers the item, its
    /// secrets are sealed under the guard key first, which must be in memory.
    fn store_item(&self, id: ItemId, revision: u64, data: &ItemData) -> Result<ItemRecord> {
        if data.is_locked() || !(self.guard.encrypts() && self.guards(data)) {
            return self.seal_item(id, revision, data);
        }
        let key = self.guard_key.as_ref().ok_or(Error::SecretsLocked)?;
        let summary = ItemSummary::from_data(id, data);
        let mut outer = data.clone();
        let secrets = outer.take_secrets();
        let encoded = format::encode_secret(&secrets)?;
        let padded = padding::pad(&encoded, padding::item_bucket)?;
        let ciphertext = aead::seal(key, &padded, &secrets_aad(&self.header.vault_id, &id))?;
        outer.sealed = Some(SealedSecrets {
            ciphertext,
            has_password: summary.has_password,
            has_totp: summary.has_totp,
            card_hint: summary.card_hint.clone(),
            card_brand: summary.card_brand,
        });
        self.seal_item(id, revision, &outer)
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

    /// The item as far as it can be read now: in full, or without its secrets while they are
    /// sealed and the guard key is not in memory.
    fn open_item(&self, record: &ItemRecord) -> Result<ItemData> {
        let padded = self.decrypt_item(record)?;
        let mut item: ItemData = format::decode_exact(padding::unpad(&padded)?)?;
        if let (Some(key), Some(sealed)) = (&self.guard_key, &item.sealed) {
            let padded = aead::open(
                key,
                &sealed.ciphertext,
                &secrets_aad(&self.header.vault_id, &record.id),
            )?;
            let secrets: ItemSecrets = format::decode_exact(padding::unpad(&padded)?)?;
            item.sealed = None;
            item.put_secrets(secrets)?;
        }
        Ok(item)
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

fn secrets_aad(vault_id: &[u8; 16], id: &ItemId) -> Vec<u8> {
    [b"vault-v0/item-secrets".as_slice(), vault_id, id.as_bytes()].concat()
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
    let slot = header.password_slot().ok_or(Error::NoMatchingSlot)?;
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
    use crate::KdfParams;

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
        let downgraded = with_header(&bytes, |h| {
            if let PasswordKdf::Argon2id(params) = &mut h.kdf {
                params.memory_kib = 1024;
            }
        });
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
        let edited = with_header(&bytes, |h| {
            if let PasswordKdf::Argon2id(params) = &mut h.kdf {
                params.iterations += 1;
            }
        });
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
                    SlotKind::PasswordKeyfile => SlotKind::PasswordKeyfile,
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
    fn sealed_secrets_are_not_in_what_the_vault_key_decrypts() {
        let (mut vault, _) = recovery_vault();
        let mut item = ItemData::login("Bank", "me", "Unique-S3cret-Value", "");
        item.reprompt = true;
        let id = vault.add_item(&item).unwrap();
        let contains = |vault: &Vault, needle: &[u8]| {
            let record = &vault.items[vault.position(&id).unwrap()];
            let plain = vault.decrypt_item(record).unwrap();
            plain.windows(needle.len()).any(|w| w == needle)
        };
        assert!(contains(&vault, b"Unique-S3cret-Value"));
        vault
            .set_item_guard(false, GuardCheck::Password, Some("guard password"), None)
            .unwrap();
        assert!(!contains(&vault, b"Unique-S3cret-Value"));
        assert!(contains(&vault, b"Bank"));
        // Sealed secrets are bound to their item: moved to another one, they don't open.
        let other = vault.add_item(&item).unwrap();
        let (ia, ib) = (
            vault.position(&id).unwrap(),
            vault.position(&other).unwrap(),
        );
        let mut a = vault.open_item(&vault.items[ia]).unwrap();
        vault.lock_secrets();
        let b = vault.open_item(&vault.items[ib]).unwrap();
        a.sealed = None;
        a.password.clear();
        a.sealed.clone_from(&b.sealed);
        vault.items[ia] = vault.seal_item(id, 9, &a).unwrap();
        assert!(vault.unlock_secrets("guard password").unwrap());
        assert!(vault.get_item(&id).is_err());
        assert!(vault.get_item(&other).is_ok());
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
            .change_password("a brand new passphrase", &secret_key, None, &kdf)
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
