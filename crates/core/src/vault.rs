//! The unlocked vault: open, modify, and serialize (spec: VAULT_FORMAT.md).

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Error, Folder, FolderId, GuardCheck, ItemData, ItemGuard, ItemId, ItemSummary, PasswordKdf,
    RecoveryKey, RecoveryPart, RecoveryParts, Result, SecretKey, VaultSettings, aead,
    format::{
        self, ItemRecord, KeySlot, PartsSlot, SlotKind, VaultBody, VaultBodyV0, VaultBodyV1,
        VaultBodyV2, VaultBodyV3, VaultBodyV4, VaultBodyV5, VaultBodyV6, VaultHeader,
    },
    guard::{GuardKeySlots, GuardOpened, GuardSlot, WrappedGuardKey},
    item::{
        FolderV1, FolderV3, ItemDataV0, ItemDataV1, ItemDataV2, ItemDataV3, ItemDataV5, ItemDataV8,
        ItemDataV9, ItemSecrets, PasswordChange, SealedSecrets,
    },
    keys::{self, Keyfile, VaultKey},
    memory::ShieldedKey,
    padding,
    sync::{DeviceId, Gone, SyncDevice, SyncState, guard_key_id, record_digest},
};

mod merge;

/// A time for a change to something merged by "newest wins": now, but never earlier than the
/// last change to it, so a clock that is behind can't make a new change look old.
fn later(previous: i64) -> i64 {
    crate::item::unix_now().max(previous.saturating_add(1))
}

const SUBKEY_BODY: &[u8] = b"body";
const SUBKEY_ITEM_WRAP: &[u8] = b"item-wrap";
const SUBKEY_PARTS: &[u8] = b"parts";
const SUBKEY_KIT_PDF: &[u8] = b"kit-pdf";

/// What each sealed value of the recovery parts is (the last byte of its AAD).
mod part_role {
    pub(super) const VAULT_KEY: u8 = 0x01;
    /// Pair wraps: AB, AC, BC follow it.
    pub(super) const PAIR: u8 = 0x02;
    pub(super) const PAIR_KEY: u8 = 0x05;
    pub(super) const SECRET_KEY: u8 = 0x06;
}

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
    /// Recovery Key from an emergency kit made before format v8. Opens the vault on its own,
    /// keyfile or not.
    Recovery(&'a RecoveryKey),
    /// All three recovery parts of the current kit, in any order. Open the vault on their own,
    /// keyfile or not, so a forgotten master password can be replaced.
    Parts([&'a RecoveryPart; 3]),
}

impl fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unlock::Password { .. } => f.write_str("Unlock::Password(<redacted>)"),
            Unlock::PasswordAndKeyfile { .. } => {
                f.write_str("Unlock::PasswordAndKeyfile(<redacted>)")
            }
            Unlock::Recovery(_) => f.write_str("Unlock::Recovery(<redacted>)"),
            Unlock::Parts(_) => f.write_str("Unlock::Parts(<redacted>)"),
        }
    }
}

/// Public header information, readable without credentials (see [`Vault::inspect`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub id_hex: String,
    pub kdf: PasswordKdf,
    /// A Recovery Key from a kit made before format v8 opens it.
    pub has_recovery_key: bool,
    /// Recovery parts open it (format v8).
    pub has_recovery_parts: bool,
    /// The master password alone doesn't open it: a keyfile is needed too.
    pub needs_keyfile: bool,
    /// Names what opens this copy (its key slots and kit), without telling anything about
    /// them: it changes with a new master password, Secret Key, keyfile or kit, and with a
    /// renewed vault key. A device keeps the ones it retired by renewing or taking a new key
    /// ([`Vault::unlock_id`]), so a copy it can't open is known as one written before.
    pub unlock_id: [u8; 16],
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
    /// The item guard key, while guarded secrets are open (see [`Vault::unlock_secrets`]);
    /// encrypted between uses when the program installed a key shield (`memory.rs`).
    guard_key: Option<ShieldedKey>,
    /// What sync needs (format v7).
    sync: SyncState,
    /// A newer item lock with another key, from another device's copy, that this copy can't
    /// take yet: in memory only (see `merge::IncomingGuard`).
    incoming_guard: Option<merge::IncomingGuard>,
}

/// A vault as it was, to put back when a change could not be written (see
/// [`Vault::snapshot`]). Items stay sealed in it.
pub struct VaultSnapshot {
    header: VaultHeader,
    revision: u64,
    items: Vec<ItemRecord>,
    folders: Vec<Folder>,
    settings: VaultSettings,
    guard: ItemGuard,
    sync: SyncState,
}

/// What [`Vault::renew_key`] hands back.
pub struct RenewedKey {
    /// The vault's new Secret Key: shown once (with the new kit) and kept on this device.
    pub secret_key: SecretKey,
    /// The new emergency kit's recovery parts.
    pub parts: RecoveryParts,
    /// The vault key this copy had before, for what this device sealed with it.
    pub former: FormerKey,
}

impl fmt::Debug for RenewedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RenewedKey(<redacted>)")
    }
}

/// A vault key this copy no longer uses, after [`Vault::renew_key`] or [`Vault::adopt_key`].
/// It opens only what this device sealed with it outside the vault file
/// ([`Vault::seal_local`]: the generator's history, the extension's connection key...), so
/// that can be sealed again under the new key; it is wiped when dropped. Keep it no longer
/// than that.
pub struct FormerKey {
    vault_key: VaultKey,
    vault_id: [u8; 16],
}

impl FormerKey {
    /// Opens data [`Vault::seal_local`] sealed with this key for `purpose`.
    pub fn open_local(&self, purpose: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        aead::open(
            &local_key(&self.vault_key, &self.vault_id, purpose),
            sealed,
            &local_aad(&self.vault_id, purpose),
        )
    }
}

impl fmt::Debug for FormerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FormerKey(<redacted>)")
    }
}

impl fmt::Debug for VaultSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSnapshot")
            .field("revision", &self.revision)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
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
                parts: None,
            },
            vault_key,
            revision: 0,
            items: Vec::new(),
            folders: Vec::new(),
            settings: VaultSettings::default(),
            guard: ItemGuard::default(),
            guard_key: None,
            incoming_guard: None,
            sync: SyncState::default(),
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
            Unlock::Parts(parts) => {
                let parts = keys::ordered_parts(parts)?;
                let slot = header.parts.as_ref().ok_or(Error::NoMatchingSlot)?;
                let kek = keys::parts_kek(parts, &header.vault_id, &slot.kit_id);
                let key_bytes = aead::open(
                    &kek,
                    &slot.vault_key,
                    &parts_aad(&header.vault_id, &slot.kit_id, part_role::VAULT_KEY),
                )?;
                return Self::from_parsed(parsed, VaultKey::from_slice(&key_bytes)?);
            }
        };
        let slot = header.slot(kind).ok_or(Error::NoMatchingSlot)?;
        let key_bytes = aead::open(
            &kek,
            &slot.wrapped_vault_key,
            &slot_aad(&header.vault_id, kind),
        )?;
        Self::from_parsed(parsed, VaultKey::from_slice(&key_bytes)?)
    }

    /// The Secret Key, from any two of the three recovery parts (format v8). The master
    /// password is still needed to open the vault with it.
    pub fn recover_secret_key(
        bytes: &[u8],
        first: &RecoveryPart,
        second: &RecoveryPart,
    ) -> Result<SecretKey> {
        let parsed = format::parse(bytes)?;
        let header = &parsed.header;
        let slot = header.parts.as_ref().ok_or(Error::NoMatchingSlot)?;
        let (index, x, y) = keys::ordered_pair(first, second)?;
        let kek = keys::pair_kek(x, y, &header.vault_id, &slot.kit_id);
        let pair_key = aead::open(
            &kek,
            &slot.pairs[index],
            &parts_aad(
                &header.vault_id,
                &slot.kit_id,
                part_role::PAIR + index as u8,
            ),
        )?;
        open_parts_secret_key(&pair_key, header, slot)
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

    /// A fresh device secret for [`Vault::seal_for_device`], for a device whose secure
    /// hardware keeps a secret it is handed (a phone's keystore, behind its fingerprint)
    /// rather than working one out (Windows Hello's signature). 32 random bytes.
    pub fn new_device_secret() -> Result<Zeroizing<[u8; 32]>> {
        crate::random::secret_array()
    }

    /// Wraps the vault key for quick unlock on this device (Windows Hello and similar).
    /// The result is kept on the device, never in the vault file, and is useless without
    /// `device_secret`, which only the device's secure hardware can produce again.
    pub fn seal_for_device(&self, device_secret: &[u8]) -> Result<Vec<u8>> {
        let kek = keys::device_kek(device_secret, &self.header.vault_id)?;
        aead::seal(
            &kek,
            self.vault_key.open().as_slice(),
            &device_aad(&self.header)?,
        )
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
                    sync: SyncState::default(),
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
                    sync: SyncState::default(),
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
                    sync: SyncState::default(),
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
                    sync: SyncState::default(),
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
                    sync: SyncState::default(),
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
                    sync: SyncState::default(),
                }
            }
            6 => {
                let old: VaultBodyV6 = format::decode_exact(plain)?;
                VaultBody {
                    revision: old.revision,
                    items: old.items,
                    folders: old.folders,
                    settings: old.settings,
                    guard: old.guard,
                    sync: SyncState::default(),
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
            incoming_guard: None,
            sync: body.sync,
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
                6..=8 => format::decode_exact::<ItemDataV8>(plain)?.upgrade(),
                9 => format::decode_exact::<ItemDataV9>(plain)?.upgrade(),
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
        self.sync.settings_changed_at = later(self.sync.settings_changed_at);
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
                Some(key) => key.open(),
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
                Some(ShieldedKey::new(guard_key)),
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
        let previous_sync = self.sync.clone();
        let previous_incoming = self.incoming_guard.clone();
        self.note_guard_change();
        let records = self
            .items
            .iter()
            .zip(&items)
            .map(|(record, item)| self.store_item(record.id, record.revision, item))
            .collect::<Result<Vec<_>>>();
        match records {
            Ok(records) => {
                for old in &self.items {
                    self.sync.descend(old.id, record_digest(&old.data));
                }
                self.items = records;
                Ok(())
            }
            Err(err) => {
                (self.guard, self.guard_key) = previous;
                self.sync = previous_sync;
                self.incoming_guard = previous_incoming;
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
        Ok(self.unlock_guard(secret)? == GuardOpened::Own)
    }

    /// [`Vault::unlock_secrets`], telling a wrong try from the PIN or password of a newer item
    /// lock that waits from another device ([`Vault::guard_waiting`]). That one is remembered
    /// for the move to it until the secrets are closed; it doesn't open this copy's own lock,
    /// nor close it when that is open. The same secret often opens both.
    pub fn unlock_guard(&mut self, secret: &str) -> Result<GuardOpened> {
        let newer = self.open_incoming_guard(secret, GuardSlot::Check)?;
        let own = if let Some(slots) = &self.guard.key {
            let key = slots
                .check
                .unwrap(secret, &self.header.vault_id, GuardSlot::Check)?;
            match key {
                Some(key) => {
                    self.open_guard_with(key);
                    true
                }
                None => {
                    if !newer {
                        self.guard_key = None;
                    }
                    false
                }
            }
        } else if self.guard.verify_legacy(secret)? {
            let (all_items, check) = (self.guard.all_items, self.guard.check);
            self.set_item_guard(all_items, check, Some(secret), None)?;
            true
        } else {
            false
        };
        Ok(opened(own, newer))
    }

    /// Opens guarded secrets with the master password, when the guard kept a copy of its key
    /// for it ([`ItemGuard::master_can_reset`]). `false` when there is none or it is wrong.
    pub fn unlock_secrets_with_master(&mut self, master_password: &str) -> Result<bool> {
        Ok(self.unlock_guard_with_master(master_password)? == GuardOpened::Own)
    }

    /// [`Vault::unlock_guard`] with the master password, which opens a newer item lock waiting
    /// from another device too, when each lock kept a copy of its key for it.
    pub fn unlock_guard_with_master(&mut self, master_password: &str) -> Result<GuardOpened> {
        let newer = self.open_incoming_guard(master_password, GuardSlot::Master)?;
        let slot = self.guard.key.as_ref().and_then(|k| k.master.as_ref());
        let key = slot
            .map(|slot| slot.unwrap(master_password, &self.header.vault_id, GuardSlot::Master))
            .transpose()?
            .flatten();
        let own = key.is_some();
        if let Some(key) = key {
            self.open_guard_with(key);
        }
        Ok(opened(own, newer))
    }

    /// Guarded secrets are open with `key`. A copy that never said which key seals its items
    /// (a lock from before format v7, not changed since) says so from now on, so sync can tell
    /// a new PIN for this key from another key.
    fn open_guard_with(&mut self, key: Zeroizing<aead::Key>) {
        if self.sync.guard_key_id == [0; 8] {
            self.sync.guard_key_id = guard_key_id(key.as_ref());
        }
        self.guard_key = Some(ShieldedKey::new(key));
    }

    /// Wraps the item guard key for this device, so that the device's user verification
    /// (Windows Hello) can open guarded secrets in place of the PIN or password. The result
    /// is kept on the device, never in the vault file. Needs open secrets.
    ///
    /// It is bound to the current PIN or password: setting a new one revokes it.
    pub fn seal_guard_for_device(&self, device_secret: &[u8]) -> Result<Vec<u8>> {
        let key = self.guard_key.as_ref().ok_or(Error::SecretsLocked)?.open();
        let kek = keys::guard_device_kek(device_secret, &self.header.vault_id)?;
        aead::seal(&kek, key.as_ref(), &self.guard_device_aad()?)
    }

    /// Opens guarded secrets with what [`Vault::seal_guard_for_device`] made on this device.
    /// `false` when the device secret is another one or the PIN was changed since.
    pub fn unlock_secrets_with_device(
        &mut self,
        device_secret: &[u8],
        sealed: &[u8],
    ) -> Result<bool> {
        if !self.guard.encrypts() {
            return Ok(false);
        }
        let kek = keys::guard_device_kek(device_secret, &self.header.vault_id)?;
        let Ok(bytes) = aead::open(&kek, sealed, &self.guard_device_aad()?) else {
            return Ok(false);
        };
        let key: aead::Key = bytes.as_slice().try_into().map_err(|_| Error::Malformed)?;
        self.open_guard_with(Zeroizing::new(key));
        Ok(true)
    }

    fn guard_device_aad(&self) -> Result<Vec<u8>> {
        let slots = self.guard.key.as_ref().ok_or(Error::SecretsLocked)?;
        Ok([
            b"vault-v0/guard-device".as_slice(),
            &self.header.vault_id,
            &slots.check.fingerprint(),
        ]
        .concat())
    }

    /// Records that the item lock changed, for sync: a newer revision, and which key now
    /// seals guarded items. Newer than a lock that was waiting from another device too: the
    /// person set this one after it, so it is the one that counts.
    fn note_guard_change(&mut self) {
        let waiting = self.incoming_guard.take().map_or(0, |lock| lock.revision);
        self.sync.guard_revision = self.sync.guard_revision.max(waiting).saturating_add(1);
        self.sync.guard_key_id = self
            .guard_key
            .as_ref()
            .map_or([0; 8], |key| guard_key_id(key.open().as_ref()));
    }

    /// Closes guarded secrets again: the guard key leaves memory.
    pub fn lock_secrets(&mut self) {
        self.guard_key = None;
        if let Some(incoming) = self.incoming_guard.as_mut() {
            incoming.key = None;
        }
    }

    /// Whether encrypted secrets are open right now.
    pub fn secrets_open(&self) -> bool {
        self.guard_key.is_some()
    }

    /// Whether changing this item needs open secrets first: the guard encrypts, covers the
    /// item, and its key is not in memory. Adding a new item never does (see
    /// [`Vault::add_item`]).
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
        self.touch_folder(id);
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
        self.sync.order_changed_at = later(self.sync.order_changed_at);
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
        self.touch_folder(*id);
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
        self.touch_folder(*id);
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
        self.touch_folder(*id);
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
        self.sync.folder_times.retain(|(folder, _)| folder != id);
        self.sync
            .bury(Gone::Folder, *id.as_bytes(), crate::item::unix_now());
        Ok(())
    }

    fn touch_folder(&mut self, id: FolderId) {
        let at = later(self.sync.folder_time(&id));
        self.sync.touch_folder(id, at);
    }

    /// Reads the public, unencrypted header information without unlocking.
    pub fn inspect(bytes: &[u8]) -> Result<VaultInfo> {
        let parsed = format::parse(bytes)?;
        Ok(VaultInfo {
            id_hex: hex(&parsed.header.vault_id),
            has_recovery_key: parsed.header.slot(SlotKind::Recovery).is_some(),
            has_recovery_parts: parsed.header.parts.is_some(),
            needs_keyfile: parsed.header.slot(SlotKind::PasswordKeyfile).is_some(),
            unlock_id: unlock_id(&parsed.header),
            kdf: parsed.header.kdf,
        })
    }

    /// [`VaultInfo::unlock_id`] of this copy as it is in memory now.
    pub fn unlock_id(&self) -> [u8; 16] {
        unlock_id(&self.header)
    }

    /// Checks that `bytes` is a whole, readable copy of this vault, with the key already in
    /// memory (no password asked again): the same vault, a header that parses, a body whose
    /// every byte is authenticated (the header is its AAD) and whose items and folders read
    /// back. Used to confirm a backup after it is written. Returns the copy's revision.
    pub fn check_copy(&self, bytes: &[u8]) -> Result<u64> {
        let parsed = format::parse(bytes)?;
        if parsed.header.vault_id != self.header.vault_id {
            return Err(Error::OtherVault);
        }
        let copy = Self::from_parsed(parsed, self.vault_key.duplicate())?;
        for record in &copy.items {
            copy.decrypt_item(record)?;
        }
        Ok(copy.revision)
    }

    /// Serializes the vault into file bytes. Increments the vault revision.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        let next_revision = self.revision.checked_add(1).ok_or(Error::Malformed)?;
        self.sync.prune(crate::item::unix_now());
        let header_bytes = format::encode_header(&self.header)?;
        let body = VaultBody {
            revision: next_revision,
            items: self.items.clone(),
            folders: self.folders.clone(),
            settings: self.settings.clone(),
            guard: self.guard.clone(),
            sync: self.sync.clone(),
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
        local_key(&self.vault_key, &self.header.vault_id, purpose)
    }

    /// What [`Vault::seal_local`] sealed for `purpose` under `former` (this vault's key before
    /// [`Vault::renew_key`] or [`Vault::adopt_key`]), sealed again under the key it has now.
    pub fn reseal_local(
        &self,
        former: &FormerKey,
        purpose: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>> {
        if former.vault_id != self.header.vault_id {
            return Err(Error::OtherVault);
        }
        let plain = former.open_local(purpose, sealed)?;
        self.seal_local(purpose, &plain)
    }

    /// Random identifier of this vault, as hex.
    pub fn id_hex(&self) -> String {
        hex(&self.header.vault_id)
    }

    /// The vault key and the guard key (while guarded secrets are open), for the memory test
    /// only (see [`crate::memory_test`]).
    #[cfg(feature = "memory-test")]
    pub(crate) fn keys_for_memory_test(
        &self,
    ) -> (Zeroizing<aead::Key>, Option<Zeroizing<aead::Key>>) {
        (
            self.vault_key.open(),
            self.guard_key.as_ref().map(ShieldedKey::open),
        )
    }

    /// Incremented on every save; compare with the last value seen to detect rollbacks.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn kdf_params(&self) -> &PasswordKdf {
        &self.header.kdf
    }

    /// A Recovery Key from a kit made before format v8 opens this vault.
    pub fn has_recovery_key(&self) -> bool {
        self.header.slot(SlotKind::Recovery).is_some()
    }

    /// Recovery parts open this vault (format v8).
    pub fn has_recovery_parts(&self) -> bool {
        self.header.parts.is_some()
    }

    /// The password of the emergency kit's saved PDF files (CRYPTO.md §3.10), `secret_key`
    /// being this vault's Secret Key: derived from the vault key, the Secret Key and the
    /// current kit, never stored. The same until one of them changes (a new Secret Key, new
    /// recovery parts, a renewed vault key), so it can be shown again whenever the vault is
    /// open.
    pub fn kit_pdf_password(&self, secret_key: &SecretKey) -> crate::KitPdfPassword {
        let vault_id = &self.header.vault_id;
        crate::kit_password::derive(
            &self.vault_key.subkey(SUBKEY_KIT_PDF, vault_id),
            secret_key,
            vault_id,
            self.header.parts.as_ref().map(|parts| &parts.kit_id),
        )
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// A fingerprint of the item as stored now: it changes with every change to the item (its
    /// secrets, websites, anything), whether or not its secrets are open here. Not secret (a
    /// hash of encrypted bytes). `None` for an unknown id.
    ///
    /// What is kept outside the vault for one version of an item (the locked-fill file) is
    /// tied to it, so it is never used for another version.
    pub fn item_stamp(&self, id: &ItemId) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let record = self.items.iter().find(|record| record.id == *id)?;
        let mut hash = Sha256::new();
        hash.update(b"vault-v0/item-stamp/");
        hash.update(record.id.as_bytes());
        hash.update(record.revision.to_le_bytes());
        hash.update(&record.data);
        Some(hash.finalize().into())
    }

    pub fn item_ids(&self) -> impl Iterator<Item = ItemId> + '_ {
        self.items.iter().map(|record| record.id)
    }

    /// Adds an item and returns its new id.
    ///
    /// A new item the guard covers is sealed under the guard key right away when that key is
    /// in memory. When it isn't, the item is stored under the vault key alone, like an item the
    /// guard doesn't cover, and sealed the next time the guard is opened
    /// ([`Vault::seal_pending`]): saving a login needs no PIN. Until then the app still asks
    /// for the guard's check before showing its secrets.
    pub fn add_item(&mut self, data: &ItemData) -> Result<ItemId> {
        let id = loop {
            let candidate = ItemId::generate()?;
            if self.position(&candidate).is_none() {
                break candidate;
            }
        };
        data.check_attachments()?;
        data.check_passkeys()?;
        let mut data = data.clone();
        if data.password_changed_at == 0 && !data.password.is_empty() {
            data.password_changed_at = data.created_at;
        }
        let record = if self.needs_unlock_to_store(&data) {
            self.seal_item(id, 1, &data)?
        } else {
            self.store_item(id, 1, &data)?
        };
        self.items.push(record);
        Ok(id)
    }

    /// Items the guard covers whose secrets are not sealed under its key yet (added while it
    /// was closed, see [`Vault::add_item`]).
    pub fn pending_seal(&self) -> Result<usize> {
        if !self.guard.encrypts() {
            return Ok(0);
        }
        let mut count = 0;
        for record in &self.items {
            if self.waits_for_seal(record)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Seals the secrets of the items added while the guard was closed, now that its key is in
    /// memory. Returns how many were sealed: the vault must then be saved.
    pub fn seal_pending(&mut self) -> Result<usize> {
        if !self.guard.encrypts() || self.guard_key.is_none() {
            return Ok(0);
        }
        let mut sealed = 0;
        for index in 0..self.items.len() {
            if !self.waits_for_seal(&self.items[index])? {
                continue;
            }
            let record = &self.items[index];
            let (id, revision) = (
                record.id,
                record.revision.checked_add(1).ok_or(Error::Malformed)?,
            );
            let data = self.open_item(record)?;
            let record = self.store_item(id, revision, &data)?;
            self.replace_record(index, record);
            sealed += 1;
        }
        Ok(sealed)
    }

    /// Whether this stored item is covered by the guard but its secrets are not sealed.
    fn waits_for_seal(&self, record: &ItemRecord) -> Result<bool> {
        let padded = self.decrypt_item(record)?;
        let item: ItemData = format::decode_exact(padding::unpad(&padded)?)?;
        Ok(item.sealed.is_none() && self.guards(&item))
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
    /// fails with [`Error::SecretsLocked`]. An item not sealed yet ([`Vault::pending_seal`])
    /// can be changed while the guard is closed and keeps waiting for its seal.
    pub fn update_item(&mut self, id: &ItemId, data: &ItemData) -> Result<()> {
        data.check_attachments()?;
        data.check_passkeys()?;
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        let mut old = self.open_item(&self.items[index])?;
        let mut data = data.clone();
        if data.is_locked() {
            // Its passkeys' keys stay sealed in their order: one can't be added or removed
            // until the item is open.
            if !data.same_passkeys(&old) {
                return Err(Error::SecretsLocked);
            }
            if old.is_locked() {
                data.sealed.clone_from(&old.sealed);
                let record = self.seal_item(*id, revision, &data)?;
                self.replace_record(index, record);
                return Ok(());
            }
            // Read while locked, written after the secrets were opened: they are unchanged.
            data.sealed = None;
            data.put_secrets(old.take_secrets())?;
            let record = self.store_item(*id, revision, &data)?;
            self.replace_record(index, record);
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
        // An item still waiting for its seal (added while the guard was closed) stays that
        // way: it can be starred, moved or edited without the guard's check, like when it was
        // added. `old` was read in full with the guard key out of memory, so it was not sealed.
        let record = if self.needs_unlock_to_store(&data) && self.guards(&old) {
            self.seal_item(*id, revision, &data)?
        } else {
            self.store_item(*id, revision, &data)?
        };
        self.replace_record(index, record);
        Ok(())
    }

    /// Puts a new version of item `index` in place, remembering the one it replaces: sync
    /// tells a later edit from a concurrent one by it.
    fn replace_record(&mut self, index: usize, record: ItemRecord) {
        let old = std::mem::replace(&mut self.items[index], record);
        self.sync.descend(old.id, record_digest(&old.data));
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
        let record = self.store_item(*id, revision, &item)?;
        self.replace_record(index, record);
        Ok(())
    }

    pub fn remove_item(&mut self, id: &ItemId) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        self.items.remove(index);
        self.sync.forget_item(id);
        // Kept as a tombstone, so a copy on another device that still has it doesn't bring it
        // back when the two are merged.
        self.sync
            .bury(Gone::Item, *id.as_bytes(), crate::item::unix_now());
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

    /// Runs `change`: a change to what opens the vault (password, keyfile, hashing, Recovery
    /// Key) together with the write that makes it real. When it fails, the vault is put back
    /// as it was, so the copy in memory never needs a factor the file on disk doesn't (a
    /// keyfile that was never saved, say) and a later save can't lock the person out.
    pub fn change_unlock<T>(&mut self, change: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let header = self.header.clone();
        let guard = self.guard.clone();
        let revision = self.revision;
        let sync = self.sync.clone();
        let result = change(self);
        if result.is_err() {
            self.header = header;
            self.guard = guard;
            self.revision = revision;
            self.sync = sync;
        }
        result
    }

    /// What the vault holds now, for [`Vault::roll_back`]: everything a change to items,
    /// folders, settings, the item lock or sync can touch. Items stay sealed in it; no key is
    /// copied (keys and whether guarded secrets are open stay as they are).
    ///
    /// For a change whose write may still fail: the copy in memory is put back as it was, so
    /// it never holds what the file on disk doesn't (a login the browser was told was saved,
    /// say) and a later save can't write it behind the person's back.
    pub fn snapshot(&self) -> VaultSnapshot {
        VaultSnapshot {
            header: self.header.clone(),
            revision: self.revision,
            items: self.items.clone(),
            folders: self.folders.clone(),
            settings: self.settings.clone(),
            guard: self.guard.clone(),
            sync: self.sync.clone(),
        }
    }

    /// Puts back what [`Vault::snapshot`] took. When the item lock is not the one it was,
    /// guarded secrets are closed: the key open now belongs to the other one.
    pub fn roll_back(&mut self, snapshot: VaultSnapshot) {
        let VaultSnapshot {
            header,
            revision,
            items,
            folders,
            settings,
            guard,
            sync,
        } = snapshot;
        self.header = header;
        self.revision = revision;
        self.items = items;
        self.folders = folders;
        self.settings = settings;
        if self.guard != guard {
            self.guard_key = None;
        }
        self.guard = guard;
        self.sync = sync;
    }

    /// Re-protects the vault with a new master password and/or Secret Key, KDF cost and
    /// keyfile. The vault key and items are unchanged; only the password slot is rewritten.
    ///
    /// `keyfile` is what the vault needs from now on: `Some` makes (or keeps) it a third
    /// factor, `None` removes it. Callers that only change the password pass the keyfile the
    /// vault was opened with.
    ///
    /// The item guard's copy of its key for the master password follows the new password
    /// while guarded secrets are open (after [`Vault::unlock_secrets_with_master`] with the
    /// current password, for instance). With them closed it can't be rewrapped, so it is
    /// dropped: left as it was, the old master password would still open guarded secrets.
    /// The PIN or password still opens them, and the copy comes back the next time the
    /// guard is set up with the master password.
    pub fn change_password(
        &mut self,
        new_password: &str,
        secret_key: &SecretKey,
        keyfile: Option<&Keyfile>,
        kdf: impl Into<PasswordKdf>,
    ) -> Result<()> {
        let kdf = kdf.into().with_fresh_salt()?;
        let slot = self.password_slot(new_password, secret_key, keyfile, &kdf)?;
        // The recovery parts keep bringing back the Secret Key, even a new one.
        let parts_secret_key = self.seal_parts_secret_key(secret_key)?;
        if let Some(slots) = &mut self.guard.key {
            slots.master = match &self.guard_key {
                Some(key) => Some(WrappedGuardKey::wrap(
                    new_password,
                    &key.open(),
                    &self.header.vault_id,
                    GuardSlot::Master,
                )?),
                None => None,
            };
            self.sync.guard_revision = self.sync.guard_revision.saturating_add(1);
        }
        self.header.kdf = kdf;
        self.header
            .slots
            .retain(|s| !matches!(s.kind, SlotKind::Password | SlotKind::PasswordKeyfile));
        self.header.slots.insert(0, slot);
        if let (Some(parts), Some(sealed)) = (&mut self.header.parts, parts_secret_key) {
            parts.secret_key = sealed;
        }
        self.sync.unlock_revision = self.sync.unlock_revision.saturating_add(1);
        Ok(())
    }

    /// Whether the master password needs a keyfile next to it.
    pub fn needs_keyfile(&self) -> bool {
        self.header.slot(SlotKind::PasswordKeyfile).is_some()
    }

    /// Makes one Recovery Key the vault's way to recover, as kits made before format v8 had,
    /// or (with `None`) leaves it with none. Either way, recovery parts stop opening it. New
    /// kits use [`Vault::set_recovery_parts`].
    pub fn set_recovery_key(&mut self, recovery_key: Option<&RecoveryKey>) -> Result<()> {
        let slot = recovery_key
            .map(|key| self.recovery_slot(key))
            .transpose()?;
        self.header.slots.retain(|s| s.kind != SlotKind::Recovery);
        self.header.parts = None;
        if let Some(slot) = slot {
            self.header.slots.push(slot);
        }
        self.sync.unlock_revision = self.sync.unlock_revision.saturating_add(1);
        Ok(())
    }

    /// Makes `parts` the vault's way to recover (a new kit): any two of them bring back
    /// `secret_key`, the vault's current Secret Key, and all three open the vault. The Recovery
    /// Key or parts it had before stop opening it. Changing the master password or the Secret
    /// Key later keeps them working.
    pub fn set_recovery_parts(
        &mut self,
        parts: &RecoveryParts,
        secret_key: &SecretKey,
    ) -> Result<()> {
        let vault_id = self.header.vault_id;
        let kit_id: [u8; 16] = crate::random::array()?;
        let pair_key = crate::random::secret_array::<{ aead::KEY_LEN }>()?;
        let aad = |role| parts_aad(&vault_id, &kit_id, role);

        let kek = keys::parts_kek(parts.all(), &vault_id, &kit_id);
        let vault_key = aead::seal(
            &kek,
            self.vault_key.open().as_slice(),
            &aad(part_role::VAULT_KEY),
        )?;
        let mut pairs: [Vec<u8>; 3] = Default::default();
        let [a, b, c] = parts.all();
        for (index, (x, y)) in [(a, b), (a, c), (b, c)].into_iter().enumerate() {
            let kek = keys::pair_kek(x, y, &vault_id, &kit_id);
            pairs[index] =
                aead::seal(&kek, pair_key.as_ref(), &aad(part_role::PAIR + index as u8))?;
        }
        let for_vault = aead::seal(
            &self.vault_key.subkey(SUBKEY_PARTS, &vault_id),
            pair_key.as_ref(),
            &aad(part_role::PAIR_KEY),
        )?;
        let secret_key = aead::seal(
            &keys::parts_secret_key_key(pair_key.as_ref(), &vault_id, &kit_id),
            secret_key.open().as_slice(),
            &aad(part_role::SECRET_KEY),
        )?;
        self.header.slots.retain(|s| s.kind != SlotKind::Recovery);
        self.header.parts = Some(PartsSlot {
            kit_id,
            vault_key,
            pairs,
            pair_key: for_vault,
            secret_key,
        });
        self.sync.unlock_revision = self.sync.unlock_revision.saturating_add(1);
        Ok(())
    }

    /// Renews the vault key (CRYPTO.md §3.8): a new vault key, a new Secret Key and a new
    /// recovery kit, with the master password the person just typed. Every item's key is
    /// wrapped again under the new vault key (its sealed contents stay as they are, so other
    /// devices still recognise each item), the body is sealed under it from the next
    /// [`Vault::to_bytes`] on, and the header keeps only the new password slot and the new
    /// kit's parts.
    ///
    /// That is what a new master password, Secret Key or kit alone doesn't do: the vault key
    /// never changes with them, so whoever opened an older copy of the file (with its old
    /// factors, or its kit) would hold the key to every newer copy too. After a renewal, an
    /// older copy opens only itself.
    ///
    /// `password`, `secret_key` and `keyfile` must open this vault now (a typo must not
    /// become the master password); they are checked against the current password slot.
    /// Nothing changes when that or anything else fails. The item lock keeps its key (it is
    /// wrapped by its PIN or password, not by the vault key). Other devices take the new key
    /// with [`Vault::adopt_key`].
    pub fn renew_key(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        keyfile: Option<&Keyfile>,
    ) -> Result<RenewedKey> {
        let vault_id = self.header.vault_id;
        let kind = if self.needs_keyfile() {
            SlotKind::PasswordKeyfile
        } else {
            SlotKind::Password
        };
        if kind == SlotKind::PasswordKeyfile && keyfile.is_none() {
            return Err(Error::KeyfileRequired);
        }
        let keyfile = keyfile.filter(|_| kind == SlotKind::PasswordKeyfile);
        let slot = self.header.slot(kind).ok_or(Error::NoMatchingSlot)?;
        let kek = keys::password_kek(password, secret_key, keyfile, &self.header.kdf, &vault_id)?;
        let opened = aead::open(&kek, &slot.wrapped_vault_key, &slot_aad(&vault_id, kind))?;
        if opened.as_slice() != self.vault_key.open().as_slice() {
            return Err(Error::DecryptionFailed);
        }

        let new_key = VaultKey::generate()?;
        let items = self
            .items
            .iter()
            .map(|record| rewrap_item_key(record, &self.vault_key, &new_key, &vault_id))
            .collect::<Result<Vec<_>>>()?;
        let new_secret_key = SecretKey::generate()?;
        let parts = RecoveryParts::generate()?;
        let kdf = self.header.kdf.with_fresh_salt()?;

        let former = std::mem::replace(&mut self.vault_key, new_key);
        let (header, sync) = (self.header.clone(), self.sync.clone());
        let built = (|| -> Result<()> {
            let slot = self.password_slot(password, &new_secret_key, keyfile, &kdf)?;
            self.header.kdf = kdf;
            // Only the new password slot: a Recovery Key of an older kit goes too.
            self.header.slots = vec![slot];
            self.header.parts = None;
            self.set_recovery_parts(&parts, &new_secret_key)
        })();
        if let Err(err) = built {
            self.vault_key = former;
            self.header = header;
            self.sync = sync;
            return Err(err);
        }
        self.items = items;
        Ok(RenewedKey {
            secret_key: new_secret_key,
            parts,
            former: FormerKey {
                vault_key: former,
                vault_id,
            },
        })
    }

    /// Takes the vault key another device renewed ([`Vault::renew_key`]): `renewed` is that
    /// device's copy, opened with the master password and the new Secret Key from the new
    /// kit. This copy's items are wrapped under the new key and its header becomes the
    /// renewed one (the new password slot and kit), so the renewed copy merges as usual
    /// afterwards ([`Vault::merge`]). Returns the key this copy had, for what this device
    /// sealed with it, or `None` when both already share one key (nothing changes then).
    pub fn adopt_key(&mut self, renewed: &Vault) -> Result<Option<FormerKey>> {
        if renewed.header.vault_id != self.header.vault_id {
            return Err(Error::OtherVault);
        }
        if renewed.vault_key.open() == self.vault_key.open() {
            return Ok(None);
        }
        let vault_id = self.header.vault_id;
        let items = self
            .items
            .iter()
            .map(|record| rewrap_item_key(record, &self.vault_key, &renewed.vault_key, &vault_id))
            .collect::<Result<Vec<_>>>()?;
        let former = std::mem::replace(&mut self.vault_key, renewed.vault_key.duplicate());
        self.items = items;
        self.header = renewed.header.clone();
        self.sync.unlock_revision = self.sync.unlock_revision.max(renewed.sync.unlock_revision);
        Ok(Some(FormerKey {
            vault_key: former,
            vault_id,
        }))
    }

    /// Undoes [`Vault::renew_key`] or [`Vault::adopt_key`] when what follows them fails (the
    /// write, or keeping the new Secret Key): `snapshot` is [`Vault::snapshot`] taken right
    /// before, `former` the key they handed back. The vault is then as it was, key and all.
    pub fn put_back_key(&mut self, snapshot: VaultSnapshot, former: FormerKey) -> Result<()> {
        if former.vault_id != self.header.vault_id {
            return Err(Error::OtherVault);
        }
        self.vault_key = former.vault_key;
        self.roll_back(snapshot);
        Ok(())
    }

    /// Retires the recovery parts: once used (typed on a device to bring back the Secret Key,
    /// or to choose a new master password), a kit's parts stop opening anything, and a new
    /// kit takes their place. Nothing else changes; without parts, nothing happens.
    pub fn clear_recovery_parts(&mut self) {
        if self.header.parts.take().is_some() {
            self.sync.unlock_revision = self.sync.unlock_revision.saturating_add(1);
        }
    }

    /// The Secret Key sealed again for the current recovery parts (`None` without parts).
    fn seal_parts_secret_key(&self, secret_key: &SecretKey) -> Result<Option<Vec<u8>>> {
        let Some(slot) = &self.header.parts else {
            return Ok(None);
        };
        let vault_id = &self.header.vault_id;
        let pair_key = aead::open(
            &self.vault_key.subkey(SUBKEY_PARTS, vault_id),
            &slot.pair_key,
            &parts_aad(vault_id, &slot.kit_id, part_role::PAIR_KEY),
        )?;
        aead::seal(
            &keys::parts_secret_key_key(&pair_key, vault_id, &slot.kit_id),
            secret_key.open().as_slice(),
            &parts_aad(vault_id, &slot.kit_id, part_role::SECRET_KEY),
        )
        .map(Some)
    }

    // ---- devices (sync) ----

    /// The device this copy is written by (zero until sync is set up on this device).
    pub fn device(&self) -> DeviceId {
        self.sync.writer
    }

    /// Makes this device the writer of the copies saved from now on. Called after opening,
    /// with the id kept in the device state.
    pub fn set_device(&mut self, id: DeviceId) {
        self.sync.writer = id;
    }

    /// The devices that sync this vault.
    pub fn sync_devices(&self) -> &[SyncDevice] {
        &self.sync.devices
    }

    /// Adds a device to those that sync this vault, or renames it. Refused for a device that
    /// was removed: it gets a new id when it is added again.
    pub fn add_sync_device(&mut self, device: SyncDevice) -> Result<()> {
        let name = device.name.trim();
        if device.id.is_none()
            || name.is_empty()
            || name.chars().count() > SyncDevice::MAX_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(Error::InvalidName);
        }
        if self
            .sync
            .tombstone(Gone::Device, device.id.as_bytes())
            .is_some()
        {
            return Err(Error::DeviceRemoved);
        }
        let device = SyncDevice {
            name: name.to_owned(),
            ..device
        };
        match self.sync.devices.iter_mut().find(|d| d.id == device.id) {
            Some(known) => *known = device,
            None => self.sync.devices.push(device),
        }
        Ok(())
    }

    /// Removes a device: copies it writes from now on are refused by every device that has
    /// merged this change.
    pub fn remove_sync_device(&mut self, id: &DeviceId) -> Result<()> {
        let before = self.sync.devices.len();
        self.sync.devices.retain(|d| d.id != *id);
        if self.sync.devices.len() == before {
            return Err(Error::ItemNotFound);
        }
        self.sync
            .bury(Gone::Device, *id.as_bytes(), crate::item::unix_now());
        self.drop_lock_of_removed_devices();
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
            self.vault_key.open().as_slice(),
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
        let key = self.guard_key.as_ref().ok_or(Error::SecretsLocked)?.open();
        let summary = ItemSummary::from_data(id, data);
        let mut outer = data.clone();
        let secrets = outer.take_secrets();
        let encoded = format::encode_secret(&secrets)?;
        let padded = padding::pad(&encoded, padding::item_bucket)?;
        let ciphertext = aead::seal(&key, &padded, &secrets_aad(&self.header.vault_id, &id))?;
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
                &key.open(),
                &sealed.ciphertext,
                &secrets_aad(&self.header.vault_id, &record.id),
            )?;
            let secrets = ItemSecrets::decode(padding::unpad(&padded)?)?;
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

/// What a try opened: this copy's `own` lock, the `newer` one waiting, or neither.
fn opened(own: bool, newer: bool) -> GuardOpened {
    match (own, newer) {
        (true, _) => GuardOpened::Own,
        (false, true) => GuardOpened::NewerOnly,
        (false, false) => GuardOpened::Neither,
    }
}

fn slot_aad(vault_id: &[u8; 16], kind: SlotKind) -> Vec<u8> {
    [b"vault-v0/slot".as_slice(), vault_id, &[kind.aad_byte()]].concat()
}

fn parts_aad(vault_id: &[u8; 16], kit_id: &[u8; 16], role: u8) -> Vec<u8> {
    [b"vault-v0/parts".as_slice(), vault_id, kit_id, &[role]].concat()
}

/// The Secret Key the recovery parts keep, opened with the pair key.
fn open_parts_secret_key(
    pair_key: &[u8],
    header: &VaultHeader,
    slot: &PartsSlot,
) -> Result<SecretKey> {
    let key = keys::parts_secret_key_key(pair_key, &header.vault_id, &slot.kit_id);
    let bytes = aead::open(
        &key,
        &slot.secret_key,
        &parts_aad(&header.vault_id, &slot.kit_id, part_role::SECRET_KEY),
    )?;
    SecretKey::from_slice(&bytes)
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

/// A digest of the header's key slots and kit: public bytes only, so it says nothing that
/// the header doesn't.
fn unlock_id(header: &VaultHeader) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"vault-v0/unlock-id");
    hash.update(header.vault_id);
    for slot in &header.slots {
        hash.update([slot.kind.aad_byte()]);
        hash.update((slot.wrapped_vault_key.len() as u64).to_le_bytes());
        hash.update(&slot.wrapped_vault_key);
    }
    if let Some(parts) = &header.parts {
        hash.update(parts.kit_id);
        hash.update(&parts.vault_key);
    }
    let digest = hash.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn local_key(vault_key: &VaultKey, vault_id: &[u8; 16], purpose: &str) -> Zeroizing<aead::Key> {
    let label = [b"local/".as_slice(), purpose.as_bytes()].concat();
    vault_key.subkey(&label, vault_id)
}

/// `record` with its item key wrapped under `to` instead of `from`; its sealed contents (and
/// so its digest, which sync compares) stay the same.
fn rewrap_item_key(
    record: &ItemRecord,
    from: &VaultKey,
    to: &VaultKey,
    vault_id: &[u8; 16],
) -> Result<ItemRecord> {
    let aad = item_key_aad(vault_id, &record.id);
    let item_key = aead::open(
        &from.subkey(SUBKEY_ITEM_WRAP, vault_id),
        &record.wrapped_key,
        &aad,
    )?;
    Ok(ItemRecord {
        wrapped_key: aead::seal(&to.subkey(SUBKEY_ITEM_WRAP, vault_id), &item_key, &aad)?,
        ..record.clone()
    })
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
    fn a_failed_unlock_change_leaves_the_vault_as_it_was() {
        let secret_key = SecretKey::generate().unwrap();
        let mut vault = Vault::create(
            "correct horse battery staple",
            &secret_key,
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let revision = vault.revision();
        let keyfile = Keyfile::from_bytes(&[7u8; 32]).unwrap();
        // The keyfile is added, the write "fails".
        let failed: Result<()> = vault.change_unlock(|vault| {
            let kdf = vault.kdf_params().clone();
            vault.change_password(
                "correct horse battery staple",
                &secret_key,
                Some(&keyfile),
                &kdf,
            )?;
            vault.to_bytes()?;
            Err(Error::Malformed)
        });
        assert!(failed.is_err());
        assert_eq!(vault.revision(), revision);
        assert!(
            !vault.needs_keyfile(),
            "the unsaved keyfile is not required"
        );
        let bytes = vault.to_bytes().unwrap();
        Vault::open(
            &bytes,
            Unlock::Password {
                password: "correct horse battery staple",
                secret_key: &secret_key,
            },
        )
        .unwrap();
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
