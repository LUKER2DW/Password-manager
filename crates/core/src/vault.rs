//! The unlocked vault: open, modify, and serialize (spec: VAULT_FORMAT.md).

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    Error, ItemData, ItemId, ItemSummary, KdfParams, RecoveryKey, Result, SecretKey, aead,
    format::{self, ItemRecord, KeySlot, SlotKind, VaultBody, VaultHeader},
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

/// An unlocked vault. Items stay encrypted in memory; each one is decrypted only when asked for.
pub struct Vault {
    header: VaultHeader,
    vault_key: VaultKey,
    revision: u64,
    items: Vec<ItemRecord>,
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
        let vault_key = VaultKey::from_slice(&key_bytes)?;

        let body_key = vault_key.subkey(SUBKEY_BODY, &header.vault_id);
        let padded = aead::open(&body_key, parsed.body, &body_aad(parsed.header_bytes))?;
        let body: VaultBody = format::decode_exact(padding::unpad(&padded)?)?;

        let mut ids: Vec<ItemId> = body.items.iter().map(|record| record.id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Malformed);
        }

        Ok(Self {
            header: parsed.header,
            vault_key,
            revision: body.revision,
            items: body.items,
        })
    }

    /// Serializes the vault into file bytes. Increments the vault revision.
    pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
        let next_revision = self.revision.checked_add(1).ok_or(Error::Malformed)?;
        let header_bytes = format::encode_header(&self.header)?;
        let body = VaultBody {
            revision: next_revision,
            items: self.items.clone(),
        };
        let encoded = postcard::to_allocvec(&body).map_err(|_| Error::Malformed)?;
        let padded = padding::pad(&encoded, padding::body_bucket)?;
        let body_key = self.vault_key.subkey(SUBKEY_BODY, &self.header.vault_id);
        let sealed = aead::seal(&body_key, &padded, &body_aad(&header_bytes))?;
        let bytes = format::assemble(&header_bytes, &sealed)?;
        self.revision = next_revision;
        Ok(bytes)
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
        let record = self.seal_item(id, 1, data)?;
        self.items.push(record);
        Ok(id)
    }

    /// Decrypts one item.
    pub fn get_item(&self, id: &ItemId) -> Result<ItemData> {
        let record = &self.items[self.position(id).ok_or(Error::ItemNotFound)?];
        self.open_item(record)
    }

    /// Replaces an item's contents (new item key, revision + 1).
    pub fn update_item(&mut self, id: &ItemId, data: &ItemData) -> Result<()> {
        let index = self.position(id).ok_or(Error::ItemNotFound)?;
        let revision = self.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        self.items[index] = self.seal_item(*id, revision, data)?;
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
        let padded = aead::open(
            &item_key,
            &record.data,
            &item_aad(vault_id, &record.id, record.revision),
        )?;
        format::decode_exact(padding::unpad(&padded)?)
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
