//! File envelope and serialized structures (spec: VAULT_FORMAT.md).

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{Error, Folder, ItemId, KdfParams, Result, VaultSettings, item::FolderV1};

pub(crate) const MAGIC: &[u8; 8] = b"PMVAULT\0";
/// Version written by this build.
/// v0 = original layout; v1 = folders in the body, folder and recovery codes in items;
/// v2 = vault settings in the body, password history in items;
/// v3 = folder icons and colours, an icon website per item.
pub(crate) const FORMAT_VERSION: u16 = 3;
/// Oldest version this build still reads (and upgrades on the next save).
pub(crate) const OLDEST_READABLE_VERSION: u16 = 0;
const ENVELOPE_PREFIX: usize = 8 + 2 + 4;
const MAX_HEADER_LEN: usize = 64 * 1024;
const MAX_BODY_LEN: usize = 1 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SlotKind {
    Password,
    Recovery,
}

impl SlotKind {
    /// Byte used in the slot AAD (CRYPTO.md §6).
    pub(crate) fn aad_byte(self) -> u8 {
        match self {
            SlotKind::Password => 0x01,
            SlotKind::Recovery => 0x02,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeySlot {
    pub(crate) kind: SlotKind,
    pub(crate) wrapped_vault_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultHeader {
    pub(crate) vault_id: [u8; 16],
    pub(crate) kdf: KdfParams,
    pub(crate) slots: Vec<KeySlot>,
}

impl VaultHeader {
    pub(crate) fn slot(&self, kind: SlotKind) -> Option<&KeySlot> {
        self.slots.iter().find(|slot| slot.kind == kind)
    }

    /// Exactly one password slot, at most one recovery slot, valid KDF parameters.
    pub(crate) fn validate(&self) -> Result<()> {
        self.kdf.validate()?;
        let count = |kind| self.slots.iter().filter(|s| s.kind == kind).count();
        if count(SlotKind::Password) != 1 || count(SlotKind::Recovery) > 1 {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ItemRecord {
    pub(crate) id: ItemId,
    pub(crate) revision: u64,
    pub(crate) wrapped_key: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultBody {
    pub(crate) revision: u64,
    pub(crate) items: Vec<ItemRecord>,
    pub(crate) folders: Vec<Folder>,
    pub(crate) settings: VaultSettings,
}

/// Body layout of format v1 (no settings, plain folders).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultBodyV1 {
    pub(crate) revision: u64,
    pub(crate) items: Vec<ItemRecord>,
    pub(crate) folders: Vec<FolderV1>,
}

/// Body layout of format v2 (plain folders).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultBodyV2 {
    pub(crate) revision: u64,
    pub(crate) items: Vec<ItemRecord>,
    pub(crate) folders: Vec<FolderV1>,
    pub(crate) settings: VaultSettings,
}

/// Body layout of format v0 (no folders).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultBodyV0 {
    pub(crate) revision: u64,
    pub(crate) items: Vec<ItemRecord>,
}

/// A parsed (but not yet decrypted) vault file.
#[derive(Debug)]
pub(crate) struct ParsedFile<'a> {
    /// Format version of this file (between OLDEST_READABLE_VERSION and FORMAT_VERSION).
    pub(crate) version: u16,
    /// Magic, version, length and header: the exact bytes used as body AAD.
    pub(crate) header_bytes: &'a [u8],
    pub(crate) header: VaultHeader,
    pub(crate) body: &'a [u8],
}

pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedFile<'_>> {
    if bytes.len() < ENVELOPE_PREFIX || &bytes[..8] != MAGIC {
        return Err(Error::NotAVault);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if !(OLDEST_READABLE_VERSION..=FORMAT_VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    let header_len = read_u32(bytes, 10)? as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(Error::Malformed);
    }
    let header_end = ENVELOPE_PREFIX + header_len;
    let header: VaultHeader = decode_exact(
        bytes
            .get(ENVELOPE_PREFIX..header_end)
            .ok_or(Error::Malformed)?,
    )?;
    header.validate()?;

    let body_len = read_u32(bytes, header_end)? as usize;
    let body_start = header_end + 4;
    if body_len > MAX_BODY_LEN || body_start.checked_add(body_len) != Some(bytes.len()) {
        return Err(Error::Malformed);
    }
    Ok(ParsedFile {
        version,
        header_bytes: &bytes[..header_end],
        header,
        body: &bytes[body_start..],
    })
}

/// Serializes the envelope prefix + header: the exact bytes that become body AAD.
pub(crate) fn encode_header(header: &VaultHeader) -> Result<Vec<u8>> {
    let encoded = postcard::to_allocvec(header).map_err(|_| Error::Malformed)?;
    let len = u32::try_from(encoded.len()).map_err(|_| Error::Malformed)?;
    let mut out = Vec::with_capacity(ENVELOPE_PREFIX + encoded.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Concatenates header bytes and the sealed body into a complete file.
pub(crate) fn assemble(header_bytes: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let body_len = u32::try_from(body.len()).map_err(|_| Error::Malformed)?;
    let mut out = Vec::with_capacity(header_bytes.len() + 4 + body.len());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Deserializes `T`, rejecting trailing bytes.
pub(crate) fn decode_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|_| Error::Malformed)?;
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(value)
}

/// Serializes a secret-bearing value into an exactly-sized buffer that is wiped on drop
/// (no reallocation, so no stray copies on the heap).
pub(crate) fn encode_secret<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let size = postcard::experimental::serialized_size(value).map_err(|_| Error::Malformed)?;
    let mut buf = Zeroizing::new(vec![0u8; size]);
    let used = postcard::to_slice(value, &mut buf)
        .map_err(|_| Error::Malformed)?
        .len();
    buf.truncate(used);
    Ok(buf)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Malformed)?;
    Ok(u32::from_le_bytes(raw))
}
