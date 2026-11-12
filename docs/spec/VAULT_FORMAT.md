# Vault File Format — v0

> Status: **draft v0**, not stable. Cryptographic operations are defined in [CRYPTO.md](CRYPTO.md).
> Structures are serialized with [postcard](https://postcard.jamesmunns.com/wire-format) 1.x
> (stable wire format). Integers in the file envelope are little-endian.

## 1. Envelope

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `"PMVAULT\0"` |
| 8 | 2 | `format_version` (u16) = `0` |
| 10 | 4 | `header_len` (u32) |
| 14 | `header_len` | `header` (postcard `VaultHeader`) |
| … | 4 | `body_len` (u32) |
| … | `body_len` | `body` (sealed, see §3) |

- No trailing bytes are allowed.
- `header_bytes` (used as AAD) = bytes `0 .. 14 + header_len`, i.e. magic, version, length and header.
- A reader must reject any `format_version` it does not implement. There is no negotiation and
  no fallback (downgrade protection).
- Limits: `header_len` ≤ 64 KiB, `body_len` ≤ 1 GiB.

## 2. Header (plaintext, authenticated)

```rust
struct VaultHeader {
    vault_id: [u8; 16],      // random, never changes
    kdf: KdfParams,
    slots: Vec<KeySlot>,     // exactly one Password slot, at most one Recovery slot
}

struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; 32],
}

struct KeySlot {
    kind: SlotKind,          // postcard enum: Password (0), Recovery (1);
                             // the slot AAD uses 0x01 / 0x02 (CRYPTO.md §6)
    wrapped_vault_key: Vec<u8>, // seal(KEK, vault_key, slot AAD)
}
```

The header reveals only: that this is a vault, its random id, the KDF cost, and whether a
recovery slot exists. It reveals nothing about the items.

## 3. Body (sealed)

`body = seal(subkey("body"), pad_body(postcard(VaultBody)), "vault-v0/body" ‖ header_bytes)`

```rust
struct VaultBody {
    revision: u64,           // incremented on every save; used for rollback detection
    items: Vec<ItemRecord>,
}

struct ItemRecord {
    id: [u8; 16],
    revision: u64,           // incremented on every change to the item
    wrapped_key: Vec<u8>,    // seal(subkey("item-wrap"), item_key, item-key AAD)
    data: Vec<u8>,           // seal(item_key, pad_item(postcard(ItemData)), item AAD)
}
```

Items are encrypted twice on disk (item layer + body layer) on purpose: after unlocking, the
app keeps items encrypted in memory and decrypts only the one being used; the body layer hides
the item count, sizes and ids. Item records are also the unit of future sync.

## 4. Item data (v0)

```rust
struct ItemData {
    kind: ItemKind,          // Login, Card, SecureNote, Passkey
    title: String,
    username: String,
    password: String,
    urls: Vec<String>,
    notes: String,
    totp: String,            // otpauth:// URI or base32 secret; empty = none
    favorite: bool,
    custom_fields: Vec<CustomField>,
    created_at: i64,         // Unix seconds
    updated_at: i64,
}

struct CustomField {
    name: String,
    value: String,
    sensitive: bool,         // hidden by default in the UI
}
```

## 5. Rules

- Writes are atomic: write `vault.tmp`, flush to disk, keep the previous file as `vault.bak`,
  then rename over the original.
- Item ids are unique within a vault; duplicates make the vault invalid.
- Clients remember the highest `(vault_id, revision)` they have seen and warn if a file with a
  lower revision is opened (rollback).
