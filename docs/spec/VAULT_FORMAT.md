# Vault File Format — v10

> Status: **draft v10**, not stable. v0–v9 files are still read and upgraded to v10 on the next save. Cryptographic operations are defined in [CRYPTO.md](CRYPTO.md).
> Structures are serialized with [postcard](https://postcard.jamesmunns.com/wire-format) 1.x
> (stable wire format). Integers in the file envelope are little-endian.

## 1. Envelope

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `"PMVAULT\0"` |
| 8 | 2 | `format_version` (u16) = `9` (`0`–`8` are read and upgraded) |
| 10 | 4 | `header_len` (u32) |
| 14 | `header_len` | `header` (postcard `VaultHeader`) |
| … | 4 | `body_len` (u32) |
| … | `body_len` | `body` (sealed, see §3) |

- No trailing bytes are allowed.
- `header_bytes` (used as AAD) = bytes `0 .. 14 + header_len`, i.e. magic, version, length and header.
- A reader must reject any `format_version` it does not implement. There is no negotiation and
  no fallback (downgrade protection). The version is part of `header_bytes` (the body AAD), so
  relabelling a file as another version makes its body fail to open.
- Limits: `header_len` ≤ 64 KiB, `body_len` ≤ 1 GiB.

## 2. Header (plaintext, authenticated)

```rust
struct VaultHeader {
    vault_id: [u8; 16],      // random, never changes
    kdf: PasswordKdf,        // v6; a bare KdfParams (always Argon2id) in v0–v5
    slots: Vec<KeySlot>,     // exactly one Password or PasswordKeyfile slot, at most one Recovery slot
    parts: Option<PartsSlot>,// v8; absent before. Never together with a Recovery slot
}

struct PartsSlot {           // v8: the three recovery parts (CRYPTO.md §3.6)
    kit_id: [u8; 16],        // random per kit
    vault_key: Vec<u8>,      // seal(KEK_parts, vault_key)
    pairs: [Vec<u8>; 3],     // seal(KEK_pair, pair_key) for AB, AC, BC
    pair_key: Vec<u8>,       // seal(subkey("parts"), pair_key)
    secret_key: Vec<u8>,     // seal(K_secret_key, secret_key)
}

enum PasswordKdf {           // postcard enum; limits in CRYPTO.md §4
    Argon2id(KdfParams),                              // 0
    Scrypt { log_n: u8, p: u32, salt: [u8; 32] },     // 1: N = 2^log_n, r = 8
    Pbkdf2Sha256 { iterations: u32, salt: [u8; 32] }, // 2
}

struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; 32],
}

struct KeySlot {
    kind: SlotKind,          // postcard enum: Password (0), Recovery (1), PasswordKeyfile (2, v5);
                             // the slot AAD uses 0x01 / 0x02 / 0x03 (CRYPTO.md §6)
    wrapped_vault_key: Vec<u8>, // seal(KEK, vault_key, slot AAD)
}
```

A `PasswordKeyfile` slot takes the place of the `Password` slot when the vault uses a keyfile:
its KEK also depends on the keyfile (CRYPTO.md §3), so the master password and Secret Key alone
don't open it. A reader that sees it without a keyfile fails before any hashing.

The header reveals only: that this is a vault, its random id, the KDF cost, whether it can be
recovered (Recovery Key or parts) and whether a keyfile is needed. It reveals nothing about the items.

## 3. Body (sealed)

`body = seal(subkey("body"), pad_body(postcard(VaultBody)), "vault-v0/body" ‖ header_bytes)`

```rust
struct VaultBody {
    revision: u64,           // incremented on every save; used for rollback detection
    items: Vec<ItemRecord>,
    folders: Vec<Folder>,    // v1; absent in v0
    settings: VaultSettings, // v2; absent before
    guard: ItemGuard,        // v5; absent before
    sync: SyncState,         // v7; absent before (defaults: never synced)
}

struct SyncState {           // what merging copies from several devices needs (SYNC.md)
    writer: [u8; 16],        // device id of the device that wrote this copy; zero = never synced
    tombstones: Vec<Tombstone>,
    folder_times: Vec<([u8; 16], i64)>, // when each folder last changed (Unix seconds)
    order_changed_at: i64,   // when the folders were last put in another order
    settings_changed_at: i64,
    unlock_revision: u64,    // +1 on every change to the key slots or the password hashing
    guard_revision: u64,     // +1 on every change to the item guard
    guard_key_id: [u8; 8],   // SHA-256("vault-v0/guard-key-id" ‖ guard key)[..8]; zero = none
    devices: Vec<SyncDevice>,
    lineage: Vec<([u8; 16], Vec<[u8; 8]>)>, // per item, the versions its current one was made
                             // from, newest first, at most 8: SHA-256("vault-v0/record" ‖
                             // ItemRecord.data)[..8]
}

struct Tombstone {
    id: [u8; 16],
    kind: Gone,              // postcard enum: Item (0), Folder (1), Device (2)
    deleted_at: i64,         // kept 400 days, then dropped on save
}

struct SyncDevice {
    id: [u8; 16],
    name: String,            // ≤ 60 characters
    signing_key: Option<[u8; 32]>, // Ed25519 public key, for a sync server
    added_at: i64,
}

struct ItemGuard {           // a second check before guarded items show their secrets
    all_items: bool,         // every item, or only items with `reprompt`
    check: GuardCheck,       // postcard enum: Master (0), Pin (1), Password (2)
    verifier: Option<Verifier>, // v5 guards only: a hash, nothing encrypted (see §5)
    key: Option<GuardKeySlots>, // v6: the wrapped guard key, for Pin and Password
}

struct Verifier {
    kdf: KdfParams,          // Argon2id at the format's floor, own salt
    hash: [u8; 32],          // Argon2id(PIN or password)
}

struct GuardKeySlots {
    check: WrappedGuardKey,          // opened by the PIN or password
    master: Option<WrappedGuardKey>, // opened by the master password, to replace a forgotten PIN
}

struct WrappedGuardKey {
    kdf: KdfParams,          // Argon2id at the Standard level, own salt
    wrapped: Vec<u8>,        // seal(guard KEK, guard_key), CRYPTO.md §3.2
}

struct VaultSettings {
    name: String,            // shown instead of the file name when not empty (≤ 60 chars)
    history_limit: u16,      // old passwords kept per item, 0–100 (default 10)
}

struct Folder {
    id: [u8; 16],            // random; unique within the vault
    name: String,            // encrypted with the body like everything else
    icon: String,            // v3: icon name chosen by the user, "" = plain folder
    color: u8,               // v3: colour index 0–15, 0 = default
    icon_url: String,        // v4: website or picture link whose image replaces the icon, "" = none
}
```

`folders` is in the user's order (the index shows them as stored; dragging one rewrites the
order). `icon_url` is at most 2 048 characters without whitespace or control characters. A link
whose path ends in `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.ico` or `.bmp` is a picture;
anything else is a website whose own icon is used. Pictures are downloaded by the client over
HTTPS only, once, and cached encrypted with the vault key outside the vault file.

```rust
struct ItemRecord {
    id: [u8; 16],
    revision: u64,           // incremented on every change to the item
    wrapped_key: Vec<u8>,    // seal(subkey("item-wrap"), item_key, item-key AAD)
    data: Vec<u8>,           // seal(item_key, pad_item(postcard(ItemData)), item AAD)
}
```

Items are encrypted twice on disk (item layer + body layer) on purpose: after unlocking, the
app keeps items encrypted in memory and decrypts only the one being used; the body layer hides
the item count, sizes and ids. Item records are also the unit of sync (SYNC.md §4).

## 4. Item data (v10)

```rust
struct ItemData {
    kind: ItemKind,          // Login, Card, SecureNote, Passkey, SshKey (v9)
    title: String,
    username: String,
    password: String,
    urls: Vec<String>,
    notes: String,
    totp: String,            // otpauth://totp/ or otpauth://hotp/ (with &counter=N) URI, or base32 secret; empty = none
    favorite: bool,
    custom_fields: Vec<CustomField>,
    created_at: i64,         // Unix seconds
    updated_at: i64,
    folder: Option<[u8; 16]>,          // v1: folder id, None = no folder
    recovery_codes: Vec<RecoveryCode>, // v1: the account's two-step backup codes
    password_history: Vec<PasswordChange>, // v2: earlier passwords, oldest first
    password_changed_at: i64,              // v2: when the password was set; 0 = unknown
    icon_url: String,                      // v3: website (or picture link) whose image stands for the item; "" = urls[0]; "glyph:<name>" = a preset line icon
    reprompt: bool,                        // v5: the item is guarded even when `guard.all_items` is off
    sealed: Option<SealedSecrets>,         // v6: present while the item's secrets are encrypted
    attachments: Vec<Attachment>,          // v9: files kept with the item; empty while sealed
    passkeys: Vec<Passkey>,                // v10: the login's passkeys (keys empty while sealed)
}

struct Passkey {             // v10, CRYPTO.md §3.7
    credential_id: Vec<u8>,  // as the site knows it; 16 random bytes when made here; 1..=1023
    rp_id: String,           // the site (relying party id), a domain in ASCII form
    user_handle: Vec<u8>,    // the site's id for the account, at most 64 bytes
    user_name: String,       // at most 256 characters
    display_name: String,    // at most 256 characters
    created_at: i64,         // Unix seconds
    key: Vec<u8>,            // the P-256 private scalar (32 bytes, big-endian); empty while sealed
}

struct Attachment {          // v9
    name: String,            // the file's name, without a path
    added_at: i64,           // Unix seconds
    data: Vec<u8>,           // at most 5 MiB; at most 10 per item
}

struct SealedSecrets {       // a guarded item under a PIN or password guard
    ciphertext: Vec<u8>,     // seal(guard_key, pad(ItemSecrets)), CRYPTO.md §3.2
    has_password: bool,      // what a locked item still tells
    has_totp: bool,
    card_hint: String,       // cards: "Visa •••• 4242", else ""
    card_brand: Brand,       // postcard enum, in the order of `card::Brand`
}

struct ItemSecrets {         // moved out of the item; those fields are stored empty
    password: String,
    totp: String,
    notes: String,           // only for secure notes (a login's notes stay readable)
    fields: Vec<String>,     // values of the `sensitive` custom fields, in order
    recovery_codes: Vec<RecoveryCode>,
    password_history: Vec<PasswordChange>,
    attachments: Vec<Attachment>,  // v9; sealed secrets written by v6–v8 end before it
    passkey_keys: Vec<Vec<u8>>,    // v10: each passkey's `key`, in order; v9 ones end before it
}

struct PasswordChange {
    password: String,
    replaced_at: i64,        // when it stopped being the password
}

struct RecoveryCode {
    code: String,
    used: bool,              // marked by the user once spent
}

struct CustomField {
    name: String,
    value: String,
    sensitive: bool,         // hidden by default in the UI
}
```

## 5. Upgrading older files

A v0 file has no `folders` in the body and its items end after `updated_at`; a v1 file has no
`settings` and its items end after `recovery_codes`; a v2 file's folders end after `name` and its
items after `password_changed_at`; a v3 file's folders end after `color`; v3 and v4 items end
after `icon_url`. When an older file is opened, every item is decrypted with its old layout and
re-encrypted with the current layout in memory (same ids and revisions, new item keys); the next
save writes a v10 file. v5 items end after `reprompt`; a v0–v5 header holds a bare `KdfParams`.
A v0–v6 body has no `sync`; it is read as never synced (no writer, no tombstones, revisions
at 0). The item layout is unchanged in v7. A v0–v7 header ends after `slots` (no `parts`); the
body and items are unchanged in v8. Such a vault keeps its Recovery Key until a new emergency
kit is made, which replaces the Recovery slot with `parts`. v6–v8 items end after `sealed`
(no `attachments`) and are re-encrypted in the v9 layout on open; their sealed secrets stay
sealed as they are and are read in either layout when the guard opens (a v6–v8 `ItemSecrets`
ends after `password_history`). v9 items end after `attachments` (no `passkeys`) and are
re-encrypted in the v10 layout on open; their sealed secrets (ending after `attachments`) are
read as they are.

**Passkeys (v10).** A login's passkeys are part of the item. Who and where (`credential_id`,
`rp_id`, `user_handle`, the names, `created_at`) stay readable while the item is sealed, like
its username; each passkey's `key` moves into the sealed `ItemSecrets` in the order of
`passkeys`, so a sealed item can be written back only with the same passkeys in the same order
(adding or removing one needs the guard open). Within an item no `credential_id` appears twice;
at most 16 passkeys per item.

**SSH keys (v9).** An `SshKey` item keeps the private key in `password` (OpenSSH's text,
without a passphrase; one in OpenSSH's form without a passphrase is kept exactly as it came,
other forms and keys with a passphrase are written in it), so the item guard covers it like a
password, and its public key, fingerprint and type in the plain custom fields `Public key`,
`Fingerprint` and `Key type` (`vault_core::ssh`; `Key type` from November 2026, read from the
key when missing). A key made by the apps is Ed25519.

**Chosen line icons.** `icon_url` = `glyph:<name>` is a preset line icon; `glyph:<name>:<c>:<t>`
adds its colour and its tile's colour (indices 1–9 into the apps' palette, 0 = the icon's own;
`view::IconLook`). Older readers see an unknown `icon_url` and show the item's own picture.

**Folders inside folders.** A folder named `Outer/Inner` is shown inside the folder named
`Outer` (when there is one), as other managers name them in their exports; nothing else is
stored for it.

**Attachments (v9).** Files are part of the item, so they are encrypted with its item key and,
when the item guard covers the item, sealed with its secrets. The whole vault is one file,
written and synced whole: the limits keep it small enough for that.

v0–v4 bodies have no `guard` (it defaults to: only marked items, master password). A v5 guard
ends after `verifier`.

**The item guard.** With the vault open, a client shows a guarded item's title, username,
websites, plain fields and notes (not a secure note's text), and keeps its password, one-time
code, recovery codes, hidden fields, card number and history closed until the check passes.
Editing and deleting need the check too. After 5 wrong tries the client locks the whole vault.

- `check = Master`: a rule for clients, not encryption. The master password is re-derived
  against the file; guarded items are stored like any other.
- `check = Pin` (4–8 digits) or `Password` (6+ characters): encryption. A random 256-bit
  guard key seals the `ItemSecrets` of every guarded item; the key is stored only wrapped
  (`GuardKeySlots`). The vault key alone, and so the Recovery Key alone, reads who the
  accounts are but not their secrets. A locked item may be written back with its visible
  fields changed (`sealed` is carried over); changing its secrets needs the guard key.
  Changing the guard re-seals every item, and needs the guard key (through the PIN, or the
  master password via `master`).
- A v5 guard (`verifier` set, `key` absent) encrypts nothing. The first time its PIN or
  password is typed correctly, the client creates the guard key, seals the guarded items and
  drops `verifier`. `verifier` and `key` are never both present.

Limits, stated plainly: anyone who already holds the vault key can try PINs offline against
`check`, at one Argon2id (256 MiB, 3 passes) per try. Four digits fall in hours; eight digits
or a real password do not. Secrets are readable in memory while they are open. Fixtures for every version are committed
(`crates/core/tests/fixtures`) and must keep opening.

When an item's password changes, `Vault::update_item` moves the old one into
`password_history` (dropping the oldest past `history_limit`) and sets `password_changed_at`.

## 6. Rules

- Writes are atomic: write `vault.tmp`, flush to disk, keep the previous file as `vault.bak`,
  then rename over the original.
- Item ids are unique within a vault, and so are folder ids; duplicates make the vault invalid.
- Clients remember the highest `(vault_id, revision)` they have seen and warn if a file with a
  lower revision is opened (rollback).
