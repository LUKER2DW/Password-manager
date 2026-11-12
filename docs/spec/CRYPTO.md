# Cryptographic Specification — v0

> Status: **draft v0**. Implemented by `crates/core`. Any change that affects bytes on disk
> requires a new format version (see [VAULT_FORMAT.md](VAULT_FORMAT.md)).

## 1. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Password hashing | Argon2id v1.3 (RFC 9106) | `argon2` |
| Key derivation | HKDF-SHA-256 (RFC 5869) | `hkdf`, `sha2` |
| Authenticated encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| Checksums | SHA-256 | `sha2` |
| Randomness | OS CSPRNG | `getrandom` |
| Constant-time comparison | — | `subtle` |

All labels below are ASCII byte strings and are used verbatim (no terminator).

## 2. Secrets the user holds

### 2.1 Master password
- Normalized with Unicode **NFKC** before use, so the same password typed on different
  keyboards/OSes yields the same bytes. No trimming, no case folding.
- Must not be empty. Strength rules are enforced by the UI, not the format.

### 2.2 Secret Key (128 bits)
- 16 random bytes generated on vault creation. Stored on enrolled devices and in the emergency kit.
- Text form: `S0-` + 4 groups of 7 characters (Crockford Base32, 26 data chars + 2 checksum chars),
  e.g. `S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345`.
- Checksum: the top 10 bits of `SHA-256("vault-v0/key-checksum" ‖ "S0" ‖ key_bytes)`.
- Parsing is case-insensitive, ignores spaces and dashes, and accepts Crockford aliases
  (`O`→`0`, `I`/`L`→`1`).

### 2.3 Recovery Key (256 bits)
- 32 random bytes, optional, printed in the emergency kit. Opens the vault on its own, so the kit
  must be stored offline and physically safe.
- Text form: `R0-` + 9 groups of 6 characters (52 data chars + 2 checksum chars), checksum as
  above with prefix `"R0"`.

## 3. Key hierarchy

```
password_key = Argon2id(NFKC(password), salt = kdf.salt, m, t, p, out = 32)
KEK_password = HKDF-SHA-256(ikm  = password_key ‖ secret_key,
                            salt = vault_id,
                            info = "vault-v0/kek/password")            → 32 bytes
KEK_recovery = HKDF-SHA-256(ikm  = recovery_key,
                            salt = vault_id,
                            info = "vault-v0/kek/recovery")            → 32 bytes

vault_key    = 32 random bytes (generated once per vault)
subkey(p)    = HKDF-SHA-256(ikm = vault_key, salt = vault_id, info = "vault-v0/subkey/" ‖ p)
               p ∈ { "body", "item-wrap" }
item_key     = 32 random bytes per item revision
```

The vault key never changes when the password, Secret Key or Recovery Key changes; only the key
slots that wrap it are rewritten.

## 4. Argon2id parameters

| | memory (KiB) | iterations | parallelism |
|---|---|---|---|
| **Floor** (rejected below) | 65 536 (64 MiB) | 2 | 1 |
| **Ceiling** (rejected above) | 4 194 304 (4 GiB) | 64 | 16 |
| **Default (desktop)** | 262 144 (256 MiB) | 3 | 4 |

- The floor stops downgrade attacks (a tampered header cannot make cracking cheap); the
  ceiling stops memory-exhaustion attacks through a crafted file.
- `salt` is 32 random bytes, regenerated whenever the password slot is rewritten.

## 5. Sealing (AEAD with key commitment)

`seal(K, plaintext, aad)`:

```
N        = 24 random bytes
PRK      = HKDF-Extract(salt = N, ikm = K)
K_enc    = HKDF-Expand(PRK, "vault-v0/aead/enc",    32)
C_commit = HKDF-Expand(PRK, "vault-v0/aead/commit", 32)
ct‖tag   = XChaCha20-Poly1305(K_enc, N, plaintext, aad)
output   = 0x01 ‖ N ‖ C_commit ‖ ct‖tag
```

`open(K, sealed, aad)`: require version byte `0x01` (no other value is accepted), recompute
`C_commit` and compare in constant time, then decrypt. Any failure returns one generic error.

Why: Poly1305 alone is not key-committing (one ciphertext can decrypt under two keys —
"partitioning oracle" attacks). The commitment value binds the ciphertext to exactly one key.
Deriving a fresh `K_enc` per message also removes any risk from random-nonce collisions.

## 6. Associated data (what each ciphertext is bound to)

| Ciphertext | Key | AAD |
|---|---|---|
| Password slot | `KEK_password` | `"vault-v0/slot" ‖ vault_id ‖ 0x01` |
| Recovery slot | `KEK_recovery` | `"vault-v0/slot" ‖ vault_id ‖ 0x02` |
| Vault body | `subkey("body")` | `"vault-v0/body" ‖ header_bytes` |
| Item key | `subkey("item-wrap")` | `"vault-v0/item-key" ‖ vault_id ‖ item_id` |
| Item data | `item_key` | `"vault-v0/item" ‖ vault_id ‖ item_id ‖ revision (u64 LE)` |

`header_bytes` is the exact serialized header as stored in the file (magic and version
included), so any change to the header — KDF parameters, slots — makes the body fail to open.

## 7. Padding

Plaintexts are padded before sealing: `u32 LE length ‖ data ‖ zeros`.
- Items: total size rounded up to a multiple of 256 bytes.
- Body: at least 4 KiB; above that, rounded up to a multiple of `max(4 KiB, next_pow2(n) / 8)`
  (≤ 12.5 % overhead), which hides the exact number and size of items.

## 8. Memory hygiene

- Key material lives in `Zeroizing` buffers and is wiped on drop.
- Decrypted items are wiped on drop (`ZeroizeOnDrop`).
- Intermediate serialization buffers are allocated at their exact final size to avoid
  reallocation copies, and are zeroized.
- `Debug` output of secret types is redacted.
