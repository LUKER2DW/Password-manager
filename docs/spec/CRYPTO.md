# Cryptographic Specification — v0

> Status: **draft**, not audited. Implemented by `crates/core` (file format v9); the labels
> have carried `vault-v0` since the first version and stay so. Any change that affects bytes
> on disk requires a new format version (see [VAULT_FORMAT.md](VAULT_FORMAT.md)).

## 1. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Password hashing | Argon2id v1.3 (RFC 9106); by choice scrypt (RFC 7914) or PBKDF2-HMAC-SHA-256 (RFC 8018), §4.1 | `argon2`, `scrypt`, `pbkdf2` |
| Key derivation | HKDF-SHA-256 (RFC 5869) | `hkdf`, `sha2` |
| Authenticated encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| Checksums | SHA-256 | `sha2` |
| Randomness | OS CSPRNG | `getrandom` |
| Constant-time comparison | — | `subtle` |
| Sealing to a public key (browser drop box only, §3.5) | libsodium sealed box: X25519 + XSalsa20-Poly1305, nonce = BLAKE2b(eph_pk ‖ pk) | `crypto_box` |
| The browser extension's link only (§3.9) | ECDH P-256 to agree on its key; AES-256-GCM to seal its messages (the AEAD the browser's WebCrypto offers: XChaCha20-Poly1305 isn't there, and written in JavaScript it would be home-made) | `p256`, `aes-gcm` |

All labels below are ASCII byte strings and are used verbatim (no terminator).

Sync server requests (spec/SYNC.md §5.3) are signed with **Ed25519** (`ed25519-dalek`, strict
verification, weak keys refused); the key is per device and vault, kept in the OS credential
store, and never touches the vault's own keys.

SSH key items (format v9) may hold a key the app made for the person: Ed25519 from
`ed25519-dalek`, written in OpenSSH's own format. It is data the vault keeps, like a
password, and plays no part in the vault's own keys. A key brought in is read and written
with RustCrypto's `ssh-key` (OpenSSH's form; PKCS#8, PKCS#1 and SEC1 through `rsa`, `p256`,
`p384` and `ed25519-dalek`). One with a passphrase is opened once with it (bcrypt-pbkdf and
the cipher OpenSSH used, at most 2000 bcrypt rounds: more is refused) and kept without it, as
other managers keep keys: the vault is its protection, and the passphrase is never stored.

Passkeys (format v10, §3.7) are ECDSA P-256 keys with SHA-256 (ES256, RFC 6979 nonces) from
`p256`, made by the app for websites. Like SSH keys, they are data the vault keeps and play no
part in the vault's own keys.

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

### 2.3 Recovery Key (256 bits, kits made before format v8)
- 32 random bytes, optional, printed in the emergency kit. Opens the vault on its own, so the kit
  must be stored offline and physically safe.
- Text form: `R0-` + 9 groups of 6 characters (52 data chars + 2 checksum chars), checksum as
  above with prefix `"R0"`.
- Still read: a vault that has one keeps it until a new kit is made, which replaces it with
  recovery parts (§2.4). New vaults get parts.

### 2.4 Recovery parts (3 × 128 bits, format v8)
- Three parts, A, B and C, each 16 random bytes, printed on separate pages of the emergency kit
  (part C may also be kept as a picture file). Keep them in three different places.
- **One part** reveals nothing. **Any two** bring back the Secret Key; the master password is
  still needed to open the vault. **All three** open the vault on their own, so a forgotten
  master password can be replaced.
- Text form: `A0-`, `B0-` or `C0-` + 4 groups of 7 characters (26 data chars + 2 checksum
  chars), checksum as above with the part's prefix, so a part typed with the wrong letter is
  caught.
- Changing the master password or the Secret Key keeps the parts working. A new kit (new parts)
  makes the old parts useless for the file from then on.

## 3. Key hierarchy

```
password_key = Argon2id(NFKC(password), salt = kdf.salt, m, t, p, out = 32)
KEK_password = HKDF-SHA-256(ikm  = password_key ‖ secret_key,
                            salt = vault_id,
                            info = "vault-v0/kek/password")            → 32 bytes
KEK_recovery = HKDF-SHA-256(ikm  = recovery_key,
                            salt = vault_id,
                            info = "vault-v0/kek/recovery")            → 32 bytes

vault_key    = 32 random bytes (generated when the vault is made, and again when it is
               renewed, §3.8)
subkey(p)    = HKDF-SHA-256(ikm = vault_key, salt = vault_id, info = "vault-v0/subkey/" ‖ p)
               p ∈ { "body", "item-wrap", "parts", "local/" ‖ purpose }
item_key     = 32 random bytes per item revision
```

The vault key does not change when the password, Secret Key, keyfile, Recovery Key or kit
changes; only the key slots that wrap it are rewritten. It changes only when it is renewed
(§3.8).

### 3.0 Keyfile (optional third factor)

```
keyfile_key  = SHA-256("vault-v0/keyfile" ‖ file bytes)      file: 16 bytes to 1 MiB
KEK_password = HKDF-SHA-256(ikm  = password_key ‖ secret_key ‖ keyfile_key,
                            salt = vault_id,
                            info = "vault-v0/kek/password+keyfile")   → 32 bytes
```

A vault that uses a keyfile has a `PasswordKeyfile` slot instead of the `Password` slot, wrapped
with this KEK. The different `info` and slot AAD keep the two derivations apart. Any file can be
a keyfile; one generated by the app is a line of text holding 256 random bits. The keyfile adds
entropy that never touches the device's credential store, so it is worth most on removable
storage. The Recovery Key still opens the vault on its own, and recovering resets the lock to
master password + (new) Secret Key. Setting or removing the keyfile rewrites the password slot,
which revokes device unlocks (§3.1).

### 3.2 Item guard key (format v6)

When the item guard checks a PIN or a separate password (VAULT_FORMAT.md §5), the secrets of
guarded items are sealed under a random 256-bit `guard_key` that is never stored unwrapped:

```
stretched = Argon2id(NFKC(secret), salt, 256 MiB, 3 passes, 4 lanes, out = 32)
KEK_guard = HKDF-SHA-256(ikm = stretched, salt = vault_id, info = "vault-v0/kek/guard")
wrapped   = seal(KEK_guard, guard_key, aad = "vault-v0/guard-key" ‖ vault_id ‖ slot)
sealed    = seal(guard_key, pad(ItemSecrets), aad = "vault-v0/item-secrets" ‖ vault_id ‖ item_id)
```

`slot` is 0x01 for the PIN or password and 0x02 for the copy wrapped by the master password
(so a forgotten PIN can be replaced). When the master password changes, that copy is rewrapped
under the new password if the guard key is in memory, and removed if it is not: kept as it
was, the old master password would still open guarded secrets. The apps open the guard with
the current master password before changing it, so the copy normally follows; once removed,
it comes back the next time the guard is set up with the master password. `sealed` sits inside the item, which is then sealed as usual (§5), so
tampering, swapping and rollback protection are unchanged; the AAD ties the secrets to their
item. The guard key leaves memory when the secrets are locked again.

**A new item needs no check.** When an item the guard covers is added while the guard key is
not in memory, it is stored like an unguarded item (sealed under the vault key, §5) and sealed
under the guard key the next time it is in memory (`Vault::seal_pending`, which the apps call
right after the guard opens; the item's revision goes up by one). Until then the apps still
ask for the guard's check before showing its secrets, but the core doesn't enforce it for
that item, which can also be changed and stays unsealed until then. Changing an item already
sealed under the guard key still needs that key.

**On one device, Windows Hello can stand in for the PIN.** The security chip signs a fixed
challenge after verifying the user (as in §3.1, with a key of its own), and

```
KEK_guard_device = HKDF-SHA-256(ikm = device_secret, salt = vault_id, info = "vault-v0/kek/guard-device")
sealed = seal(KEK_guard_device, guard_key,
              aad = "vault-v0/guard-device" ‖ vault_id ‖ SHA-256(wrapped check slot))
```

is kept on the device (`item-lock-<vault id>.bin`), never in the vault file. A new PIN or
password changes the check slot and so revokes it. Unlike a short PIN, this key cannot be
guessed offline: the chip holds it and limits tries.

The browser extension's key, and how its requests are signed and sealed, are in §3.9.

This puts a second key between an unlocked vault and its most sensitive data. It does not
make a short PIN strong: with the vault key in hand, 10 000 four-digit PINs cost 10 000
Argon2id runs.

### 3.3 Export protected by a password

An export of every item (the JSON layout) sealed for carrying elsewhere. It has one factor
only, the password chosen for the file, so clients ask for at least 12 characters.

```
file      = "PMVEXP" ‖ 0x00 ‖ 0x01 ‖ header_len (u16 LE) ‖ header ‖ sealed
header    = postcard(KdfParams)            // Argon2id, standard level, fresh salt
stretched = Argon2id(NFKC(password), header)
key       = HKDF-SHA-256(ikm = stretched, salt = "vault-v0/export", info = "vault-v0/key/export")
sealed    = seal(key, pad(contents), aad = everything before `sealed`)
```

The header is checked against the Argon2id floor and ceiling (§4) before any hashing, and
is part of the associated data, so its cost can't be lowered. Contents are padded like the
vault body (§7).

The contents are every item whole (`vault_import::export_sealed`): earlier passwords,
attached files (base64) and passkeys with their private keys (the 32-byte P-256 scalar,
base64url), in keys only this app reads (`attachedFiles`, `passkeys`, `passkeyItem`). The plain
JSON export never holds files or passkey keys. Whoever opens the file can sign in with those
passkeys, so its password is all that guards them: the apps ask for a long one.

### 3.1 Device unlock (Windows Hello)

A per-device wrapping of the vault key, kept **outside** the vault file
(`<app dir>/quick-unlock-<vault id>.bin`):

```
device_secret = TPM signature (RSA-2048, PKCS#1 v1.5, SHA-256 — deterministic) over
                "vault-v0/windows-hello/" ‖ vault_id_hex, released by Windows Hello
                (KeyCredentialManager, key name "vault-quick-unlock-" ‖ vault_id_hex)
KEK_device    = HKDF-SHA-256(ikm = device_secret, salt = vault_id, info = "vault-v0/kek/device")
device_unlock = seal(KEK_device, vault_key, AAD_device)
AAD_device    = "vault-v0/device" ‖ vault_id ‖ SHA-256(password slot's wrapped_vault_key)
```

- `device_secret` is never stored; the private key never leaves the TPM and signs only after
  Windows Hello verifies the user (face, fingerprint or Windows PIN, with the TPM's
  anti-hammering). Device secrets shorter than 32 bytes are refused.
- Binding to the password slot means **changing the master password revokes every device
  unlock** — including one made on another device, once the changed file arrives.
- Renewing the vault key (§3.8) revokes it too: `device_unlock` holds the former vault key,
  and the new password slot no longer matches its AAD. The app deletes it (Windows Hello is
  off until the person turns it on again).
- Every 14 days the master password is required once. The date of the last password unlock is
  device-local data sealed with the vault key (`local/last-password-unlock`, see §6), so it can't
  be moved forward without the vault key; missing or future dates count as expired.

### 3.4 Filling from the browser while the vault is locked

Kept **outside** the vault file, per vault, in `<app dir>/browser-locked-v2-<vault id>.bin`,
only while the setting is on and the item lock opens with Windows Hello
(`vault_core::locked_fill`):

```
K               = 32 random bytes (the blob's key)
G, G_pub        = an X25519 key pair (GuardedFillKey) for logins behind the item lock
device_secret   = the item lock's Windows Hello secret (§3.2: TPM signature after verification)
KEK_locked      = HKDF-SHA-256(ikm = device_secret, salt = vault_id_hex,
                               info = "vault-v0/kek/locked-fill")
key_by_device   = seal(KEK_locked, K, "vault-v0/locked-fill/key/" ‖ vault_id_hex)
key_by_vault    = seal_local("browser-locked-fill", K)          (vault-key subkey, §6)
guarded_key_by_device = seal(KEK_locked, G, "vault-v0/locked-fill/guarded-key/" ‖ vault_id_hex)
guarded_public_by_vault = seal_local("browser-locked-fill-public", G_pub)
passwords       = seal(K, pad(postcard([(item_id_hex, password)…])),
                       "vault-v0/locked-fill/passwords/" ‖ vault_id_hex)
                  (logins outside the item lock only)
stamp           = SHA-256("vault-v0/item-stamp/" ‖ item_id ‖ revision_le ‖ item record bytes)
guarded         = [(item_id_hex, stamp, sealed_box(G_pub, P ‖ pad(password)))…]
                  P = "vault-v0/locked-fill/guarded/" ‖ vault_id_hex ‖ "/" ‖ item_id_hex ‖ "/" ‖ stamp
                  (logins behind an item lock that encrypts, §3.3; libsodium sealed box as §3.5)
logins          = DPAPI(postcard([(id, title, username, urls, fillable, stamp)…]))  (current user)
```

- The locked app opens `key_by_device` or `guarded_key_by_device` only with Windows Hello,
  once per request, and hands out one password. Nothing typed opens them: a PIN could be
  guessed offline against a copied file, a TPM-backed signature can't (each try needs the
  person and the chip's anti-hammering).
- The vault key opens `K` (to keep `passwords` current without asking), never `G`: a locked
  login's password is sealed to `G_pub`, so the vault key alone (malware reading an open vault
  from memory) can't read it from this file either. The item lock keeps its meaning here.
- A locked login's password is sealed for one version of the login (`stamp`). While the item
  lock is closed the open app carries an entry over only when the login's stamp is unchanged;
  a login changed meanwhile (a sync from another device moving it to another website, say)
  is listed as not fillable until the item lock opens in the app, never filled with the old
  password on the new website. The locked app checks the entry's stamp against the listed
  login's before opening it.
- Saving the item lock makes `K` and `G` anew; turning Windows Hello or the setting off deletes
  the file. The file of earlier versions (`browser-locked-<vault id>.bin`, whose `key_by_vault`
  opened every password) is deleted with its backup whenever the index is read or written.
- The extension's connection key is kept a second time, DPAPI-protected
  (`browser-pairing-<vault id>.dpapi`), so the locked app can check requests.

### 3.1.1 Device unlock on a phone (fingerprint)

The same `device_unlock` (§3.1), with a device secret the phone's secure hardware keeps
instead of one it works out:

```
device_secret = 32 random bytes (Vault::new_device_secret), made when fingerprint unlock is
                turned on
hardware      = AES-256-GCM(K_keystore, device_secret)   (IV ‖ ciphertext ‖ tag)
K_keystore    = Android Keystore key "vault-unlock-" ‖ vault_id_hex (StrongBox when the phone
                has it): usable only right after a strong (Class 3) biometric check or, on
                Android 11+ (API 30), the phone's screen lock (PIN, pattern or password;
                AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL, timeout 0), once per use, and
                deleted by Android when a fingerprint is added
file          = unlock-<vault id>.json next to the vault: { sealed_key: device_unlock,
                hardware, password_at }
```

- The device secret crosses to the Java side only to be sealed or after the prompt opened it,
  and is wiped there and in Rust once used.
- A key made before the screen lock was allowed (biometrics only) keeps working as it was; the
  prompt offers the screen lock only for a key that accepts it (`KeyInfo`). Below Android 11
  the key is biometrics only.
- With the screen lock allowed, whoever knows the phone's PIN or pattern can open the vault on
  that phone within the 14 days: the Keystore still rate-limits guesses, but a short PIN is
  weaker than the master password (THREAT_MODEL.md, the phone).
- `password_at` is the last master password unlock: after 14 days fingerprint unlock waits for
  the master password again. A new master password revokes it (the AAD binds the password
  slot), and the app deletes the file and the key. So does a renewed vault key taken on the
  phone (§3.8): fingerprint unlock is off until the person turns it on again.
- Autofill's fingerprint path opens the vault file with `device_unlock` for one fill and
  drops it (`vault_mobile::autofill`).

### 3.5 Saving from the browser while the vault is locked (drop box)

Kept **outside** the vault file, per vault, in `<app dir>/browser-drop-<vault id>.bin`, made at
an unlock while the browser extension setting is on (`vault_core::drop_box`):

```
sk, pk      = X25519 key pair (sk = 32 random bytes)
sealed_key  = seal_local("browser-drop-box", sk)                 (vault-key subkey, §6)
entry       = crypto_box_seal(pk, vault_id_hex ‖ pad(postcard(url, title, username, password)))
file        = postcard(pk, sealed_key, [entry…])
```

- The locked app appends an entry for each login saved from the browser, with `pk` alone: it
  asks for nothing and cannot read back what it wrote. At most 200 entries wait.
- The phone does the same for logins Android's autofill saves while the vault is locked, in
  `autofill-drop-<vault id>.json` next to the vault (JSON instead of postcard, same keys and
  sealing).
- At the next unlock the app opens `sealed_key`, then each entry (checking the vault id
  prefix), adds the logins that aren't there yet as items (§3.2 for the item lock) and empties
  the list. A key that doesn't open (another vault, damage) replaces the file.
- A renewed vault key (§3.8) seals `sealed_key` again; `sk` and `pk` stay, so the entries
  waiting still open.
- `pk` is not authenticated while locked: nothing secret is available then. A program running
  as the user could swap it and read later entries; it would already see those passwords
  where they are typed (THREAT_MODEL.md).

### 3.6 Recovery parts (format v8)

```
kit_id        = 16 random bytes per kit (public, in the header)
KEK_parts     = HKDF-SHA-256(ikm  = A ‖ B ‖ C,
                             salt = vault_id,
                             info = "vault-v0/kek/parts" ‖ kit_id)             → 32 bytes
KEK_pair(XY)  = HKDF-SHA-256(ikm  = X ‖ Y,                 XY ∈ { AB, AC, BC }
                             salt = vault_id,
                             info = "vault-v0/kek/parts-pair/" ‖ "XY" ‖ kit_id)
pair_key      = 32 random bytes per kit
K_secret_key  = HKDF-SHA-256(ikm = pair_key, salt = vault_id,
                             info = "vault-v0/key/parts-secret-key" ‖ kit_id)

parts.vault_key  = seal(KEK_parts, vault_key)
parts.pairs[i]   = seal(KEK_pair(XY_i), pair_key)          i = 0 AB, 1 AC, 2 BC
parts.pair_key   = seal(subkey("parts"), pair_key)
parts.secret_key = seal(K_secret_key, secret_key)
```

- No Argon2: each pair has 256 random bits, all three 384. One part leaves 128 unknown bits
  before anything opens, two parts leave 128 before the vault key opens: the same margin as
  the Secret Key itself.
- Two parts open `pair_key` and with it the Secret Key; then the master password opens the
  vault as usual, which also checks the header (it is the body's AAD). `pair_key` stays
  sealed under the vault key, so when the Secret Key changes the vault seals the new one
  again without the parts. The master password is not stored anywhere.
- A new kit draws a new `kit_id` and `pair_key`, so nothing the old parts open is left in the
  file. The vault key itself is not changed: an old copy of the file still opens with that
  copy's parts (as with a changed master password), and the vault key it gives opens every
  newer copy too. Renewing the vault key (§3.8) is what ends that.
- Parts work once. Parts typed on a device may have been seen there, so once they have
  opened the vault (two of them bringing back the Secret Key, then the master password; or
  all three for a new master password) the apps remove the whole slot
  (`Vault::clear_recovery_parts`) and offer a new kit at once: the desktop right after the
  unlock or on the recovery's kit page, the command line by printing new parts with the
  recovery. A vault without the slot is a valid v8 file (as before the first kit).
- Not added: a word chosen or drawn per part, needed with it. Read with its part, a short
  word adds at most a few bits that the slot's quick HKDF opens offline in moments; kept in
  memory, it is one more thing to forget, in the one place meant for when memory fails. The
  parts' 128 bits each and the kit kept apart from the devices are the protection.
- Only HKDF-SHA-256 and the AEAD of §5; there is no secret sharing scheme to get wrong.


### 3.7 Passkeys (format v10)

A passkey is a WebAuthn credential kept in a login (VAULT_FORMAT.md §4), made and used by the
app for the browser extension. Only primitives from audited crates are used: ECDSA over
P-256 with SHA-256 (ES256, COSE algorithm −7) from RustCrypto's `p256` crate, with nonces
derived deterministically (RFC 6979), and SHA-256.

- **Making one.** The private key is a uniformly random scalar from the OS generator (a 32-byte
  string is drawn again in the rare case it is not a valid scalar); the credential id is 16
  random bytes. The site gets the public key as a COSE_Key (kty EC2, crv P-256, x, y, in
  CTAP2 canonical order) inside the attested credential data, and a `none` attestation (no
  attestation statement, AAGUID all zeros).
- **Authenticator data** (WebAuthn §6.1): SHA-256 of the RP id, the flags user present (UP),
  user verified (UV), backup eligible (BE) and backed up (BS) (plus AT when made), and a sign
  counter of 0. There is no counter: the same passkey is in every synced copy of the vault,
  and 0 tells the site that the authenticator keeps none. UV is set only when the person was
  verified for this very request: Windows Hello, or the item lock's PIN or password (for a
  login the lock covers, opening it for the request counts), on the phone the fingerprint or
  the phone's lock, which Android asks for before any passkey answers. An open vault alone is
  not verification. The site's `userVerification` decides when to ask: `required` and
  `preferred` (also when missing or unknown) verify when there is a way to; `discouraged`
  never asks. With no way here (no Windows Hello, no PIN or password item lock), `preferred`
  answers with UV clear and `required` is left to the browser's own handler. UP means the
  person chose it in the extension's own window.
- **Signing in.** The signature is ES256 over `authenticatorData || SHA-256(clientDataJSON)`,
  DER-encoded. The client data (`type`, `challenge`, `origin`, `crossOrigin: false`) is
  written by the app from the page's origin as the browser reports it and the site's
  challenge, never taken from the page.
- **Which site.** A page may make or use passkeys only for its own host or a domain its host
  is under that is not a public suffix (the Public Suffix List compiled into the app), never
  for an IP address, and only on HTTPS in the top frame (`vault_browser::origin::passkey_site`).
- **At rest.** The private key is item data: encrypted with the item key, and sealed under the
  item guard key with the item's other secrets when the guard covers the item (§3.2).

### 3.8 Renewing the vault key

A new master password, Secret Key, keyfile or kit rewrites only the slots (§3): the vault key
stays. So whoever opened one copy of the file (a stolen copy with its factors, an old kit, a
backup) holds the key to every copy written after it. Renewing draws a new vault key, so that
from then on newer copies are out of that key's reach (`Vault::renew_key`). There is no new
format version: a renewed file is an ordinary file of the current version.

**What the person gives.** The master password, typed again, with the Secret Key and (when the
vault has a `PasswordKeyfile` slot) the keyfile this device holds. They must open the current
password slot, and the key it opens must be the vault key in memory; otherwise the renewal
fails with `DecryptionFailed` (`KeyfileRequired` without the keyfile) and nothing changes. A
typo never becomes the master password. The master password itself stays.

**What is generated.**

```
vault_key'   = 32 random bytes
secret_key'  = a new Secret Key (§2.2)
A', B', C'   = new recovery parts (§2.4), with a new kit_id' and pair_key' (§3.6)
kdf'         = the same method and cost as kdf, with a new random salt
```

**What is wrapped again.** Every item record keeps its id, revision and sealed `data`; only its
wrapped item key changes:

```
item_key     = open(subkey(vault_key,  "item-wrap"), wrapped_key, AAD_item_key)
wrapped_key' = seal(subkey(vault_key', "item-wrap"), item_key,    AAD_item_key)
AAD_item_key = "vault-v0/item-key" ‖ vault_id ‖ item_id        (unchanged, §6)
```

Item keys are not drawn again. An item's `data` is the same bytes, so its record digest
(§6.1) and lineage stay the same and other devices see no item change. Whoever held the former
vault key gains nothing from that: an unchanged item is the version already in the older copy,
and the body around it is sealed under the new key. An item saved after the renewal gets a new
item key (§3), wrapped under `vault_key'`.

**The header after.**

- `kdf = kdf'`.
- `slots` holds one slot only: the password slot, `seal(KEK_password, vault_key')` with
  `KEK_password` worked out from the master password, `secret_key'`, the keyfile when the vault
  needs one, and `kdf'` (kind `Password` or `PasswordKeyfile`, AAD as in §6). A `Recovery`
  slot from a kit made before format v8 is dropped.
- `parts` is the new kit (§3.6 with `A'`, `B'`, `C'`, `kit_id'`, `pair_key'`, sealing
  `vault_key'` and `secret_key'`). The former kit's slot is gone.
- `unlock_revision` goes up by one (SYNC.md §4.5).

The body is sealed under `subkey(vault_key', "body")` from the next write on, with the new
header bytes as its AAD.

**What stays.** The item guard key (§3.2): it is wrapped by the PIN, the password, Windows Hello
or the master password, never by the vault key, so the item lock keeps working, and guarded
secrets stay sealed under it. The drop box's `sk` and `pk` (§3.5). The vault id.

**Unlock id.** A name for what opens a copy, read from its public header without any key
(`Vault::inspect`, `VaultInfo::unlock_id`). Sync uses it to tell a copy still under a former
key from one under a key renewed elsewhere (SYNC.md §4.7):

```
unlock_id = SHA-256( "vault-v0/unlock-id"
                   ‖ vault_id                                   (16 bytes)
                   ‖ for each slot, in header order:
                         kind (1 byte: 0x01 Password, 0x02 Recovery, 0x03 PasswordKeyfile)
                       ‖ len(wrapped_vault_key) (u64 LE)
                       ‖ wrapped_vault_key
                   ‖ if the header has parts:
                         kit_id (16 bytes) ‖ parts.vault_key (the sealed vault key, no length) )[..16]
```

It digests public bytes only, so it says nothing the header doesn't. It changes with every
change to the slots or the kit (a new master password too), not only with a renewal; a device
records the ones it stopped using only when it renews or takes a renewed key.

**Device-local data.** What a device sealed outside the file with `seal_local` under the former
key (§6: the generator's history, the extension's connection key, the website icon cache, the
leak watch, the drop box's `sealed_key`, the locked-fill index's `key_by_vault` and
`guarded_public_by_vault`) is opened once with the former key (`FormerKey::open_local`, the
same `subkey("local/" ‖ purpose)` and AAD) and sealed again under `vault_key'`
(`Vault::reseal_local`). A file's `.bak`, still under the former key, is deleted. The date of
the last password unlock is written anew. Then the former key is dropped and wiped
(`FormerKey` zeroizes on drop). Device unlocks (§3.1, §3.1.1) can't be sealed again without the
person: they are deleted. The `vault` command seals the desktop app's whole-file ones again
too, and refuses to renew or take a key while the app keeps a drop box or a locked-fill index
for the vault (files only the app reads): those are renewed from the app.

**Writing it.** The renewed file is written only over the bytes read before (AGENTS.md §4.1,
rule 7), and kept only together with `secret_key'` in the OS credential store. When storing the
key fails, the file is put back and `Vault::put_back_key` restores the vault in memory, former
key and all. The new kit is shown once, to be printed.

**What it protects, and what it can't.**

- After a renewal, the former factors, the former kit (and an older Recovery Key) and the vault
  key of any older copy open no copy written from then on.
- An older copy still opens itself with its own factors and kit: a backup, a stolen copy, a
  server's or folder's old copies, and the `.bak` written next to the file by the renewal's own
  save (it holds the copy from before, until the next save replaces it). What was in it is
  as exposed as before.
- Data an attacker already decrypted is not taken back. A password read from an older copy
  must be changed on its website.
- Devices that haven't taken the new key yet keep writing their copies under the former key
  (SYNC.md §4.7). Until each one does, its copy is readable with the former key.
- It does nothing against someone who can still read this device (malware): the new Secret Key
  is kept on it, and the master password is typed there.
- Other devices take the new key with the master password and `secret_key'`
  (`Vault::adopt_key`, SYNC.md §4.7): their item keys are wrapped again the same way and the
  renewed header is taken as it is.

### 3.9 The browser extension's link (not part of the vault file)

The extension and the app share a 256-bit connection key `K`, agreed when the person connects
the extension (`crates/browser/src/pairing.rs`, `apps/extension/link.js`):

1. The extension makes an ephemeral P-256 key pair (the private half a non-extractable
   WebCrypto key) and sends `commit = SHA-256("vault-browser/pairing-commit" ‖ E)`, `E` its
   public key as an uncompressed SEC1 point (65 bytes).
2. The app makes an ephemeral key pair and answers its public key `A`.
3. The extension sends `E`; the app refuses it unless it matches `commit`.
4. Both compute
   ```
   K    = HKDF-SHA-256(ikm = ECDH(E, A) x-coordinate, salt = E ‖ A, info = "vault-browser/pairing")
   code = 8 characters of "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789" (56, without
          I l 1 O o 0): the bytes of SHA-256("vault-browser/pairing-code" ‖ E ‖ A ‖ i) for
          i = 0, 1, … (one byte), each byte below 224 taken as byte mod 56, the others skipped;
          shown as two groups of four
   ```
   The extension and the app both show the code; the person connects in the app with the
   master password only when the two are the same.

A program in between must run one exchange with each side and can't make the two codes agree
by choosing its keys: the commitment makes it answer the extension before it knows `E`, and
commit towards the app before it knows `A` (the same reason Bluetooth's numeric comparison
commits first). Each attempt has one chance in 56^8 (about 10^14), in front of the person.

An extension older than this asks without a commitment and is handed a random `K` with a
six-digit code (the first 4 bytes of `SHA-256("vault-browser/pairing-code" ‖ K)`, big-endian,
mod 10^6), which the person types into the app: whoever asked knows it, so the app never shows
it. That key travels through whatever is between the browser and the app. Still accepted until
a version floor ends it.

From `K`, by one block of HKDF-SHA-256-Expand (`HMAC-SHA-256(K, info ‖ 0x01)`; `K` is 32 uniform
bytes, so there is no extract step, RFC 5869 §3.3):

```
K_req = HKDF-Expand(K, info = "vault-browser/requests", L = 32)
K_ans = HKDF-Expand(K, info = "vault-browser/answers",  L = 32)
```

A request is `{"type":"sealed","counter":c,"data":base64(n ‖ ciphertext ‖ tag)}` with
`AES-256-GCM(K_req, nonce n (12 random bytes), request text, aad = "vault-browser/request" ‖ c
(8 bytes LE))`; `c` is the sender's clock in milliseconds × 1000 plus a random part below 1000,
accepted once and only within two minutes of the app's clock. Its answer is
`{"type":"sealed","data":base64(m ‖ ciphertext ‖ tag)}` with `AES-256-GCM(K_ans, nonce m (12
random bytes), answer text, aad = "vault-browser/answer" ‖ c ‖ n)`: bound to that request. Only
"not connected", "not running" and "not understood" travel plain. Nonces are random, never the
counter (the app's record of counters seen starts empty at every start); at a few requests per
minute, random 96-bit nonces stay far from GCM's limits.

An extension older than sealed requests sends `{"type":"signed","counter":c,"body":…,"mac":…}`
with `mac = HMAC-SHA-256(K, c (8 bytes LE) ‖ body)` and gets plain answers.

The app keeps `K` sealed with the vault (`subkey("local/browser-pairing")`, §6) and a copy under
DPAPI for filling while locked (§3.4); the extension keeps it as a non-extractable WebCrypto
key. That key object is still written to the browser's profile, so a program that copies the
profile takes it (THREAT_MODEL.md).

## 4. Argon2id parameters

| | memory (KiB) | iterations | parallelism |
|---|---|---|---|
| **Floor** (rejected below) | 65 536 (64 MiB) | 2 | 1 |
| **Ceiling** (rejected above) | 4 194 304 (4 GiB) | 64 | 16 |
| **Default (desktop)** | 262 144 (256 MiB) | 3 | 4 |

- The floor stops downgrade attacks (a tampered header cannot make cracking cheap); the
  ceiling stops memory-exhaustion attacks through a crafted file.
- The user can pick a level (`KdfStrength`); all use 4 lanes and stay inside the limits above.
  Changing it rewrites only the password slot (fresh salt), after the current master password
  is checked against the file; the new file is opened once in memory before it is written.

  | Level | memory | iterations |
  |---|---|---|
  | Light | 64 MiB | 3 |
  | Standard (default) | 256 MiB | 3 |
  | Strong | 512 MiB | 4 |
  | Maximum | 1 GiB | 5 |

- `salt` is 32 random bytes, regenerated whenever the password slot is rewritten.

### 4.1 Other password hashing methods (format v6)

Argon2id is the default and the recommendation. The header may instead name one of two older
methods, for people who must follow a rule that names them; clients warn that both are weaker.
`password_key` in §3 is then that method's 32-byte output over the same NFKC password and
32-byte salt; everything after it is unchanged.

| Method | Parameters | Floor | Ceiling |
|---|---|---|---|
| scrypt | N = 2^`log_n`, r = 8, `p` | `log_n` 17 (128 MiB), p 1 | `log_n` 22 (4 GiB), p 16 |
| PBKDF2-HMAC-SHA-256 | `iterations` | 600 000 | 100 000 000 |

| Level | scrypt | PBKDF2 |
|---|---|---|
| Light | 2^17 | 600 000 |
| Standard | 2^18 | 1 200 000 |
| Strong | 2^19 | 2 400 000 |
| Maximum | 2^20 | 5 000 000 |

scrypt is memory-hard but older, and custom hardware does better against it than against
Argon2id. PBKDF2 needs almost no memory per guess, so graphics cards and ASICs attack it far
more cheaply; its floor is the current OWASP minimum. bcrypt is not offered.

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
| Password + keyfile slot | `KEK_password` (§3.0) | `"vault-v0/slot" ‖ vault_id ‖ 0x03` |
| Vault key under the three parts (§3.6) | `KEK_parts` | `"vault-v0/parts" ‖ vault_id ‖ kit_id ‖ 0x01` |
| Pair key under a pair of parts | `KEK_pair` | `"vault-v0/parts" ‖ vault_id ‖ kit_id ‖ 0x02 + i` (AB 0x02, AC 0x03, BC 0x04) |
| Pair key for the open vault | `subkey("parts")` | `"vault-v0/parts" ‖ vault_id ‖ kit_id ‖ 0x05` |
| Secret Key for two parts | `K_secret_key` | `"vault-v0/parts" ‖ vault_id ‖ kit_id ‖ 0x06` |
| Vault body | `subkey("body")` | `"vault-v0/body" ‖ header_bytes` |
| Item key | `subkey("item-wrap")` | `"vault-v0/item-key" ‖ vault_id ‖ item_id` |
| Item data | `item_key` | `"vault-v0/item" ‖ vault_id ‖ item_id ‖ revision (u64 LE)` |
| Guard key (§3.2) | `KEK_guard` | `"vault-v0/guard-key" ‖ vault_id ‖ slot (0x01 check, 0x02 master)` |
| Item secrets (§3.2) | `guard_key` | `"vault-v0/item-secrets" ‖ vault_id ‖ item_id` |
| Device unlock (§3.1) | `KEK_device` | `"vault-v0/device" ‖ vault_id ‖ SHA-256(password slot)` |
| Device-local data (e.g. icon cache) | `subkey("local/" ‖ purpose)` | `"vault-v0/local" ‖ vault_id ‖ purpose` |
| Browser link request (§3.9) | `K_req` | `"vault-browser/request" ‖ counter (u64 LE)` |
| Browser link answer (§3.9) | `K_ans` | `"vault-browser/answer" ‖ counter (u64 LE) ‖ request nonce` |

Device-local data is not part of the vault file: it is a per-device cache that can be deleted and
rebuilt at any time, encrypted so that it reveals nothing (such as which sites you use) without
the vault key.

`header_bytes` is the exact serialized header as stored in the file (magic and version
included), so any change to the header — KDF parameters, slots — makes the body fail to open.

### 6.1 Names used by sync (not keys)

Merging copies (SYNC.md) compares two short digests kept inside the sealed body. Neither is a
key or reveals one:

- guard key id = `SHA-256("vault-v0/guard-key-id" ‖ guard_key)[..8]`: whether two copies
  seal guarded items under the same guard key;
- record digest = `SHA-256("vault-v0/record" ‖ ItemRecord.data)[..8]`: names one stored
  version of an item (its ciphertext is new for every version and copied unchanged between
  devices).

Another device's copy is opened with this vault's own key (`subkey("body")` and the item
keys under `subkey("item-wrap")`); nothing in it is used to derive or select a key.

A third digest, the unlock id (§3.8), is read from a copy's public header, not its body. It
only sorts the copies this vault's key doesn't open (SYNC.md §4.7); it opens nothing and
selects no key.

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
