# Architecture

> How the pieces fit and why they were chosen. The exact bytes are in
> [spec/CRYPTO.md](spec/CRYPTO.md), [spec/VAULT_FORMAT.md](spec/VAULT_FORMAT.md) and
> [spec/SYNC.md](spec/SYNC.md); who we defend against is in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Overview

```
 apps/desktop          apps/mobile              apps/cli
 Slint, Windows        Slint, Android           the `vault`
 (tray, Hello)         (apps/mobile-android,    command
                        apps/mobile-web)
       │                     │                     │
       └──────────┬──────────┴──────────┬──────────┘
                  ▼                     ▼
        crates/platform          crates/import
        credential store,        other managers' files,
        clipboard, Hello,        browsers' own stores
        kit PDF, sync targets    (on request)
                  │                     │
                  └──────────┬──────────┘
                             ▼
                       crates/core
          crypto · vault format · items · merge
          generator · TOTP · health · SSH keys

 apps/extension ── Native Messaging ── vault-desktop.exe ── named pipe ── desktop app
 (no secrets)                          (started as the host: crates/browser's relay)

 platform's sync targets ── signed requests (crates/sync-wire) ──► apps/server
                                                                   (sealed copies only)
```

**Core rule:** all cryptography lives **only** in `crates/core`. The apps, the extension and
the server never implement crypto themselves. `apps/` holds what people run; `crates/` holds
the libraries the apps share, and a library never depends on an app.

## 2. Key hierarchy

```
Master password ──► Argon2id(salt, params ≥ floor) ──┐
                                                     ├─► HKDF ──► Key Encryption Key (KEK)
Secret Key (128 bits) ───────────────────────────────┤
Keyfile [optional] ──────────────────────────────────┘
                                                             │ unwraps (AEAD)
                                                             ▼
                                                 Vault Key (256 bits, random)
                                                             │ HKDF per purpose
                                  ┌──────────────────────────┼──────────────────────┐
                                  ▼                          ▼                      ▼
                           Item keys                  Body key               Device-local keys
                           (one per item revision)    (the sealed body)      (icon cache, …)
```

- **Random Vault Key**: changing the master password only re-wraps this key (fast, no
  re-encryption).
- **Secret Key** combined with the password (the "two-secret" model): even a mediocre master
  password can't be cracked offline from the file alone. Each device keeps it in the OS
  credential store; on Windows, where there is a TPM, under a key that never leaves the chip
  (an RSA key in the TPM wraps the key that seals it, `crates/platform/src/tpm.rs`,
  CRYPTO.md §2.2.1), so a copied disk, profile or Credential Manager doesn't carry it. Without
  a TPM it stays with DPAPI alone, which Settings → Security says is weaker.
- **Item lock**: with a PIN or a second password, the secrets of locked items are sealed under
  a guard key only that PIN or password unwraps, so an unlocked vault taken from memory still
  doesn't show them (CRYPTO.md §3.2).
- **Quick unlock** is another wrapping of the same Vault Key, done by a hardware-held key:
  - Windows ✅: Windows Hello (IR face, fingerprint or PIN), key in the TPM
    (`crates/platform/src/quick_unlock.rs`, CRYPTO.md §3.1).
  - Android ⬜: Keystore/StrongBox + `BiometricPrompt` Class 3.
  - Any platform ⬜: YubiKey touch (`hmac-secret`).
  - Policy: the master password is asked every 14 days; changing it revokes every device
    unlock; failed attempts are rate-limited by Windows Hello / the TPM itself.
- **Emergency kit**: a printable PDF with the Secret Key, room to write the master password,
  and three **recovery parts** (A, B, C), one per page, to keep in different places: any two
  bring back the Secret Key, all three open the vault so a new master password can be set,
  one alone opens nothing. No secret-sharing scheme: pairwise HKDF wraps in the header
  (CRYPTO.md §3.6). Parts work once: after one is used the app offers a new kit. Part C can
  also live inside a photo of the person's own (a PNG with it in its pixels). Every PDF of a kit
  with keys (printed or saved) is encrypted with the PDF's own AES-256 protection under four
  words derived from the vault key, the Secret Key and the kit, shown on the kit page behind
  the item lock, never printed (CRYPTO.md §3.10).
- **Renewing the Vault Key**: a new master password, Secret Key or kit leaves the Vault Key as
  it is, so whoever opened an older copy holds the key to newer ones. A renewal (desktop
  Emergency kit page, `vault renew-key`) draws a new Vault Key, Secret Key and kit and wraps
  every item key again; other devices take it once with the new Secret Key (CRYPTO.md §3.8,
  SYNC.md §4.7).

## 3. Primitives

| Purpose | Choice | Notes |
|---|---|---|
| Password hashing | **Argon2id** | Calibrated per device, with a hard floor and ceiling; scrypt and PBKDF2-SHA-256 by choice, marked weaker |
| Subkey derivation | **HKDF-SHA-256** | Domain separation by label |
| Encryption | **XChaCha20-Poly1305**, made key-committing | A fresh key and commitment per message from HKDF over a random 192-bit nonce |
| Browser drop box | libsodium sealed box (X25519) | Only for logins saved while the vault is locked |
| Sync server requests | **Ed25519** signatures | One key per device and vault; no password reaches the server |
| Releases | **Ed25519** in minisign's format (`minisign-verify`) | Every release's `manifest.json` (each file's size and SHA-256) signed in the release workflow after the maintainer's approval; every updater checks it against two embedded keys (CRYPTO.md §9) |
| The Secret Key kept on Windows | **RSA-2048 OAEP-SHA-256** in the TPM (NCrypt's Platform Crypto Provider) | Wraps a random key that seals the Secret Key with the AEAD above; not exportable, no prompt (CRYPTO.md §2.2.1) |
| Randomness | OS CSPRNG (`getrandom`) | |
| Memory | `zeroize`; a global allocator that wipes every block it frees; typed secrets in one area locked in RAM; the vault and guard keys encrypted between uses (`CryptProtectMemory`, Windows) | A test reads the running app's memory after it locks (THREAT_MODEL §3) |

Only audited RustCrypto crates (and `ed25519-dalek`, `crypto_box`). Sharing (later) is planned
with HPKE and a hybrid X25519 + ML-KEM-768 KEM against "harvest now, decrypt later".

## 4. Vault file

- **Envelope and header** (plaintext but **authenticated**: the exact header bytes are the
  body's associated data): magic, version, password hashing parameters, salts, the key slots
  (password, keyfile, recovery parts).
- **Body**: sealed whole and padded, so the number and size of items stay hidden. Inside it,
  each item is sealed again under its own key, bound to the vault id, the item id and its
  revision, so items can't be swapped or rolled back one by one.
- **Revision** counter in the body; each device remembers the highest revision it saw, so an
  older file is noticed (rollback).
- **Atomic writes** with one backup copy; a save never overwrites a file something else
  changed since it was read.
- Every change to the bytes is a new format version; older versions are read and upgraded,
  and a committed test vault per version must keep opening (AGENTS.md §5.1).

## 5. Browser and autofill

- WebExtension (`apps/extension/`, Manifest V3) with **no secrets and no crypto**, in plain
  JavaScript with no build step and no packages: what is reviewed is what the browser runs. It
  talks to the desktop app over **Native Messaging** (local process, no network).
- Path of a request: extension window → native host (the desktop app's own executable,
  started by the browser with our extension's id as its argument, which it checks; it then
  only relays and shows nothing) → named pipe of the signed-in user → desktop app. Each end
  checks the other is that same executable (by the path of its process). The link is off
  until turned on in Settings.
- A content script on https pages (top frame) notices sign-in fields and submitted forms; a
  background worker relays to the app. When a sign-in field is focused and the app has a
  login for the site, a small frame (the extension's own page, `inline.html`, in a
  cross-origin iframe) lists usernames; on a new-password field it offers a password made by
  the app's generator, fitted to the field's `maxlength`, `minlength`, `pattern` and
  `passwordrules`; after a sign-in it offers to save the login. Clicks in the frame count only
  while the browser reports it fully visible (IntersectionObserver v2), against extension
  clickjacking. The extension's window (button or Ctrl+Shift+L) lists the site's logins and
  the whole vault (passwords shown or copied one at a time, each through the item lock), the
  generator and a form for a new login. The app announces each fill.
- Copying from the extension is done by the app (`copy` request): the value never reaches the
  browser, and the clipboard copy is kept out of Windows clipboard history.
- With the vault locked the app still answers, from a file kept for the extension
  (`vault_core::locked_fill`, `vault_browser::locked`): logins are listed, and one password
  leaves after Windows Hello. Saving, generating and one-time codes wait for the vault to be
  unlocked. See CRYPTO.md §3.4; logins saved meanwhile go to a drop box (§3.5).
- Exact origin matching (scheme + host + port), decided by the app with the WHATWG URL rules
  (`crates/browser/src/origin.rs`); the top frame only; no filling over plain HTTP. A password
  leaves the app only for the one login picked, and only for a page of its origin.
- **Pairing:** the first time, the extension asks to be connected: it and the app agree on a
  key by ECDH (the key never travels), both show an eight-character code computed from the
  exchange, and the app comes forward and asks the person to compare it and type the master
  password (in the app, never in the browser). From then on every request and every answer is sealed
  with keys derived from it (AES-256-GCM, each answer bound to its request; CRYPTO.md §3.9),
  so a program that merely starts the native host gets nothing, and one put between the
  browser and the app reads nothing and can't forge an answer.
- A login behind the item lock is opened for one fill only: by **Windows Hello** (the app
  shows the system's prompt) or by the item lock's **PIN**, typed in the extension's own
  window and counted with the app's wrong tries.
- A login is used on more sites only by choice: every website saved in it counts, and
  `*.example.com` covers that site and everything under it.
- On Android: the Autofill Service for logins and the Credential Manager for passkeys
  (`CredentialProviderService`, Android 14+), both validating the app's package and signing
  certificate (defence against AutoSpill), and a web page's origin only from a browser known
  by its release certificate.

## 6. Sync

Full design: [spec/SYNC.md](spec/SYNC.md). In short:

- Every device keeps a whole vault file and works offline; sync only moves sealed copies.
- A **server is optional**. The same engine syncs through a folder (OneDrive, Drive,
  Syncthing, a NAS), a WebDAV host or our own `vault-server` (Docker, reached over Tailscale or
  with its own pinned HTTPS), plus an optional backup place.
- Each device writes only its own copy (`devices/<device id>.vault`) and merges the others
  in `vault-core` (`Vault::merge`): items by lineage, deletions as tombstones, the newer edit
  wins and the other password goes into the history. Nothing is lost to a conflict.
- The other copies are opened with the vault key already in memory: the target never
  supplies a key or a password hashing parameter. Rollback, replay and forks are refused per
  writer.
- The server authenticates devices by signed requests (Ed25519 keys made on each device);
  no password or password hash reaches it. New devices join with a one-time invite.
- The browser extension does not sync: it follows the desktop app on the same computer.

### Updates

- The desktop app, the phone and the sync server (`--app-updates`) read GitHub's newest
  release with `vault_sync_wire::releases`, and take it only with its `manifest.json` signed by
  one of the two manifest keys the apps carry (`RELEASE_KEYS`): the primary, which the release
  workflow uses after the maintainer's approval, and a backup that never leaves the maintainer's
  computer. The manifest's version, its signed comment and the release's tag must agree, and a
  version not newer than the one installed is never offered.
- A file is taken only as the manifest lists it (size and SHA-256): the phone's package, the
  browser extension's zip the desktop app keeps. A sync server keeps the manifest and its
  signature beside the phone app it hands on, and the phone checks them itself.
- `tools/release` (`vault-release`) writes the manifest, signs it and checks it the apps' way,
  in the release workflow; `tools/release/make-manifest-keys.ps1` makes the keys
  (docs/CODE_SIGNING.md). Windows Authenticode signing through the SignPath Foundation is
  pending; every Windows program already carries the same version information.

## 7. User interface: native Rust with Slint

**Requirement:** passwords and other secrets must not pass through memory we cannot control.

### Why native instead of a WebView (Tauri)

| Concern | Tauri 2 (WebView) | Slint (native Rust) |
|---|---|---|
| Master password typing | Every keystroke goes through the DOM and the JS engine; strings are copied by the GC and cannot be wiped | A custom secure field captures key events in Rust and appends them to a `Zeroizing` buffer; the UI layer only knows how many bullets to draw |
| Revealing a password | The value is serialized over IPC as JSON, then lives in the JS heap and the DOM | The value is shown in one text element only while asked for, and cleared when hidden; the Rust copy is zeroized and Slint's own string is wiped when freed (the wiping allocator); what the renderer (Skia, C++) makes of it to draw it isn't |
| Copy to clipboard | Can be done in Rust (OK in both) | Done in Rust |
| Attack surface | Browser engine + JS + npm supply chain | Rust crates only |
| Design freedom | Highest (HTML/CSS ecosystem) | High: custom components, gradients, shadows, animations, custom fonts, SVG; fewer ready-made components, limited effects such as backdrop blur |
| Platforms | Windows, Linux, Android | Windows, Linux, Android (Rust) |

Note: no UI toolkit can make a secret vanish completely. The OS delivers keystrokes as events,
and a revealed password has to be in the renderer's memory while it is on screen. What native
Rust gives us is **control**: short lifetimes, no hidden copies, explicit zeroization.

### Slint details

- Declarative `.slint` markup + Rust logic; renders with its own renderer, no WebView.
- License: GPL-3.0-only OR royalty-free OR commercial. The GPL-3.0 option fits this project.
- One design for both apps: the phone imports the desktop's tokens, widgets and icons
  (`apps/desktop/ui`), with `Theme.touch` sizing them for fingers.
- Android: Slint's Android backend from Rust, with a small Java activity
  (`apps/mobile-android/java`) for what native code can't reach alone (the file picker,
  "save as", Back). Secret fields use the system keyboard through an unseen input that only
  ever holds stand-ins (MOBILE.md §6.1, §7.2). Autofill, the Credential Manager and
  BiometricPrompt are Android services in the same shell, calling the same Rust core.

### Alternatives kept on file

- **Tauri 2**: fallback if a native UI cannot reach the design we want, with a locked-down
  configuration (minimal capabilities, Isolation Pattern, strict CSP, secrets kept in Rust).
- **Iced**, **Makepad**, **Freya**, **Dioxus Native/Blitz**: looked at, not chosen.

## 8. Internationalization (i18n)

- All code, identifiers, comments, logs and docs are in **English**.
- No user-facing string is hard-coded: every UI string goes through `@tr()`, compiled from
  gettext catalogues (`apps/desktop/translations/`); the extension uses its own
  `_locales/`. The core returns error codes, never text.
- Default locale `en`; Brazilian Portuguese (`pt-BR`) is the first translation, under way.

## 9. Import / export

- Import: JSON exports in the common layout, CSV from browsers and managers, KeePass KDBX
  3/4 (with a key file), an export sealed under a password (`.vaultx`), and on Windows a
  browser's own store read directly on request.
- Export: JSON (also sealed under a password) and CSV; plain-text export only after the master
  password again, and plain-text files the app read are offered for secure wiping. Before a file
  is made the app shows what the chosen format leaves out and what it writes in plain text
  (`vault_import::export_report`), and an import names what it left out.

What each format keeps:

| What an item holds | `.vault` (vault file, backup) | `.vaultx` (sealed export) | JSON (plain) | CSV (plain) |
|---|---|---|---|---|
| Title, username, password, notes, favourite, "ask again" | kept | kept | kept, in clear | kept, in clear |
| Websites | all | all | all | the first only |
| One-time code (TOTP; a HOTP counter inside its URI) | kept | kept | kept, in clear | kept, written as is |
| Custom fields | kept, hidden mark kept | kept, hidden mark kept | kept, hidden mark kept, in clear | "name: value" lines, no hidden mark (the app hides names that look secret again); a value of several lines comes back whole unless a later line holds ": " |
| Recovery codes | codes, used marks | codes, used marks | as `.vaultx`, in clear | one text field, hidden again by name |
| Earlier passwords | kept | kept | left out (named on import) | left out |
| Created, changed, password set dates | kept | kept | kept | left out |
| Attached files | kept | kept (name, date, bytes) | left out (counted, named on import) | left out |
| Passkeys | kept | kept, with their private keys (sealed under the file's password) | left out (a key in clear would sign in as you) | left out |
| Item kind | kept | kept | passkey items as logins | cards and SSH keys as notes, passkey items as logins |
| Folders | name, icon, colour, picture, order | names | names | a name per item |
| Item lock | kept | not carried (the importing vault's applies) | not carried | not carried |
| Items whose secrets are locked | sealed | export refused until they are opened | refused | refused |
| Protection | master password and Secret Key | its own password (Argon2id) | none | none |

From other managers: passkeys in a JSON export and KeePass attachments are not imported and
are counted in a warning; a website rule narrower than an origin is kept for reference and not
filled; KeePass entry history is not imported (one warning per file counts the entries with
earlier passwords).
- Passkeys, later: the FIDO Alliance Credential Exchange Protocol/Format.

## 10. Licensing

- Apps, libraries, CLI and browser extension: **GPL-3.0-or-later** ([LICENSE](../LICENSE)).
- Sync server: **AGPL-3.0-or-later** ([apps/server/LICENSE](../apps/server/LICENSE)):
  modified versions offered as a network service must share their source.
- Code from other projects is only reused when its licence is compatible, with attribution.

## 11. Development security

- Known-answer test vaults per format version, tamper, rollback and downgrade tests, property
  tests (`proptest`), headless end-to-end tests of each app, `clippy -D warnings`.
- Tests against a hostile sync place from the device's side (SYNC.md §9, THREAT_MODEL §2.1),
  and `cargo deny check advisories` in CI.
- Fuzzing (`cargo-fuzz`, `fuzz/`) of what the apps read from someone else: the vault file and
  a copy merged into an open vault, the sync protocol both ways, the extension's messages and
  release zip, imports, invite lines, `otpauth://` links and the part C picture; every target
  five minutes a day in CI (`.github/workflows/fuzz.yml`).
- Every release's manifest is signed and checked by every updater (§6, Updates; CRYPTO.md §9),
  and every released file attested by GitHub.
- Planned: reproducible builds, Authenticode-signed Windows programs (the SignPath
  Foundation, pending: docs/CODE_SIGNING.md), and an independent external audit before
  any stable release.
