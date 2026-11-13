# Implementation Plan

> Companion to [ROADMAP.md](ROADMAP.md) (the *what*) — this document is the *how*: repository
> layout, milestones, and the definition of done for each one. Status markers: ✅ done,
> 🚧 in progress, ⬜ not started.

## Repository layout

```
password-manager/
├── Cargo.toml                 # workspace
├── rust-toolchain.toml
├── crates/
│   ├── core/                  # vault-core: crypto, vault format, items (no I/O except storage.rs)
│   ├── cli/                   # vault-cli: command-line client
│   ├── desktop/               # vault-desktop: Slint app (Windows/Linux)
│   ├── platform/              # OS integration: Windows Hello, TPM, clipboard, screen capture
│   └── server/                # vault-server: self-hosted sync (AGPL-3.0)
├── android/                   # Kotlin services (Autofill, Credential Manager) + Slint UI
├── extension/                 # browser extension (TypeScript, Native Messaging)
├── docs/
│   └── spec/                  # crypto and file-format specifications
└── prototypes/                # throwaway experiments (not shipped)
```

Rules:
- `core` has **no UI and no network**. It is the only place that touches key material.
- Every crate is `#![forbid(unsafe_code)]` except `platform`, where each `unsafe` block carries
  a `// SAFETY:` comment.
- Every user-facing string lives in a UI crate; `core` returns typed errors only.

## Milestones

### M0 — Specification ✅
- ✅ Threat model, architecture, roadmap
- ✅ UI prototype (Slint)
- ✅ [Crypto spec](spec/CRYPTO.md) and [vault format v0](spec/VAULT_FORMAT.md) (drafts)

### M1 — Core: primitives ✅ (`crates/core`)
- ✅ AEAD wrapper: XChaCha20-Poly1305 with key commitment and mandatory AAD
- ✅ KDF: Argon2id with hard-coded floor and ceiling
- ✅ KDF calibration (iterations from a target duration; Argon2 lanes run in parallel)
- ✅ Secret Key and Recovery Key: generation, Crockford Base32 text form with checksum, parsing
- ✅ Key hierarchy: KEK derivation (password + Secret Key), vault-key wrapping, HKDF subkeys
- ✅ Password normalization (Unicode NFKC)
- ✅ Known-answer fixture: a committed v0 vault file must keep opening
  (`crates/core/tests/fixtures`); RFC 6238 vectors for TOTP
- **Done when:** unit tests + known-answer tests pass, tamper tests fail closed, clippy clean.

### M2 — Core: vault ✅ (`crates/core`)
- ✅ Vault header with key slots (password slot, recovery slot)
- ✅ Items encrypted individually (own random key), whole body encrypted and padded
- ✅ Create / unlock / save / add / get / update / delete / list / change password / recovery slot
- ✅ Atomic file writes + one backup generation
- ✅ Revision counter in the body (rollback *detection* needs the client-side memory from M3)
- ✅ Property tests: random and mutated files never panic and are never accepted
- ⬜ `cargo-fuzz` target for the file parser (Linux CI)
- **Done when:** round-trip, tamper, downgrade, wrong-credential and corruption tests pass ✅.

### M3 — CLI 🚧 (`crates/cli`, binary `vault`)
- ✅ `init`, `info`, `list`, `add`, `show`, `edit`, `rm`, `generate`, `totp`, `passwd`,
  `recover`, `kit`, `forget`
- ✅ Secret Key kept in the OS credential store; typed from the kit on a new device
- ✅ Rollback detection: highest revision seen per vault is remembered on the device
- ✅ Hidden prompts, clipboard copy excluded from history with auto-clear after 20 s
- ✅ Password generator (uniform, guaranteed character classes); TOTP (RFC 6238)
- ✅ Passphrase generator (EFF large word list, vendored from eff.org with attribution,
  SHA-256 pinned in a test)
- ✅ Import (`crates/import`, `vault import`): Bitwarden JSON, KeePass KDBX 3/4 (+ key file),
  CSV from Chrome/Edge/Firefox/Bitwarden; duplicate skipping, `--dry-run`, `--delete-source`
- ⬜ Import of attachments (KeePass) and folders/tags (needs tags in the item model)
- ⬜ Printable emergency kit (PDF) — terminal version done
- **Done when:** a vault can be fully managed from the terminal ✅; import tests use fixtures ✅.

### M4 — Desktop app (Windows first) 🚧 (`crates/desktop`, design in [DESIGN.md](DESIGN.md))
- ✅ `crates/platform`: OS integration shared with the CLI (Secret Key store, device state and
  rollback, secure clipboard, capture blocking, page-locked secure input buffer)
- ✅ Visual system: "locksmith's notebook" tokens, hand-drawn strokes generated in Rust
- ✅ Onboarding (master password with confirmation, passphrase suggestion, emergency kit),
  unlock (Secret Key typed once per device), recovery with the Recovery Key
- ✅ Vault: index tabs, search, list, item page (reveal with countdown, copy with auto-clear,
  live TOTP), editor, favorites, delete with confirmation
- ✅ Generator: length slider, "use words instead" checkbox, separator, strength meter and a
  realistic crack-time estimate (≈10¹² guesses/s on leaked fast hashes) with a light comparison
- ✅ Settings (appearance, auto-lock, clipboard timeout, Windows Hello, change master password)
- ✅ Entry screens with a side panel (brand, steps, what is set up) and the form centered
- ✅ Folders (format v1): index with counts, create/rename/delete, folder picker in the editor
- ✅ Recovery codes per login (format v1): paste, show on request, copy, mark used
- ✅ Cards: number checked with Luhn and grouped as typed, brand detected (Visa, Mastercard,
  Amex, Elo, Hipercard, …), expiry validated and flagged when past, security code and PIN
  checked as digits; the PIN is never generated (the bank issues it); the list shows
  "Visa •••• 4242"
- ✅ Authenticator page: every one-time code in the vault with title, live countdown, search,
  copy and a jump to the item
- ✅ Extra fields on any item (name, value, hidden or not), stored as custom fields
- ✅ Several vaults: recent vaults remembered per device (no secrets, only the path), a chooser
  on the lock and new-vault screens, "Switch vault" in the index; the app opens the last one
- ✅ A vault file changed by something else while open (another window, a sync tool) is never
  overwritten: the save is refused with an explanation until it matches again
- ✅ Import & export page: Bitwarden/KeePass/CSV import with preview, duplicate skipping and
  wiping of the plain-text file; encrypted backup copy; unencrypted export after a password check
- ✅ Emergency kit page and printable PDF (hand-written, standard fonts; print copies wiped on lock)
- ✅ Performance: optimized dependencies in dev builds, summaries decrypted once per change,
  Windows Hello availability checked off the UI thread
- ✅ Auto-lock, screen-capture blocking, every UI string through `@tr()`
- ✅ Headless end-to-end test of the whole app flow (Slint testing backend)
- ✅ Visual review with off-screen screenshots; dark theme by default (light available)
- ✅ Item icons (opt-in website icons cached encrypted, type glyphs, initials) and "(?)" hints
  that say what to type in each field
- ⬜ Accessibility pass
- ✅ Windows Hello quick unlock: TPM-signed device secret wraps the vault key, revoked by a
  password change, master password every 14 days (tested with a fake verifier; the real prompt
  needs a manual check)
- ⬜ YubiKey (FIDO2 `hmac-secret`) slot; optional "master password after every restart"
- ⬜ `pt-BR` translation file
- ✅ Password history (format v2): the old password is kept when it changes, shown with its
  date, revealed and copied on request, cleared on request; how many are kept is a vault setting
- ✅ Password health page: strength (zxcvbn) with the reason a password is weak, reused
  passwords, passwords over a year old, expired cards, a score; leak check against Have I Been
  Pwned on request with k-anonymity (5 hex characters of the SHA-1 leave the device, padded
  answers)
- ✅ Strength while typing in the editor; strength, reuse and age on the item page
- ✅ Generator: A–Z, a–z, 0–9, symbols, extended ASCII (Latin-1), "also use" and "never use"
  characters, 4–128 characters; passphrases of 3–20 words with word case (lower, UPPER, Title,
  MIXED), any separator up to 3 characters, a digit, and the user's own word lists (Diceware
  format accepted, at least 500 words); options remembered per device
- ✅ Vault settings stored inside the vault (format v2): name, password history size; settings
  page grouped into cards with the vault's encryption facts
- ✅ Import from browsers (Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi, Safari) and
  managers (Bitwarden, 1Password, LastPass, KeePass/KeePassXC, Dashlane, Proton Pass, NordPass,
  any CSV/JSON): how to export from each one, a button that opens an installed browser's
  passwords page, then a review of every entry (passwords hidden, duplicates unticked) and the
  folder to put them in. One `import` function reads every format. On Windows a browser can
  also be read directly, on request: Chromium browsers (DPAPI-protected key, AES-GCM; Chrome's
  app-bound `v20` entries are reported and left to the CSV route) and Firefox (NSS `key4.db`,
  optional primary password), databases opened from memory, never copied to disk
- ✅ Field icons (Lucide), the network's mark for cards (Visa, Mastercard, Amex, Elo,
  Hipercard…), brand icons for import sources, icons in the index; tool pages use the full width
- ✅ Secure fields: Ctrl+A / double click selects all, typing replaces it, Ctrl+V and Shift+Insert
  paste the clipboard's first line, Ctrl+Backspace clears; copying out stays impossible
- ✅ Emergency kit PDF: the Recovery Key (fixed shape) is written into boxes on two lines, one
  character each, empty when the app doesn't have it; a box for the master password; no file
  location, the vault id only in small print
- ✅ Folders (format v3): name, icon and colour, edited from the folder's page or the pencil
  next to it in the index
- ✅ An item's icon can come from another website ("Icon from", format v3), fetched once even
  when website icons are off for the rest of the vault
- ✅ Required fields marked with a red asterisk
- ✅ Folders (format v4): created and edited in a dialog (name, icon, colour, a picture from a
  website or an image link, previewed before saving), right-click menu (open, settings, move
  up/down, delete), drag to reorder; the pencil in the index no longer flickers
- ✅ Back and forward through the places visited: arrows in the index, mouse buttons 4/5,
  Alt+Left/Right and the keyboard's Back/Forward keys; Ctrl+N new item, Ctrl+L lock
- ✅ Right-click menu on items: copy username, password or code, open the website, edit,
  favourite, delete
- ✅ Websites on the item page open in the default browser (http/https only); every hidden
  value (hidden fields, card number, security code, notes) has Show and Hide
- ✅ Unlock protection: the Argon2id level (Light, Standard, Strong, Maximum) chosen in
  Settings, applied after a master password check, with the unlock time on this computer
- ✅ Buttons, checkboxes and dropdowns react to the first click (a focus scope on top used to
  take it)
- ✅ Keyfile (format v5): an optional third factor next to the master password and Secret Key.
  Created or chosen in Settings after a master password check, asked for on the lock screen
  (its location is remembered per device, never the key), removed the same way; `vault keyfile
  create|use|remove` and `--vault-keyfile` in the CLI. The Recovery Key still opens the vault
- ✅ Item lock (format v5): with the vault open, an item still shows its name, username,
  website, plain fields and notes, but its password, one-time code, recovery codes, hidden
  fields and history open only after a second check. Settings choose the check (master
  password, a 4–8 digit PIN, or another password) and whether it covers every item or only
  the ones marked in the editor; 5 wrong tries lock the whole vault. Edit, delete and the
  right-click menu follow the lock, and locked items' codes leave the Authenticator page.
  The mark is imported from and exported to the `reprompt` field of other managers
- ⬜ Attachments, tags; passkeys
- **Done when:** daily use on Windows is possible with a test vault.

### M5 — Browser extension ⬜
- Native Messaging host in the desktop app; extension in TypeScript with no secrets
- Fill with confirmation outside the page DOM; strict origin matching
- **Done when:** fills logins on Chromium with confirmation; clickjacking test page fails to leak.

### M6 — Sync server ⬜
- Rust server (axum) in Docker, reachable via Tailscale only
- OPAQUE login, encrypted item records, signed manifest, rollback/fork detection
- **Done when:** two devices converge; ZK-AE-Tester style malicious-server tests pass.

### M7 — Android ⬜
- Slint UI + Kotlin Autofill Service + Credential Manager provider (passwords, passkeys)
- BiometricPrompt Class 3 quick unlock (StrongBox)

### M8 — Advanced ⬜
- Secure sharing (Send-style links, HPKE hybrid X25519 + ML-KEM-768)
- Passkey storage on desktop, health report (HIBP k-anonymity), SSH agent, Shamir recovery, Linux

### M9 — Hardening and audit ⬜
- Threat model review, fuzzing campaign, dependency review, external audit, then real use.

## Engineering practices

- Tests: unit + known-answer vectors + property tests (`proptest`) + fuzzing (`cargo-fuzz`).
- CI (later, GitHub Actions): `fmt`, `clippy -D warnings`, tests on Windows and Linux,
  `cargo-deny` (advisories + licenses).
- Every change to the file format bumps the format version; old versions are rejected unless an
  explicit migration exists.
- Commit messages and code in English.
