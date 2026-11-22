# Implementation Plan

> Companion to [ROADMAP.md](ROADMAP.md) (the *what*) — this document is the *how*: repository
> layout, milestones, and the definition of done for each one. Status markers: ✅ done,
> 🚧 in progress, ⬜ not started.

## Repository layout

```
password-manager/
├── Cargo.toml                 # workspace
├── rust-toolchain.toml
├── apps/                      # what people run
│   ├── cli/                   # vault-cli: the `vault` command
│   ├── desktop/               # vault-desktop: Slint app (Windows; ui/ is vault-desktop-ui)
│   ├── mobile/                # vault-mobile: the phone's screens and controller (Slint)
│   ├── mobile-android/        # vault-mobile-android: the APK (cargo-apk + a Java activity)
│   ├── mobile-web/            # vault-mobile-web: the phone app in a web page (WebAssembly)
│   ├── server/                # vault-server: self-hosted sync (AGPL-3.0), Docker files
│   └── extension/             # browser extension (Manifest V3, plain JavaScript)
├── crates/                    # libraries the apps share
│   ├── core/                  # vault-core: crypto, vault format, items, merge (no I/O but storage.rs)
│   ├── platform/              # OS integration: credential store, Windows Hello, clipboard, sync targets
│   ├── import/                # vault-import: other managers' files, browsers' stores
│   ├── browser/               # vault-browser: the extension's protocol and native host
│   └── sync-wire/             # vault-sync-wire: signed requests between devices and the server
└── docs/
    └── spec/                  # crypto, file-format and sync specifications
```

Rules:
- `core` has **no UI and no network**. It is the only place that touches key material.
- Every crate forbids `unsafe` except `platform`, `desktop` and `mobile-android`, where each
  `unsafe` block carries a `// SAFETY:` comment.
- A crate in `crates/` never depends on an app in `apps/`.
- Every user-facing string lives in a UI crate; `core` returns typed errors only.

## Milestones

### M0 — Specification ✅
- ✅ Threat model, architecture, roadmap
- ✅ UI prototype (Slint): the secure field validated on Windows, then retired
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

### M3 — CLI 🚧 (`apps/cli`, binary `vault`)
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

### M4 — Desktop app (Windows first) 🚧 (`apps/desktop`, design in [DESIGN.md](DESIGN.md))
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
- 🚧 `pt-BR` translation (started: tray menu, auto-lock countdown, language setting; see M4.x)
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
- ✅ Other hash methods (format v6): scrypt and PBKDF2-SHA-256 can be chosen instead of
  Argon2id, each at the four levels, with a warning that they are weaker; `vault init --hash`
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
  right-click menu follow the lock.
  The mark is imported from and exported to the `reprompt` field of other managers
- ✅ Item lock as encryption (format v6): with a PIN or another password, the secrets of locked
  items are sealed under a key only that PIN or password unwraps, so the vault key alone (an
  unlocked vault read from memory, or the Recovery Key) no longer shows them. One right check
  opens every locked item for 5 minutes or until "Lock"; the master password replaces a
  forgotten PIN. The CLI asks for the PIN when a command needs a locked item
- ✅ Authenticator with locked items: their codes are listed masked with Copy off, and one
  check on that page opens them all
- ✅ Faster builds and app: the Slint screens are a crate of their own (`vault-desktop-ui`), so
  a change to the controller rebuilds in about a third of the time; `vault-core` is optimized
  in debug builds; the password health audit runs off the UI thread
- ✅ Onboarding sets up the item lock (PIN on every item and Windows Hello suggested) and
  offers to import passwords, or to skip
- ✅ Tray mode: closing the window keeps the app in the notification area (nothing drawn,
  timers stopped), with Open, Lock and Quit
- ✅ Attachments (format v9, see M7); ⬜ tags; passkeys
- **Done when:** daily use on Windows is possible with a test vault.

### M4.x — Polish (November 2026)
- ✅ Generator: icons on the generate buttons; crack times keep growing past the age of the
  universe (in ages of the universe, then powers of ten) with comparisons that change with
  them; the passphrase separator is one row (buttons and a box)
- ✅ Editor: Generate opens the generator's options under the password (length, characters or
  words, separator); a password just generated shows its real entropy; a new item starts as
  the kind of the list it was asked from; "Authenticator" items (a login with only a setup key)
  and Add a code on the Authenticator page
- ✅ The last minute before the auto-lock is counted down in the corner, with Stay unlocked
- ✅ Website icons: the site's own port, SVG icons, web app manifests, links relative to the
  page; a site whose certificate isn't trusted (self-signed…) shows a globe with a warning
  mark instead of its own picture
- ✅ The notification area menu is a window of the app's own (rounded, dark, minutes left);
  the .exe carries the app's icon (Explorer, taskbar, Windows Hello prompt)
- ✅ Extension: the generator works with the vault locked; the card under a field is nearly
  opaque (a real blur would void the click protection: see `apps/extension/inline.css`)
- ✅ Saving asks for nothing: a new item is stored without the item lock's PIN and sealed under
  it the next time it opens (`Vault::seal_pending`); from the browser, a login saved while the
  vault is locked is sealed to the drop box (CRYPTO.md §3.5) and added at the next unlock
- ✅ Tray menu: thin and text-only; the card under a field: arrow with a visible rim, no item
  name next to the username, no dark box behind it on pages with another colour scheme
- 🚧 Translations: catalogues compiled in (`apps/desktop/translations/`), language chosen in
  Settings → Appearance or from Windows, template of every text; Brazilian Portuguese started

### M5 — Browser extension 🚧 (`apps/extension/`, `crates/browser`)
- ✅ Native Messaging host (`vault-browser-host`) relaying to the desktop app over a per-user
  named pipe; both ends check the other program; off until turned on in Settings, which also
  registers the host for Chrome and Edge
- ✅ Extension (Manifest V3, plain JavaScript, no packages) with no secrets
- ✅ Fill with the login chosen in the extension's own window; strict origin matching in the
  app (scheme + host + port, https only, top frame only); the item lock is respected; each fill
  is announced in the app
- ✅ Tests: origin matching and address tricks, the protocol against a vault, the pipe, the
  relay, the page-side fill function (`node --test`), a manual clickjacking page
- ✅ Pairing: the extension is connected once, with a code allowed in the app; every request
  is signed, replayed or unsigned ones are refused; Settings can disconnect it
- ✅ Locked logins: opened for one fill by Windows Hello (the item lock can now be opened by
  Hello in the app too, with its guard key wrapped by the security chip) or by the PIN typed
  in the extension's window; Ctrl+Shift+L opens the extension
- ✅ `*.example.com` as a login's website covers the site and its subdomains
- ⬜ Checked by hand in Chrome and Edge with a test vault
- ✅ Connecting is confirmed in the app: Connect in the extension brings the app forward,
  the master password is typed there (never in the browser), and the extension carries on
  by itself once connected
- ✅ Export protected by a password (`.vaultx`): every item in one file encrypted with a
  password chosen for it; Import (app and CLI) reads it back
- ✅ Extension 0.2: connect on first open; tabs for this site, all logins (show or copy one
  at a time, through the item lock; copying done by the app) and the generator; a form for a
  new login; a frame under sign-in fields with the site's logins; a strong password offered on
  new-password fields, made by the app and fitted to the field's rules; "Save this login?"
  after a sign-in
- ✅ History of generated passwords in the app (sealed per vault on this computer, behind the
  item lock, cleared on demand)
- ✅ Fill while the vault is locked, with Windows Hello for each password (a file only
  Windows Hello opens); the connection survives locking; replay check tolerant of requests
  sent at once
- ✅ Fill one-time codes (a card under the code field, spread over one box per digit; only
  for the login's own site); "Update the saved password?" after signing in with another
  password, the old one kept in the history
- ⬜ Firefox
- ⬜ Installer that puts the app and the host side by side; store listing
- **Done when:** fills logins on Chromium with confirmation; clickjacking test page fails to leak.

### M6 — Sync 🚧 ([design](spec/SYNC.md))
- ✅ Design: one sealed copy per device on a folder, WebDAV or own server; merge in the core;
  the server optional and blind
- ✅ M6.1 Core: format v7 (writer, tombstones, change times, unlock and item lock revisions,
  devices, item lineage) and `Vault::merge`: items by lineage, both passwords kept on a
  conflict, rollback/fork/other-vault/removed-device copies refused; property test with
  three devices (they converge, no typed password is lost)
- ✅ M6.2 Folder target: `vault sync [FOLDER] [--stop]` in the CLI; Settings → Sync in the
  desktop app (choose a folder, last synced, computers, Sync now, Stop syncing), with a round
  at unlock, a few seconds after each save, every 5 minutes and when the item lock opens
  with edits waiting for it; notices for changes, conflicts, edits waiting for the lock, a
  new master password, refused copies and this computer removed
- ✅ Removing a device from the app (Settings → Sync → Remove) and the CLI (`--remove`)
- ✅ The desktop app watches the sync folder (a round a second after another device's copy
  lands) besides the 5-minute rounds
- ✅ M6.3 `vault-server` (`apps/server`: axum, files on disk, Docker image and Compose,
  Tailscale HTTPS in front, [setup](SERVER.md)): Ed25519-signed requests with time and nonce
  (no password at the server), one-time invites stored as digests, enrollment that proves the
  key, a device writes only its own copy, long-poll for changes, limits per device and per
  failing address. The protocol in `crates/sync-wire`. Clients in `vault-platform`: server
  and WebDAV targets, tags so unchanged copies aren't read again, `http://` only to this
  computer or Tailscale. Desktop: Use a server… / Use WebDAV…, Add a device (QR code and
  `vaultsync:` line), Remove, the server's long-poll while open. CLI: `vault sync --server
  --invite`, `--join`, `--webdav --user`, `--add-device`, `--devices`, `--remove`. End-to-end
  tests: two devices converge through a running server; strangers, replays, altered bodies,
  writing another device's copy, other vaults' keys, used invites are refused
- ✅ M6.3.1 HTTPS of the server's own for a home network (`serve --tls`): a certificate
  authority made on first start, pinned by its SHA-256 in the address (`#pin=`), fetched
  from `/v1/certificate` and checked before anything else is sent; the pin travels in
  `vaultsync:` invites. Tested: wrong or missing pin refused, the pin survives a restart
- ✅ Format v8: three recovery parts in place of the Recovery Key (CRYPTO.md §2.4, §3.6).
  Any two bring back the Secret Key, all three open the vault, one alone nothing; pairwise
  HKDF wraps of a random pair key, no new primitive. A new password or Secret Key keeps them
  working, a new kit makes the old ones useless; v0–v7 vaults keep their Recovery Key until
  a new kit. Kit PDF: a page for the Secret Key and the handwritten password, then one page
  per part (each copies whole). Part C can be hidden in a photo of one's own (PNG, the part
  in its pixels, read back to check). Desktop: recovery with three parts, unlock on a new
  computer with two parts in place of the Secret Key; CLI: `recover`, `kit --new-parts`,
  `part-picture`, a part typed where the Secret Key is asked
- ⬜ M6.6 Cloud drive APIs for the phone (Google Drive and OneDrive app folders, Dropbox),
  once OAuth apps are registered ([viability](spec/SYNC.md#11-onedrive-google-drive-and-dropbox-on-the-phone))
- ✅ M6.4 Phone sync: Settings → Sync on the phone joins the server with the `vaultsync:`
  line from Add a device, then syncs at unlock, after saves, every 5 minutes, on the
  server's news and on demand; tested headless against a running server (a computer's item
  comes in, the phone's goes out). The phone window keeps its own device state in
  `<app dir>/phone`, so it syncs as a device of its own
- ✅ WebDAV on the phone (Settings → Sync → Use WebDAV); the WebDAV target tested end to end
  against a small WebDAV server (authentication, temporary file then MOVE, ETags)
- ⬜ Scanning the invite's QR code with the camera (M7); on the phone, fetching copies while
  the vault is locked so the merge at unlock needs no network
- ⬜ M6.5 nearby sync over the LAN
- **Done when:** two devices converge; ZK-AE-Tester style malicious-server tests pass.

### M7 — Android 🚧
Plan, screens and security decisions: [MOBILE.md](MOBILE.md).
- ✅ M7.0 Base: `apps/mobile` (vault-mobile) with the phone's screens in Slint (start,
  unlock, the list with search and filters, the item page with the item lock, editor for
  logins and notes, one-time codes, generator, settings), its own controller, a headless
  end-to-end test and off-screen screenshots
  (`cargo run -p vault-mobile --example phone_screens`). Shares the desktop's tokens, widgets
  and icons; `Theme.touch` makes text a step larger and controls 48 px tall
- ✅ The phone opens a vault made on the computer and never makes one: a chosen file
  (`Controller::bring_vault`) replaces the phone's copy only after it opens with the person's
  keys and is no older than what the phone saw; "Bring a newer copy" in Settings
- ✅ The phone app in a browser (`apps/mobile-web`, WebAssembly): the real screens and
  controller on a canvas with a demo vault, to try it on a computer (MOBILE.md §7.1)
- 🚧 M7.1 Runs on a phone: ✅ an APK (`apps/mobile-android`, `cargo-apk`, NDK 28, Slint's
  Android backend) with the system keyboard for secret fields (stand-ins only, MOBILE.md
  §7.2), setup from the sync server on the start screen, the Keystore-backed credential
  store and the system clipboard over JNI; tried on a phone; Back; ⬜ bundled fonts
- 🚧 M7.2 Phone storage: ✅ the activity's Java side (`VaultActivity`, built into the APK
  by `build.ps1` with javac and d8) with the system's file picker: the start screen opens a
  `.vault` file (offline; sync turned on later) or sets up from the server, "Bring a newer
  copy" takes a file, "Save a copy" saves a backup that is read back and checked; the
  launcher icon; ✅ Keystore-backed credential store, sensitive clipboard; ⬜ "open with"
  for `.vault` files, `FLAG_SECURE`: MOBILE.md §6.3
- ✅ Changing the master password on the phone (checked against the file, saved, synced)
- ✅ A backup sync place (SYNC.md §5.4): read and written every round with the main one; while
  one is down the round goes on through the other and is tried every minute; the newest copy
  of each device is taken from either, older ones passed over without a false rollback
  warning; the place that comes back gets this device's copy at once. Desktop: Settings →
  Sync → Add a backup server / Remove the backup, warnings when one is down and notices when
  it is back; invites carry the backup's too (`&backup=…&backup_invite=…`), and the phone
  joins both. Tested with two places, one taken down and brought back
- ✅ Confirmed backups on the desktop and the phone: written, read back, compared with the
  vault file and opened with the vault's key (`Vault::check_copy`), deleted when they
  fail
- ✅ Recovery parts work once (CRYPTO.md §3.6): retired after use, a new kit offered at once
  (desktop, CLI); recovery in two steps (the parts checked, then the new password); an eye on
  the master password, Secret Key and parts (parts and key also in boxes, as printed); the
  kit PDF printed with the keys or with empty boxes to fill in by hand, and shorter
- ✅ Phone: Back goes one step back (the app goes to the background only at the top); the
  list's filters fit without scrolling; the doodle backdrop; a launcher icon that fits round
  masks; cards and authenticator items in the editor (an authenticator item named after
  its setup key, also on the desktop, without recovery codes); its own settings file
  (theme, lock, clipboard, backdrop, website icons, generator); website icons, opt-in, with
  the desktop's fetcher and sealed cache (now `vault_platform::website_icons`), for every
  item with a website (a card's is its bank's site; "Icon from" is gone)
- ✅ Generators: at least N capitals, small letters, digits and symbols (Advanced options,
  both apps); on the phone also word case, separator and a digit for passphrases
- ✅ Format v9 (VAULT_FORMAT.md): SSH key items (a new Ed25519 key, or one loaded or pasted;
  the public key and fingerprint read from it, `vault_core::ssh`) and files attached to items
  (5 MiB each, 10 per item, sealed with the item lock); both apps, the JSON export and import
  (type 5); v8 items upgraded on open, older sealed secrets read in either layout
- ⬜ Settings in groups (account security, autofill, vault, import and export, appearance,
  sync with the server's copy size and how each way works, devices, screen captures,
  clipboard, updates); several vaults with a switcher on the vault's name; a leak and
  strength check for one password; scanning a code's QR with the camera
- ⬜ M7.3 BiometricPrompt Class 3 quick unlock (StrongBox) and an app lock
- ⬜ M7.4 Autofill Service; M7.5 Credential Manager provider (passwords, passkeys)
- ⬜ Updates of the app from the person's own server, without carrying a new APK
- ✅ M7.6 Sync (M6.4)
- 🚧 M7.7 Parity with the desktop: ✅ cards, authenticator items, SSH keys, files;
  ⬜ custom fields, folders, health, import, translations, a Portuguese word list

### M8 — Advanced ⬜
- Secure sharing (Send-style links, HPKE hybrid X25519 + ML-KEM-768)
- Passkey storage on desktop, SSH agent, Linux

### M9 — Hardening and audit ⬜
- Threat model review, fuzzing campaign, dependency review, external audit, then real use.

## Engineering practices

- Tests: unit + known-answer vectors + property tests (`proptest`) + fuzzing (`cargo-fuzz`).
- CI (later, GitHub Actions): `fmt`, `clippy -D warnings`, tests on Windows and Linux,
  `cargo-deny` (advisories + licenses).
- Every change to the file format bumps the format version; old versions are rejected unless an
  explicit migration exists.
- Commit messages and code in English.
