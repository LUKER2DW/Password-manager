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
│   ├── mobile-android/        # vault-mobile-android: the APK (cargo + Gradle, a Java activity)
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
- ✅ `cargo-fuzz` targets for the file parser and a copy merged into an open vault, every day
  on Linux CI (`fuzz/`, `.github/workflows/fuzz.yml`; M10 S14)
- **Done when:** round-trip, tamper, downgrade, wrong-credential and corruption tests pass ✅.

### M3 — CLI 🚧 (`apps/cli`, binary `vault`)
- ✅ `init`, `info`, `list`, `add`, `show`, `edit`, `rm`, `generate`, `totp`, `passwd`,
  `recover`, `kit`, `forget`; `renew-key` and `sync --take-new-key` (M9)
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
- ✅ Leak watch (desktop and phone, off until turned on): every login's password checked once
  a day while the vault is open (k-anonymous), counts kept sealed per vault on the device,
  a password found in more breaches than before told at once (Password health on the
  desktop, a mark in the phone's list)
- ⬜ Leak checks against offline lists (the breach service's downloadable corpus, or other
  lists), with nothing sent
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
- ✅ Starting at sign-in (Settings → Appearance, off by default): one value in the user's
  `Run` key, what Task Manager's Startup apps shows and turns off (`autostart.rs`), started
  in the notification area unless the person wants the window; the entry follows a moved or
  newer copy of the app. One running copy: starting the app again brings its window to the
  front (`single_instance.rs`)
- ✅ `.vault` files show the app's icon and open in it (double-click, "Open with"): the
  release app registers the file type for this user at start (`file_types.rs`); ⬜ a second
  copy started by a double-click hands the file to the one already running; ⬜ `.vaultx`
  opening the import
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
- ✅ Native Messaging host relaying to the desktop app over a per-user named pipe; both ends
  check the other program; off until turned on in Settings, which also registers the host for
  Chrome and Edge. Since 0.4.3 the host is `vault-desktop.exe` itself (started with the
  extension's origin, it only relays), so the desktop app is one file
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
  password chosen for it, whole (earlier passwords, attached files, passkeys with their
  private keys, the passkey item kind); Import (app and CLI) reads it back
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
- ✅ Extension 0.3: Chrome's own "Offer to save passwords and passkeys" is off while the
  extension's setting leaves saving to Vault (the default; `privacy` permission, for that
  setting only)
- ✅ Passkeys (extension 0.4, format v10): the extension stands in front of a page's
  `navigator.credentials` (top frame, HTTPS), the person chooses in the extension's own window,
  the app makes the passkey (ES256) in the login for that site and username, or signs in with
  one; the site check uses the Public Suffix List. A site with no passkey in Vault, a closed
  app or a security key go to the browser. Listed on the item page, taken out in the editor
  (desktop); listed on the phone; a Passkeys tab (desktop) and filter (phone) list every item
  that keeps one
- ✅ Passkeys in the field's autofill list (conditional mediation): the site's request waits
  in the page, the card under a sign-in field lists the vault's passkeys for the site above
  the logins, a pick signs through the same checks as the passkey window; no passkey for the
  site or a locked vault leave the browser's list. ⬜ checked by hand in a browser
- ✅ Passkeys from the phone (M7.5); passkeys and attached files in the protected export
- ✅ Firefox 153+ from the same folder (`background.scripts` beside the service worker, a
  gecko id; the desktop registers a Firefox host manifest with `allowed_extensions` and starts
  as the host from Firefox's arguments). No card in pages there (no IntersectionObserver v2
  to confirm a click was on an uncovered frame): fill and save from the extension's window,
  the toolbar button marks a login waiting to be saved. ⬜ checked by hand; ⬜ a signed `.xpi`
  in the release (Mozilla signs unlisted add-ons; until then a temporary add-on)
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
- ✅ Scanning the invite's QR code on the phone with Google's code scanner (start screen,
  Settings → Sync)
- ⬜ On the phone, fetching copies while
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
- 🚧 M7.1 Runs on a phone: ✅ an APK (`apps/mobile-android`, cargo + Gradle, NDK 30, Slint's
  Android backend) with the system keyboard for secret fields (stand-ins only, MOBILE.md
  §7.2), setup from the sync server on the start screen, the Keystore-backed credential
  store and the system clipboard over JNI; tried on a phone; Back; ⬜ bundled fonts
- 🚧 M7.2 Phone storage: ✅ the activity's Java side (`VaultActivity`, built into the APK
  by Gradle) with the system's file picker: the start screen opens a
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
- ✅ Settings in groups (Security, Autofill, Vault, Import and export, Sync, Appearance,
  Updates, About); sync as on a computer (Add a device with a QR code, change the server's
  address, a backup server, the devices, the server's copies and their size, how sync
  works); several vaults with a card on the vault's name; import of another manager's
  export; "Check this password" (strength and leak check); ✅ scanning the invite's QR code;
  ✅ scanning a one-time code's QR code
- ✅ M7.3 Fingerprint unlock (BiometricPrompt Class 3, Keystore/StrongBox, CRYPTO.md
  §3.1.1), and the phone's screen lock too; lock as soon as the app is left,
  screenshots kept out unless allowed; ⬜ the first prompt at start tried on a device
- ✅ The phone's pages rebuilt (2026-11): each page scrolls on its own with a stretch at the
  ends and a thin bar, swiping between the four places, sync and the vaults pages redone,
  "About and updates" with short notes per version, a confirmation sheet before sensitive
  actions, the vault chosen on the unlock screen, an icon per vault
- ✅ Phone items: open the website, notes in Markdown, created and last edited, a card's
  number, CVV and PIN shown and copied, preset line icons (`glyph:<name>` in `icon_url`, with
  their colour and their tile's: `glyph:<name>:<c>:<t>`; the desktop draws and chooses them
  too), previews of attached pictures, text and PDFs, counter-based one-time codes (RFC 4226,
  `otpauth://hotp/`) with Next, website icons that tell an untrusted certificate apart and try
  the bare and `www.` hosts
- ✅ Phone, the round of November 23, 2026:
  - secret fields with a cursor (a tap places it, the text edited there; both apps), a long
    password scrolling inside its field instead of widening the page
  - a stretch past the ends of every page; a held slider keeps the finger from the page
  - Codes: a card dragged either way opens its editor, the seconds next to the pie, the code's
    kind under Advanced options
  - folders: a picker with counts and a way out, the folders under All, folders inside folders
    (`Outer/Inner`), an icon colour
  - icon and tile colours for items and vaults, the choices behind a button
  - the vault renamed on the phone; adding or removing a device, stopping sync, removing the
    backup server or the vault confirmed with the master password; the generator's history
    deleted after a confirmation, with the time of each
  - icons in the page titles, a yellow Add and New, the lock screen higher (clear of Android's
    prompt), the recent apps view without the app's screen, the sync card and "How sync works"
    measured right
  - SSH keys read in every common form, a passphrase asked once and the key kept without it,
    its type kept (both apps)
  - the APK a third of its size (the library stripped and compressed)
- ✅ The round of November 24, 2026 (built and tested):
  - sync: a device removed from the vault can join again, as a new device (a new id per
    vault on each join with an invite, the old one retired from the list); a device listed
    without a copy where the vault syncs now says so; a removed device's copy and key leave
    the backup server too (both apps)
  - phone updates: every server the vault syncs through is asked, the version the server has
    is said (or that it has none), and the servers are asked once after the first sync of an
    unlock; `publish-app` says which data folder it wrote to
  - phone: a rubber-band overscroll that springs back (the timers now start), the Codes page
    (tap or drag left to copy, drag right to edit, hold to reorder, a green-to-red pie),
    password health rebuilt (a ring, filters, tags, the leak watch's switch), the site's icon
    next to the Website field (both apps), recovery with the emergency kit (three parts for a
    new master password and Secret Key, two for a missing Secret Key, each part scanned or
    typed), the vault's doodles under the lock screen's form
  - website icons: a site's wide logo (its name written out) is no icon; the next candidate
    is tried, and such an icon kept by an older version is looked for again
  - the emergency kit PDF: a QR code for the Secret Key and each recovery part (filled kits)
  - desktop Settings in categories (Security, This vault, Sync, Browser extension,
    Appearance, About); the master password, the item lock, the keyfile, the unlock
    protection, joining a server or WebDAV, a backup server, stopping sync, adding or
    removing a device and disconnecting the extension each in a dialog that asks first, with
    the master password where it matters; the extension's switches kept here (saving logins
    from pages, passkeys, a notice for each fill), refused by the app and told to the
    extension; the drawn texture behind the vault as a switch
  - the sync server hardened: uploads read only for an enrolled device, requests in flight
    and their time capped, the device and invite files changed under one lock (no lost
    changes, no invite used twice), an enrolled device's place not taken by a new
    enrollment (409), private file permissions and synced folders, headers no cache keeps,
    SIGTERM handled, the container's limits and logs
  - joining a server without typing `address#pin`: `vault-server invite --address` prints one
    link (address, pin and invite) and its QR code; the apps take the address, the pin and
    the invite in fields of their own, or the link, pasted or scanned
  - a security pass over what reaches the network: the server serves its connections itself
    (headers within 30 seconds, an answer not read for a minute ends the connection, open
    connections and TLS handshakes capped in all and per address), checks an upload's whole
    signature before reading it (the body's SHA-256 sent with the request), counts an IPv6
    /64 as one address, holds copies being sent four at a time, makes a vault's live state
    only for an enrolled device, and takes an admin invite without `--vault` for a new vault
    only; device names can't carry invisible or text-turning characters; each sync target has
    a budget of 64 copy read attempts (including failures) and 256 MiB per round; website
    icons can't be steered into the local network by
    a site's links or redirects (checked at each name lookup); the leak check follows no
    redirect
- ✅ A second round the same day (built and tested; the APK 0.4.1):
  - a monospace font built into both apps (JetBrains Mono, SIL OFL): a shown password, drawn
    one character to a box, no longer runs its letters into each other where the system has
    no such font (every phone)
  - phone: the Secret Key's boxes two groups to a line in bigger boxes (they ran off the
    screen), the scan button under the field; recovery parts scanned or read from the
    picture part C was hidden in; the servers asked for an update after unlock, after Sync
    now and every 10 minutes, a newer version offered in a sheet (Install, or later)
  - desktop: the window draws its own title bar (the system's move, resize, snap and shadow
    kept; minimize, maximize or restore and close with the usual glyphs); the server's and
    the backup server's address changed in a dialog (kept only once the server answers there
    with this vault); showing the kit, issuing new parts and exporting asked in dialogs; an
    eye on every password field; part C saved in a picture is left out of the printed kit
    (its page says it is kept apart, not where); flags in the language pickers (both apps)
- ✅ Phone generator: "Make a strong one" in the editor opens it and Use brings the password
  back, "New login with it", the history of copied passwords (sealed, masked, used ones hidden)
- ✅ M7.4 Autofill Service (exact site or app, a fingerprint or the phone's lock before every
  fill, a strong password suggested, "Save to Vault?" with a drop box while locked);
  ⬜ tried on a device
- ✅ M7.5 Passkeys through the Credential Manager (Android 14+, `VaultCredentialService`,
  `PasskeyActivity`, `vault_mobile::passkeys`): sign-in and new passkeys for the browsers
  known by their release certificates (the page's origin, given by Android to the browsers
  listed as privileged) and for apps (their own `android:apk-key-hash:` origin), after a
  fingerprint or the phone's lock; with the vault locked, fingerprint unlock opens the file
  for the request (the passkeys read stay ready for a minute, for that caller only; a passkey
  made is written back only over the very file read). ⬜ tried on a device; ⬜ passwords
  through the Credential Manager (autofill serves them)
- ✅ Updates of the app from the project's releases on GitHub (the default) or the person's own
  server (`vault-server publish-app`, or the server following the releases), checked against
  the release, installed by Android only when signed like the app; looked for every hour
  while a vault is open (a switch turns it off)
- ✅ M7.6 Sync (M6.4)
- ✅ Brazilian Portuguese: every text of the phone (647, `apps/mobile/translations/`, with the
  desktop's shared widgets), the language from Settings → Appearance or the phone's (the browser's
  in the web preview); `cargo test -p vault-mobile i18n` checks that none is missing
- 🚧 M7.7 Parity with the desktop: ✅ cards, authenticator items, SSH keys, files, Portuguese,
  folders, password health, import, export (master password again, refused while items are
  locked), the phone's preset item icons drawn and chosen on the desktop; ⬜ custom fields, a
  Portuguese word list; ⬜ counter-based codes with Next on the desktop; ⬜ folders inside
  folders shown as a tree on the desktop

### M8 — Advanced ⬜
- Secure sharing (Send-style links, HPKE hybrid X25519 + ML-KEM-768)
- SSH agent; Linux (the desktop app and the CLI never built there yet: Secret Service, a
  local link for the extension, capture and clipboard rules; ROADMAP.md Phase 6)
- The CLI brought level with the apps: SSH keys, attached files, folders, export, health,
  item lock settings

### M9 — Hardening and audit 🚧
- Threat model review, fuzzing campaign, dependency review, external audit, then real use.
- 🚧 Fixes from the internal security audit of 2026-11-25, each with a regression test:
  - Extension: only the form that is sent is read (N-01); a login picked in the frame goes
    into that field's own form, never over `http:` (N-02); "saved" only once the vault file
    is written (N-03); Save acts on the offer its card shows; a passkey is made or signed
    only while the very document that asked still waits, and its window names the page and
    the site; the "Vault offers to save" setting stops capture too; a page's password
    pattern can't stall the worker.
  - Desktop: locked-fill passwords behind the item lock sealed to a Windows Hello key, bound to
    the login's version (PM-03, PM-05); pairing installs the key that was approved (PM-04);
    the generator's result leaves the screen with the item lock (PM-18); a late job result
    restores nothing after a lock or a vault switch (PM-19); a backup only of the file this
    session read; an imported file wiped only if it is the one read.
  - Core and sync: a new item-lock key from another device waits until both keys are open
    here, never leaving a sealed item without its seal (PM-13).
  - Import: website rules narrower than an origin kept, not filled (N-04); duplicates only
    when an entry brings nothing new (N-07); what each export format leaves out is reported
    (`export_report`) and shown in the desktop's and the phone's export dialogs, and the phone
    shows an import's warnings; `.vaultx` carries attachments and passkeys.
  - Phone: `*.` rules over a public suffix fill nothing (N-05); the generator's history
    follows the item lock (PM-01); two recovery parts are retired before the key is kept
    (PM-07); leaving the app locks also while a job holds the vault (PM-08); the 14 days of
    fingerprint unlock run from the last master password (PM-09).
  - Android: who receives a login is worked out from the fields (known browsers by
    certificate, https, one web view); app logins bind the package to an Android-verified
    signer lineage, with package-only facets rebound only by an explicit save that shows the
    current signer; saving follows the item lock (PM-02, PM-06); PDF previews from memory,
    wiped over their full length, within a pixel budget (PM-15, PM-16); updates only of this
    app, newer, same certificate; the APK signed with a release key of its own
    (`make-release-key.ps1`, kept outside the repository). ⬜ tried on a device.
  - Server: a listing agrees with an admin's removal (N-06); a removed device's request
    already under way changes nothing (PM-11); admin commands and the server share one lock;
    enrollment tells nothing without a good invite.
  - Sync and CLI: WebDAV over plain http only to this computer (PM-10); folder sync writes
    under fresh names, never through a link (PM-12); recovery parts retired only over the file
    they were checked against (PM-14); `vault rm` asks for the item lock (PM-17); one-time codes
    shown only with `--reveal`, their secret can be typed at a prompt.
  - CI: CodeQL leaves test code out (`.github/codeql/codeql-config.yml`), gitleaks allows
    `Cargo.lock`, Dependabot holds jni at 0.21 until the Android code moves; if-addrs 0.15,
    notify 9, resvg 0.49 and base64 0.23 taken; the code scanning alerts triaged (false
    positives and test code dismissed with their reason).
- ✅ Renewing the vault key (CRYPTO.md §3.8, SYNC.md §4.7): a new vault key, Secret Key and
  kit with the master password kept, every item key wrapped again under the new key
  (`Vault::renew_key`), so that an old copy opened with old factors or an old kit no longer
  opens newer copies. Renewed on a computer: the desktop's Emergency kit page ("Renew the vault
  key…") or `vault renew-key`. Other devices tell copies still under a former key from renewed
  ones by their unlock id, and take the new key once with the new Secret Key and the master
  password (`Vault::adopt_key`): desktop Settings → Sync, `vault sync --take-new-key`, the
  phone's Settings → Sync, with no merge conflicts. Side files sealed again, Windows Hello and
  fingerprint unlock turned off; tests in `crates/core/tests/renew.rs`.
- ✅ Releases (`.github/workflows/release.yml`, `CHANGELOG.md`): each version on `main` builds
  the desktop exe, the CLI, the server (Linux x64/arm64, Windows, and its image on ghcr.io),
  the signed and checked APK and the extension, attests every file and publishes
  `v<version>`. The sync server can follow the releases and hand new phone apps to the phones
  (`--app-updates`, `vault-server fetch-app`); the desktop and the phone look for a newer
  release by themselves every hour (About), and the phone installs it from GitHub. Every
  release checks that the phone's library loads on Android (`check-library.ps1`: 0.4.2 and
  0.4.3 closed at start, Skia built with a newer NDK).
- ✅ Exploit protections on Windows: Control Flow Guard in every Windows build
  (`-Ccontrol-flow-guard` in `.cargo/config.toml`, passed on to the C that cc compiles), so the
  tests run under it; the release checks ASLR, DEP and the guard in each exe
  (`apps/desktop/check-exe.ps1`). ⬜ Authenticode signing of the exes.

### M10 — Second review: hardening first, then features ⬜

From a review of how other password managers work and how they were attacked (November
2026). Done in this order: every security item before the features; each one with its tests,
committed by area. Items marked (owner) need the maintainer's own accounts or keys.

**Security**
- ✅ S1. Lock when Windows locks the session, switches user, signs out, sleeps or
  hibernates (Settings → Security, on by default): a hidden window on a thread of its own
  hears the session and power messages (`session_watch.rs`) and waits for the lock before
  answering a suspend.
- ✅ S2. DLL loading: `/DEPENDENTLOADFLAG:0x800` in every Windows program and
  `SetDefaultDllDirectories(System32)` first thing in the desktop app and the CLI
  (`process.rs`), so a DLL dropped next to an exe run from Downloads isn't loaded;
  `check-exe.ps1` checks the flag. The C runtime stays a DLL (from System32, so the Visual
  C++ runtime must be installed: a copy beside the exe is ignored now): a static one would
  need Skia built from source, as no static-runtime Skia is published.
- ✅ S3. Process hardening: a process DACL other programs of the same user can't read or
  write memory through (with an OWNER RIGHTS entry), threads closed too (a TLS callback and
  sweeps), the mitigation policies that don't break GPU drivers (image load, extension points
  when no legacy input method needs them, heap termination), crash reports without the heap;
  also in the native-host mode and the CLI (`process.rs`). A child-process test checks that
  another program of the same user can't read the protected process.
- ✅ S4. Emergency kit: the saved PDF holds the Secret Key only; recovery parts each in a
  PDF of its own ("Save each part apart", on the Kit page and in onboarding), never two in one
  folder; neither in a folder a cloud copies away (`files::cloud_folder`).
- ✅ S5. Extension: nothing offered, filled, saved or signed in a sandboxed (opaque-origin)
  document: the scripts compare the document's own origin with its address's, the worker
  ignores a page message whose browser-given origin isn't the tab's, the card shows nothing
  under a "null" ancestor, and passkey requests there stay with the browser. Tested in
  `fill`, `passkeys` and `background` tests.
- ✅ S6. Passkeys: "user verified" only after Windows Hello, the PIN or a fingerprint in that
  operation, as the site's `userVerification` asks (`required` and `preferred` verify when
  there is a way, `required` without one goes to the browser, `discouraged` never asks);
  core, the browser service, the extension and the phone.
- ✅ S7. The docs say only what the code does: what is locked in RAM and what isn't, the
  hibernation file, how far the release pipeline is trusted, the revealed password's Slint
  copy (THREAT_MODEL, ARCHITECTURE).
- ✅ S8. Releases: the Gradle wrapper's download checked against its pinned SHA-256
  (`distributionSha256Sum`); the `android-release` environment (the APK's signing key) needs
  the maintainer's approval for each run, admins included, only `main` may use it, and only a
  run that publishes asks for it (the others build with a key made for them), so no push
  alone signs and publishes an APK the phones take within the hour.
- ✅ S9. Revealed passwords, codes and the Secret Key kept out of the accessibility tree: on
  the desktop each such text names what it is instead of its value (item page, notes,
  recovery codes, generator, authenticator, kit); the headless test walks the whole tree for
  the secrets.
- ✅ S10. The browser link: every request and answer sealed with AES-256-GCM under keys
  derived from the connection key, each answer bound to its request (`pairing.rs`
  `seal_request`/`open_request`/`seal_answer`, `link.js` `seal`/`opened`), so a relay put in
  the host's place reads nothing and can't forge answers; connecting by ECDH P-256 with a
  commitment first, an eight-character code (56 letters and digits) both sides show for the
  person to compare before typing the master password (`Offer`, `link.js` `agree`), so the key
  never travels; the host's registration (registry values and manifests) checked while
  the link runs and put back, with a notice. Known-answer vectors computed apart (Node's
  OpenSSL) are checked on both sides. An app older than this answers the new extension "not
  understood", and the extension says to update the app. The older extensions' way (signed
  requests, a key handed over at connecting with a six-digit code typed into the app) ended
  with S25: they are refused, and the code is gone from the app (`Pending::handed_over`,
  `PairingKey::verify`, the dialog's typed code); their tests are refusal tests now. Not done:
  the host checking that its parent process is a browser with a valid Authenticode signature.
  Chrome and Edge start the host through `cmd.exe` (`COMSPEC`, Chromium's
  `launch_context_win.cc`), so the parent is the command prompt and the browser the one above
  it, found by process ids that can be reused; and any program of the same user can start the
  host with a parent of its choosing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with a handle to
  the browser), which is the attacker the check is for. It would need new `unsafe` (a
  process snapshot, `WinVerifyTrust`, a list of the browsers' signers kept current) to stop
  no one, while the host is a relay that reads nothing: the sealed link is the defence
  (THREAT_MODEL.md).
- ✅ S11. Keys in memory: a global allocator that wipes every block before freeing it (and
  never grows one in place) in the desktop app, the CLI and the phone app
  (`wiping_alloc.rs`); typed secrets in one area of memory locked in RAM once and left out
  of crash reports (`secure_memory.rs`, where `SecretBuffer` keeps them; it used to unlock
  pages other secrets shared); the vault key, the item guard key, and the Secret Key and
  keyfile the vault was opened with kept encrypted between uses by a `KeyShield` the program
  installs (`vault_core::memory`; `CryptProtectMemory` on Windows, whole 16-byte blocks; none
  on the phone), from the moment each is made or read, and opened only into a wiped copy;
  SHA-1 and SHA-2 wiping their state, and the stack cleared after a key is hashed (its
  checksum, a keyfile's digest, the password KEK) and when the vault locks. Subkeys are
  derived for each use and wiped right after. Not covered: memory the renderer and Windows
  allocate for themselves, and the phone's keys while its vault is open (THREAT_MODEL §3).
- ✅ S12. The Secret Key on Windows kept under a key in the TPM (CRYPTO.md §2.2.1): an
  RSA-2048 key made in the chip per user and vault through NCrypt's Platform Crypto Provider
  (decrypt only, not exportable, no prompt) wraps, with OAEP-SHA-256, a random key that seals
  the Secret Key (`tpm.rs`, `vault_core::kept_key`, `secret_store.rs`). Written, read back and
  compared before it counts; a key kept the older way is moved after the next unlock
  (`settle`), the plain entry deleted only once the new one opened to the same key. Without a
  TPM, DPAPI alone, which Settings → Security says is weaker; a cleared or replaced chip asks
  once for the kit's Secret Key, an error that may pass deletes nothing; entries no longer
  roam with a domain profile. The desktop app and the CLI use it. The apps' tests use a
  stand-in chip (`MemoryChip`); the TPM's own tests an ephemeral key and a named one they
  delete (skipped in CI and without a TPM); the CLI's end-to-end test and the memory test go
  through the real chip, their keys removed with the vault's.
  Measured on a firmware TPM: the key made in 1.4–5 s once (off the UI thread), the Secret
  Key unwrapped in about 65 ms at each unlock (up to 0.9 s while the chip is still busy after
  making a key). The TPM takes only zero-terminated OAEP labels of up to about 34 bytes.
  Later: that unwrap moved into the unlock's job, off the UI thread; Windows Hello asked for
  the Secret Key too, as an option.
- ✅ S13. Android: Android 12 at least (`minSdk 31`, the native library built for it too).
  Other apps' overlays hidden over every window of the app (`setHideOverlayWindows`,
  `Shield.java`), and Android 12 blocks taps through another app's window by itself: the
  app's screen is one NativeActivity surface, whose touches skip Android's views, so
  `filterTouchesWhenObscured` can't apply (a Slint patch would be needed for that, and isn't
  with the overlays hidden); accessibility tools only on Android 14
  (`setAccessibilityDataSensitive`); no task affinity (`taskAffinity=""`; StrandHogg 2 fixed
  in every Android the app installs on); nothing in cloud backup or a copy to a new phone
  (`data_extraction_rules.xml`, every domain). `check-manifest.ps1` checks the built APK's
  merged manifest in `build.ps1` and the release: those protections, the permissions listed
  and no exported part but those meant to be. ⬜ Tried on a device (an overlay app over the
  unlock screen, `bmgr backupnow`).
- 🚧 S14. Tests: memory searched for secrets after a lock, a hostile sync target and server,
  more fuzz targets run on a schedule. Done: the memory test (`apps/desktop/tests/memory.rs`,
  a step of its own in CI): a running copy of the app opens a vault with a keyfile, shows a
  guarded item's password and hides it, shows the kit and hides it, and locks; its whole
  memory is read from outside at each of these moments. The master password, the Secret
  Key's bytes, the keyfile and the vault and guard keys may never be found in the clear, the
  Secret Key's text only while the kit shows it, the item's password only while it is shown,
  and after the lock no 16-byte piece of anything. Before S11 it found the revealed password
  in two dozen places of the heap and the keys on the stack.
  Done: a hostile sync place, from the device's side (SYNC.md §9, THREAT_MODEL §2.1). The
  copies (`crates/core/tests/hostile_copies.rs`: every byte altered, every length cut,
  garbage, another vault's, rollbacks, forks, another device's name, a removed device's, an
  old copy never seen past), the round (`crates/platform/tests/hostile_sync.rs`: a lying
  backup or main place, a target listing what it likes), the HTTP targets against a hostile
  server written in the test (`crates/platform/src/sync/hostile.rs`: lying listings, answers
  that don't fit, redirects, plain `http://` elsewhere, answers that never end or never stop,
  an invite that isn't one, a long-poll that doesn't wait, WebDAV listings that disagree with
  their files, writes that fail half-way), and the whole round through `vault sync` with the
  vault file compared byte for byte (`apps/cli/tests/cli.rs`: a hostile folder, the real
  `vault-server` with its store altered, a lying server) and the desktop's notices. Fixed on
  the way: a copy found under another device's name was merged as its writer's (now refused,
  `Vault::merge_from`, `WrongWriter`, as §4.1 always said); a server answering every long-poll
  at once had the apps ask it again without a pause (now at most once a second); an invite a
  server handed back was shown whatever it was (now only 32 hex).
  Done: fuzzing on a schedule (`fuzz/`, `.github/workflows/fuzz.yml`): seven new targets
  (`sync_copy`, `sync_requests`, `sync_answers`, `browser_link`, `extension_zip`, `otpauth`,
  `part_picture`) beside `vault_file`, `import` and `invite_link`, each run five minutes a day
  on Linux with AddressSanitizer and debug assertions, seeded from `fuzz/seeds/` and the test
  vaults. Found and fixed: a picture said to hold part C whose header named a huge size made
  the app allocate it (over 100 GB) and stop; refused at the header now.
  Done: the copies a round couldn't use, named (SYNC.md §8): the phone says when it refuses
  one, as the desktop did, and both say when a copy couldn't be read, each once, with the
  device's name; Settings → Sync shows under that device why and since when until a copy from
  it is used again (`sync::CopyProblems`, one entry per device, the item lock's and another
  vault key's said apart). Still to do: the same reading of the release exe's memory by hand
  (the renderer and UI Automation, which the test's backend doesn't have).
- 🚧 S15. A signed release manifest every updater checks, and the groundwork for Authenticode
  signing through the SignPath Foundation. Done: every release holds `manifest.json` (each
  file's name, size and SHA-256, the commit, the APK's certificate) and its signature in
  minisign's format (CRYPTO.md §9), made in the release workflow by a job that gets the manifest
  key only after the maintainer's approval (the `android-release` environment) and checks the
  signature with the apps' own code and keys before anything is published (`tools/release`,
  `vault-release`; keys made by `tools/release/make-manifest-keys.ps1`: a primary in the
  environment, a backup that stays on the maintainer's computer). The desktop app, the phone
  and the sync server take a release only with that signature, by one of the two keys they
  carry (`RELEASE_KEYS`, pinned by id in a test), the manifest's version, its signed comment
  and the release's tag all agreeing, and never a version not newer than the one installed (a
  desktop that told of a version doesn't show an older one); the phone's package and the
  extension's zip only at the size and SHA-256 the manifest lists. A sync server keeps the
  manifest and its signature with the phone app (`publish-app --manifest`, `--app-updates`)
  and the phone checks them itself, refusing an update without them. Every Windows program
  carries the same version information (`apps/windows-version-info.rs`), checked by
  `check-exe.ps1 -Version` in the release, which has an `-Authenticode` check ready (SignPath
  Foundation's signature). The update check is told on each app's first screen with its switch.
  docs/CODE_SIGNING.md (signing policy, roles, SignPath's attribution) and docs/PRIVACY.md (what
  each app sends). Waiting for the maintainer: the real manifest keys (the stand-ins in
  `RELEASE_KEYS` replaced, the primary put in the environment with `-SetSecrets`, the public
  keys in CODE_SIGNING.md), immutable releases turned on, the SignPath Foundation's
  application, then its signing step in release.yml and `-Authenticode` turned on.
- ✅ S16. A warning when a vault password is pasted or sent on a site that isn't its own: a
  password pasted into a password field, or sent from a sign-in form, goes to the app
  (`elsewhere`) only to be compared with the other sites' logins outside the item lock, and is
  kept nowhere; the answer is that site's name at most (none for the page's own owner, a page
  whose owner has a login behind the item lock, or fewer than six characters). The frame says
  "This password is for …" under the field (Remove it / Keep it) or "You sent the password of
  …" in the corner, and no save is offered for it; Firefox marks the toolbar button and the
  window says it. Settings → Browser extension, "Warn when a page isn't the site a password
  belongs to", on by default (off: the request is refused, the answers say `warns: false`, and
  the extension reads nothing for it). Tests: `vault-browser` service, the desktop's headless
  test, the extension's `background` and `fields` tests.
- ✅ S17. The Secret Key, the recovery parts and the older Recovery Key refused in any page, no
  exception: `kit.js` in every https document, frames too, at `document_start`, recognises their
  printed shape (prefix, Crockford Base32 groups, the zero padding bits; lower case, aliases,
  spaces or no separators) and stops a paste or drop before the page's listeners, takes one
  typed by hand out of the field, and the corner says why. The app checks the same shape in
  whatever a page sends (`vault_browser::kit`) and never saves, compares or keeps one (also
  while locked). Test keys with real checksums shared by `crates/browser/tests/kit.rs` and
  `apps/extension/test/kit.test.mjs`.
- ✅ S18. What a stolen pairing reaches (format v11, THREAT_MODEL §3): an item kept out of the
  browser (`no_browser`, the editor's "Keep out of the browser"), a folder kept out or kept to
  the browser connected now (`FolderBrowser`, the folder dialog; the pairing's id, CRYPTO.md
  §3.9), the extension's window listing only the open site's logins unless the person lets it
  list the whole vault (Settings → Browser extension, off by default; `vault` names the page).
  `vault_browser::service` reads every login through `Vault::reaches_browser`, the
  locked-fill file leaves them out, and items in the trash, archived or templates never reach
  the browser.
- ✅ S19. The one-factor floor: 10^14 guesses by zxcvbn (`vault_core::health::
  ONE_FACTOR_MIN_GUESSES_LOG10`, the arithmetic in CRYPTO.md §3.3.1). A protected export's
  password below it is refused (`sealed_export::seal`, and before the slow work in each app),
  with "Use a generated passphrase" (six EFF words, shown); a KDBX export will use the same
  check. A new master password (onboarding, recovery, Settings; the phone's sheet and recovery;
  `vault init`, `passwd`, `recover`) or item lock password below it is warned about and kept
  only if the person says so; a new master password can be checked against known breaches
  first (a box, off by default; `--check-leaks`), with the leak check's k-anonymous query.
  Desktop `controller/passwords.rs` and `ui/review.slint`, phone `controller/passwords.rs`.
  The new vault's suggested master password comes from the generator's compact options (the
  same as a new login's, folded under the suggestion), words first, and never one below the
  floor: the words or the length grow until it holds (the phone never makes a vault).
- ✅ S20. Unlock attempts (`vault_core::attempts`): failed tries counted per vault in the device
  state (`device.rs`; the phone's `prefs.rs`), surviving a restart; from the fifth in a row a
  wait of 30 s doubling up to 15 min, counted down on the unlock screen and enforced in the
  controller and the CLI; timed by the wall clock (set back: the wait starts again) and the
  time since the device started (`device::uptime_seconds`), whichever says less time passed;
  told once at the next right unlock ("5 failed tries … since …"). The phone may remove its
  copy after 10 failures, only for a vault that syncs, off by default. The honest limit (an
  offline copy never meets the counter) is in THREAT_MODEL.md.
- ✅ S21. A warning for a domain that looks like a saved site, from the vault's own sites,
  offline (`vault_browser::lookalike`): registrable domains compared by skeleton (accents off,
  look-alike letters of other scripts, `0`/`1`, `rn`/`vv`), one or two edits for names of five
  letters or more, the same name under a mistyped or a hosting company's suffix, the saved
  site in the page's name or subdomains; never for a saved site's own owner. A page with no
  login of its own gets "Check the address" under its first sign-in field and in the
  extension's window, and the save card says it; the locked app answers it too. Hosts that mix
  scripts (or are all Latin-looking letters of another script) are shown in punycode. Tested
  with a table of lookalikes and of ordinary other sites that must not warn.
- ✅ S22. Android autofill against the AutoFail cases (USENIX Security 2026): a "null"
  domain (a sandboxed frame, an opaque origin) is nobody's site; a form in a frame of another
  site than the page around it (`autofill::same_site`, the registrable domain) gets no offer
  and saves nothing; the fields filled are only those of the origin the login is for (already
  so: one form per origin). The account oracle doesn't apply: an app that isn't a known
  browser sees only its own logins, and a locked vault offers the same single line to every
  app. Within one origin all of a page's fields are one form, which crosses no boundary (the
  page reads them all anyway). ⬜ Tried on a device with the paper's test pages.
- ✅ S23. Android's keyboard learns nothing typed in the vault's fields: every text field asks
  it not to (`IME_FLAG_NO_PERSONALIZED_LEARNING`), through Slint's Android backend built from
  `vendor/` with that one line added (Slint's Java side has no way to set it), a test failing
  when a Slint update leaves the copy unused (`vendor/update-slint-android.ps1` makes it
  again). ⬜ Tried on a device (Gboard's incognito mark in a note and the search).
- ✅ S24. The extension frame's address changes each session: `"use_dynamic_url": true` on
  `inline.html` (the only web-accessible resource), its address made only with
  `chrome.runtime.getURL`, so the frame's `src` carries no fixed id and a page can't probe
  `chrome-extension://<id>/inline.html` to learn that Vault is installed. Chrome (130 and
  later) serves the session's address from the extension's own (a redirect, Chromium's
  `extension_protocols.cc`), so the worker knows the frame by either (`isFrameUrl`, tested),
  and the card moving above its field loads the frame again (its click check starts over).
  Firefox has no such key (its manifest schema lists it as an unknown property: a warning on
  `about:debugging`, nothing else); its `moz-extension://` address is already a random id per
  profile, and it draws no frame in pages. ⬜ Tried in a real Chrome (the card under a field,
  moved above it, the save card).
- ✅ S25. Versions. (a) The extension names its version (its manifest's) when it connects
  (`pair`) and inside every sealed request (`{"version","request"}`, `protocol::asked`, the
  request passed on as it came); the app connects and answers only one of
  `MIN_EXTENSION_VERSION` or later and refuses any other with `outdated_extension` (sealed to
  the connected extension, with the version the app carries so a copy in its folder reloads
  into it; plain for connecting and for the old signed requests), and says so once a run in a
  notice. The extension's window says *Update the extension* and how (Settings → Browser
  extension → Add to a browser). The floor is 0.4.7: the sealed link isn't in a release yet
  and carries 0.4.7 until the next release raises every app's version, and every released
  extension up to 0.4.7 names no version, so it is refused whatever the floor; raise it when
  a release fixes a fault in the extension. (b) The device state keeps, for each vault, the
  newest version of the apps that opened it on this computer (`DeviceState::note_version`,
  never lowered; the desktop app and the CLI share it, released at one version); an older
  one opens the vault all the same and says so, every time: the desktop app in a notice after
  the unlock, the CLI on stderr, with how to get the newest. The phone: Android refuses a
  lower `versionCode` over the installed app (docs/MOBILE.md), nothing to build.
- ✅ S26. A local security log, sealed on this device (`vault_platform::security_log`,
  CRYPTO.md §3.11, THREAT_MODEL §3): unlocks and failed unlocks (master password, Windows
  Hello or fingerprint, the kit's parts), each use through the browser extension (site, item
  title, what was given: fill, copy, code, passkey, a password shown, a login saved or
  changed; while locked too), Android's autofill and passkeys on the phone, exports, the kit
  shown, saved or printed (desktop), devices joined or removed (also those a sync round brings),
  the vault key renewed or taken, the master password changed. Each entry is sealed to a key
  pair whose private half is sealed under the vault key (the drop box's construction): the
  locked app writes, only the open vault reads; no secret in it. 500 entries at most; a file
  that doesn't open, or whose key was swapped, starts again with a line saying so; clearing
  leaves one line. Settings → Security → Security log on the desktop (newest first, "Show
  older", "Clear the log…") and Settings, Security on the phone. Not in the CLI.
- ✅ S27. The master password typed on a secure desktop (Windows; Settings → Security →
  Master password, off by default): the unlock screen's "Type it on a secure desktop" makes a
  desktop of its own, switches to it and asks in a native window (`vault_platform::
  secure_desktop`), each `WM_CHAR` into a `SecretBuffer`, only dots drawn; Enter unlocks,
  Escape or two minutes go back, the switch back done by a guard whatever ends the prompt.
  What it stops and doesn't, accessibility, several screens and getting back:
  THREAT_MODEL §3. Tested: the typing and the window on a desktop of its own that isn't shown
  (keys sent to it). ⬜ Tried by hand: the switch itself, the app killed while it shows, two
  screens.
- ✅ S28. Tabs driven by an AI agent get no offers in the page, only the extension's window:
  while the browser says a program drives it (`navigator.webdriver`, read in the isolated
  world) or the person turns on "An AI agent or a program is using this browser" in the
  extension's Settings (`vaultAgent` in `chrome.storage.local`: the content scripts read it
  there, and a browser an agent drives is usually one kept for it, so it stays until turned
  off), nothing is drawn in pages: no card under fields, no save card, no warning, no passkeys
  in a field's suggestions (`agent.js`, loaded before `passkeys.js`, `content.js` and
  `inline.js`). The window fills, saves and copies with its checks; the toolbar button marks
  what waits; Vault's passkey window still answers. Unknown until read counts as on; turned
  on, the cards on screen go; the frame refuses clicks and the worker answers no frame too.
  No other standard signal of agentic browsing was found (Chrome sets `webdriver` for
  `--enable-automation`, headless, `--remote-debugging-pipe` and `--remote-debugging-port=0`
  only; agentic browsers and `chrome.debugger` set nothing; user-agent strings are not
  used). Tests in `fields.test.mjs`, `background.test.mjs`, `passkeys.test.mjs`.
- ✅ S29. The extension asks every time: by default every password, one-time code, fill,
  copy and passkey the extension uses asks for Windows Hello (the item lock's key, or the
  vault's quick unlock key) or the item lock's PIN or password in that request, with no grace
  period; Settings says when nothing here can ask. The extension's Lock button, and one-time
  codes shown in its window (`reveal` with `what: "code"`), with the redesigned window.
- ✅ S30. Emergency kit page: the Secret Key and the recovery parts drawn as dots until
  "Show the keys for 15 seconds"; the actions grouped (print; keep a copy in a file; change
  the keys), each with a line saying what it does; the pairing code shown one character per
  box.
- ✅ S31. The phone asks every time: by default every password, one-time code, card number or
  security code, secure note, attached file, the editor and the generator's history asks
  Android's own prompt (fingerprint, face or screen lock) in that action, with no grace
  period (Settings → Security, "Ask for the fingerprint or screen lock every time";
  `System::check_person`, `controller/each_use.rs`). One-time codes are dots with an eye (item
  page, and each row of the Codes page): shown after the check until that code runs out, then
  dots again. A phone with no screen lock asks the item lock's PIN or password instead, or
  shows nothing, and Settings says so; the item lock asks once per action, never twice.
  Headless tests: on by default, each use asks again, a refusal shows and copies nothing, a
  code back to dots once it runs out or the item is left, the Codes page per row, off asks
  nothing, no screen lock with and without an item PIN.
- ✅ S32. The emergency kit's PDFs protected by a password (CRYPTO.md §3.10): the printed
  kit's temporary PDF, "Save as PDF", "Save each part apart" (Kit page and onboarding) and
  `vault kit --pdf` are encrypted with the PDF standard security handler, revision 6 (AES-256;
  `kit_pdf/protect.rs`, by hand on `aes`, `cbc` and `sha2`); saved files are read back before
  they are called done. The password is four EFF words, derived, never stored or printed
  (`Vault::kit_pdf_password`: `subkey("kit-pdf")`, the Secret Key and the kit's id), opening
  with or without the spaces; the Kit page shows it next to the print and save actions (dots
  until shown for 15 seconds, Copy), and the keys and the password wait for the item lock's
  check when one is in use; `vault kit --pdf-password` shows it alone. Known-answer vectors
  computed apart (Python's `cryptography` for the password, pypdf's revision 6 code for the
  hash and the dictionary, `cryptography`'s AES-CBC for a string), and the files opened by
  pypdf, qpdf (pikepdf) and PDFium (pypdfium2) with either spelling, a wrong password refused.

**Features** (F2, F7 and F8 change the file format: one format version for the three)
- ⬜ F1. Lock options: ask for the master password at every start of the app.
- ✅ F2. Trash (format v11): Delete puts an item in the trash (`trashed_at`), restorable for 30
  days, then deleted for good on the next save; "Delete for good" from the trash. A deletion's
  tombstone names the versions it removed (SYNC.md §4.2), so a restore or an edit elsewhere
  survives it whatever the clocks; of a trashed and an untrashed version, the untrashed wins
  (§4.3). Desktop: the Trash list, Restore and Delete for good; phone: the Trash filter.
- ⬜ F3. Health without the network: two-factor available, saved without HTTPS, passkey
  available, card expiring.
- ⬜ F4. Username generator: plus-addressed email, a domain's catch-all, random words.
- ✅ F5. Cards filled in the browser (`cards`, `card_fill`): payment fields found by `cc-*`
  autofill marks and common names (`card-fill.js`, `fields.js`), the vault's cards offered
  under a payment field and in the extension's window (brand, last four, holder, expiry;
  never a number), each fill through the item lock and the per-use check, typed field by
  field (expiry joined or split, selects, two or four digits as the field shows). Frames: the
  page's own origin fills; a frame of another site (a payment provider's) only once the person
  approved that frame's site for the page's site, in the card (click check) or the window,
  kept by the app with the site's rules (`card_frames`, F16) and shown in Settings; a frame of
  a site not approved is named, never filled; sandboxed documents get nothing (`cards.js`,
  S22's rule on the extension side). Addresses: an address field (autocomplete's address
  tokens, or named like a street, city or postal code; a name, email or phone alone is not)
  gets the vault's identities (F7) under it and in the window (`identities`,
  `identity_fill`: the name, email, phone, address, city, region, postal code, country and
  company, never a document number), typed into the page's own top document only
  (`address-fill.js`; no frame of another site), through the item lock and the per-use
  check; never-fill rules hold for them too. ⬜ Tried in a real Chrome on a checkout with an
  embedded provider's frame, and on an address form.
- ⬜ F6. Unlock with a hardware key (challenge-response, or FIDO2 `hmac-secret`).
  Designed (CRYPTO.md §3.13): FIDO2 `hmac-secret` through Windows' `webauthn.dll`, each
  enrolled key wrapping one hardware factor that joins the password slot's KEK, recovery
  unchanged. Done without the format: the slot's sealing and the factor's key
  (`vault_core::hardware_key`, a known-answer HKDF vector computed apart), the `HardwareKey`
  trait with a stand-in and the API version check (`vault_platform::hardware_key`). Still to
  do: the header's fields (a format version: slot kinds, the enrolled keys, the factor
  sealed under the vault key), the two `webauthn.dll` calls tried with a real key, the
  unlock and Settings screens, the CLI and the phone.
- ✅ F7. Identity items (`ItemKind::Identity`, details as fields with fixed names,
  `vault_core::identity`, document numbers hidden; JSON import and export as the common
  layout's identities) and templates (`template`: listed apart, never filled, "New item from
  it" with no secrets, `ItemData::from_template`). Phone: identities show as items; templates
  and archived items stay on the desktop.
- ✅ F8. Tags (searched, `#tag` too) and an expiry date on items; Password health lists what
  expires within 30 days (`HealthReport::expiring`, under Expiring).
- ✅ F9. SSH agent, with approval for each use: Settings → Security (off by default); OpenSSH's
  agent protocol on `\\.\pipe\openssh-ssh-agent` or, when Windows' agent holds it, a pipe of
  its own with the `SSH_AUTH_SOCK` line to copy (`vault_platform::ssh_agent`, its access list
  the user's alone); the vault's SSH keys listed while open, every signature approved in a
  dialog naming the key, the program and its parent, and what it is for (sign-in user or
  SSHSIG namespace), "don't ask again" 5 minutes for one key and program, the item lock
  respected, everything refused at the lock, each signature in the security log
  (`controller/ssh_agent.rs`); signatures by
  `vault_core::ssh::agent_sign` (Ed25519, ECDSA P-256/P-384, RSA SHA-256/512; SHA-1 refused).
  Tests: each signature checked by its crate's verifier, the protocol cut anywhere, the real
  pipe with two test clients, the app's whole flow headless.
- ✅ F10. Credential Exchange Format (CXF) import and export. CXF 1.0, the FIDO Alliance's
  Proposed Standard of 14 August 2025 (`vault_import::cxf`): basic-auth, passkeys (PKCS#8),
  TOTP, notes, cards, SSH keys (PKCS#8, `vault_core::ssh::pkcs8_der`) and custom fields onto
  items, collections onto folders; addresses, identity documents, passports, names, Wi-Fi and
  API keys as fields of a note (identity items once F7 lands), files, links and unknown kinds
  counted in the review. The export carries passkeys with their keys (counted as readable in
  the export dialog), leaves files and earlier passwords out (counted). Desktop: Export →
  "Credential Exchange (CXF), not encrypted"; Import detects it. Still to do: the Credential
  Exchange Protocol (app to app, HPKE), when platforms offer it to third-party apps.
- ✅ F11. Auto-type into programs outside the browser: the item page's Auto-type and the
  right-click menu type username, Tab, password and Enter (`SendInput`, Unicode characters)
  into the window behind the app after its title and a 3-second countdown, only while that
  window (same handle, program and title) has the keyboard, never into the app's own, not
  with Ctrl, Alt, Shift or Win held; a locked login types nothing, the lock cancels it; each
  one in the security log with the window's title (`vault_platform::autotype`,
  `controller/autotype.rs`). Limits in THREAT_MODEL §3.
- ⬜ F12. Distribution: the extension in the stores, an installer, the desktop updating itself.
  Done: the desktop app writes the extension into a folder of its own
  (`vault_platform::extension_folder`): by default the newest GitHub release's zip, taken with
  the app's own updates when its SHA-256 is the one the release list gives and read strictly
  (`vault_platform::extension_source`), or the copy built into the exe (`build.rs`) when that is
  newer or nothing was downloaded; or a folder of the person's instead. Settings → Browser
  extension → Add to a browser offers the installed browsers with their icons (the default one
  first), starts the chosen one on its extensions page with the folder's path copied, and shows
  the steps (Developer mode and Load unpacked; Firefox: a temporary add-on), and says which
  source is in use. The folder is written again when a new version of the app starts and when
  a newer release is taken, and checked while the browser link runs (a file another program
  changed is put back, notice 97; one it can't put right on two checks in a row, notice 98; a
  release that doesn't check out, notice 99); the answers to `status` and `logins` name the
  version in use, and an extension loaded from that folder reloads itself into it at its next
  request (`apps/extension/update.js`, once per version; it waits while a save or a window is
  open).
  Still to do (owner): publishing on the Chrome Web Store, Edge Add-ons and addons.mozilla.org
  (no browser lets a program add an off-store extension by itself on a normal Windows
  computer, and Firefox keeps only signed add-ons past a restart), then the store's own
  updates; an installer.
  Done too: the desktop app replacing itself (`vault_platform::self_update`): a newer release
  found by the hourly look (or Check for updates) downloads its `vault-desktop.exe` in the
  background, checks it against the signed manifest (size and SHA-256), renames the running
  program aside and puts the new one in its place, with a rollback; the title bar's update
  button and Settings → About show each step (manifest, download with MB and %, SHA-256,
  install) and what failed; then "Version X is installed. Restart now?" (Restart locks the
  vault, starts the new program, which waits for this one to end, and quits; Later leaves it
  to the next start). Settings → About → "Install updates by itself" (on by default); off, the
  version is only told and Install now does the same. A folder that can't be written is told
  and the release page opens.
- ⬜ F13. Sharing and emergency access (a written design first, `docs/spec/SHARING.md`).
- ⬜ F14. Passkey provider for Windows 11. Designed (ARCHITECTURE.md §5.2): the plugin
  passkey manager API, what it needs (package identity, a COM server, Windows' credential
  list), what is reused (`vault_core::passkey`, the Android provider's flow) and the risks;
  no code until it can be tried on Windows 11.
- ⬜ F15. Linux, macOS, and the CLI level with the apps.
- ✅ F16. Per-site rules: never offer to save, never show the card, never fill, no passkeys
  (`vault_browser::rules`), for a host and the hosts under it, the most specific winning.
  Kept per device in `state.json` (`device::SiteRule`), not in the vault: no format change in
  this batch, so they don't sync (a later format version can carry them). The app refuses what
  they forbid before answering, locked or not (`site_rule`), and names the rule in its
  `logins` answer so the extension offers nothing it forbids. Set in Settings → Browser
  extension → Site rules and from the extension's window for the site in front (`site_rule`,
  told in the app).
- ⬜ F17. More lock triggers and "lock everything": on minimising to the tray, hiding revealed
  text on losing focus, how often Windows Hello asks for the master password, Lock in the
  extension, a global shortcut, `--lock`.
- ✅ F18. The save card and the editor warn of a reused or leaked new password: reuse from the
  vault's open logins (counts only), leaks through the leak check's k-anonymous range query
  only while the leak watch is on, off the UI thread, each prefix's answer kept a few minutes
  (`controller/weigh.rs`, `weigh`). The editor weighs leaks once typing pauses.
- ✅ F19. Help changing a password: *Change password* among a login's buttons (Edit, Change
  password, Delete) makes a strong password for it and opens the site's page from the
  `password-manager-resources` list (sites that don't answer the standard address), else its
  `/.well-known/change-password` (always https). The browser extension, asked for a suggestion on a
  new-password field of that login's site, gets that very password when it fits the field
  (`controller/change.rs`, in memory only, 30 minutes at most, gone at the lock), and its
  update card saves it after the form is sent. *Change on the site* on health warnings opens
  the same page. The list's password rules feed the generator for a field that says none
  (`password_rules`).
- ✅ A yes/no question (no master password) before what takes a secret away: a login's saved
  password replaced in the editor, a passkey removed (in the editor, or because its site said
  it is gone), an attached file or a hidden field with a value removed, a password history
  or the generator's history cleared (`controller/confirm.rs`). The lists are pinned in
  `crates/browser/data/password-manager-resources/` (MIT, notice kept, commit named in its
  README), compiled in, never fetched (`vault_browser::resources`).
- ✅ F20. Authenticator: five-character codes (`encoder=steam` or `otpauth://steam/`, the
  platform's name only where the person reads it), import from other authenticator apps
  (`otpauth-migration://` transfer payloads, `otpauth://` link lists and the common apps' JSON
  exports, encrypted ones refused with how to make a plain one; `vault_import::authenticator`),
  and on the desktop a QR code read from a picture file (Authenticator → From a QR picture…,
  `rqrr`): a site's key opens a new code item, a transfer code goes to the import review.
  Still to do: the phone's own QR scanner for transfer codes; picking five-character codes in
  the editor (they come from links and imports today).
- ✅ F21. The whole item's history: every change to an item's contents keeps the version it
  replaces (`ItemData::versions`, up to the history limit, sealed with its secrets under the
  item lock), merged so that neither device's edit is lost (SYNC.md §4.3); the item page lists
  them with Restore (`Vault::restore_version`).
- ✅ F22. Archived items: out of search, filling, the authenticator and health, not deleted;
  the Archive list on the desktop.
- ✅ F23. The WebAuthn Signal API: `signalUnknownCredential`, `signalAllAcceptedCredentials`
  and `signalCurrentUserDetails` are wrapped in the page's world (the browser's own handler
  still called), relayed and bounded (`signals.js`, 10 a minute per tab), and the app notes
  them on the matching passkeys of the site the page may speak for (`passkey_signal`). The
  item page says what the site said under the passkey, with *Remove it* / *Use this name* and
  *Keep as it is*; nothing changes by itself. Notes live in memory while the app runs.
- ✅ Website icons in the extension's window from the app's sealed cache (`icons`), only while
  Website icons is on; the extension fetches nothing (the window's policy takes `data:`
  images).
- ⬜ F24. Show a password in large type.
- ⬜ F25. A settings review on the health page, and "ignore this warning".
- ⬜ F26. Quick access by a global shortcut (search, copy, type) and configurable shortcuts.
- ✅ F27. Export as KDBX 4 (`vault_import::export_kdbx`, CRYPTO.md §3.12): the `keepass`
  crate, ChaCha20 and Argon2id 256 MiB / 3 passes / 4 lanes, a password of the person's (12
  characters at least) and optionally a keyfile; every item whole in KeePassXC's places
  (`KP2A_URL_n`, `otp`, `KPEX_PASSKEY_*`, attachments, history) and the rest in `vault.item`.
  Round trip tested against the importer, and opened by KeePassXC 2.7's CLI. Desktop only for
  now (Export → KeePass database); the phone's export keeps its three formats.
- ✅ F28. More import sources: other managers' JSON shapes (vaults of typed items, items of
  labelled fields, records with typed custom fields), more CSV columns (password and URL
  aliases, more websites in one cell, tags, created and modified dates, card columns), the
  KeePass reader's passkeys, files, extra websites and history, each tested with constructed
  rows. Not read: zip exports (a manager's `.1pux`, a zip of CSVs: unzip first), headerless
  CSVs, XML exports.
- ⬜ F29. CLI automation through the open app (`vault run`, `vault inject`, a git credential
  helper), each use approved in the app.

F2, F7, F8, F21, F22 and S18 are format v11. A copy of another format version is said plainly
on the desktop (which device, and whether this app or that one needs updating); the phone still
says nothing about refused copies (S14's leftover).

## Engineering practices

- Tests: unit + known-answer vectors + property tests (`proptest`) + fuzzing (`cargo-fuzz`).
- `cargo deny check advisories` passes with nothing ignored (`deny.toml`).
- CI (GitHub Actions, `.github/workflows`): `ci.yml` (fmt, clippy `-D warnings` and tests on
  Windows, the WebAssembly build, the extension's tests, the core and protocol tests on Linux,
  the server's Docker image), `security.yml` (cargo-deny every push and every day, gitleaks
  over the history, zizmor, dependency review on pull requests), `codeql.yml`, `scorecard.yml`,
  `fuzz.yml` (every fuzz target five minutes a day, a finding kept as the run's artifact);
  Dependabot for cargo, actions, Gradle and Docker. ⬜ licences in cargo-deny.
- Every change to the file format bumps the format version; old versions are rejected unless an
  explicit migration exists.
- Commit messages and code in English.
