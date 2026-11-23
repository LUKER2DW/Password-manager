# AGENTS.md — working on this repository

This file is for anyone changing the code: people and AI coding agents alike. It explains what
the project is, how it is laid out, how to build, test and review it, and the rules that keep it
safe. Read it before your first change; the linked documents go deeper.

## 1. What this is

A local-first, zero-knowledge password manager written in Rust.

- **Security comes first.** The design assumes a realistic attacker: malware on the user's
  computer (infostealers), stolen vault files, tampered files, leaked website databases. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Local-first.** The vault is one encrypted file. Nothing leaves the device unless the user
  asks for it (website icons, leak check, sync). Sync is optional: a folder, WebDAV or the
  project's own small server that the person runs; never a hosted service.
- **Zero-knowledge.** The vault key depends on the master password *and* a 128-bit Secret Key
  that is never stored in the vault file. A stolen file alone is useless.
- **Platforms:** Windows desktop and the Chrome/Edge extension (working), Android (early),
  Linux (later).
- **Status:** early development, not audited. Never test with real passwords.
- **Licences:** GPL-3.0-or-later for the apps and libraries ([LICENSE](LICENSE));
  AGPL-3.0-or-later for the sync server ([apps/server/LICENSE](apps/server/LICENSE)).

## 2. Repository layout

`apps/` holds what people run, `crates/` the libraries the apps share. An app may depend on
crates and, for tests, on another app (the server); a crate never depends on an app.

```
Cargo.toml              workspace (edition 2024, shared lints, release profile)
rust-toolchain.toml     stable toolchain + clippy + rustfmt
apps/
  cli/                  vault-cli: the `vault` command-line client
  desktop/              vault-desktop: the Slint desktop app (ui/ is vault-desktop-ui)
  mobile/               vault-mobile: the phone app's screens and controller (Android first)
  mobile-android/       vault-mobile-android: the phone app as an APK (cargo-apk, Java activity)
  mobile-web/           vault-mobile-web: the phone app in a browser page (WebAssembly), demo vault
  server/               vault-server: the self-hosted sync server (AGPL-3.0), Docker files
  extension/            the Chrome/Edge extension (Manifest V3, plain JavaScript)
crates/
  core/                 vault-core: cryptography, file format, item model (no UI, no network)
  platform/             vault-platform: OS integration (Windows first, Android)
  import/               vault-import: import from / export to other managers and browsers
  browser/              vault-browser: what the extension may ask and get, and its native host
  sync-wire/            vault-sync-wire: what devices and the sync server say (signed requests)
docs/
  THREAT_MODEL.md       who we defend against and the principles that follow
  ARCHITECTURE.md       overall design and decisions
  DESIGN.md             visual system and UI rules
  ROADMAP.md            phases and where each one stands
  IMPLEMENTATION_PLAN.md  milestones and what is done (keep it current)
  MOBILE.md             the phone app: plan, screens, security on a phone, milestones
  SERVER.md             running your own sync server (Docker, Tailscale), what it can see
  spec/CRYPTO.md        exact cryptography (normative)
  spec/VAULT_FORMAT.md  exact file format (normative)
  spec/SYNC.md          sync: the merge, the targets, the server protocol
research/               local notes, git-ignored, never committed
```

### 2.1 `crates/core` (vault-core)

The security-critical heart. It owns all key material and has **no UI, no network, no
filesystem policy** beyond atomic writes.

| Module | What it does |
|---|---|
| `aead.rs` | Key-committing XChaCha20-Poly1305 (`seal` / `open`) |
| `kdf.rs` | Password hashing (Argon2id; scrypt and PBKDF2-SHA-256 by choice) with a hard floor and ceiling on parameters |
| `keys.rs` | Secret Key, recovery parts (and the Recovery Key of older kits), keyfile, vault key, subkeys, device KEK |
| `guard.rs` | Item guard: which items ask for a second check, and the guard key wrapped by the PIN or password |
| `encoding.rs` | Crockford Base32 for the printed keys |
| `padding.rs` | Length-hiding padding for items and body |
| `format.rs` | File envelope, header, body, and the layouts of older versions |
| `vault.rs` | `Vault`: open, create, items, folders, settings, history, save |
| `vault/merge.rs` | Folding another device's copy into this one (`Vault::merge`, SYNC.md §4) |
| `sync.rs` | What sync needs from the vault: writers, tombstones, devices, revisions |
| `item.rs` | `ItemData`, `ItemSummary`, folders, recovery codes, password history, attachments |
| `card.rs` | Payment cards: Luhn, brand detection, expiry, masking |
| `ssh.rs` | SSH keys: a new Ed25519 key in OpenSSH's format, the public half and fingerprint of any OpenSSH key |
| `generator.rs` | Passwords and passphrases (uniform sampling, word lists) |
| `health.rs` | Strength (zxcvbn), reuse, age, and the k-anonymous breach query |
| `sealed_export.rs` | An export sealed under a password of its own (`.vaultx`) |
| `drop_box.rs` | Logins saved from the browser while locked, sealed to a public key only the open vault reads |
| `locked_fill.rs` | Logins the extension may fill while the vault is locked (CRYPTO.md §3.4) |
| `passkey.rs` | Passkeys in logins: ES256 keys, authenticator data, attestation, signatures (CRYPTO.md §3.7) |
| `totp.rs` | RFC 6238 one-time codes |
| `storage.rs` | Atomic file writes with a `.bak` copy |
| `random.rs` | OS randomness |

### 2.2 `crates/platform` (vault-platform)

Everything that touches the operating system: Secret Key in the credential store
(`secret_store.rs`; the Android Keystore on a phone), per-device state and rollback detection
(`device.rs`), clipboard that stays out of history (`clipboard.rs`, `clipboard_android.rs`),
screen-capture blocking (`screen.rs`), locked memory for typed secrets (`secure_buffer.rs`),
the leak check and the leak watch's sealed memory (`leak_check.rs`),
Windows Hello quick unlock (`quick_unlock.rs`), DPAPI (`dpapi.rs`), keyfiles on disk
(`keyfile.rs`), the person's language (`locale.rs`), installed browsers (`browsers.rs`), the
extension's local pipe and host registration (`browser_link.rs`), the emergency kit PDF
(`kit_pdf.rs`), a recovery part hidden in a picture (`part_picture.rs`), opt-in website icons
fetched directly from each site with a sealed cache (`website_icons.rs`), file helpers and
secure wiping (`files.rs`), app paths (`paths.rs`), sync targets and one sync
round (`sync.rs`: the folder target, fetch, merge, this device joining the vault;
`sync/server.rs` the sync server client, `sync/webdav.rs` WebDAV, `sync/http.rs` which
addresses are allowed). The server key and the WebDAV password live in the credential store
(`secret_store.rs`), the place in device state (`SyncTo`).

### 2.3 `crates/import` (vault-import)

One entry point, `vault_import::import(bytes, format, password, keyfile)`, reads every
supported file. Readers are named by format, never by product:

- `json.rs` — unencrypted JSON exports in the common layout.
- `csv_import.rs` — CSV from browsers and managers, detected by header aliases.
- `kdbx.rs` — KeePass-format databases.
- `browser.rs` — reads a browser's own store directly on Windows (Chromium via DPAPI +
  AES-GCM, Firefox via NSS `key4.db`), only on an explicit user action. DPAPI is passed in by
  the caller so this crate stays free of `unsafe`.
- `export.rs` — JSON and CSV exports, and the JSON export sealed under a password.
- `lib.rs` — `ImportReport`, review rows, duplicate detection, `FolderTarget`, `Source` list.

Importers only produce `ItemData`; they never touch keys.

### 2.4 `apps/cli` (vault-cli)

`vault init | info | list | add | show | edit | rm | generate | totp | passwd | recover | kit |
part-picture | forget | keyfile | import | sync`. Same vault and device state as the desktop
app. `tests/cli.rs` runs the binary, including sync through a running server.

### 2.4.1 `crates/browser` (vault-browser) and `apps/extension/`

The extension holds no secrets. `origin.rs` decides which saved website belongs to which page
(exact scheme, host and port; https only) and which site a page may use passkeys for, `protocol.rs` is the JSON it exchanges with the
app, `pairing.rs` is the connection key and the proof on every request, `service.rs` answers
from an open vault (with the item lock as a `Gate`), `host.rs` + `main.rs` are the native host
(`vault-browser-host`) that relays between the browser and the app's pipe. In `apps/extension/`,
`popup.js` is the extension's window, `link.js` its connection key and request signing, and
`fill.js` the function that types a login into a page, `content.js` + `fields.js` the
content script (sign-in fields, submitted forms), `inline.html`/`inline.js` the frame shown
under a field, `background.js` the worker between them and the app, `generator.js` the
reading of a site's password rules, `app.js` the native messaging calls. Passkeys:
`passkeys-page.js` (in the page's own world, in front of `navigator.credentials`), `passkeys.js`
(the relay), `passkey-worker.js` (the worker's side) and `passkey.html`/`passkey.js` (the window
where the person chooses). See
[apps/extension/README.md](apps/extension/README.md). Tests: `cargo test -p vault-browser` and
`node --test apps/extension/test/fill.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs`.

Rules for this part: UI in a page only as the extension's own frame (`inline.html`), never as
page DOM, and every click there goes through the visibility check; no new permission without
a threat-model note; passwords are made, copied and decided on by the app, not the extension;
the extension stays free of packages and build steps.

### 2.5 `apps/desktop` (vault-desktop)

Slint UI (`ui/*.slint`) driven by a Rust controller.

| File | Role |
|---|---|
| `src/controller.rs` | Wires every callback, background jobs, timers, state |
| `src/controller/features.rs` | Generator, password history, health, leak check, import review, vault settings, unlock protection (hash method and level) |
| `src/controller/folders.rs` | Folder dialog (create, settings, picture preview, delete) and reordering |
| `src/controller/protection.rs` | Keyfile (unlock, set, remove) and the item lock (PIN, password or master password before secrets show) |
| `src/controller/browser.rs` | The browser extension's link: listens on the pipe, answers from the open vault |
| `src/controller/generated.rs` | History of generated passwords (sealed per vault on this computer) |
| `src/controller/drop_box.rs` | Logins the browser saved while the vault was locked, added at the next unlock |
| `src/controller/syncing.rs` | Sync through a folder, the server or WebDAV: Settings → Sync (join, add a device with a QR code, remove one), rounds at unlock, after saves, every 5 minutes, on the server's news and on demand (the target read and written off the UI thread) |
| `src/controller/locked_fill.rs` | Filling from the browser while the vault is locked |
| `src/controller/attachments.rs` | Files attached to items and SSH key items in the editor and on the item page |
| `src/controller/watch.rs` | The leak watch: every login checked once a day while open, new leaks told and shown on Password health |
| `src/tray.rs` | The notification area icon (tray mode) and its menu window (`ui/tray.slint`) |
| `src/i18n.rs` | The app's language: picks a compiled-in catalogue from `translations/` |
| `src/controller/navigation.rs` | Back/forward history, mouse buttons 4/5 and keyboard shortcuts (raw window events) |
| `src/view.rs` | Pure presentation rules (unit-tested): filters, tints, crack times, dates |
| `src/sketch.rs` | Hand-drawn strokes generated in Rust |
| `src/tests.rs` | Headless end-to-end test of the whole app |
| `examples/screenshots.rs` | Renders every screen to PNG for visual review |
| `ui/Cargo.toml`, `ui/lib.rs`, `ui/build.rs` | `vault-desktop-ui`: the generated Slint code as a crate of its own, so controller changes don't recompile it (re-exported as `vault_desktop::ui`) |
| `ui/theme.slint` | Design tokens, `Secrets` bridge for secure fields |
| `ui/model.slint` | Structs shared with Rust and **every user-facing message** |
| `ui/widgets.slint` | Buttons, fields, secure field, dropdown, slider… |
| `ui/icons.slint` | Field icons (Lucide), card network marks, import source icons |
| `ui/dialogs.slint` | Dialogs over the whole window (`Modal`, `FolderDialog`, `PartsUsedDialog`) |
| `ui/strength.slint` | The strength meter (shared with the phone) |
| `ui/tray.slint` | The notification area's menu window |
| `ui/welcome.slint`, `vault.slint`, `pages.slint`, `kit.slint`, `app.slint` | Screens; right-click menus live in `app.slint` |
| `ui/brand/` | The logo, the lock screen's scene and the open vault's texture |
| `translations/` | gettext catalogues compiled into the app (see its README) |

### 2.6 `apps/mobile` (vault-mobile)

The phone app (Android first), see [docs/MOBILE.md](docs/MOBILE.md). `ui/app.slint` is the
phone's layout and imports the desktop's `theme.slint`, `widgets.slint` and `icons.slint`
(one design for both; `Theme.touch` sizes it for fingers). `src/controller.rs` wires it to the
vault with the same rules as the desktop (secure fields, item lock, `changed_outside`-style
save check, clipboard cleared). `src/tests.rs` runs it headless;
`examples/phone_screens.rs` renders every screen to PNG. A change to a shared widget must
look right in both apps' screenshots. The controller's submodules are `syncing.rs` (sync on
the phone, updates from the server), `settings.rs` (vaults on the phone, fingerprint unlock,
import, "Check this password"), `filling.rs` (autofill from the open vault),
`attachments.rs` (files and SSH keys) and `icons.rs` (website icons). `prefs.rs` is the
phone's own settings file, `bio.rs` a vault's fingerprint unlock file, `autofill.rs` which
logins belong to the app or site asking (and the drop box for logins saved while locked), and
`system.rs` the `System` trait: what only Android does, implemented by the Android crate. The controller reaches the system only through
`src/platform.rs` (the platform crate, or `src/platform/web.rs` in a browser), so the same
code also runs as the web preview in `apps/mobile-web` (build: `apps/mobile-web/build.ps1`).

`apps/mobile-android` is the APK: `src/lib.rs` starts Slint's Android backend with the same
screens, `src/shell.rs` talks to the activity over JNI, `src/system.rs` is the `System` the
controller asks, and `src/autofill.rs` answers autofill. The Java side is in
`java/org/passwordvault/phone/`: `VaultActivity` (Android's `NativeActivity` plus the file
picker, "save as", Back, screenshots, updates), `Biometrics` (the Keystore key behind the
fingerprint), `VaultAutofillService`, `AutofillActivity` and `Fields` (autofill). `res/` holds
the launcher icon and autofill's own words and layout. Build:
`apps/mobile-android/build.ps1` (docs/MOBILE.md §7.2).

### 2.7 `crates/sync-wire` and `apps/server`

`vault-sync-wire` is the request protocol shared by clients and server (signed messages,
enrollment, invites, JSON bodies). `vault-server` (AGPL-3.0) stores sealed copies, device
public keys and invite digests as plain files (`store.rs`) behind the API in `api.rs`
(signature, time and nonce checks, limits), with an HTTPS of its own for a home network
(`tls.rs`). Tests: `cargo test -p vault-server` runs a real server with two devices. Setup:
[docs/SERVER.md](docs/SERVER.md); Docker files next to the code.

## 3. Build, run, test

The toolchain comes from `rust-toolchain.toml`. On Windows, if `cargo` is not on `PATH`, prefix
the shell with `$env:Path = "$HOME\.cargo\bin;$env:Path"` (PowerShell).

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

All four must pass before a commit. Clippy runs with `-D warnings`.

Run the desktop app against a **test** vault (a missing file opens the "new vault" screen):

```powershell
$env:VAULT_FILE = "$HOME\Documents\vault-test.vault"; cargo run --release -p vault-desktop
```

`VAULT_HOME` moves the whole app directory (device state, caches, word lists); the tests set it
to a temporary folder.

Visual review without touching the real screen:

```bash
cargo run -p vault-desktop --example screenshots -- target/screenshots
# SHOT_ICONS=1 also fetches real website icons for the demo items
```

It writes numbered PNGs, an `index.html` gallery and a demo emergency kit PDF. Open the PNGs
to review layout; do not drive the real desktop to check UI.

The other apps:

```bash
cargo run -p vault-mobile                                  # the phone app in a phone-sized window
cargo run -p vault-mobile --example phone_screens -- target/phone-screens   # its screens as PNGs
cargo run -p vault-cli -- --help                           # the `vault` command
cargo run -p vault-server -- serve                         # a sync server (docs/SERVER.md)
node --test apps/extension/test/fill.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs
```

The APK and the browser build have their own scripts, `apps/mobile-android/build.ps1` and
`apps/mobile-web/build.ps1` (what each needs is at its top; docs/MOBILE.md §7).

### 3.1 Tests that matter

- `crates/core/tests/format_v*.rs` — known-answer tests: each committed fixture in
  `crates/core/tests/fixtures/` must keep opening forever. Never regenerate an old fixture.
- `crates/core/tests/vault.rs`, `robustness.rs` — tampering, swapping, rollback, downgrade,
  malformed input. `sync.rs` — the merge, with a property test over three devices;
  `recovery_parts.rs` — the kit's three parts.
- `apps/desktop/src/tests.rs` — the whole app flow headless (onboarding, unlock, items, cards,
  folders, history, health, generator, import, export, kit, second vault). Slow work runs inline
  there (`Runner::Inline`); dialogs and network are skipped.
- `apps/mobile/src/tests.rs` — the phone app headless, including sync against a running server.
- `apps/server/tests/sync.rs` — two devices through a real server; strangers, replays and
  altered requests refused.

## 4. Rules

### 4.1 Security rules (non-negotiable)

1. **No home-made cryptography.** Only the primitives in [docs/spec/CRYPTO.md](docs/spec/CRYPTO.md),
   from audited crates. Any change to bytes on disk follows §5.1.
2. **Secrets are wiped.** Keys and decrypted data live in `Zeroizing` / `ZeroizeOnDrop` types.
   Serialization buffers are sized exactly (no reallocation copies). `Debug` of secret types is
   redacted. Never log, print, or put a secret in an error message.
3. **Typed secrets never enter Slint strings.** Password fields are `SecretField`, whose
   keystrokes go straight to Rust (`Secrets` global → `SecretBuffer`); the UI only knows the
   length. A secret is shown as text only while the user asked to see it, and cleared after.
4. **No `unsafe`** except in `platform`, `desktop` and `mobile-android` (lint level `deny`),
   each block with `#[allow(unsafe_code)]` and a `// SAFETY:` comment. Every other crate
   forbids it.
5. **No network in `core`.** Network use anywhere is opt-in and per action: website icons
   (setting, off by default), the leak check (button; k-anonymous, 5 hex chars of SHA-1,
   padded) and the leak watch (the same check once a day; setting, off by default), an icon
   site or picture link chosen for an item or folder, sync to a place the person set up
   (sealed copies only), and the phone app's updates from that server. Nothing is sent to a
   third-party service for icons. Links handed to the OS to open are `http(s)` only
   (`vault_platform::browsers::web_link`). The browser extension's link is local only (a
   named pipe), off by default.
6. **Browser stores are read only on an explicit click**, in memory, for the signed-in user.
   Plain-text exports the app reads are offered for secure wiping afterwards.
7. **Never overwrite a vault changed by someone else.** Saves compare the file's hash with the
   one last read or written (`changed_outside`) and refuse otherwise.
8. **A locked item's secrets are reached only through `selected_item()`**, which returns
   nothing while the item waits for its check. New code that shows or copies a secret, or
   changes the item, must go through it; `selected_item_raw` is only for what a locked item
   still shows (title, username, website, plain fields). With a PIN or password guard the
   core enforces it too: `Vault::get_item` returns a locked item without its secrets
   (`ItemData::is_locked`) until `Vault::unlock_secrets`.
9. **Fail closed.** Unknown format versions, KDF parameters outside the floor/ceiling, duplicate
   ids, and any AEAD failure are errors, never fallbacks.

### 4.2 Project rules

- **English only** in code, comments, commit messages and docs.
- **Every user-facing string goes through `@tr(...)`** in `.slint` files. Rust sends codes, not
  text: errors are `error::*` constants and notices `notice::*` constants in `controller.rs`,
  rendered by `Messages.error` / `Messages.notice` in `ui/model.slint`. Plurals use
  `@tr("{n} item" | "{n} items" % n)`.
- **No personal data in the repository.** No real names, emails, paths with user names,
  vaults, keys, exports or screenshots of real data. Test fixtures use obvious test values and
  say so (`*.credentials.txt`). `research/` is git-ignored and stays out of commits.
- **Product names stay out of code identifiers and file names.** Importers are named by format
  (`json`, `csv`, `kdbx`). Product names appear only where the user picks a source.
- Keep [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) current, and the specs exact.

### 4.3 Commits

- Small, focused, **one commit per area**: `Core: …`, `Platform: …`, `Import: …`, `CLI: …`,
  `Browser: …`, `Extension: …`, `Desktop: …`, `Mobile: …`, `Server: …`, `Docs: …`, `Build: …`.
  A short subject in the imperative-free style used in the log ("Core: format v3 (folder icon
  and colour, item icon website)"), then a body that says what changed and why.
- Run fmt, clippy and the tests first. Never commit a failing build.
- Never commit generated output (`target/`), vault files, exports or kits (see `.gitignore`).
- Commits carry the author's GitHub no-reply address, never a personal email, and no
  attribution lines.

## 5. How to do common things

### 5.1 Change the vault file format

Anything that changes the serialized bytes of the header, body, folders or items is a new
format version.

1. In `format.rs`, bump `FORMAT_VERSION` and document the new version in its comment.
2. Keep the previous layouts as `…Vn` structs (`VaultBodyV1`, `ItemDataV2`, `FolderV1`…) with an
   `upgrade()` into the current type, and extend the `match parsed.version` in
   `Vault::from_parsed` and `Vault::upgrade_items`.
3. Add `crates/core/tests/format_vN.rs` (copy the previous one), write its fixture once with
   `cargo test -p vault-core --test format_vN -- --ignored`, and commit the `.bin` and
   `.credentials.txt`. Add an "upgraded on save" test to the previous version's test file.
   **Never regenerate an older fixture.**
4. Update the version checks in the other format tests and the "from the future" test in
   `tests/vault.rs`.
5. Update [docs/spec/VAULT_FORMAT.md](docs/spec/VAULT_FORMAT.md).

### 5.2 Add a field to items

Add it to `ItemData` (and `ItemData::new`, `Debug`), follow §5.1, decide whether
`ItemSummary` needs it (only non-secret display data), then the editor (`pages.slint`
EditorPage + `app.slint` property + `open_editor` / `save_item` in the controller), the item
page, import/export if other managers have it, and tests.

### 5.3 Add a screen or a page

1. Add the component to `pages.slint` (or a new `.slint` file imported by `app.slint`).
2. Add a `Panel` variant in `model.slint` if it is a page, its properties and callbacks to
   `AppWindow` in `app.slint`, and the `if root.panel == …` block.
3. Wire callbacks in `Controller::wire` with the `on!` macro; put the logic in
   `controller/features.rs` or a new submodule of `controller`.
4. Messages go in `model.slint` (`Messages`), with new `error::` / `notice::` codes.
5. Add steps to `src/tests.rs` and a shot to `examples/screenshots.rs`, then review the PNG.

Tool pages (generator, health, kit, import & export, settings, authenticator) take the full
width; the item list is shown only for the item page and the editor.

### 5.4 Add an import source or format

- A new CSV layout usually needs only header aliases in `csv_import.rs` plus a test.
- A new source for the picker: add it to `Source` (and `Source::ALL`, `name`, `extensions`) in
  `import/src/lib.rs`, export steps in `TransferPage.steps` (`pages.slint`), and its mark in
  `SourceMark` (`icons.slint`).
- A new file format: a new reader module named after the format, a `Format` variant,
  `detect_format`, and the `import` match.

### 5.5 Icons

Field and index icons are Lucide (ISC) paths in the `Glyphs` global of `icons.slint`, one path
per icon on a 24 × 24 grid, drawn with a 2-unit round stroke. To add one, convert the Lucide SVG
elements (paths, circles, rects, lines) into a single path string — keep a subpath's first
`m` absolute — add the property, its branch in `Glyph`, and a colour in `FieldColors` if it
needs one. Brand icons for import sources come from Simple Icons (CC0); card network marks are
drawn.

### 5.6 Slint pitfalls seen here

- A width that depends on the parent's width inside a layout causes binding loops; use
  `min-width` / `preferred-width: 0` with `horizontal-stretch`, or `max-width`.
- `forward-focus` cannot target an element inside an `if`; focus it in `init`.
- Text without `overflow: elide` has a minimum width equal to its text, which can push a
  layout wider than the window.
- Popups need `close-policy` and stay inside the window; leave a margin at the edge.
- A `FocusScope` placed on top of a `TouchArea` takes the first click to grab focus, so the
  button needs two clicks. Give such scopes `focus-on-click: false` and focus them from the
  touch area when needed.
- A `TouchArea` loses `has-hover` to any element drawn on top of it. Something shown on hover
  (the folder pencil) must be a child of that touch area, or it hides itself and flickers.
- Every UI callback goes through the `on!` macro, which also records the place for back and
  forward (`note_place`). Code that changes the page outside a callback (a finished job) calls
  `note_place` or `reset_history` itself.
- Some `.slint` files have mixed line endings: when editing with scripts, match both `\n` and
  `\r\n`.

## 6. Design

Follow [docs/DESIGN.md](docs/DESIGN.md): dark theme by default, one yellow thing at a time,
hand-drawn touches only for small details, words that say what happens, a `(?)` hint only where
a field is genuinely unclear (and it says what to type), no decorative badges or filler.

## 7. Where to look first

- Something about keys or bytes on disk → `docs/spec/CRYPTO.md`, `docs/spec/VAULT_FORMAT.md`,
  `crates/core`.
- A screen → `apps/desktop/ui/*.slint`, then the matching handler in `controller.rs` /
  `controller/features.rs`.
- A message shown to the user → `ui/model.slint` (`Messages`).
- A setting stored per device → `platform/src/device.rs` (`Settings`); stored in the vault →
  `VaultSettings` in `core/src/item.rs`.
