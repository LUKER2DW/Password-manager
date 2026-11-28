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
- **Platforms:** Windows desktop, the browser extension (Chrome, Edge, Firefox) and Android (alpha),
  Linux (later).
- **Status:** alpha: usable, not audited yet. Never test with real passwords; the CLI is
  unfinished and Linux unsupported ([docs/ROADMAP.md](docs/ROADMAP.md)).
- **Licences:** GPL-3.0-or-later for the apps and libraries ([LICENSE](LICENSE));
  AGPL-3.0-or-later for the sync server ([apps/server/LICENSE](apps/server/LICENSE)).

## 2. Repository layout

`apps/` holds what people run, `crates/` the libraries the apps share, `tools/` what the
maintainer and the release workflow run. An app may depend on crates and, for tests, on another
app (the server); a crate never depends on an app.

```
Cargo.toml              workspace (edition 2024, shared lints, release profile)
rust-toolchain.toml     stable toolchain + clippy + rustfmt
apps/
  cli/                  vault-cli: the `vault` command-line client
  desktop/              vault-desktop: the Slint desktop app (ui/ is vault-desktop-ui)
  mobile/               vault-mobile: the phone app's screens and controller (Android first)
  mobile-android/       vault-mobile-android: the phone app as an APK (cargo + Gradle, Java activity)
  mobile-web/           vault-mobile-web: the phone app in a browser page (WebAssembly), demo vault
  server/               vault-server: the self-hosted sync server (AGPL-3.0), Docker files
  extension/            the browser extension (Manifest V3, plain JavaScript; Chrome, Edge, Firefox)
  windows-version-info.rs  the version information every Windows program carries (build scripts)
crates/
  core/                 vault-core: cryptography, file format, item model (no UI, no network)
  platform/             vault-platform: OS integration (Windows first, Android)
  import/               vault-import: import from / export to other managers and browsers
  browser/              vault-browser: what the extension may ask and get, and its native host
  sync-wire/            vault-sync-wire: what devices and the sync server say (signed requests),
                        and the project's releases with their signed manifest
tools/
  release/              vault-release: the release manifest (write, sign, check) and
                        make-manifest-keys.ps1, which makes its keys
  site-lists/           update.ps1: refreshes the bundled lists of sites with codes and passkeys
docs/
  THREAT_MODEL.md       who we defend against and the principles that follow
  ARCHITECTURE.md       overall design and decisions
  DESIGN.md             visual system and UI rules
  ROADMAP.md            phases and where each one stands
  IMPLEMENTATION_PLAN.md  milestones and what is done (keep it current)
  MOBILE.md             the phone app: plan, screens, security on a phone, milestones
  SERVER.md             running your own sync server (Docker, Tailscale), what it can see
  CODE_SIGNING.md       code signing policy: the manifest key, the APK's key, SignPath (pending)
  PRIVACY.md            privacy policy: what each app sends, where and when
  spec/CRYPTO.md        exact cryptography (normative)
  spec/VAULT_FORMAT.md  exact file format (normative)
  spec/SYNC.md          sync: the merge, the targets, the server protocol
  spec/SHARING.md       sharing and emergency access: the design (not built yet)
fuzz/                   cargo-fuzz targets (outside the workspace, nightly) and their seeds
research/               local notes, git-ignored, never committed
vendor/                 third-party crates built from here with one change each (README.md):
                        Slint's Android backend, whose fields ask the keyboard not to learn
.github/                CI, security and fuzzing workflows, Dependabot, secret scanning paths
deny.toml               cargo-deny: every advisory fails the check unless listed with its reason
.gitleaks.toml          gitleaks: the test keys and test values the repository keeps on purpose
```

### 2.1 `crates/core` (vault-core)

The security-critical heart. It owns all key material and has **no UI, no network, no
filesystem policy** beyond atomic writes.

| Module | What it does |
|---|---|
| `aead.rs` | Key-committing XChaCha20-Poly1305 (`seal` / `open`) |
| `kdf.rs` | Password hashing (Argon2id; scrypt and PBKDF2-SHA-256 by choice) with a hard floor and ceiling on parameters |
| `keys.rs` | Secret Key, recovery parts (and the Recovery Key of older kits), keyfile, vault key, subkeys, device KEK |
| `kit_password.rs` | The password of the emergency kit's PDFs (four words), derived from the vault key, the Secret Key and the kit (CRYPTO.md §3.10) |
| `guard.rs` | Item guard: which items ask for a second check, and the guard key wrapped by the PIN or password |
| `encoding.rs` | Crockford Base32 for the printed keys |
| `padding.rs` | Length-hiding padding for items and body |
| `format.rs` | File envelope, header, body, and the layouts of older versions |
| `vault.rs` | `Vault`: open, create, items, folders, settings, history, save; renewing the vault key and taking a renewed one (`renew_key`, `adopt_key`, CRYPTO.md §3.8) |
| `vault/merge.rs` | Folding another device's copy into this one (`Vault::merge`; `merge_from` for a copy found under a device's name, which the sync rounds use; SYNC.md §4) |
| `sync.rs` | What sync needs from the vault: writers, tombstones, devices, revisions |
| `item.rs` | `ItemData`, `ItemSummary`, folders, recovery codes, password history, attachments |
| `card.rs` | Payment cards: Luhn, brand detection, expiry, masking |
| `ssh.rs` | SSH keys: a new Ed25519 key, a key brought in read in any common form (OpenSSH's, a passphrase asked once; PKCS#8, PKCS#1, SEC1) and kept in OpenSSH's without a passphrase, its public half, fingerprint and type (RustCrypto `ssh-key`); the SSH agent's signatures (`agent_sign`: Ed25519, ECDSA P-256/P-384, RSA with SHA-2) and the key blob it lists |
| `generator.rs` | Passwords, passphrases (uniform sampling, word lists) and usernames (two words, an email tagged after a `+`, a name at a catch-all domain) |
| `health.rs` | Strength (zxcvbn), reuse, age, what a login's site offers that it doesn't use (`Advice`), the k-anonymous breach query, and the one-factor floor (`holds_alone`, CRYPTO.md §3.3.1) |
| `site_lists.rs` | The sites that offer one-time codes and those that take passkeys, lists bundled in `data/` (2FA Directory, Passkeys Directory) and compared offline; websites saved without HTTPS |
| `attempts.rs` | Unlock attempts on one device: the count, the growing wait, its two clocks (THREAT_MODEL.md) |
| `sealed_export.rs` | An export sealed under a password of its own (`.vaultx`) |
| `drop_box.rs` | Logins saved from the browser while locked, sealed to a public key only the open vault reads |
| `kept_key.rs` | The Secret Key as a Windows device keeps it: sealed under a random key the TPM wraps (CRYPTO.md §2.2.1) |
| `locked_fill.rs` | Logins the extension may fill while the vault is locked (CRYPTO.md §3.4) |
| `passkey.rs` | Passkeys in logins: ES256 keys, authenticator data, attestation, signatures (CRYPTO.md §3.7) |
| `hardware_key.rs` | A hardware key as a factor (designed, CRYPTO.md §3.13): its slot sealing the vault's hardware factor, and the factor's key; not in the file format yet |
| `totp.rs` | RFC 6238 one-time codes, RFC 4226 counter-based ones (`otpauth://hotp/`), five-character codes (`encoder=steam`), links made from an export's parts (`LinkParts`) |
| `storage.rs` | Atomic file writes with a `.bak` copy |
| `random.rs` | OS randomness |
| `memory.rs` | Keys in memory: the `KeyShield` a program installs (the vault key, the guard key, the Secret Key and the keyfile kept encrypted between uses), and `clear_stack`, called after a key is hashed and when the vault locks |

### 2.2 `crates/platform` (vault-platform)

Everything that touches the operating system: Secret Key in the credential store
(`secret_store.rs`; the Android Keystore on a phone), on Windows under a key in the TPM where
there is one (`tpm.rs`: RSA-2048 made in the chip through NCrypt's Platform Crypto Provider,
not exportable, CRYPTO.md §2.2.1; the plain form kept only without a TPM, an older one moved
under the chip after an unlock, checked first; the chip behind `KeyWrapper`, and the tests'
stand-in `MemoryChip` behind the `test-chip` feature, so the apps' tests make no keys in the
real chip), per-device state, rollback detection, the newest version of the apps that
opened each vault here and unlock attempts (`device.rs`), clipboard that stays out of history (`clipboard.rs`, `clipboard_android.rs`),
screen-capture blocking (`screen.rs`), typed secrets (`secure_buffer.rs`) kept in one area
locked in RAM, and the Windows key shield (`secure_memory.rs`), the global allocator that wipes
every block it frees (`wiping_alloc.rs`),
the leak check and the leak watch's sealed memory (`leak_check.rs`),
Windows Hello quick unlock (`quick_unlock.rs`), the master password typed on a secure desktop
of its own (`secure_desktop.rs`), the security log of each vault on this device
(`security_log.rs`, sealed to a key only the open vault reads), DPAPI (`dpapi.rs`), keyfiles on disk
(`keyfile.rs`), the person's language (`locale.rs`), installed browsers and the default one (`browsers.rs`), the
extension's local pipe and host registration (`browser_link.rs`), the SSH agent's protocol and
pipe (`ssh_agent.rs`), auto-type into the window behind the app (`autotype.rs`, `SendInput`
behind a `Desktop` trait), a hardware key asked through `webauthn.dll` behind a trait with a
stand-in (`hardware_key.rs`; designed, only the API version read so far), the extension's own folder
that the browser loads it from, kept as the app wrote it (`extension_folder.rs`), where its
files come from: a GitHub release's zip read strictly, a folder of the person's, or the copy
built into the app (`extension_source.rs`), the
emergency kit PDF
(`kit_pdf.rs`, with a QR code for each key; a kit saved as a file is encrypted by the PDF's own
AES-256 password protection, `kit_pdf/protect.rs`), a recovery part hidden in a picture (`part_picture.rs`), opt-in website icons
fetched directly from each site with a sealed cache (`website_icons.rs`), the `.vault` file
type for this user on Windows (icon, opens in the app; `file_types.rs`), starting at sign-in
(`autostart.rs`, the user's `Run` key), one running copy of the desktop app
(`single_instance.rs`, and `--lock` passed to it), shortcuts from any program (`hotkeys.rs`),
the `vault` command's requests to the open app (`cli_link.rs`, on the browser link's pipe code), the registry calls these share (`registry.rs`), locking with Windows
(`session_watch.rs`: session lock, user switch, sign-out, sleep), the process's own hardening
(`process.rs`: DLLs from System32 only), file helpers and
secure wiping (`files.rs`), app paths (`paths.rs`), the apps' updates from GitHub's releases
(`updates.rs`: the release list, taken only with its manifest signed, and the phone's package
and the extension's zip checked against that manifest; `self_update.rs`: the desktop app's
program downloaded, checked against that manifest and swapped in place of the running one,
undone if that fails; `os_notice.rs`: a notification of Windows' own, counts only), sync targets and one sync
round (`sync.rs`: the folder target, fetch, merge, this device joining the vault;
`sync/server.rs` the sync server client, `sync/webdav.rs` WebDAV, `sync/http.rs` which
addresses are allowed). The server key and the WebDAV password live in the credential store
(`secret_store.rs`), the place in device state (`SyncTo`).

### 2.3 `crates/import` (vault-import)

One entry point, `vault_import::import(bytes, format, password, keyfile)`, reads every
supported file. Readers are named by format, never by product:

- `json.rs` — unencrypted JSON exports in the common layout.
- `csv_import.rs` — CSV from browsers and managers, detected by header aliases.
- `kdbx.rs` — KeePass-format databases (with KeePassXC's passkeys, extra websites, files and
  history); `kdbx_export.rs` writes one (KDBX 4, CRYPTO.md §3.12).
- `cxf.rs` — the FIDO Alliance's Credential Exchange Format (CXF 1.0), read and written.
- `authenticator.rs` — authenticator apps' keys: `otpauth://` link lists, the
  `otpauth-migration://` transfer payload (a protocol buffer read by hand), the apps' JSON
  exports by shape.
- `managers.rs` — other managers' own JSON shapes, told by their keys.
- `browser.rs` — reads a browser's own store directly on Windows (Chromium via DPAPI +
  AES-GCM, Firefox via NSS `key4.db`), only on an explicit user action. DPAPI is passed in by
  the caller so this crate stays free of `unsafe`.
- `export.rs` — JSON and CSV exports, and the JSON export sealed under a password.
- `lib.rs` — `ImportReport`, review rows, duplicate detection, `FolderTarget`, `Source` list.

Importers only produce `ItemData`; they never touch keys.

### 2.4 `apps/cli` (vault-cli)

`vault init | info | list | add | show | edit | rm | generate | totp | passwd | renew-key |
recover | kit | part-picture | forget | keyfile | import | sync | run | inject | git-credential`
(`sync --take-new-key` takes a vault key renewed on another device; `kit --pdf` saves the kit
protected by its PDF password, `kit --pdf-password` shows that password; `run`, `inject` and
`git-credential` ask the open desktop app instead of opening the vault, each use approved there,
`src/through_app.rs`). Same vault and device state as the desktop app. `tests/cli.rs` runs the binary, including sync through a running server.

### 2.4.1 `crates/browser` (vault-browser) and `apps/extension/`

The extension holds no secrets. `origin.rs` decides which saved website belongs to which page
(exact scheme, host and port; https only) and which site a page may use passkeys for,
`lookalike.rs` which saved site a page only looks like (from the vault's own sites, offline)
and how a host is shown (punycode when it mixes scripts), `kit.rs` the emergency kit's keys
recognised in what a page sends, `rules.rs` the person's rules per site (never save, no card,
never fill, no passkeys, the payment frames allowed; kept in the device state),
`resources.rs` where a site changes its password and its password rules (the pinned
`password-manager-resources` lists in `data/`, MIT), `protocol.rs` is the JSON it exchanges with the
app (and the oldest extension the app answers, `MIN_EXTENSION_VERSION`: every sealed request
names the extension's version), `pairing.rs` is the connection key and the sealing of every
request and answer, `service.rs` answers
from an open vault (with the item lock as a `Gate`), `host.rs` is the native host's relay
between the browser and the app's pipe, run by the desktop app's own executable when a browser
starts it with the extension's origin (`apps/desktop/src/main.rs`). In `apps/extension/`,
`popup.js` is the extension's window (its views and their rules in `popup/`), `link.js` its connection key (agreed with the app by
ECDH), the sealing of each request and the opening of each answer, and
`fill.js` the function that types a login into a page, `card-fill.js` and `cards.js` the
payment fields and the cards typed into them (another site's frames only once approved),
`signals.js` a site's WebAuthn Signal API calls, `content.js` + `fields.js` the
content script (sign-in fields, submitted forms, a password pasted, the warnings), `kit.js` the
emergency kit's keys refused in every page (every frame, at `document_start`), `agent.js`
whether an AI agent or a program drives the browser (then nothing is shown in pages),
`inline.html`/`inline.js` the frame shown under a field (and its warnings), `background.js`
the worker between them and the app, `generator.js` the
reading of a site's password rules, `app.js` the native messaging calls, `update.js` the
extension reloading itself into the newer version the app wrote into its folder. Passkeys:
`passkeys-page.js` (in the page's own world, in front of `navigator.credentials`), `passkeys.js`
(the relay), `passkey-worker.js` (the worker's side) and `passkey.html`/`passkey.js` (the window
where the person chooses). See
[apps/extension/README.md](apps/extension/README.md). Tests: `cargo test -p vault-browser` and
`node --test apps/extension/test/fill.test.mjs apps/extension/test/fields.test.mjs apps/extension/test/background.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs apps/extension/test/popup.test.mjs apps/extension/test/update.test.mjs apps/extension/test/kit.test.mjs apps/extension/test/cards.test.mjs`.

Rules for this part: UI in a page only as the extension's own frame (`inline.html`, at the
session's address `chrome.runtime.getURL` gives), never as page DOM, and every click there goes
through the visibility check; nothing in pages while an agent drives the browser; no new permission without
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
| `src/controller/extension.rs` | The extension: its files built into the app (`build.rs`), a newer release's taken when the app looks for updates, or the person's folder; Settings → Browser extension → Add to a browser; the folder kept as written while the link runs; the version the `status` and `logins` answers name |
| `src/controller/generated.rs` | History of generated passwords (sealed per vault on this computer) |
| `src/controller/drop_box.rs` | Logins the browser saved while the vault was locked, added at the next unlock |
| `src/controller/syncing.rs` | Sync through a folder, the server or WebDAV: Settings → Sync (join, add a device with a QR code, remove one), rounds at unlock, after saves, every 5 minutes, on the server's news and on demand (the target read and written off the UI thread) |
| `src/controller/locked_fill.rs` | Filling from the browser while the vault is locked |
| `src/controller/attachments.rs` | Files attached to items and SSH key items in the editor and on the item page |
| `src/controller/ssh_agent.rs` | The SSH agent: Settings → Security, its pipe, every signature approved in a dialog ("don't ask again" 5 minutes for one key and program), the item lock respected |
| `src/controller/autotype.rs` | Auto-type: the window behind the app, its title and a 3-second countdown, then username, Tab, password, Enter while that window has the keyboard |
| `src/controller/cli_link.rs` | The `vault` command's requests (`run`, `inject`, `git-credential`): heard while Settings allows it, each shown and answered only once allowed |
| `src/controller/health_ignored.rs` | Password health's ignored warnings, kept per vault on this computer in a file sealed with the vault key |
| `src/controller/watch.rs` | The leak watch: every login checked once a day while open, new leaks told and shown on Password health |
| `src/controller/passwords.rs` | A new password's review: the one-factor floor's warnings, the breach check of a new master password, the protected export's refusal (`ui/review.slint`) |
| `src/controller/attempts.rs` | Unlock attempts: counted in the device state, the wait enforced and counted down, told once at the next unlock |
| `src/controller/updates.rs` | Updates: GitHub's newest release, looked for every hour (Settings → About → Look for updates by itself) and on Check for updates; a newer one installs itself (Install updates by itself, or Install now: `vault_platform::self_update`), each step shown in the title bar and About, then Restart now or Later |
| `src/controller/toolbar.rs` | The title bar's toolbar: the sidebar hidden or shown (device setting), search from anywhere (Ctrl+F), the vault's name and its icon on this computer (device state), the alerts (marked as read for a week, by count, in device state) and Windows' own notification of new leaks |
| `src/controller/security.rs` | The security log (what is recorded, Settings → Security → Security log) and the unlock screen's secure desktop |
| `src/controller/site_rules.rs` | Settings → Browser extension → Site rules |
| `src/controller/change.rs` | "Change password": a strong password made for a login, offered by the extension on its site's change page |
| `src/controller/confirm.rs` | The yes/no question before replacing a saved password, removing a passkey, a file or a hidden field, clearing a history |
| `src/controller/weigh.rs` | A new password weighed: reused in the vault, or known leaked (leak watch on) |
| `src/controller/signals.rs` | What sites said of passkeys (the Signal API), for the person to decide on the item page |
| `src/tray.rs` | The notification area icon (tray mode) and its menu window (`ui/tray.slint`) |
| `src/i18n.rs` | The app's language: picks a compiled-in catalogue from `translations/` |
| `src/controller/navigation.rs` | Back/forward history, mouse buttons 4/5 and keyboard shortcuts (raw window events), the shortcuts from any program (`apply_hotkeys`), hiding what is shown when the window loses the focus |
| `src/view.rs` | Pure presentation rules (unit-tested): filters, tints, crack times, dates |
| `src/qr.rs` | A QR code read from a picture file (Authenticator → From a QR picture…; `rqrr`) |
| `src/sketch.rs` | Hand-drawn strokes generated in Rust |
| `src/tests.rs` | Headless end-to-end test of the whole app |
| `examples/screenshots.rs` | Renders every screen to PNG for visual review |
| `ui/Cargo.toml`, `ui/lib.rs`, `ui/build.rs` | `vault-desktop-ui`: the generated Slint code as a crate of its own, so controller changes don't recompile it (re-exported as `vault_desktop::ui`) |
| `ui/theme.slint` | Design tokens, `Secrets` bridge for secure fields |
| `ui/model.slint` | Structs shared with Rust and **every user-facing message** |
| `ui/widgets.slint` | Buttons, fields, secure field, dropdown, slider… |
| `ui/icons.slint` | Field icons (Lucide), card network marks, import source icons |
| `ui/dialogs.slint` | Dialogs over the whole window (`Modal`, `FolderDialog`, `PartsUsedDialog`, `LargeTypeDialog`) |
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
look right in both apps' screenshots. The controller's submodules are `attempts.rs` (failed
unlocks, the wait, removing the copy after 10 when chosen), `passwords.rs` (a new master
password's review, the export's floor), `syncing.rs` (sync on
the phone, updates from the server), `settings.rs` (vaults on the phone, fingerprint unlock,
import, "Check this password"), `filling.rs` (autofill from the open vault),
`attachments.rs` (files and SSH keys), `preview.rs` (previews of attached pictures, text and
PDFs), `icons.rs` (website icons and the preset `glyph:` icons), `each_use.rs` (every use of a
secret asks the phone's check first: a fingerprint, a face or the screen lock, else the item
lock's PIN), `folders.rs`, `health.rs`
(password health), `generated.rs` (the generator's sealed history) and `passkeys.rs` (passkeys
for other apps from the open vault), `security.rs` (the security log on the phone). `prefs.rs` is the
phone's own settings file, `bio.rs` a vault's fingerprint unlock file, `autofill.rs` which
logins belong to the app or site asking (and the drop box for logins saved while locked),
`passkeys.rs` which passkeys answer a browser's page or an app through Android's Credential
Manager and what they answer, and
`system.rs` the `System` trait: what only Android does, implemented by the Android crate. The controller reaches the system only through
`src/platform.rs` (the platform crate, or `src/platform/web.rs` in a browser), so the same
code also runs as the web preview in `apps/mobile-web` (build: `apps/mobile-web/build.ps1`).

`apps/mobile-android` is the APK: `src/lib.rs` starts Slint's Android backend with the same
screens, `src/shell.rs` talks to the activity over JNI, `src/system.rs` is the `System` the
controller asks, `src/autofill.rs` answers autofill and `src/passkeys.rs` the passkey
provider. The Java side is in
`java/org/passwordvault/phone/`: `VaultActivity` (Android's `NativeActivity` plus the file
picker, "save as", Back, screenshots, updates), `Biometrics` (the Keystore key behind the
fingerprint), `VaultAutofillService`, `AutofillActivity`, `Autofill`, `Fields` and `Place`
(autofill, and who would receive a login), `VaultCredentialService`, `PasskeyActivity` and
`Passkeys` (passkeys through the Credential Manager, Android 14+), `PdfPreview` and `Wipe`
(previews of attached PDFs), `Updates` and `InstallReceiver` (updates), `Shield` (what every
window of the app gets: other apps' overlays hidden, accessibility tools only). `res/` holds
the launcher icon and the words and layouts of autofill and the passkey provider. Build:
`apps/mobile-android/build.ps1` (docs/MOBILE.md §7.2), which runs `check-library.ps1` (the
native library loads on Android 12, the oldest it installs on) and `check-manifest.ps1` (the
built APK's manifest keeps its protections and opens nothing else); the release runs both.

### 2.7 `crates/sync-wire` and `apps/server`

`vault-sync-wire` is the request protocol shared by clients and server (signed messages,
enrollment, invites, JSON bodies), and the reading of the project's releases (`releases.rs`):
GitHub's answer, the release manifest and its minisign signature checked against the two
embedded keys (`RELEASE_KEYS`, CRYPTO.md §9), the version binding, and the check of a sync
server's update the phone makes itself. `vault-server` (AGPL-3.0) stores sealed copies, device
public keys and invite digests as plain files (`store.rs`) behind the API in `api.rs`
(signature, time and nonce checks, limits), served by `connections.rs` (open connections
capped, header and write time limits), with an HTTPS of its own for a home network
(`tls.rs`), and can follow the project's releases to hand new phone apps to the phones
(`updates.rs`, `--app-updates`; the release list is read by `vault_sync_wire::releases`, and
the manifest and its signature kept and handed on unchanged).
Released as binaries and as an image on ghcr.io (`release.Dockerfile`). Tests:
`cargo test -p vault-server` runs a real server with two devices. Setup:
[docs/SERVER.md](docs/SERVER.md); Docker files next to the code.

## 3. Build, run, test

The toolchain comes from `rust-toolchain.toml`. On Windows, if `cargo` is not on `PATH`, prefix
the shell with `$env:Path = "$HOME\.cargo\bin;$env:Path"` (PowerShell). Windows builds get
Control Flow Guard from `.cargo/config.toml`; a `RUSTFLAGS` variable replaces those flags, so
don't set one for a Windows build (the release refuses an exe without it,
`apps/desktop/check-exe.ps1`). Each checkout, git worktrees included, builds in its own build
folder: never point `CARGO_TARGET_DIR` or `--target-dir` at another checkout's `target/`. Cargo
names a workspace's own crates by their path inside the workspace, so two checkouts sharing one
folder overwrite each other's builds (a stale build script, the other's test binaries).

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

All four must pass before a commit. Clippy runs with `-D warnings`. `cargo deny check
advisories` must pass too: a dependency with a known vulnerability is updated (or replaced),
not ignored. CI (`.github/workflows/ci.yml`, `security.yml`) runs the same checks on every
push. A key or password a test needs is made for it and kept in a test path that
`.gitleaks.toml` and `.github/secret_scanning.yml` allow (`tests/`, `tests.rs`,
`crates/core/testdata/`).

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
node --test apps/extension/test/fill.test.mjs apps/extension/test/fields.test.mjs apps/extension/test/background.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs apps/extension/test/popup.test.mjs apps/extension/test/update.test.mjs apps/extension/test/kit.test.mjs apps/extension/test/cards.test.mjs
```

Fuzzing needs a nightly toolchain and `cargo install cargo-fuzz` (on Windows, see
[fuzz/README.md](fuzz/README.md)): `cd fuzz`, then
`cargo +nightly fuzz run --debug-assertions <target> corpus/<target> seeds/<target>`.

The APK and the browser build have their own scripts, `apps/mobile-android/build.ps1` and
`apps/mobile-web/build.ps1` (what each needs is at its top; docs/MOBILE.md §7).

### 3.1 Tests that matter

- `crates/core/tests/format_v*.rs` — known-answer tests: each committed fixture in
  `crates/core/tests/fixtures/` must keep opening forever. Never regenerate an old fixture.
- `crates/core/tests/vault.rs`, `robustness.rs` — tampering, swapping, rollback, downgrade,
  malformed input. `sync.rs` — the merge, with a property test over three devices;
  `hostile_copies.rs` — copies a hostile sync place could hand over (every byte altered,
  every length cut, garbage, another vault's, rollbacks, forks, another device's name), each
  refused with the vault left exactly as it was; `recovery_parts.rs` — the kit's three parts;
  `renew.rs` — a renewed vault key, what older copies open afterwards and other devices
  taking the new key.
- `crates/platform/src/sync/hostile.rs`, `crates/platform/tests/hostile_sync.rs` — the HTTP
  targets against a hostile server written in the test (lies, redirects, answers that never
  end, WebDAV listings that disagree, writes that fail half-way) and rounds against lying
  places; `apps/cli/tests/cli.rs` — the whole round through `vault sync` against a hostile
  folder, a tampered `vault-server` store and a lying server, the vault file compared byte for
  byte (SYNC.md §9, THREAT_MODEL §2.1).
- `apps/desktop/src/tests.rs` — the whole app flow headless (onboarding, unlock, items, cards,
  folders, history, health, generator, import, export, kit, second vault). Slow work runs inline
  there (`Runner::Inline`); dialogs and network are skipped.
- `apps/desktop/tests/memory.rs` — a running copy of the app (a process of its own, protected
  as in a release build) opens a vault with a keyfile, shows and hides a guarded item's
  password and the kit, and locks; its whole memory is read from outside at each step. Keys
  are never found in the clear, what is on screen only while it is, and after the lock no
  piece of any secret (UTF-8, UTF-16, 16-byte pieces). Windows only; also a step of its own
  in CI.
- `apps/mobile/src/tests.rs` — the phone app headless, including sync against a running server.
- `apps/server/tests/sync.rs` — two devices through a real server; strangers, replays and
  altered requests refused.
- `fuzz/` — cargo-fuzz targets for what the apps read from someone else (a copy merged into an
  open vault, the vault header, the sync protocol both ways, the extension's messages and its
  release zip, imports, invite lines, `otpauth://` links, the part C picture), each run for
  five minutes every day by `.github/workflows/fuzz.yml`. A finding becomes a regression test
  in its crate ([fuzz/README.md](fuzz/README.md)).

## 4. Rules

### 4.1 Security rules (non-negotiable)

1. **No home-made cryptography.** Only the primitives in [docs/spec/CRYPTO.md](docs/spec/CRYPTO.md),
   from audited crates. Any change to bytes on disk follows §5.1.
2. **Secrets are wiped.** Keys and decrypted data live in `Zeroizing` / `ZeroizeOnDrop` types.
   Serialization buffers are sized exactly (no reallocation copies). `Debug` of secret types is
   redacted. Never log, print, or put a secret in an error message. Every program installs
   `vault_platform::wiping_alloc::WipingAllocator` as its global allocator, and the desktop app
   and the CLI the key shield (`vault_platform::secure_memory::install_key_shield`) first thing
   in `main`.
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
   (sealed copies only), the apps' updates (GitHub's release list, one anonymous request:
   looked at by the desktop and the phone every hour while they run and on the **Check for
   updates** button, a setting on by default so a fix reaches everyone, told on each app's
   first screen with its switch (docs/PRIVACY.md); the phone may take them from its sync
   server instead; `vault_platform::updates`), with the desktop app taking the browser
   extension's zip of that release when it is newer than the extension it has (unless the
   person chose a folder of theirs), checked against the size and SHA-256 the release's
   signed manifest lists (`vault_platform::extension_source`). Every updater fails closed: a
   release counts only with its manifest signed by one of `RELEASE_KEYS`
   (`vault_sync_wire::releases`), and a sync server following
   the releases (`--app-updates`, its owner's choice; `apps/server/src/updates.rs`). Nothing is sent to a
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
- Dependabot's pull requests are never merged as they are: the update is redone in a `Build:`
  commit of the maintainer's and the pull request closed, so every commit on `main` has the one
  author.
- Releases: bump the version in every app (`.github/workflows/release.yml` lists the files),
  add the phone's notes for it (`apps/mobile/ui/app.slint`, with its pt_BR translation) and
  write its section in `CHANGELOG.md`; the push to `main` builds, signs and publishes
  `v<version>` (the desktop exe, the CLI, the server for Linux and Windows and its image on
  ghcr.io, the APK, the extension, and `manifest.json` with its signature), once the
  maintainer approves the run's two signing jobs (the APK's and the manifest's,
  docs/CODE_SIGNING.md).
- The manifest keys are in `RELEASE_KEYS` (`crates/sync-wire/src/releases.rs`) and pinned by
  id in its test: changing them is a release of its own, signed with a key the apps already
  take (docs/CODE_SIGNING.md, "Changing the keys"). A test never uses them: tests sign with
  keys of their own (`releases::testing`, the `test-signing` feature).

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
- A `Flickable` takes any drag that moves 8 px along its axis in the first half second, even
  from a control under the finger. A control dragged sideways (the `Slider`) sets
  `Gesture.holding` while held, and the phone's pages turn their scrolling and swiping off
  while it is set.
- Wrapped text that an `if` or a `for` shows inside a card is measured as one line, so the card
  comes out short and the text runs out of it. Write such blocks out, or show them through the
  phone's `Fold` (a height limit instead of `if`).
- A `Timer` that was never started ignores `restart()`. Set `running: true` first (then
  `restart()` to count again from now), and stop it with `running = false`.

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
