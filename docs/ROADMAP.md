# Roadmap

> **Alpha.** The Windows desktop app, the browser extension, the Android app and the sync
> server are usable every day, and were built with security first, but nothing has had an
> independent audit yet (Phase 7). Keep a copy of anything you put in it somewhere else.
> The *how* and the detailed state of each piece: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
> ✅ done, 🚧 in progress, ⬜ not started.

## Where each app stands

| App | State |
|---|---|
| Desktop (Windows) | ✅ Alpha: every feature below, in English and (in part) Brazilian Portuguese |
| Browser extension (Chrome, Edge, Firefox) | ✅ Alpha: loaded unpacked (a temporary add-on in Firefox); not in a store yet |
| Android | ✅ Alpha: an APK you build and install yourself; updates from your own server |
| Sync server | ✅ Alpha: Docker, behind Tailscale or with its own HTTPS |
| CLI (`vault`) | 🚧 Works for the basics, behind the apps (see Phase 1) |
| Linux | ⬜ Not built or tested yet, except the server (see Phase 6) |
| Web preview of the phone app | ✅ A demo in a browser page with a made-up vault, not a real client |

## Phase 0: Research and specification ✅
- ✅ Threat model and architecture
- ✅ Cryptographic specification (KDF, AEAD with key commitment, key hierarchy)
- ✅ Vault format specification, with a committed test vault for every version
- ✅ Licences: GPL-3.0 (apps and libraries) / AGPL-3.0 (server)

## Phase 1: Rust core + CLI 🚧
- ✅ Vault: create, open, items, folders, change master password, recovery
- ✅ Secret Key, calibrated Argon2id, emergency kit with three recovery parts
- ✅ Renewing the vault key (new key, Secret Key and kit), so an older copy opens only itself
- ✅ Password and passphrase generator (EFF word list), TOTP and HOTP
- ✅ Property tests and tamper tests; no known vulnerability in any dependency (`cargo deny`)
- ✅ CI on every push: tests, advisories, secret scanning of the history, CodeQL, Scorecard
- ✅ Fuzzing of the file parser, sync copies, the sync protocol, the extension's messages and
  imports, every day in CI; tests against a hostile sync place
- 🚧 **The CLI is unfinished.** It does: `init`, `info`, `list`, `add`, `show`, `edit`, `rm`
  (logins, cards, secure notes), `generate`, `totp`, `passwd`, `renew-key`, `recover`, `kit`,
  `part-picture`, `forget`, `keyfile`, `import` and `sync` (folder, server, WebDAV, invites,
  devices, taking a renewed vault key). It does not yet: make or show SSH key items and attached files, manage folders
  beyond putting an item in one, export, check password health or leaks, set the item lock
  or the unlock protection, or use Windows Hello. Locked items stay locked in it. It was
  only tried on Windows.

## Phase 2: Windows desktop app ✅
- ✅ Native UI with its own title bar, translations, auto-lock, secure clipboard,
  screen-capture exclusion
- ✅ Windows Hello quick unlock; ⬜ hardware keys (YubiKey)
- ✅ Keyfile, item lock (PIN or second password, encrypted)
- ✅ Import from browsers and managers; export (plain or sealed under a password)
- ✅ Logins, cards, secure notes, SSH keys, one-time codes, passkeys, attached files
- ✅ Health page with a k-anonymous leak check and an optional daily leak watch
- 🚧 Brazilian Portuguese (the phone is complete, the desktop is not); ⬜ accessibility pass

## Phase 3: Browser extension 🚧
- ✅ Chromium (Chrome, Edge) with Native Messaging to the desktop app
- ✅ Filling chosen in the extension's own frame, strict origin matching, pairing
- ✅ Offer to save and update logins; one-time codes; fill while locked with Windows Hello
- ✅ Passkeys kept in the vault, made and used by the app, also from the field's suggestions
- ✅ Firefox 153+ (filling from the extension's window, no card in pages); ⬜ signed for
  Firefox, store listings

## Phase 4: Sync ([design](spec/SYNC.md)) ✅
- ✅ Merge in the core (tombstones, per-device writer, unlock and guard revisions)
- ✅ Folder, WebDAV and the self-hosted server (Docker, Tailscale or its own HTTPS, signed
  device requests, connection and upload limits), with a backup place
- ✅ Adding a device with an invite (a link and a QR code, also drawn in the server's
  terminal); removing a lost one; a removed device can join again as a new one
- ✅ Rollback and fork detection per device, both passwords kept on a conflict
- ⬜ Malicious-server test suite, direct PC ↔ phone sync on the same Wi-Fi

## Phase 5: Android ✅
- ✅ Slint Android app with the same design, the Keystore-backed credential store, the
  system's file picker, sync
- ✅ Fingerprint unlock (Class 3, StrongBox where the phone has it), Autofill Service,
  screenshots and the recent apps view kept out, updates from the person's own server
- 🚧 Parity with the desktop (custom fields, nested folders shown as a tree)
- ✅ Passkeys in the phone's browsers and apps (Credential Manager, Android 14+); ⬜ passwords
  through it (autofill serves them)

## Phase 6: Advanced features ⬜
- **Linux.** The core, import, sync and the server are written without Windows in mind,
  and the server already runs on Linux in its Docker image. The desktop app and the CLI
  have never been built there: they need the credential store through Secret Service (the
  `keyring` crate supports it), a local link for the extension in place of the Windows named
  pipe, and an answer for what Windows gives them today (capture exclusion, clipboard
  history exclusion, Windows Hello, DPAPI for browser import and the `.vault` file type).
  Until that work is done and tested, Linux is unsupported.
- **Secure sharing** of passwords and files: links with the key in the URL fragment, expiry
  and view limits, and user-to-user sharing with post-quantum hybrid HPKE
- SSH agent
- macOS (after Linux)
- More translations

## Phase 7: Hardening and audit ⬜
- Full threat model review, fuzzing campaign
- Independent external audit
- A first stable release only after it

## Decided NOT to do
- **Custom face recognition**: open-source projects (Howdy, howrs) can be fooled by a photo and
  have no liveness detection. We use the OS's own recognition (Windows Hello with an IR camera,
  Android Class 3 biometrics), which releases hardware-held keys.
- **Server-side recovery**: it would break the zero-knowledge model.
- **Longer recovery parts, or an extra word per part**: each part already carries 128 random
  bits, and a part alone opens nothing; more length would only make the kit harder to type.
- **A hosted service**: sync goes only through places the person runs or chooses.
