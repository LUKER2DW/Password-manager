# Roadmap

> Security first, convenience second. No phase holds real passwords before Phase 7.
> The *how* and the detailed state of each piece: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
> ✅ done, 🚧 in progress, ⬜ not started.

## Phase 0: Research and specification ✅
- ✅ Threat model and architecture
- ✅ Cryptographic specification (KDF, AEAD with key commitment, key hierarchy)
- ✅ Vault format specification, with a committed test vault for every version
- ✅ Licences: GPL-3.0 (apps and libraries) / AGPL-3.0 (server)
- ✅ A Slint prototype of the secure password field, validated on Windows, then retired

## Phase 1: Rust core + CLI ✅
- ✅ Vault: create, open, items, folders, change master password, recovery
- ✅ Secret Key, calibrated Argon2id, emergency kit
- ✅ Password and passphrase generator (EFF word list), TOTP
- ✅ Property tests and tamper tests; ⬜ fuzzing, dependency auditing in CI

## Phase 2: Windows desktop app 🚧
- ✅ Native UI with translations, auto-lock, secure clipboard, screen-capture exclusion
- ✅ Windows Hello quick unlock; ⬜ YubiKey
- ✅ Keyfile, item lock (PIN or second password, encrypted)
- ✅ Import from browsers and managers; export
- ✅ Cards, secure notes, SSH keys, one-time codes, attached files
- ✅ Health page with a k-anonymous leak check
- 🚧 Brazilian Portuguese; ⬜ accessibility pass

## Phase 3: Browser extension 🚧
- ✅ Chromium (Chrome, Edge) with Native Messaging to the desktop app
- ✅ Filling chosen in the extension's own frame, strict origin matching, pairing
- ✅ Offer to save and update logins; one-time codes; fill while locked with Windows Hello
- ⬜ Checked by hand in each browser, Firefox, store listing

## Phase 4: Sync ([design](spec/SYNC.md)) 🚧
- ✅ Merge in the core (format v7: tombstones, per-device writer, unlock and guard revisions)
- ✅ Folder, WebDAV and the self-hosted server (Docker, Tailscale or its own HTTPS, signed
  device requests), with a backup place
- ✅ Adding a device with an invite (QR code or a `vaultsync:` line); removing a lost one
- ✅ Rollback and fork detection per device, both passwords kept on a conflict
- ⬜ Malicious-server test suite, direct PC ↔ phone sync on the same Wi-Fi

## Phase 5: Android 🚧
- ✅ Slint Android app with the same screens, the Keystore-backed credential store, the
  system's file picker, sync
- ⬜ Biometric unlock (Class 3, StrongBox), Autofill Service, Credential Manager (passwords and
  passkeys), `FLAG_SECURE`, in-app updates from the person's own server

## Phase 6: Advanced features ⬜
- **Secure sharing** of passwords and files: links with the key in the URL fragment, expiry
  and view limits, and user-to-user sharing with post-quantum hybrid HPKE
- Passkey storage on the desktop
- SSH agent
- Linux
- More translations

## Phase 7: Hardening and audit ⬜
- Full threat model review
- Independent external audit
- Only then: migrate real passwords

## Decided NOT to do
- **Custom face recognition**: open-source projects (Howdy, howrs) can be fooled by a photo and
  have no liveness detection. We use the OS's own recognition (Windows Hello with an IR camera,
  Android Class 3 biometrics), which releases hardware-held keys.
- **Server-side recovery**: it would break the zero-knowledge model.
- **Longer recovery parts, or an extra word per part**: each part already carries 128 random
  bits, and a part alone opens nothing; more length would only make the kit harder to type.
