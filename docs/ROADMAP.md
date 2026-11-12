# Roadmap

> Status: **draft**. Security first, convenience second. No phase holds real passwords before Phase 7.

## Phase 0: Research and specification _(current)_
- [x] Initial threat model
- [x] Proposed architecture
- [ ] Vault format specification + test vectors
- [ ] Cryptographic specification (KDF, AEAD, key commitment, key hierarchy)
- [x] License: GPL-3.0 (clients) / AGPL-3.0 (server)
- [x] Slint prototype: unlock screen with a secure password field + vault item list
      (`prototypes/slint-ui`), design and secret handling validated on Windows
- [ ] Prototype follow-ups: dead keys/IME, screen reader, Android build
- [ ] Confirm i18n workflow with Slint translations
- [ ] Learn Rust (the Rust Book + exercises on the core itself)

## Phase 1: Rust core + CLI
- Vault: create, open, add/edit/remove items, change master password
- Secret Key, calibrated Argon2id, emergency kit generation
- Password and passphrase generator (EFF word list)
- TOTP
- Fuzzing, tests, dependency auditing

## Phase 2: Windows desktop app
- Native UI with i18n, auto-lock, secure clipboard, screen-capture exclusion
- Quick unlock: **Windows Hello** (face/fingerprint/PIN via TPM) and **YubiKey**
- Keyfile, re-prompt for critical items
- Import: KeePass, Bitwarden, Chrome/Edge/Firefox, 1Password
- Secure notes and encrypted attachments

## Phase 3: Browser extension
- Chromium (Chrome/Edge) first, Firefox later
- Native Messaging to the desktop app
- Autofill **with confirmation** outside the DOM, strict origin matching
- Offer to save newly detected credentials

## Phase 4: Self-hosted sync
- Rust server as a Docker image + Compose file, OPAQUE, encrypted blobs only
- Reachable only over a private overlay network (e.g. Tailscale), with TLS
- Device enrollment via QR code / Secret Key
- Rollback/fork detection, conflict resolution
- Testing with ZK-AE-Tester

## Phase 5: Android
- Slint Android app (same UI) + Kotlin services calling the Rust core
- Autofill Service + Credential Manager (passwords and **passkeys**)
- Class 3 biometric unlock (face/fingerprint) via StrongBox/Keystore

## Phase 6: Advanced features
- **Secure sharing** of passwords/files: links with the key in the URL fragment, expiration and
  view limits (like Bitwarden Send), plus user-to-user sharing with post-quantum hybrid HPKE
- Passkey storage on desktop
- Health dashboard: weak, reused and breached passwords (HIBP k-anonymity)
- SSH agent
- Shamir-based recovery (emergency kit shares)
- Linux
- Additional translations

## Phase 7: Hardening and audit
- Full threat model review
- Independent external audit
- Only then: migrate real passwords

## Decided NOT to do
- **Custom face recognition**: open-source projects (Howdy, howrs) can be fooled by a photo and
  have no liveness detection. We use the OS's own recognition (Windows Hello with an IR camera,
  Android Class 3 biometrics), which releases hardware-held keys.
- **Server-side recovery**: it would break the zero-knowledge model.
