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
- ✅ Generator (characters / words), settings (auto-lock, clipboard timeout, change master
  password, show Secret Key, new Recovery Key — all re-verify the master password)
- ✅ Auto-lock, screen-capture blocking, every UI string through `@tr()`
- ✅ Headless end-to-end test of the whole app flow (Slint testing backend)
- ⬜ Visual review and polish (built without screenshots), dark theme, accessibility pass
- ⬜ Windows Hello quick unlock (TPM-backed key slot), YubiKey (FIDO2 `hmac-secret`) slot
- ⬜ Emergency kit as a printable PDF
- ⬜ `pt-BR` translation file
- ⬜ Custom fields editing, attachments, tags/folders
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
