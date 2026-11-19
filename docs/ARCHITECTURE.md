# Architecture (proposal)

> Status: **draft** (research phase). Decisions marked _Proposal_ will be validated with
> prototypes. See also [THREAT_MODEL.md](THREAT_MODEL.md) and [ROADMAP.md](ROADMAP.md).

## 1. Overview

```
                    ┌──────────────────────────────────────────┐
                    │           Rust core (library)            │
                    │  crypto · vault format · sync · TOTP     │
                    │  import/export · generator · zeroize     │
                    └───────┬──────────────┬──────────────┬────┘
                            │              │              │ UniFFI
                    ┌───────▼─────┐  ┌─────▼─────┐  ┌─────▼──────────────┐
                    │ Desktop     │  │ CLI       │  │ Android            │
                    │ Slint       │  │ (Rust)    │  │ Slint UI +         │
                    │ (native)    │  └───────────┘  │ Kotlin services:   │
                    │ Windows /   │                 │ Autofill Service + │
                    │ Linux       │                 │ Credential Manager │
                    └──────┬──────┘                 └────────────────────┘
          Native Messaging │ (stdio, local only)
                    ┌──────▼──────────────┐       ┌──────────────────────────┐
                    │ Browser extension   │       │ Self-hosted sync server  │
                    │ (TS, no secrets,    │       │ (Rust), stores only      │
                    │ asks the desktop)   │       │ encrypted blobs          │
                    └─────────────────────┘       └──────────────────────────┘
```

**Core rule:** all cryptography lives **only** in the Rust core. UIs, the extension and the server
never implement crypto themselves.

## 2. Key hierarchy

```
Master password ──► Argon2id(salt, params ≥ floor) ──┐
                                                     ├─► HKDF ──► Key Encryption Key (KEK)
Secret Key (128 bits) ───────────────────────────────┤
Hardware key (hmac-secret) [optional] ───────────────┤
Keyfile [optional] ──────────────────────────────────┘
                                                             │ unwraps (AEAD)
                                                             ▼
                                                 Vault Key (256 bits, random)
                                                             │ HKDF per purpose
                       ┌───────────────────┬─────────────────┴──┬─────────────────────┐
                       ▼                   ▼                    ▼                     ▼
                Item keys           Index/metadata        Vault integrity        X25519 + ML-KEM
                (one per item)      key                   key (manifest)         key pair (sharing)
```

- **Random Vault Key**: changing the master password only re-wraps this key (fast, no re-encryption).
- **Secret Key** combined with the password (1Password's "2SKD" model): even a mediocre master
  password becomes uncrackable offline.
- **Quick unlock** is another wrapping of the same Vault Key, done by a hardware-held key:
  - Windows ✅: Windows Hello (IR face, fingerprint or PIN), key in the TPM; modeled on KeePassXC's
    Quick Unlock (`crates/platform/src/quick_unlock.rs`, spec in [CRYPTO.md §3.1](spec/CRYPTO.md)).
  - Android: Keystore/StrongBox + `BiometricPrompt` Class 3.
  - Any platform: YubiKey touch (`hmac-secret`).
  - Policy: the master password is asked every 14 days; changing it revokes every device unlock;
    failed attempts are rate-limited by Windows Hello / the TPM itself. Planned: optional
    "master password after every restart".
- **Emergency kit**: printable PDF with the Secret Key, a QR code and instructions. Optionally a
  separate **recovery key** that wraps the Vault Key, which can be split with Shamir's Secret
  Sharing (e.g. 2 of 3 shares kept in different places).

## 3. Primitives (_Proposal_)

| Purpose | Choice | Notes |
|---|---|---|
| Password KDF | **Argon2id** | Calibrated per device (~1 s; hundreds of MiB on desktop). Hard-coded floor, well above the OWASP server-side minimum. |
| Subkey derivation | **HKDF-SHA-256** | Domain separation by label |
| Encryption | **XChaCha20-Poly1305** | Random 192-bit nonces are safe; alternative AES-256-GCM-SIV |
| Key commitment | TBD | Avoid partitioning-oracle attacks on non-committing AEADs |
| Sharing | **HPKE** with hybrid **X25519 + ML-KEM-768** KEM | Resists quantum "harvest now, decrypt later" |
| Server authentication | **OPAQUE** (PAKE) | The server never sees the password or a crackable verifier |
| Randomness | OS CSPRNG (`getrandom`) | |
| Memory | `zeroize`, `secrecy`, `VirtualLock`/`mlock` | |

Candidate libraries: the **RustCrypto** ecosystem (`argon2`, `chacha20poly1305`, `hkdf`,
`x25519-dalek`, `ml-kem`), `opaque-ke`, `hpke`. The audit status of each crate is still being researched.

## 4. Vault format (_Proposal_, to be specified)

- **Header** (plaintext but **authenticated** as AAD): magic, version, KDF parameters, salts,
  wrapped keys (password, hardware, recovery).
- **Items**: each encrypted with its own key, AAD = `vault_id ‖ item_id ‖ version`.
- **Manifest**: list of (item_id, version, hash), authenticated with the integrity key. It detects
  removal, swapping, reordering and **rollback** of items.
- **Padding** to fixed size buckets to hide each item's real size.
- **Atomic writes** plus version history so data is never corrupted or lost.
- A public specification in `docs/spec/` (to be written), with test vectors.

## 5. Browser and autofill

- WebExtension (`extension/`, Manifest V3) with **no secrets and no crypto**, in plain
  JavaScript with no build step and no packages: what is reviewed is what the browser runs. It
  talks to the desktop app over **Native Messaging** (local process, no network).
- Path of a request: extension window → native host (`vault-browser-host`, started by the
  browser, accepts only our extension id) → named pipe of the signed-in user → desktop app.
  The app and the host each check the other end is the program installed next to them. The
  link is off until turned on in Settings.
- A content script on https pages (top frame) notices sign-in fields and submitted forms; a
  background worker relays to the app. When a sign-in field is focused and the app has a
  login for the site, a small frame (the extension's own page, `inline.html`, in a
  cross-origin iframe) lists usernames; on a new-password field it offers a password made by
  the app's generator, fitted to the field's `maxlength`, `minlength`, `pattern` and
  `passwordrules`; after a sign-in it offers to save the login. Clicks in the frame count only
  while the browser reports it fully visible (IntersectionObserver v2), against extension
  clickjacking (DEF CON 2025). The extension's window (button or Ctrl+Shift+L) lists the
  site's logins and the whole vault (passwords shown or copied one at a time, each through the
  item lock), the generator and a form for a new login. The app announces each fill.
- Copying from the extension is done by the app (`copy` request): the value never reaches the
  browser, and the clipboard copy is kept out of Windows clipboard history.
- With the vault locked the app still answers, from a file kept for the extension
  (`vault_core::locked_fill`, `vault_browser::locked`): logins are listed, and one password
  leaves after Windows Hello. Saving, generating and one-time codes wait for the vault to be
  unlocked. See CRYPTO.md §3.4.
- Exact origin matching (scheme + host + port), decided by the app with the WHATWG URL rules
  (`crates/browser/src/origin.rs`); the top frame only; no filling over plain HTTP. A password
  leaves the app only for the one login picked, and only for a page of its origin.
- **Pairing:** the first time, the extension asks to be connected; the app comes forward,
  shows a code and asks for the master password (typed in the app, never in the browser). From then on every request is signed with the shared key
  (HMAC-SHA-256 over a counter and the request), so a program that merely starts the native
  host gets nothing. The extension never holds the master password.
- Nothing is answered while the vault is locked. A login behind the item lock is opened for
  one fill only: by **Windows Hello** (the app shows the system's prompt; nothing is typed in
  the browser) or by the item lock's **PIN**, typed in the extension's own window and counted
  with the app's wrong tries. With the master password as the check, it is opened in the app.
- A login is used on more sites only by choice: every website saved in it counts, and
  `*.example.com` covers that site and everything under it.
- On Android: Autofill Service + Credential Manager (`CredentialProviderService`, Android 14+),
  validating the app package and signature (defense against AutoSpill).

## 6. Sync

Full design: [spec/SYNC.md](spec/SYNC.md). In short:

- Every device keeps a whole vault file and works offline; sync only moves sealed copies.
- A **server is optional**. The same engine syncs through a folder (OneDrive, Drive, Syncthing,
  a NAS), a WebDAV host, our own `vault-server` (Docker, reached over Tailscale) or, later,
  directly between PC and phone on the same Wi-Fi.
- Each device writes only its own copy (`devices/<device id>.vault`) and merges the others
  in `vault-core` (`Vault::merge`): items by id, deletions as tombstones, the newer edit wins
  and the other password goes into the history. Nothing is lost to a conflict.
- The other copies are opened with the vault key already in memory: the target never
  supplies a key or a KDF parameter. Rollback, replay and forks are refused per writer.
- The server authenticates devices by signed requests (Ed25519 keys made on each device);
  no password or password hash reaches it.
- The browser extension does not sync: it follows the desktop app on the same computer.

## 7. User interface: native Rust with Slint (_Proposal_, prototype passed)

> A working prototype lives in [`prototypes/slint-ui`](../prototypes/slint-ui/README.md): secure
> password field, Argon2id unlock, reveal with countdown, clipboard exclusion and auto-clear,
> screen-capture blocking and lock, all verified on Windows.

**Requirement:** passwords and other secrets must not pass through memory we cannot control.

### Why native instead of a WebView (Tauri)

| Concern | Tauri 2 (WebView) | Slint (native Rust) |
|---|---|---|
| Master password typing | Every keystroke goes through the DOM and the JS engine; strings are copied by the GC and cannot be wiped | A custom secure field captures key events in Rust and appends them to a `Zeroizing` buffer; the UI layer only knows how many bullets to draw |
| Revealing a password | The value is serialized over IPC as JSON, then lives in the JS heap and the DOM | The value is a short-lived Rust string shown in one text element, cleared and zeroized when hidden |
| Copy to clipboard | Can be done in Rust (OK in both) | Done in Rust |
| Attack surface | Browser engine + JS + npm supply chain | Rust crates only |
| Design freedom | Highest (HTML/CSS ecosystem) | High: custom components, gradients, shadows, rounded corners, animations and transitions, states, custom fonts, SVG; live preview; Figma-to-Slint inspector plugin. Weaker: fewer ready-made component libraries, limited effects such as backdrop blur |
| Platforms | Windows, Linux, Android | Windows, Linux, Android (Rust) |

Note: no UI toolkit can make a secret vanish completely. The OS delivers keystrokes as events,
and a revealed password has to be in the renderer's memory while it is on screen. What native
Rust gives us is **control**: short lifetimes, no hidden copies, explicit zeroization.

### Slint details

- Declarative `.slint` markup + Rust logic; renders with its own GPU/software renderer, no WebView.
- License: GPL-3.0-only OR royalty-free OR commercial. The GPL-3.0 option fits this project.
- Android: supported from Rust. Autofill Service, Credential Manager and BiometricPrompt are still
  **Kotlin** Android services that call the same Rust core.
- To validate in the prototype: a secure password field built on key-event handling (no
  `TextInput` holding the secret), accessibility (screen readers), IME/keyboard layouts, Android
  build, and whether the visual result matches the intended design.

### Alternatives kept on file

- **Tauri 2**: fallback if a native UI cannot reach the design we want. It would run with a
  locked-down configuration (minimal capabilities, Isolation Pattern, strict CSP, secrets kept in
  Rust, a native prompt for the master password).
- **Iced** (Elm-style, used by the COSMIC desktop), **Makepad** (shader-based, very flexible
  visuals, thin documentation), **Freya** (Skia, Dioxus-style), **Dioxus Native/Blitz** (HTML/CSS
  rendered natively, not yet stable).

## 8. Internationalization (i18n)

- All code, identifiers, comments, logs and docs are in **English**.
- No user-facing string is hard-coded: every UI string goes through a translation layer from day one.
- UI: Slint's built-in translation support (`@tr()` strings, gettext `.po` files or bundled
  translations). Android system services: Android string resources. Core error messages: stable error codes
  that the UI translates (the core itself returns no user-facing text).
- Default locale `en`; the first translation will be `pt-BR`.

## 9. Import / export

- Import: KeePass (KDBX 4), Bitwarden (JSON), Chrome/Edge/Firefox (CSV), 1Password (1PUX).
- Passkeys: follow the **FIDO Alliance Credential Exchange Protocol/Format**.
- Plaintext export only after a strong confirmation and a warning; the file is overwritten
  before deletion when possible.

## 10. Licensing (_Decided_)

- Clients, core, CLI and browser extension: **GPL-3.0-or-later**.
- Sync server: **AGPL-3.0-or-later** (modified versions offered as a network service must share source).
- Dependencies are checked for license compatibility with `cargo-deny`.
- Code from other projects is only reused when its license is compatible, with attribution.

## 11. Development security

- `cargo-audit` / `cargo-deny` (vulnerabilities and licenses), fuzzing (`cargo-fuzz`) of the
  vault parser, property-based tests, known-answer test vectors.
- Reproducible builds and signed releases.
- An independent external audit before any stable release.
