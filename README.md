# Vault

An open-source, local-first, zero-knowledge password manager written in Rust, with security
above all.

> ⚠️ **Early development.** The Windows desktop app, the browser extension and the CLI work,
> and the Android app runs, but nothing has been audited. Do not store real passwords in it yet.

## The idea

An attacker who obtains the vault file cannot extract anything from it. The vault is one
encrypted file, and its key needs two things that are never stored in that file: the master
password and a 128-bit Secret Key. Each device keeps the whole vault and works offline; sync
is optional and only ever moves sealed copies.

## What it does

- **Desktop app (Windows):** logins, payment cards, secure notes, SSH keys and one-time codes,
  files attached to items, folders, favourites and search. A password generator (characters
  or words), password history, a health page (weak, reused, old and leaked passwords; the
  leak check is k-anonymous and runs when asked, or every day with the leak watch on), import from browsers and other
  managers, encrypted and plain exports, an item lock (a PIN or second password before
  secrets show), Windows Hello, an optional keyfile, and a printable emergency kit with three
  recovery parts.
- **Browser extension (Chrome, Edge):** fills logins and one-time codes from the desktop app
  and offers to save new ones, in place of the browser's own offer. It holds no passwords of
  its own.
- **Android app (early):** opens the vault made on the computer and edits the same items;
  codes, generator, sync, attached files, several vaults, fingerprint unlock, autofill into
  other apps and browsers (a fingerprint or the phone's lock before every fill), the leak
  watch, and updates from your own server.
- **CLI:** the same vault from a terminal (`vault`).
- **Sync (optional):** through a folder, a WebDAV host or a small server you run yourself
  (Docker, behind Tailscale or with its own HTTPS). The server never sees anything that opens
  the vault.

## Repository layout

`apps/` holds what people run, `crates/` the libraries the apps share.

| Folder | What it is |
|---|---|
| [`apps/desktop`](apps/desktop) | The desktop app (Slint); design notes in [docs/DESIGN.md](docs/DESIGN.md) |
| [`apps/mobile`](apps/mobile) | The phone app's screens and controller (Slint), see [docs/MOBILE.md](docs/MOBILE.md) |
| [`apps/mobile-android`](apps/mobile-android) | The phone app as an Android APK |
| [`apps/mobile-web`](apps/mobile-web) | The phone app in a web page (WebAssembly), with a demo vault |
| [`apps/extension`](apps/extension) | The Chrome/Edge extension (plain JavaScript); see its [README](apps/extension/README.md) |
| [`apps/cli`](apps/cli) | The `vault` command-line client |
| [`apps/server`](apps/server) | The self-hosted sync server; setup in [docs/SERVER.md](docs/SERVER.md) |
| [`crates/core`](crates/core) | Cryptography, the vault file format, items, merge, generator, TOTP, health (no UI, no network) |
| [`crates/platform`](crates/platform) | OS integration: credential store, device state, clipboard, capture blocking, secure input, Windows Hello, kit PDF, sync targets |
| [`crates/import`](crates/import) | Import and export: JSON, CSV and KDBX files, and browsers' own stores on request |
| [`crates/browser`](crates/browser) | What the extension may ask the app, and its native host |
| [`crates/sync-wire`](crates/sync-wire) | The signed requests devices and the sync server exchange |
| [`docs`](docs) | Threat model, architecture, design, plans and the normative specs |

## Building and trying it

Rust's stable toolchain (pinned in `rust-toolchain.toml`) is all the desktop app and the CLI
need.

```bash
cargo test --workspace
cargo run --release -p vault-desktop
cargo run -p vault-cli -- --help
```

Use test vaults only. `VAULT_FILE=C:\path\to\test.vault` points the desktop app and the CLI
at a test file (a missing file opens the "new vault" screen), and `VAULT_HOME` moves the
whole app folder. `cargo run -p vault-desktop --example screenshots -- target/screenshots`
renders every screen to PNG.

```bash
cargo run -p vault-cli -- init          # create a vault, prints the emergency kit
cargo run -p vault-cli -- add GitHub -u me --url https://github.com --generate
cargo run -p vault-cli -- list
cargo run -p vault-cli -- show GitHub --copy
cargo run -p vault-cli -- generate --words 6     # passphrase from the EFF word list
cargo run -p vault-cli -- import export.csv --dry-run
```

The Secret Key is kept in the OS credential store (Windows Credential Manager on Windows);
`vault forget` removes it from the device. The phone app, its APK and its web build are
described in [docs/MOBILE.md](docs/MOBILE.md) §7; the extension in its README; the server in
[docs/SERVER.md](docs/SERVER.md).

## Documentation

- [Threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md) and [design](docs/DESIGN.md)
- [Roadmap](docs/ROADMAP.md) and [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- Specifications: [cryptography](docs/spec/CRYPTO.md), [vault file format](docs/spec/VAULT_FORMAT.md),
  [sync](docs/spec/SYNC.md)
- Working on the code: [AGENTS.md](AGENTS.md), for people and AI agents alike

## Licence

GPL-3.0-or-later for the apps and libraries ([LICENSE](LICENSE)); AGPL-3.0-or-later for the
sync server ([apps/server/LICENSE](apps/server/LICENSE)).

Bundled third-party data: the [EFF large word list](crates/core/data/README.md)
(CC BY 3.0 US, © Electronic Frontier Foundation); interface icons from
[Lucide](https://lucide.dev) (ISC); import source icons from [Simple Icons](https://simpleicons.org)
(CC0). Brand names and logos belong to their owners and are used only to identify where an
import comes from.

## Language

The code and documentation are in English. The apps translate every text they show
(gettext catalogues); Brazilian Portuguese is under way.
