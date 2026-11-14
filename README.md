# password-manager

An open-source, local-first, zero-knowledge password manager focused on security above all.

> ⚠️ **Early development.** The Windows desktop app and the CLI work, but nothing has been
> audited. Do not store real passwords with it yet.

## Goal

An attacker who obtains the vault file cannot extract anything from it. The vault key depends on
factors that are never stored in the file: the master password, a Secret Key and, optionally, a
hardware security key.

## Documentation

- [Threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md) and [design](docs/DESIGN.md)
- [Roadmap](docs/ROADMAP.md) and [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- Specifications: [cryptography](docs/spec/CRYPTO.md), [vault file format](docs/spec/VAULT_FORMAT.md)
- Working on the code: [AGENTS.md](AGENTS.md) (people and AI agents alike) and
  [CONTRIBUTING.md](CONTRIBUTING.md)

## Development

```bash
cargo test --workspace
```

| Crate | Purpose |
|---|---|
| [`crates/core`](crates/core) | Cryptography, vault file format, item model, TOTP, generator, password health (no UI, no network) |
| [`crates/platform`](crates/platform) | OS integration: Secret Key store, device state, secure clipboard, capture blocking, secure input, Windows Hello, emergency kit PDF |
| [`crates/import`](crates/import) | Import and export: JSON, CSV and KDBX files, and browsers' own stores on request |
| [`crates/cli`](crates/cli) | `vault` command-line client |
| [`crates/desktop`](crates/desktop) | Desktop app (Slint); design notes in [docs/DESIGN.md](docs/DESIGN.md) |
| [`crates/browser`](crates/browser) | What the browser extension may ask the app, and its native host |
| [`extension`](extension) | Chrome/Edge extension that fills logins (no secrets of its own); see its [README](extension/README.md) |

### Trying the desktop app (test vaults only)

```bash
cargo run -p vault-desktop
```

It uses the same vault as the CLI by default. Point both at a test file with
`VAULT_FILE=C:\path\to\test.vault` (a missing file opens the "new vault" screen).
`cargo run -p vault-desktop --example screenshots -- target/screenshots` renders every screen
to PNG for review.

### Trying the CLI (test vaults only)

```bash
cargo run -p vault-cli -- init          # create a vault, prints the emergency kit
cargo run -p vault-cli -- add GitHub -u me --url https://github.com --generate
cargo run -p vault-cli -- list
cargo run -p vault-cli -- show GitHub --copy
cargo run -p vault-cli -- generate --words 6     # passphrase from the EFF word list
cargo run -p vault-cli -- import export.csv --dry-run
```

The Secret Key is stored in the OS credential store (Windows Credential Manager on Windows).
`vault forget` removes it from the device.

## Planned platforms

Windows → browser extension → Android → Linux, with optional sync to a self-hosted server.

## License

GPL-3.0-or-later for the apps and core; AGPL-3.0-or-later for the sync server.
(License files will be added with the first release.)

Bundled third-party data: the [EFF large word list](crates/core/data/README.md)
(CC BY 3.0 US, © Electronic Frontier Foundation); interface icons from
[Lucide](https://lucide.dev) (ISC); import source icons from [Simple Icons](https://simpleicons.org)
(CC0). Brand names and logos belong to their owners and are used only to identify where an
import comes from.

## Language

The codebase and documentation are written in English. The user interface will support
translations (i18n) from the start.
