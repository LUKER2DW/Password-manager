# password-manager

An open-source, local-first, zero-knowledge password manager focused on security above all.

> ⚠️ **Early development.** The cryptographic core exists, but there is no usable app yet and
> nothing has been audited. Do not store real passwords with it.

## Goal

An attacker who obtains the vault file cannot extract anything from it. The vault key depends on
factors that are never stored in the file: the master password, a Secret Key and, optionally, a
hardware security key.

## Documentation

- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md) and [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- Specifications: [cryptography](docs/spec/CRYPTO.md), [vault file format](docs/spec/VAULT_FORMAT.md)

## Development

```bash
cargo test --workspace
```

| Crate | Purpose |
|---|---|
| [`crates/core`](crates/core) | Cryptography, vault file format, item model, TOTP, generator (no UI, no network) |
| [`crates/import`](crates/import) | Importers: Bitwarden JSON, KeePass `.kdbx`, browser/Bitwarden CSV |
| [`crates/cli`](crates/cli) | `vault` command-line client |

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
(CC BY 3.0 US, © Electronic Frontier Foundation).

## Language

The codebase and documentation are written in English. The user interface will support
translations (i18n) from the start.
