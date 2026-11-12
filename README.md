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
| [`crates/core`](crates/core) | Cryptography, vault file format, item model (no UI, no network) |

## Planned platforms

Windows → browser extension → Android → Linux, with optional sync to a self-hosted server.

## License

GPL-3.0-or-later for the apps and core; AGPL-3.0-or-later for the sync server.
(License files will be added with the first code.)

## Language

The codebase and documentation are written in English. The user interface will support
translations (i18n) from the start.
