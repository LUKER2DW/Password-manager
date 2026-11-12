# password-manager

An open-source, local-first, zero-knowledge password manager focused on security above all.

> ⚠️ **Research phase.** There is no usable code yet. Do not store real passwords with it.

## Goal

An attacker who obtains the vault file cannot extract anything from it. The vault key depends on
factors that are never stored in the file: the master password, a Secret Key and, optionally, a
hardware security key.

## Documentation

- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)

## Planned platforms

Windows → browser extension → Android → Linux, with optional sync to a self-hosted server.

## License

GPL-3.0-or-later for the apps and core; AGPL-3.0-or-later for the sync server.
(License files will be added with the first code.)

## Language

The codebase and documentation are written in English. The user interface will support
translations (i18n) from the start.
