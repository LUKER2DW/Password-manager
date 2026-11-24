# Contributing

Thank you for looking at the code. This is a password manager, so the bar for a change is
how it holds up against the attackers in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), before
how convenient it is.

## Before you start

- **Security issues are never reported in public.** Use the private reporting described in
  [SECURITY.md](SECURITY.md).
- Read [AGENTS.md](AGENTS.md): the layout, how to build and test, and the rules (it is written
  for people and AI coding agents alike). The specs in `docs/spec/` are normative.
- For anything larger than a fix, open an issue first and say what you want to change and
  why, so the design can be agreed before the code.

## Working on a change

- Test with made-up data only: point the apps at a test vault with `VAULT_FILE` and a test
  app folder with `VAULT_HOME`. Never put a real vault, key, export, kit or screenshot of
  real data in an issue, a commit or a pull request.
- Before you send it, all of these pass:

  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  cargo deny check advisories
  ```

- UI changes: render the screens (`cargo run -p vault-desktop --example screenshots --
  target/screenshots`, and the phone's with `cargo run -p vault-mobile --example
  phone_screens -- target/phone-screens`) and look at the PNGs; a change to a shared widget
  must look right in both apps.
- Every text the apps show goes through `@tr()`; add new strings to the catalogues
  (`apps/*/translations/`).
- A change to the bytes on disk is a new format version (AGENTS.md §5.1); older test vaults
  are never regenerated.
- One commit per area (`Core:`, `Platform:`, `Desktop:`, `Mobile:`, `Server:`, `Docs:`…),
  in English, saying what changed and why.

## Licence

By contributing you agree that your work is released under the project's licences:
GPL-3.0-or-later for the apps and libraries, AGPL-3.0-or-later for the sync server
(`apps/server`).
