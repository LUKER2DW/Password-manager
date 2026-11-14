# CLAUDE.md

Guidance for Claude Code (and similar agents) in this repository. The full guide is
[AGENTS.md](AGENTS.md); it applies here in full.

@AGENTS.md

## Quick reference

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p vault-desktop --example screenshots -- target/screenshots   # visual review
```

On Windows, if `cargo` is not found: `$env:Path = "$HOME\.cargo\bin;$env:Path"`.

## Working agreements

- Everything committed is in English. User-facing text goes through `@tr()` in `.slint`; Rust
  sends codes (`error::*`, `notice::*`), and the words live in `ui/model.slint`.
- Nothing personal in the repository: no names, emails, home paths, real vaults, keys, exports
  or screenshots of real data. `research/` is git-ignored.
- Review UI changes through the off-screen screenshots (read the PNGs); don't drive the real
  desktop to check them.
- Commit and push by area (`Core:`, `Platform:`, `Import:`, `CLI:`, `Browser:`, `Extension:`, `Desktop:`, `Docs:`,
  `Build:`), after fmt, clippy and tests pass.
- Format changes follow AGENTS.md §5.1: new version, old layouts kept, new fixture, older
  fixtures never regenerated.
- Never test with real passwords or the user's real vault; use `VAULT_FILE` / `VAULT_HOME` to
  point at test files.
- Never read a real browser's password store while testing; the browser import is tested with
  constructed data.
