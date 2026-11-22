# vault-desktop

The desktop app, built with [Slint](https://slint.dev). Windows first; Linux later.

```bash
cargo run --release -p vault-desktop
cargo test -p vault-desktop                                    # the whole app, headless
cargo run -p vault-desktop --example screenshots -- target/screenshots
```

Use a test vault: `VAULT_FILE` points the app at a file (a missing one opens the "new vault"
screen) and `VAULT_HOME` moves its whole folder (device state, caches, word lists).

| Folder | What is in it |
|---|---|
| `src/` | The controller that wires the screens to the vault (`controller.rs` and its submodules), presentation rules (`view.rs`), the tray, translations |
| `ui/` | The screens, as the crate `vault-desktop-ui`; its tokens, widgets and icons are shared with the phone app |
| `ui/brand/` | The logo, the lock screen's scene and the open vault's texture |
| `translations/` | gettext catalogues compiled into the app |
| `assets/` | The .exe's icon |
| `examples/` | `screenshots.rs`: every screen rendered off-screen to PNG, with a demo kit PDF |

How it is built and the rules it follows: [AGENTS.md](../../AGENTS.md) §2.5; its look:
[docs/DESIGN.md](../../docs/DESIGN.md).
