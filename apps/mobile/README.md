# vault-mobile

The phone app's screens and controller, built with [Slint](https://slint.dev). It runs in
three places, from the same code:

| Where | Crate | Build |
|---|---|---|
| A phone-sized window on the computer | this one | `cargo run -p vault-mobile` |
| Android | [`../mobile-android`](../mobile-android) | `apps/mobile-android/build.ps1` → `target/release/apk/vault-mobile-android.apk` |
| A web page, with a demo vault | [`../mobile-web`](../mobile-web) | `apps/mobile-web/build.ps1` → `target/mobile-web` |

```bash
cargo test -p vault-mobile                                         # headless, sync included
cargo run -p vault-mobile --example phone_screens -- target/phone-screens
```

`ui/app.slint` imports the desktop's tokens, widgets and icons (`apps/desktop/ui`), with
`Theme.touch` on. The controller reaches the system only through `src/platform.rs`, which is
the platform crate on a phone or a computer and `src/platform/web.rs` in a browser.

The words are written in English in the `.slint` files. `translations/` holds the Brazilian
Portuguese (gettext, see its README), and `src/i18n.rs` picks the language (Settings →
Appearance).

What the app does, how it keeps secrets on a phone and what each build needs:
[docs/MOBILE.md](../../docs/MOBILE.md).
