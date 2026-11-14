# Browser extension (Chrome, Edge)

Fills logins from the desktop app. It keeps no passwords and does no cryptography: it asks the
app on the same computer, through a small helper program the browser starts
(`vault-browser-host`, built from `crates/browser`).

Status: early development, like the rest of the project. Use a test vault.

## How it works

0. Once: you click Connect in the extension. The app comes forward, shows a code and asks
   for your master password (typed in the app, never in the browser). The extension then
   holds a connection key (never a password), signs every request, and carries on by itself.
1. You click the extension's button (or press Ctrl+Shift+L). Only then does it learn the
   address of the tab (`activeTab`); it has no access to any site otherwise and runs nothing
   in the background.
2. It sends that address to the app. The app answers with the logins saved for **exactly that
   site** (same scheme, host and port; https only), without passwords.
3. You pick one **in the extension's own window**. The app then hands over that one login,
   after checking the site again, and the extension types it into the page's top frame.
4. The app shows a notice for every fill.

Nothing is ever drawn inside a web page, so a page has nothing to cover or click on your
behalf. A login behind the app's item lock is opened for that one fill by Windows Hello
(the system's own prompt) or by the item lock's PIN typed in the extension's window; five
wrong tries lock the vault, as in the app.

To use one login on several sites, save `*.example.com` as its website in the app: it then
covers `example.com` and every site under it.

## Install (development)

1. Build the app and the helper so they sit side by side:
   `cargo build --release -p vault-desktop -p vault-browser`
2. Run the app with a test vault and turn on **Settings → Browser extension**. This writes the
   helper's manifest under the app's data folder and points Chrome and Edge at it (one registry
   value each, for your Windows user). Turning it off removes them.
3. Open `chrome://extensions` (or `edge://extensions`), turn on *Developer mode*, choose
   *Load unpacked* and pick this `extension` folder. Pin the extension to the toolbar.
4. Open any https site, click the extension (or Ctrl+Shift+L) and choose *Connect*. In the
   app, type your master password and choose *Connect*. Done: the extension lists the logins
   saved for the site you are on.
5. Optional, for a PIN or Windows Hello on each fill: in the app, Settings → Item lock →
   PIN, tick "Lock every item" (or mark single items) and "Open locked items with Windows
   Hello too".

If the extension says the app isn't answering: the app must be running with the browser
extension turned on, and `vault-browser-host.exe` must sit next to `vault-desktop.exe`
(both are in `target/release` after step 1). Restart the browser after turning the setting
on for the first time.

The `key` in `manifest.json` fixes the extension's id, which is the only id the helper accepts.

## Files

| File | Role |
|---|---|
| `manifest.json` | Manifest V3: `activeTab`, `scripting`, `nativeMessaging`; no host permissions, no content scripts, no background worker |
| `popup.html`, `popup.css`, `popup.js` | The extension's window: asks the app, lists logins, fills the one picked |
| `link.js` | The connection key (a non-extractable browser key) and the signature on each request |
| `fill.js` | The function typed into the page (top frame, same origin, sign-in fields only) |
| `_locales/en/messages.json` | Every text shown |
| `test/fill.test.mjs`, `test/link.test.mjs` | Tests: `node --test extension/test/fill.test.mjs extension/test/link.test.mjs` |
| `test/preview.html` | Visual review of the window with fixed test data |
| `test/pages/clickjacking.html` | Manual test page that tries to steal a fill |

Plain JavaScript on purpose: no build step and no packages, so what is reviewed in this folder
is exactly what the browser runs.
