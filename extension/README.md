# Browser extension (Chrome, Edge)

Fills, shows and saves logins from the desktop app, and suggests strong passwords. It keeps
no passwords and does no cryptography of its own: it asks the app on the same computer,
through a small helper program the browser starts (`vault-browser-host`, built from
`crates/browser`).

Status: early development, like the rest of the project. Use a test vault.

## What it does

- **Connect once.** The first time you open it, it offers *Connect*. The app comes forward,
  shows a code and asks for your master password (typed in the app, never in the browser).
  The extension then holds a connection key (never a password) and signs every request.
- **Under a sign-in field**, a small card with an arrow pointing at the field lists the
  usernames saved for that exact site (same scheme, host and port; https only), with the
  site's icon and the password as dots. Pick one and it is filled; *Manage passwords…* opens
  the extension's window. Esc or a click elsewhere closes it.
- **On a sign-up or change-password field**, the frame offers a strong password made by the
  app's generator, fitted to what the field allows (`maxlength`, `minlength`, `pattern`,
  `passwordrules`). *Use this password* types it into the new-password fields.
- **After you sign in or sign up** with a login that isn't saved, it asks *Save this login?*.
- **Its window** (the toolbar button or Ctrl+Shift+L) has three tabs:
  - *This site*: the logins for the page in front, to fill; *Details* opens one.
  - *All logins*: search the whole vault; show a password or copy username, password or
    one-time code. *New* adds a login by hand.
  - *Generator*: a password from the app's generator; *Copy* or *Use for a new login*.
- Copying is done **by the app**: the value never reaches the browser, it stays out of
  Windows clipboard history, and it is cleared after the time set in the app.
- **Works with the vault locked** (the app must be running, the window may be closed to the
  notification area): logins are listed and each fill asks for Windows Hello. Turn it on or
  off in the app: Settings → Browser extension → Fill with Windows Hello while the vault is
  locked. It needs Windows Hello on in Settings → Item lock.
- Generated passwords you used are listed in the app's Generator page (encrypted with the
  vault on this computer, behind the item lock), with *Clear history*.

## How it stays safe

- Every password comes from the app, which decides whether a page may have it: the exact site
  saved in the login, top frame only, nothing while the vault is locked. Each fill or shown
  password is announced in the app.
- A login behind the item lock (every item, by default, for new vaults) needs **Windows Hello**
  (the system's own prompt) or the item lock's PIN, typed in the extension's window, for each
  fill, show or copy. Five wrong tries lock the vault, as in the app.
- The frame in pages is the extension's own page in a cross-origin iframe: the page can't read
  or script it. A click there counts only once the browser reports the frame fully visible,
  with nothing drawn over it (against extension clickjacking). It never shows a password
  except a freshly generated one.
- A login typed into a page waits in the browser's memory (never on disk) for at most two
  minutes, and goes to the app only if you choose *Save*.

To use one login on several sites, save `*.example.com` as its website in the app: it then
covers `example.com` and every site under it.

## Install (development)

1. Build the app and the helper so they sit side by side:
   `cargo build --release -p vault-desktop -p vault-browser`
2. Run the app with a test vault and turn on **Settings → Browser extension**. This writes the
   helper's manifest under the app's data folder and points Chrome and Edge at it (one registry
   value each, for your Windows user). Turning it off removes them.
3. Open `chrome://extensions` (or `edge://extensions`), turn on *Developer mode*, choose
   *Load unpacked* and pick this `extension` folder. Pin the extension to the toolbar. After an
   update of this folder, click the reload arrow on the extension's card.
4. Click the extension and choose *Connect*. In the app, type your master password and choose
   *Connect*. Done.

If the extension says the app isn't answering: the app must be running (the window may be
closed to the notification area) with the browser extension turned on, and
`vault-browser-host.exe` must sit next to `vault-desktop.exe` (both are in `target/release`
after step 1). Restart the browser after turning the setting on for the first time.

The `key` in `manifest.json` fixes the extension's id, which is the only id the helper accepts.

## Files

| File | Role |
|---|---|
| `manifest.json` | Manifest V3: `activeTab`, `scripting`, `nativeMessaging`, `storage`, `favicon`; https pages for the content script |
| `popup.html`, `popup.css`, `popup.js` | The extension's window: this site, all logins, generator, new login |
| `content.js`, `fields.js` | Content script: sign-in and new-password fields, submitted forms, placing the frame |
| `inline.html`, `inline.css`, `inline.js` | The frame under a field (logins or a new password) and the save offer |
| `background.js` | The worker between the content script, the frame and the app |
| `app.js` | Native messaging calls, and the login waiting to be saved |
| `link.js` | The connection key (a non-extractable browser key) and the signature on each request |
| `fill.js` | The function that types a login into the page (top frame, same origin) |
| `generator.js` | Reads a field's password rules for the app's generator |
| `tokens.css` | Colours and shared pieces (the desktop app's tokens) |
| `_locales/en/messages.json` | Every text shown |
| `test/*.test.mjs` | Tests: `node --test extension/test/fill.test.mjs extension/test/link.test.mjs extension/test/generator.test.mjs` |
| `test/preview.html` | Visual review of the window and the frames with fixed test data |
| `test/pages/clickjacking.html` | Manual test page that tries to steal a fill |

Plain JavaScript on purpose: no build step and no packages, so what is reviewed in this folder
is exactly what the browser runs.
