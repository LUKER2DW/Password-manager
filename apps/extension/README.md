# Browser extension (Chrome, Edge)

Fills, shows and saves logins from the desktop app, and suggests strong passwords. It keeps
no passwords and does no cryptography of its own: it asks the app on the same computer,
through a small helper program the browser starts (`vault-browser-host`, built from
`crates/browser`).

Status: early development, like the rest of the project. Use a test vault.

## What it does

- **Connect once.** The first time you open it, it offers *Connect* and shows a six-digit
  code. The app comes forward and asks you to type that code, then your master password
  (both typed in the app, never in the browser).
  The extension then holds a connection key (never a password) and signs every request.
- **Under a sign-in field**, a small card with an arrow pointing at the field lists the
  usernames saved for that exact site (same scheme, host and port; https only), with the
  site's icon and the password as dots. Pick one and it is filled; *Manage passwords…* opens
  the extension's window. Esc or a click elsewhere closes it.
- **On a sign-up or change-password field**, the frame offers a strong password made by the
  app's generator, fitted to what the field allows (`maxlength`, `minlength`, `pattern`,
  `passwordrules`). *Use this password* types it into the new-password fields.
- **After you sign in or sign up** with a login that isn't saved, it asks *Save this login?*.
  Saving asks for nothing (no PIN, no Windows Hello), even with the vault locked: the app then
  keeps the login sealed and adds it at the next unlock.
- **After you sign in with another password** for a login already saved, it asks *Update the
  saved password?*. The old password goes into the login's history in the app. A login behind
  the item lock is opened for the change (Windows Hello or the PIN), as for a fill.
- **On a one-time code field** (the second step of a sign-in: `autocomplete="one-time-code"`,
  or named like `otp`, `2fa`, `verification`), the card lists the site's logins that have a
  one-time code; pick one and its current code is typed in, spread over one box per digit
  when the site uses those. *Fill the one-time code* in a login's details does the same.
- **Passkeys.** When a site makes a passkey ("Create a passkey", "Add a security key"), Vault
  asks in a window of its own: *Save* keeps it with your login for that site and username (a
  new login when there is none). When a site asks for one, the same window lists the passkeys
  Vault has for it; pick one to sign in. *Use another device* hands the request to the browser
  (a phone, a security key, Windows Hello). Sites with no passkey in Vault, the field's
  autofill list and security keys go to the browser as before. On the item page in the app
  you see a login's passkeys; the editor takes one out. Turn it off in the extension's
  Settings: "Vault keeps passkeys, not the browser".
- **Its window** (the toolbar button or Ctrl+Shift+L) has three tabs:
  - *This site*: the logins for the page in front, to fill; *Details* opens one.
  - *All logins*: search the whole vault; show a password or copy username, password or
    one-time code. *New* adds a login by hand.
  - *Generator*: a password from the app's generator; *Copy* or *Use for a new login*. It
    works with the vault locked too: making a password needs no vault, and one you used joins
    the app's history once the vault is open again.
- Copying is done **by the app**: the value never reaches the browser, it stays out of
  Windows clipboard history, and it is cleared after the time set in the app.
- **Works with the vault locked** (the app must be running, the window may be closed to the
  notification area): logins are listed and each fill asks for Windows Hello. Turn it on or
  off in the app: Settings → Browser extension → Fill with Windows Hello while the vault is
  locked. It needs Windows Hello on in Settings → Item lock.
- Generated passwords you used are listed in the app's Generator page (encrypted with the
  vault on this computer, behind the item lock), with *Clear history*.

## How it stays safe

- **Chrome's own saving:** while "Vault offers to save passwords, not the browser" is on (the
  default, in the extension's Settings), Chrome's "Offer to save passwords and passkeys" is off,
  and Chrome's settings say the extension controls it. That is what the `privacy` permission
  is for, and nothing else.
- **What the app allows:** the desktop app's Settings → Browser extension can turn off saving
  logins from pages (new ones, changed passwords, those saved while locked) and the vault's
  passkeys. The app then refuses those requests (`turned_off`) and says so in its answers
  about a page's logins (`"saves": false`, `"passkeys": false`): the extension offers no save,
  and passkeys fall back to the browser's own. The app can also stop showing a notice for
  each fill.
- **Passkeys:** the page's address is the tab's own; the app decides which site the page may
  use passkeys for (its own host, or a domain above it that is not a public suffix), writes
  and signs the client data itself, and the answer reaches the page only while it still shows
  that origin. Nothing is made or signed before you choose in the passkey window.

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
  minutes, and goes to the app only if you choose *Save*. Before offering an update, the app
  is asked whether that password differs from the saved one; it answers only for a login
  that is not behind the item lock (for a locked one it says it can't tell), so the extension
  can't test guesses against locked logins.
- A one-time code, like a password, leaves the app only for a page of the login's own site.
- Only what the person does counts as signing in: submits and clicks a page script makes up
  are ignored, so a page can't get an offer for a password it chose by itself. A page that
  sets its fields before a real click still can, which is why an update always asks and
  keeps the old password in the login's history.

To use one login on several sites, save `*.example.com` as its website in the app: it then
covers `example.com` and every site under it. A name anyone can register under (`*.co.uk`,
`*.github.io`, from the Public Suffix List built into the app) is not accepted.

## Install (development)

1. Build the app and the helper so they sit side by side:
   `cargo build --release -p vault-desktop -p vault-browser`
2. Run the app with a test vault and turn on **Settings → Browser extension**. This writes the
   helper's manifest under the app's data folder and points Chrome and Edge at it (one registry
   value each, for your Windows user). Turning it off removes them.
3. Open `chrome://extensions` (or `edge://extensions`), turn on *Developer mode*, choose
   *Load unpacked* and pick this folder (`apps/extension`). Pin the extension to the toolbar. After an
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
| `manifest.json` | Manifest V3: `activeTab`, `scripting`, `nativeMessaging`, `storage`, `favicon`, `privacy`; https pages for the content scripts |
| `popup.html`, `popup.css`, `popup.js` | The extension's window: this site, all logins, generator, new login |
| `content.js`, `fields.js` | Content script: sign-in and new-password fields, submitted forms, placing the frame |
| `inline.html`, `inline.css`, `inline.js` | The frame under a field (logins or a new password) and the save offer |
| `background.js` | The worker between the content script, the frame and the app |
| `passkeys-page.js` | In the page's own world: stands in front of `navigator.credentials` for passkeys |
| `passkeys.js` | Content script: relays passkey requests between the page and the worker |
| `passkey-worker.js` | The worker's side of passkeys: asks the app, opens the passkey window, answers the page |
| `passkey.html`, `passkey.css`, `passkey.js` | The passkey window: the site, its passkeys or the one to make, the item lock's check |
| `app.js` | Native messaging calls, and the login waiting to be saved |
| `link.js` | The connection key (a non-extractable browser key) and the signature on each request |
| `fill.js` | The function that types a login into the page (top frame, same origin) |
| `generator.js` | Reads a field's password rules for the app's generator |
| `tokens.css` | Colours and shared pieces (the desktop app's tokens) |
| `_locales/en/messages.json` | Every text shown |
| `test/*.test.mjs` | Tests: `node --test apps/extension/test/fill.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs` |
| `test/preview.html` | Visual review of the window and the frames with fixed test data |
| `test/pages/clickjacking.html` | Manual test page that tries to steal a fill |

Plain JavaScript on purpose: no build step and no packages, so what is reviewed in this folder
is exactly what the browser runs.
