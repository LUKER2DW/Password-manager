# Browser extension (Chrome, Edge, Firefox)

Fills, shows and saves logins from the desktop app, and suggests strong passwords. It keeps
no passwords and does no cryptography of its own: it asks the app on the same computer. The
browser starts the desktop app's own program (`vault-desktop.exe`) as its native messaging
host, which relays each message to the app's window over a pipe and shows nothing itself.

Status: alpha, like the rest of the project (loaded unpacked; not in a store yet). Test with a test vault.

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
  (a phone, a security key, Windows Hello). When a site suggests passkeys in its sign-in field
  (`mediation: "conditional"`, the field's autofill list), the card under the field lists the
  passkeys Vault has for that site above the logins; pick one to sign in (a locked login asks
  for Windows Hello, or opens the passkey window for its PIN). Sites with no passkey in Vault,
  a locked vault (for the field's list) and security keys go to the browser as before. On the
  item page in the app you see a login's passkeys; the editor takes one out. Turn it off in
  the extension's Settings: "Vault keeps passkeys, not the browser".
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
  is for, and nothing else. Turned off, Vault keeps and offers nothing typed into sign-in
  forms: what a page sends is not read (nor compared with a saved login), an offer still
  waiting is dropped, and *Save* refuses; the browser's own saving is back. Filling works
  either way.
- **What the app allows:** the desktop app's Settings → Browser extension can turn off saving
  logins from pages (new ones, changed passwords, those saved while locked) and the vault's
  passkeys. The app then refuses those requests (`turned_off`) and says so in its answers
  about a page's logins (`"saves": false`, `"passkeys": false`): the extension offers no save,
  and passkeys fall back to the browser's own. The app can also stop showing a notice for
  each fill.
- **Passkeys:** the page's address is the tab's own; the app decides which site the page may
  use passkeys for (its own host, or a domain above it that is not a public suffix), writes
  and signs the client data itself, and the answer reaches the page only while it still shows
  that origin. Nothing is made or signed before you choose in the passkey window, which names
  the page that asks and, when it is another name, the site the passkey belongs to as the app
  checked it ("accounts.example.com, for example.com"; while the vault is locked the app
  hasn't, and the window names the page alone, never a site the page wrote). The app is asked
  to make or sign only while the very document that asked (same tab, same document, same
  origin) still waits for that request and passkeys are still Vault's, and the same is checked
  again before the answer goes back. A passkey the app made for a page that went away (or
  cancelled) in between stays in the vault, unknown to the site: the window says so instead of
  closing. A new passkey takes the place of the one kept before for the same site and account
  (as a security key does); when that happened too, the window says the earlier one is gone.
  A site's request for the field's suggestions opens no window: it waits in the page that
  asked until you pick a passkey in the card under a sign-in field (the same click check as
  for a fill, below), and the answer goes to that very document only, after the same checks.
  The page aborting it, leaving, or asking for another passkey ends it; closing the passkey
  window opened for a PIN doesn't (as closing the browser's own list doesn't).

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
  can't test guesses against locked logins. The page itself can see whether the update card
  appears, so for an open login it learns whether the password in its fields was the saved
  one. That is accepted: the card appears only on the login's own site, which Vault fills
  that password into anyway and whose own sign-in answers "right or wrong" for any guess;
  here each guess needs an act of yours in that form just before it is sent (below).
  An update is for the version of the login the app compared, and its username: when the
  login was changed since (edited in the app, merged by a sync), nothing is replaced and the
  card says so.
- A one-time code, like a password, leaves the app only for a page of the login's own site.
- Only what the person does counts as signing in: clicks and key presses a page script makes
  up are ignored. A form's `submit` is different: the browser reports it as the person's even
  when a page script asks for it (`requestSubmit()`, or `click()` on its button), so it counts
  only within a few seconds after your own click or Enter in that same form, and one act
  counts for one submit. So a page can't get an offer, or learn from one, for passwords it
  submits by itself. A page that sets its fields before your real click still can, which is
  why an update always asks and keeps the old password in the login's history.
- Only the form that is sent is read: its submit, Enter in one of its fields, or a click on
  one of its buttons that reads like signing in ("Sign in", "Entrar", "Next"…, but not "Sign
  in with Google", "Login help" or "Can't log in?"). A help link, an eye that shows the
  password, a menu or a button of another form reads nothing by its click. Sign-in fields
  outside any `<form>` are read only for Enter in them or a click on such a button next to
  them. With saving left to the browser (above), nothing typed is read at all.
- A login picked in the frame under a field goes into that field's own form, never into
  another sign-in form of the page, and not at all when the page has since removed the field,
  moved it into another form or changed where its form sends (its action, a submit button's
  `formaction`, or the page's `<base>`). Fields outside any `<form>` go together only when they
  sit next to each other: the password never goes into another box, nor before the field
  picked. From the extension's window it goes into the focused field's form when that is a
  sign-in field (not a search box or a code), else the page's only sign-in form; with several
  and none focused, nothing is guessed. A form that may send over plain `http:` (its action or
  a button's) gets nothing. A one-time code gets the same checks.
- A site's `pattern` for new passwords is checked against the suggestion only when it is
  plainly cheap to run (no repeated group, few repeats in a row): a pattern built to make the
  browser's regular expressions run for ages could otherwise stall the extension in every tab.

To use one login on several sites, save `*.example.com` as its website in the app: it then
covers `example.com` and every site under it. A name anyone can register under (`*.co.uk`,
`*.github.io`, from the Public Suffix List built into the app) is not accepted, nor one right
above such names (`*.nom.br`, where each `name.nom.br` is one), and an entry never reaches past
one below it (`*.amazonaws.com` doesn't cover `x.s3.amazonaws.com`, someone else's).

## Install (development)

1. Build the app (`cargo build --release -p vault-desktop`), or take `vault-desktop.exe` from a
   release.
2. Run the app with a test vault and turn on **Settings → Browser extension**. This writes the
   host's manifests (pointing at this `vault-desktop.exe`; one for Chrome and Edge, one for
   Firefox) under the app's data folder and points Chrome, Edge and Firefox at them (one
   registry value each, for your Windows user). Turning it off removes them.
3. Open `chrome://extensions` (or `edge://extensions`), turn on *Developer mode*, choose
   *Load unpacked* and pick this folder (`apps/extension`). Pin the extension to the toolbar. After an
   update of this folder, click the reload arrow on the extension's card.
4. Click the extension and choose *Connect*. In the app, type your master password and choose
   *Connect*. Done.

If the extension says the app isn't answering: the app must be running (the window may be
closed to the notification area) with the browser extension turned on. After moving or
replacing `vault-desktop.exe`, start it once so it points the browsers at its new place.
Restart the browser after turning the setting on for the first time.

The `key` in `manifest.json` fixes the extension's id in Chrome and Edge, and
`browser_specific_settings.gecko.id` its id in Firefox: the only ids the host accepts. Neither
is a secret (any copy of this folder has them): what makes the app answer is the connection
you allow in it.

## Firefox

The same folder runs in Firefox 153 or later (desktop). Firefox reads `background.scripts`
(an event page) where Chrome reads `background.service_worker`, and ignores `key`,
`minimum_chrome_version` and the `favicon` permission (with a warning on `about:debugging`).

1. Steps 1 and 2 above: the app's setting points Firefox at the host too.
2. Open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on…* and pick
   `manifest.json` in this folder (or the release's zip). It stays until Firefox closes; a
   copy that stays must be signed by Mozilla (see the release notes).
3. In `about:addons`, open the extension's *Permissions* and check that *Access your data for
   all websites* is on (the content scripts need it on https pages).
4. Click the extension's button and choose *Connect*, as above.

What differs in Firefox:

- **No card in pages.** Firefox can't tell a frame in a page whether something covers it
  (IntersectionObserver v2's `isVisible`), and a click in the card counts only when the
  browser says it was in full view. So nothing is drawn inside pages: fill from the
  extension's window (the toolbar button or Ctrl+Shift+L), which offers the logins of the site
  in front. After a sign-in Vault could save, the toolbar button shows **1**; its window
  offers *Save* or *Update* (with the vault open; while it is locked, the offer waits there
  until it is unlocked or two minutes pass).
- **Passkeys:** making one and signing in with one work as in Chrome (Vault's own window).
  A site's passkey suggestions in a field stay Firefox's own, since they would be listed in
  the card under the field.
- **Site icons:** Firefox has no `favicon` cache for extensions: the first letter of the site
  shows instead.
- **Firefox's own saving:** "Vault offers to save passwords, not the browser" turns off
  Firefox's *Ask to save passwords* the same way (the `privacy` permission).

## Files

| File | Role |
|---|---|
| `manifest.json` | Manifest V3 for Chrome, Edge and Firefox: `activeTab`, `scripting`, `nativeMessaging`, `storage`, `favicon` (Chrome, Edge), `privacy`; https pages for the content scripts |
| `popup.html`, `popup.css`, `popup.js` | The extension's window: this site, all logins, generator, new login |
| `content.js`, `fields.js` | Content script: sign-in and new-password fields, submitted forms, placing the frame |
| `inline.html`, `inline.css`, `inline.js` | The frame under a field (logins, the site's passkeys, or a new password) and the save offer |
| `background.js` | The worker between the content script, the frame and the app |
| `passkeys-page.js` | In the page's own world: stands in front of `navigator.credentials` for passkeys |
| `passkeys.js` | Content script: relays passkey requests between the page and the worker, and holds a request for a field's suggestions while it waits |
| `passkey-worker.js` | The worker's side of passkeys: asks the app, opens the passkey window, answers the page |
| `passkey.html`, `passkey.css`, `passkey.js` | The passkey window: the site, its passkeys or the one to make, the item lock's check |
| `app.js` | Native messaging calls, and the login waiting to be saved |
| `link.js` | The connection key (a non-extractable browser key) and the signature on each request |
| `fill.js` | The function that types a login into the page (top frame, same origin) |
| `generator.js` | Reads a field's password rules for the app's generator |
| `tokens.css` | Colours and shared pieces (the desktop app's tokens) |
| `_locales/en/messages.json` | Every text shown |
| `test/*.test.mjs` | Tests: `node --test apps/extension/test/fill.test.mjs apps/extension/test/fields.test.mjs apps/extension/test/background.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs` |
| `test/preview.html` | Visual review of the window and the frames with fixed test data |
| `test/pages/clickjacking.html` | Manual test page that tries to steal a fill |

Plain JavaScript on purpose: no build step and no packages, so what is reviewed in this folder
is exactly what the browser runs.
