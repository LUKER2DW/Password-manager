# Browser extension (Chrome, Edge, Firefox)

Fills, shows and saves logins from the desktop app, and suggests strong passwords. It keeps
no passwords and does no cryptography of its own: it asks the app on the same computer. The
browser starts the desktop app's own program (`vault-desktop.exe`) as its native messaging
host, which relays each message to the app's window over a pipe and shows nothing itself.

Status: alpha, like the rest of the project (added from the desktop app and loaded unpacked;
not in a store yet). Test with a test vault.

## What it does

- **Connect once.** The first time you open it, it offers *Connect* and shows an
  eight-character code. The app comes forward with the same code: if the two match, type your
  master password there (in the app, never in the browser).
  The extension then holds a connection key (never a password), agreed with the app without
  sending it, and seals every request with it; the app seals its answers the same way.
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
- **Its window** (the toolbar button or Ctrl+Shift+L) has four tabs, and says above a list
  what Vault will ask for (your PIN, your item password, or Windows Hello where the app offers
  it) before anything is shown, copied or filled:
  - *This site*: the logins for the page in front, to fill; *Code* fills a login's one-time
    code; the arrow opens the login.
  - *All logins*: search the whole vault; open a login to show its password (as text you can
    select, back to dots after 15 seconds) or its one-time code (with a ring counting down,
    back to dots when it runs out), copy username, password or code, or fill it. *New* adds
    a login by hand.
  - *Codes*: every login with a one-time code, each behind dots and an eye, with *Copy*, and
    *Fill* for the page in front.
  - *Generator*: a password from the app's generator, made again while the length slider
    moves (4 to 128 characters, or 3 to 20 words), with its strength in a word and in bits;
    *Copy* or *Use for a new login*. It works with the vault locked too: making a password
    needs no vault, and one you used joins the app's history once the vault is open again.

  Nothing shown is kept: it goes after its time, when the window shows something else, and
  when it closes. *Lock* at the bottom locks the vault in the app. When the browser's worker
  has learned of a newer extension, a notice at the top says so (with *Update now* where it
  can put it in place itself).
- Copying is done **by the app**: the value never reaches the browser, it stays out of
  Windows clipboard history, and it is cleared after the time set in the app.
- **Site icons** come first from the app, when its Settings → Website icons is on: the icons
  it fetched itself and keeps sealed with the vault, handed over as pictures (`icons`); the
  extension fetches nothing for them. Otherwise, from the browser's own cache of the pages it
  has shown (a few likely pages of the site are tried, the page in front first); nothing is
  fetched from the sites. A site with no icon keeps its initial on the colour the app gives it.
- **Cards** (F5): a payment field (marked `cc-*` for the browser's autofill, or named like a
  card's number, expiry, security code or holder) gets the vault's cards under it: the brand
  and last four digits, the name and expiry, never the number. Picking one asks the app for
  that card (with Windows Hello or the item lock's PIN when it is locked, or when every use
  asks), and types it into every payment field of the page's own documents. Fields in a
  frame of another site (a payment provider's, inside a shop's checkout) get it only once you
  allowed that site's frames for this site: the card asks *Fill there?* with the same click
  check as everywhere in the frame, and the app keeps the answer with the site's rules
  (Settings → Browser extension → Site rules, where *Stop* takes it back). A frame of a site
  not allowed is named, never filled; a sandboxed one is nobody's. The extension's window
  lists the cards under the site's logins too. Addresses wait for identity items (F7).
- **Rules for a site** (F16): *Never offer to save a login here*, *No card under its fields*,
  *Never fill here*, *No passkeys from Vault here*, for the site in front and the sites under
  it, under *Rules for this site* in the extension's window or in the app (Settings → Browser
  extension → Site rules). The app keeps them on this computer and refuses what they forbid,
  locked or not; it says in its window when the extension changed one.
- **A reused or leaked password** (F18): the save card says when the password typed is that
  of other logins in Vault, or turned up in data breaches. The breach check is the app's leak
  check (5 characters of the password's SHA-1 leave the computer), asked only while the leak
  watch is on in the app.
- **Password rules from a list** (F19): a new-password field that doesn't say what the site
  accepts gets the rules of the `password-manager-resources` list built into the app.
- **A site's word about its passkeys** (F23, the WebAuthn Signal API): when a site says a
  passkey is gone (`signalUnknownCredential`), which passkeys it still accepts
  (`signalAllAcceptedCredentials`) or the account's new names (`signalCurrentUserDetails`),
  the app notes it on the passkey's item page, and you remove it, take the names, or keep it.
  Nothing is deleted or renamed by itself. The browser's own handler is told too, where it has
  one.
- **Works with the vault locked** (the app must be running, the window may be closed to the
  notification area): logins are listed and each fill asks for Windows Hello. Turn it on or
  off in the app: Settings → Browser extension → Fill with Windows Hello while the vault is
  locked. It needs Windows Hello on in Settings → Item lock.
- Generated passwords you used are listed in the app's Generator page (encrypted with the
  vault on this computer, behind the item lock), with *Clear history*.
- **Warnings about the wrong site** (in Firefox, which draws nothing in pages: a **!** on the
  toolbar button, and the warning in the extension's window):
  - *Check the address*: on a page with no login of its own that only looks like a site you
    have a login for (`paypa1.com`, `pаypal.com` with a Cyrillic `а`, `paypal-login.com`,
    `paypal.com.evil.example`), the first sign-in field you focus gets a card that names both,
    and the extension's window says the same in place of "no login". The save card says it
    too. The page's name is shown as `xn--…` when it mixes scripts.
  - *This password is for …*: a password you paste into a password field that is the password
    of a login saved for another site gets a card under the field naming that site, with
    *Remove it* (empties the field) and *Keep it*. Sent from a sign-in form, the card in the
    corner says *You sent the password of …* and to change it there; no save is offered for it.
  - *Never type your emergency kit's keys into a website*: the Secret Key and the recovery
    parts (`S0-…`, `A0-`/`B0-`/`C0-…`, and `R0-…` of older kits) are refused in every page,
    frames too: a paste or a drop is stopped before the page hears of it, one typed by hand is
    taken out of the field, and the corner says why. No site is an exception.

  The app decides, from the vault's own sites: nothing is downloaded and the extension keeps
  nothing. The first two follow the app's Settings → Browser extension → "Warn when a page
  isn't the site a password belongs to" (on by default); the kit's keys are always refused.
- **An AI agent or a program driving the browser**: nothing is shown in pages (no card under
  fields, no save card, no passkeys among a field's suggestions, no warning drawn), as in
  Firefox: the extension's window fills, saves and copies, with its usual checks, the toolbar
  button marks a login waiting to be saved (**1**) or a warning (**!**), and Vault's passkey
  window still answers a site's request. It happens by itself when the browser says a program
  drives it (`navigator.webdriver`: WebDriver, a headless browser, Chrome started for
  automation), and when you turn on *An AI agent or a program is using this browser* in the
  extension's Settings (kept until you turn it off). Cards already on screen go at once.

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
  each fill. With its warnings about other sites off (`"warns": false`), the extension sends
  nothing to compare, reads nothing typed or pasted for them, and the app names no lookalike.
- **Warnings:** a password pasted into a password field, or sent from a sign-in form, goes to
  the app (`elsewhere`) only to be compared with the passwords of the other sites' logins, and
  is kept neither there nor in the worker. The answer is a site's name at most, never which
  login; logins behind the item lock are never compared, a page whose owner has one gets no
  warning (the password may be that one), nor does one of the login's own owner
  (`mail.example.com` for `example.com`), nor a password shorter than six characters. Only a
  paste of yours counts, not one a page script makes up. The frame gets the site's name from
  the worker, never from its own address (which the page can change). The page can see that a
  warning appeared: it then knows the password it was just given is another site's in your
  vault, not whose. With saving left to the browser and the warnings on, a sign-in is still
  read to be compared, and then dropped.
- **The kit's keys:** `kit.js` runs in every https document, frames too, at `document_start`,
  in the extension's isolated world, ahead of the page's scripts: it listens on the window in
  the capture phase, so a paste or a drop of a key is stopped (`preventDefault`,
  `stopImmediatePropagation`) before the page's own listeners run. It knows the keys by their
  printed shape only (the app's own rule, `crates/browser/src/kit.rs`, the same test keys on
  both sides), holds nothing, and tells the worker only that it refused one. A key typed by
  hand is taken out of the field as its last character comes: the page may have heard every
  key press before that.
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
- A sandboxed document (opaque origin, "null", at the site's address: a `sandbox` frame or a
  `Content-Security-Policy: sandbox` header) is not the site: the content scripts stay
  silent there, a fill refuses it, the worker ignores its messages, and its passkey requests
  go to the browser.
- A login behind the item lock (every item, by default, for new vaults) needs **Windows Hello**
  (the system's own prompt) or the item lock's PIN, typed in the extension's window, for each
  fill, show or copy. Five wrong tries lock the vault, as in the app.
- The frame in pages is the extension's own page in a cross-origin iframe: the page can't read
  or script it. A click there counts only once the browser reports the frame fully visible,
  with nothing drawn over it (against extension clickjacking). It never shows a password
  except a freshly generated one. Its address is the browser's for this session
  (`use_dynamic_url`, Chrome 130 and later; made only with `chrome.runtime.getURL`): it
  doesn't carry the extension's fixed id, and a page can't load `inline.html` at that id to
  learn that Vault is installed. Chrome serves it from the extension's own address, so the
  worker knows the frame by either (`isFrameUrl`), and a change of the address (the card
  moving above its field) loads the frame again, its click check starting over. Firefox
  ignores the key (a warning on `about:debugging`): its extension address is a random id per
  profile already, and it draws no frame in pages.
- While an agent or a program drives the browser (above, `agent.js`), the content script draws
  nothing and takes away what it drew, the frame takes no click (one drawn by a copy of the
  content script from before an update), and the worker answers no frame while the setting
  is on. The setting is in `chrome.storage.local` (the content scripts read it there; the
  session storage, which holds the logins waiting to be saved, stays closed to them), and
  until it is read it counts as on. `navigator.webdriver` is read in the extension's isolated
  world, which a page's scripts can't change; an agent can hide it, and no other standard sign
  of an agent exists, so the setting is there for those.
- **Versions:** the extension names its version (its manifest's) when it connects and inside
  every sealed request; the app answers only one of the version it accepts or later
  (`MIN_EXTENSION_VERSION`, `crates/browser/src/protocol.rs`). An older one hears
  `outdated_extension`: a copy in the app's folder reloads itself into the newer one the app
  names in that answer, any other copy says *Update the extension* (in Vault, Settings →
  Browser extension → Add to a browser writes the newest into its folder). The extensions
  of releases up to 0.4.7, which signed their requests instead of sealing them and were handed
  their key when they connected, are refused that way.
- A login typed into a page waits in the browser's memory (never on disk) for at most two
  minutes, and goes to the app to be kept only if you choose *Save* (before that only to be
  compared with other sites', while the app's warnings are on). Before offering an update, the app
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
  them. With saving left to the browser and the app's warnings off (above), nothing typed is
  read at all.
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

## Install

The desktop app writes the extension into a folder of its own,
`%LOCALAPPDATA%\vault\browser-extension`, which the browser loads. Where the files come from:

- **By default, the newest GitHub release** of the project: its `vault-extension-<version>.zip`,
  downloaded when the app looks for its own updates (Settings → About, every hour and on
  *Check for updates*), taken only when its SHA-256 is the one GitHub's release list gives for
  it, and unpacked strictly (no name outside the folder, no links, size limits). The zip is
  kept next to the folder.
- **The copy built into the app** (`apps/desktop/build.rs`: what the release's zip holds, that
  is this folder without `test/`, `package.json` and this README), whenever it is newer than
  the release kept, or nothing was downloaded yet, or there is no network.
- **A folder on this computer instead** (*Use a folder on this computer instead…*, for someone
  who changes the extension): one with a `manifest.json` at its top, read with the same rules;
  the app copies it into its own folder and follows the changes made to it. *Use the extension
  from GitHub* goes back to the default. The card says which source is in use, and its version.

1. Run the app (a release's `vault-desktop.exe`, or `cargo run --release -p vault-desktop`)
   with a test vault and turn on **Settings → Browser extension**. This writes the host's
   manifests (pointing at this `vault-desktop.exe`; one for Chrome and Edge, one for Firefox)
   under the app's data folder and points Chrome, Edge and Firefox at them (one registry value
   each, for your Windows user). Turning it off removes them.
2. On the same page, **Add to a browser** offers the browsers installed (Chrome, Edge, Brave,
   Opera, Opera GX, Vivaldi, Firefox), each with its icon, your default one first. *Add to …*
   writes the folder, copies its path, starts that browser on its extensions page
   (`chrome://extensions`, `edge://extensions`…, Firefox's
   `about:debugging#/runtime/this-firefox`) and shows the steps: turn on *Developer mode*,
   choose *Load unpacked* and paste the path. Pin the extension to the toolbar. *Open the
   folder* shows it in Explorer.
3. Click the extension and choose *Connect*. In the app, type your master password and choose
   *Connect*. Done.

Why by hand: Chrome and Edge add an extension from outside their stores only when the person
loads it (or a company's policy forces it); `--load-extension` is ignored by branded Chrome
since version 137; and the registry entries that install an extension
(`Software\Google\Chrome\Extensions\<id>`) only work for one hosted on the Chrome Web
Store. Firefox keeps only add-ons signed by Mozilla. Sources:
<https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions> (on
Windows the registry's `update_url` must be the Web Store's),
<https://groups.google.com/a/chromium.org/g/chromium-extensions/c/1-g8EFx2BBY>
(`--load-extension` removed from branded builds),
<https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/>.
Publishing in the stores is the next step (docs/IMPLEMENTATION_PLAN.md, F12).

**Updates, with no step of yours.** Each new version of the app brings the extension's: when
it starts, before its browser link answers anything, the app writes the extension in use
(the newest of the release kept and the copy built in) into the folder; when it takes a newer
release, it writes that. Every five minutes while the link runs, a file that differs is put
back (another program changed it; the app says so). The app names the version in use in its
answers to `status` and `logins` (`extension_version`), so the extension notices a new one at
its next request (a sign-in field, its window), and also asks `status` when its worker
starts, at most every ten minutes. When that version is newer it reloads itself
(`chrome.runtime.reload()`), which reads the folder again (`update.js`). It tries once per
version, and waits while a login waits to be saved or the extension's window or the passkey
window is open: `chrome.storage.local.extensionUpdate` is then `{ version, manual: false }`,
and the window's `{ kind: "apply-update" }` reloads it. A copy loaded from anywhere else (this
folder, the release's zip) stays as it is: after one reload it is marked
`{ version, manual: true }`, to be updated by hand. Pages already open keep the old content
script until they are reloaded.

For development, *Load unpacked* this folder (`apps/extension`) instead, and click the reload
arrow on the extension's card after a change.

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
`minimum_chrome_version`, `use_dynamic_url` and the `favicon` permission (with a warning on
`about:debugging`).

1. Step 1 above: the app's setting points Firefox at the host too.
2. Add to a browser → Firefox opens `about:debugging#/runtime/this-firefox`: choose *Load
   Temporary Add-on…* and pick `manifest.json` in the app's folder (its path is copied). It
   stays until Firefox closes; a copy that stays must be signed by Mozilla. A temporary add-on
   reloads from its folder too, so it takes the app's new versions while it is loaded.
3. In `about:addons`, open the extension's *Permissions* and check that *Access your data for
   all websites* is on (the content scripts need it on https pages).
4. Click the extension's button and choose *Connect*, as above.

What differs in Firefox:

- **No card in pages.** Firefox can't tell a frame in a page whether something covers it
  (IntersectionObserver v2's `isVisible`), and a click in the card counts only when the
  browser says it was in full view. So no card to act on is drawn inside pages: fill from the
  extension's window (the toolbar button or Ctrl+Shift+L), which offers the logins of the site
  in front. After a sign-in Vault could save, the toolbar button shows **1**; its window
  offers *Save* or *Update* (with the vault open; while it is locked, the offer waits there
  until it is unlocked or two minutes pass). The warnings about the wrong site aren't drawn in
  pages either: the toolbar button shows **!**, and its window says what the page was warned
  about (a page that only looks like a saved site, another site's password pasted or sent
  there, a key of the kit refused).
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
| `manifest.json` | Manifest V3 for Chrome, Edge and Firefox: `activeTab`, `scripting`, `nativeMessaging`, `storage`, `favicon` (Chrome, Edge), `privacy`; https pages for the content scripts; `inline.html` the one page a page may load, at this session's address only (`use_dynamic_url`) |
| `popup.html`, `popup.css`, `popup.js` | The extension's window: this site, all logins, codes, generator, new login, settings |
| `popup/*.js` | Its views (`site.js`, `vault.js`, `entry.js`, `codes.js`, `generator.js`, `new-login.js`, `prefs.js`, `pairing.js`) and the rules they share, each testable on its own (`throttle.js`, `countdown.js`, `asks.js`, `cells.js`, `strength.js`, `options.js`, `version.js`, `tint.js`, `icon-pages.js`, `site-rule.js`); `rules.js` the site's rules, `cards-view.js` the cards for the page in front, `favicons.js` the icons (the app's first) |
| `content.js`, `fields.js` | Content script: sign-in and new-password fields, submitted forms, a password pasted into a password field, placing the frame and the warnings |
| `kit.js` | Content script in every https document, frames too, at `document_start`: the emergency kit's keys refused in pages |
| `agent.js` | Whether an AI agent or a program drives the browser (`navigator.webdriver`, or the person's setting): loaded before `passkeys.js`, `content.js` and `inline.js`, which then show nothing in pages |
| `inline.html`, `inline.css`, `inline.js` | The frame under a field (logins, the site's passkeys, or a new password), the save offer, and the warnings (a lookalike page, another site's password pasted or sent, a key of the kit) |
| `background.js` | The worker between the content script, the frame and the app |
| `passkeys-page.js` | In the page's own world: stands in front of `navigator.credentials` for passkeys |
| `passkeys.js` | Content script: relays passkey requests between the page and the worker, and holds a request for a field's suggestions while it waits |
| `passkey-worker.js` | The worker's side of passkeys: asks the app, opens the passkey window, answers the page |
| `passkey.html`, `passkey.css`, `passkey.js` | The passkey window: the site, its passkeys or the one to make, the item lock's check |
| `app.js` | Native messaging calls, and the login waiting to be saved |
| `update.js` | Keeps the extension as new as the app: reloads itself from the app's folder when the app carries a newer version, or says to update it by hand |
| `link.js` | The connection key (agreed with the app by ECDH, kept as a non-extractable browser key), each request sealed with it, and each answer opened, sealed by the app to its request |
| `fill.js` | The function that types a login into the page (top frame, same origin) |
| `card-fill.js` | The payment fields of a document, and the function that types a card into them (each document it may: its origin checked there) |
| `cards.js` | Which documents of a tab get a card (the page's own; another site's frames once approved for this site), and the fill itself, for the worker and the window |
| `signals.js` | A site's Signal API call, checked and bounded for the app |
| `generator.js` | Reads a field's password rules for the app's generator |
| `tokens.css` | Colours and shared pieces (the desktop app's tokens) |
| `_locales/en/messages.json` | Every text shown |
| `test/*.test.mjs` | Tests: `node --test apps/extension/test/fill.test.mjs apps/extension/test/fields.test.mjs apps/extension/test/background.test.mjs apps/extension/test/link.test.mjs apps/extension/test/generator.test.mjs apps/extension/test/passkeys.test.mjs apps/extension/test/popup.test.mjs apps/extension/test/update.test.mjs apps/extension/test/kit.test.mjs apps/extension/test/cards.test.mjs` |
| `test/preview.html`, `test/preview-app.js` | Visual review of the window and the frames with fixed test data (a stand-in for the app through an import map) |
| `test/pages/clickjacking.html` | Manual test page that tries to steal a fill |

Plain JavaScript on purpose: no build step and no packages, so what is reviewed in this folder
is exactly what the browser runs.
