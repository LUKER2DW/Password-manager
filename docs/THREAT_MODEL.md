# Threat Model

> Status: **draft**, reviewed as features land. This document defines what the project protects against
> and, just as honestly, what it **cannot** protect against.

## 1. Primary security goal

> An attacker who obtains a copy of the vault file (from disk, a backup or the sync server)
> **must not be able to extract any useful information** from it: no passwords, no site names,
> not even the approximate number of items. This must hold even with practically unlimited time
> and computing power.

This works because the vault key depends on **factors that are never in the file**:

| Factor | Where it lives | Why it matters |
|---|---|---|
| Master password | The user's memory | Something you know |
| Secret Key (128 random bits) | Enrolled devices + printed emergency kit | Makes offline brute force infeasible even with a mediocre master password |
| Hardware key (FIDO2 `hmac-secret`), optional | YubiKey or similar | Something you have; requires a physical touch |
| Keyfile, optional | Separate file | Extra factor, KeePass-style |

With the Secret Key, the search space is at least 2^128 **multiplied** by the Argon2id cost, so
the file on its own is useless.

**When a copy was opened anyway.** A stolen copy together with the kit, or with the master
password and Secret Key caught on an infected computer, opens. Whoever opened it holds that
copy's vault key, and a new master password, Secret Key or kit doesn't change the vault key
(only the slots that wrap it): with it they would open every newer copy too (a backup made
later, the sync server's copies). **Renewing the vault key** (CRYPTO.md §3.8) is the answer:

- it stops the old factors, the old kit and the vault key of any older copy from opening any
  copy written from then on; every other device takes the new key once, with the new Secret
  Key and the master password (SYNC.md §4.7);
- it can't take back what was already read: the older copy still opens with its own factors
  and kit, and the passwords in it must be changed on their websites. Other older copies
  (backups, the `.bak` next to the file until the next save, a server's old copies) still open
  the same way, and a device that hasn't taken the new key yet still writes its copy under the
  former one;
- it doesn't help while malware is still on the device: the new Secret Key is kept there and
  the master password is typed there. Clean the device first, then renew.

Renew after a kit was lost or seen, after a device with the vault was stolen, or after malware
was removed. It is done on a computer (the desktop app's Emergency kit page or
`vault renew-key`), where the new kit is printed.

## 2. Adversaries

| # | Adversary | Capability | Protected? |
|---|---|---|---|
| A1 | File/backup thief | Copy of the vault, unlimited offline brute force | **Yes**, the primary goal |
| A2 | Compromised sync server | Reads, modifies, reorders, rolls back and replays data; responds maliciously | **Yes**: the server is untrusted (lessons from the ETH Zurich 2026 study) |
| A3 | Network attacker | MITM, replay | **Yes**: end-to-end encryption plus TLS |
| A4 | Malicious website / phishing | Fake pages, iframes, clickjacking, DOM manipulation | **Yes**: autofill bound to the exact origin, confirmation outside the page DOM |
| A5 | Malicious Android app | WebView hosting a third-party login (AutoSpill) | **Yes**: app package and signature validation |
| A6 | Physical access to a **locked** device | Stolen PC or phone | **Yes**: vault encrypted; quick unlock rate-limited by hardware (TPM/StrongBox) |
| A7 | Malware while the vault is **locked** | Reads disk, keylogger | **Partially**, see §3 |
| A8 | Malware while the vault is **unlocked**, running as the user | Reads process memory, screen, clipboard | **Mitigated only**, see §3 |
| A9 | Malware with administrator/kernel privileges | Full control of the machine | **No**, no software can defend against this |
| A10 | Someone on the network who reaches the sync server, with no device key | Floods it, opens connections and never finishes a request, sends huge or slow requests, guesses invites, races requests, uses a leaked admin invite | **Yes**: unsigned requests and failures are rate-limited per address (an IPv6 /64 counts as one), a copy is read only once its whole signature is checked (64 KiB for any other body), open connections are capped in all and per address and closed when the headers or the reading of an answer stall, requests in flight and their time are capped, invites are 128 random bits used once under one lock, an admin invite only starts a new vault, an enrolled device's place can't be taken by another enrollment (docs/SERVER.md, "How it holds up") |
| A11 | A website saved in the vault, with the website icons on | Its page links to, or redirects to, this computer or the local network (a router's page, a service on localhost) | **Yes**: a site on the internet makes the icon fetcher reach public addresses only, checked at each name lookup; a site saved with a local address is asked only where its name pointed when the fetch began |

## 3. Malware: the most realistic scenario

Common infostealers mainly steal **passwords saved in the browser** and **session cookies**.
Moving passwords out of the browser into a well-designed vault already removes most of that risk.
On top of that:

**Vault locked (A7)**
- Nothing in plaintext on disk; no password cache.
- A keylogger may capture the master password, **but it cannot open the vault on its own**: it
  also needs the Secret Key (protected by the OS) and, if configured, the hardware key with a
  physical touch.
- Quick unlock (Windows Hello / biometrics) avoids typing the master password day to day, which
  reduces keylogger exposure. What it does and doesn't protect:
  - The file it keeps (`quick-unlock-*.bin`) is useless when copied: it needs this PC's TPM.
  - Malware running as the user *can* ask Windows Hello for the same signature, but Windows then
    shows its prompt and the user must pass it; an unexpected Hello prompt is a warning sign.
  - **Anyone who knows the Windows PIN can open the vault on this PC.** The TPM limits guesses,
    the master password is still required every 14 days, and changing the master password
    revokes it. Users who share or reuse their PIN should leave quick unlock off.

**Vault unlocked (A8)**: shrink the window and the attack surface.
- Aggressive auto-lock (inactivity, screen lock, sleep).
- Secrets stay encrypted **per item** in memory; only the item in use is decrypted, and it is
  wiped right after (`zeroize`).
- Sensitive memory is locked (`VirtualLock`/`mlock`) so it does not reach the pagefile or
  hibernation file (lesson from KeePass CVE-2023-32784).
- A custom master-password input that does not leave copies of the string in memory.
- Window excluded from screen capture (`WDA_EXCLUDEFROMCAPTURE` on Windows, `FLAG_SECURE` on Android).
- A memory bug is harder to turn into control of the app: the Windows programs have ASLR with
  a high-entropy address space, DEP and Control Flow Guard (an indirect call to anywhere but
  the start of a function stops the program; `.cargo/config.toml`), and every release checks
  each exe for them (`apps/desktop/check-exe.ps1`). Control Flow Guard covers our code and the
  C compiled with it (ring, SQLite), not the standard library or Skia, which come
  precompiled. Most of the code is safe Rust, where such bugs can't happen to begin with.
- Clipboard: automatic clearing and exclusion from Windows clipboard history and cloud sync.
- Optional re-prompt: critical items (bank, primary email, crypto) require a fresh check
  on every use. Implemented as the item lock: the master password (re-derived against the
  file), a PIN or another password, with the vault locking after five wrong tries. A PIN or
  password also encrypts the locked secrets under its own key (format v6), which keeps them
  from malware that reads an unlocked vault until the user opens them; Windows
  Hello or a hardware-key touch as the check comes later. Adding a new item asks for nothing,
  so saving a login stays one click: the new item is sealed under the item lock's key the
  next time the lock is opened, and until then a program reading the unlocked vault's memory
  could read that one item.
- The browser extension stores no secrets; it asks the native app for each credential. The
  app decides whether the page's origin is the login's, and announces every fill. Logins are
  picked in the extension's own window or in a small frame under a sign-in field.
  Requests are accepted only from the extension the person connected (pairing), and a
  locked login needs Windows Hello or the item lock's PIN for each fill. To connect, the
  person types into the app the six-digit code the extension's own window shows, then the
  master password. The app never shows that code: any program that asks the app to connect
  is told the code too, so only the code read off the extension's window ties the approval
  to the extension. A program that sends its own request gets a dialog the person can't
  complete without a matching code.
  Known limit: a program already running as the same Windows user can copy the browser's
  stored data, pairing key included, and then ask like the extension does. It gets nothing while the vault is locked and
  nothing behind the item lock. Filling needs the exact site of the login; showing or copying
  a password from the extension's window does not (it goes by the item, as in the app), so
  with the vault unlocked such a program can read every login outside the item lock. Each
  one shows a notice in the app. The same program could already read an unlocked
  vault's memory, so the link adds no new reach, but it is one more reason for the item lock.
- **The frame shown inside pages** (since extension 0.2) brings back the risk the extension's
  own window avoided: a page can draw over it, make it see-through or move it under the
  pointer (extension clickjacking). What limits it: the frame is the extension's page in a
  cross-origin iframe, so the page can't read or script it; a click counts only once the
  browser has reported the frame fully visible, with nothing over it, for 400 ms
  (IntersectionObserver v2), and a mouse click only once the pointer has rested on the card
  for 150 ms (a frame slid under the pointer takes no click meant for the page); the card
  shows nothing inside a frame of the page (an advert, a widget), only directly in the page
  whose logins it lists; it shows usernames, never passwords; a fill goes only into the
  site the login is saved for, top frame only, and into the field the card was shown under
  and that field's own form (each card is one offer: its id is in the frame's address, which
  the page can read, but what it stands for, the field, its form and where that form sends, is
  kept in the extension's isolated world, out of the page's reach): nothing is typed when the
  page has since moved the field into another form, changed where the form sends (its action,
  a submit button's `formaction`, the page's `<base>`) or made it send over plain `http:`;
  fields outside any form go together only when they sit next to each other; and a locked login still needs Windows Hello
  (the system's own prompt, which a page can't click) or the PIN, typed in the extension's
  window. New vaults lock every item by default for that reason. The site's icon in the frame
  comes from the browser's own cache (`favicon` permission): nothing is fetched for it.
  The card is drawn half see-through inside the frame, with no blur: a blur, clip or opacity
  on the frame itself would make the browser stop vouching for its visibility (checked:
  `isVisible` turns false), and the click check would refuse every click. Residual risk: a site with
  an XSS flaw can read what is filled into its own page, as it can read what the person types.
- **The `privacy` permission** (extension 0.3) is used for one browser setting only: Chrome's
  "Offer to save passwords and passkeys", turned off while the person leaves saving to Vault
  (the default, changed in the extension's Settings; Chrome's own settings show that the
  extension controls it and can take it back). It reads and changes no other setting. Two
  password managers offering to save the same login invite saving it in the browser's store,
  which an infostealer reads more easily than the vault.
- **Passkeys** (extension 0.4): a script in each https page's own world (top frame only)
  stands in front of `navigator.credentials` and passes a passkey request, as plain data, to the
  extension. It needs no new permission, and holds nothing of the vault: it gets back only
  what WebAuthn would give that page. What keeps a page from using another site's passkeys:
  the page's address is the tab's own, as the browser reports it; the app decides which site
  (relying party id) that page may speak for (its own host or a domain above it that is not a
  public suffix) and writes the signed client data with that origin itself; and an answer is
  handed back only while the tab still shows that origin. Nothing is made or signed until the
  person chooses in a window of the extension's own (a page can't draw over it or click in it),
  and a login behind the item lock asks for its check there too. The window names the page
  that asks and, when it is another name, the site its passkey belongs to as the app checked
  it, so a subdomain can't pass for its parent (while the vault is locked the app hasn't
  checked one, and the window names the page alone, never a site the page wrote). The app is asked to make or sign only while the very document
  that asked (same tab, document and origin) still waits for that request and passkeys are
  still Vault's, and that is checked again before the answer goes back; a passkey already
  made for a page that went away stays in the vault, and the window says so (and, when it
  took the place of the account's earlier passkey, as a security key does, that the earlier
  one is gone too: the site may still expect it). A page can ask
  again and again, but only one window is open per tab, and closing it says no. A page can also see that
  something stands in front of `navigator.credentials` (that Vault is installed), as it can
  with other password managers. Residual risk: a site with an XSS flaw can ask for its own
  passkey, as it could from the browser's own passkeys, but still needs the person's click.
- **What a page sends when a form is submitted**: the content script reads the typed username
  and password (in the extension's isolated world) and passes them to the background worker,
  which keeps them in `chrome.storage.session` (memory only, closed to content scripts) for
  at most two minutes, until the person answers "Save this login?". They reach the app only if
  the person says Save; a page can't trigger the save by itself (same visibility check). Only
  the form the person sent is read (a help link, an eye button or a button of another form
  reads nothing), and only after the person's own act in that form: a made-up click or key
  press is ignored, and a form's `submit`, which the browser reports as the person's even when
  a page script asks for it (`requestSubmit()`), counts only within a few seconds after the
  person's click or Enter in that same form, one submit per act. Save acts on the one offer its card
  shows, for the site it was typed on, and an update only for the version of the login the
  app compared and its username (a login changed since is not overwritten). Turned off in the
  extension's Settings, nothing typed is read, kept or compared at all. A save or an update is answered as done only once the vault file
  is written: when it can't be (the file changed elsewhere, the disk refused it), the app puts
  the open vault back as it was and says "not saved".
- **The phone's QR code scanner** is Google's (Play services' code scanner): the camera
  screen runs in Play services, the app has no camera permission and gets back only the
  code's text. That text (the invite) passes through Play services on the phone; it opens
  nothing by itself. What is read is treated like a pasted line: an invite works once,
  within an hour, and the phone still needs the master password and the Secret Key. Residual risk: someone who films the computer's screen while
  the invite is shown can use it within the hour to enroll a device, which then still can't
  open the vault without the master password and the Secret Key. A one-time code's setup key
  scanned the same way passes through Play services too, as it would through any authenticator
  app's scanner.
- **Unlocking the phone app with the phone's screen lock** (Android 11+, when the person turns
  on unlock with the phone): the Keystore key that opens the vault answers to a strong
  fingerprint or face, or to the phone's PIN, pattern or password. Someone who knows that PIN
  and has the phone in hand can open the vault, for up to 14 days after the
  last master password (turning fingerprint unlock off and on again doesn't start them anew,
  and a clock moved back counts as too long ago); guesses are rate-limited by the phone's secure hardware, but a 4-digit
  PIN is weaker than a master password. It is the person's choice in Settings, Security, and
  the master password always works.
- **Previews of attached files on the phone**: pictures and text are decoded in the app's own
  memory. A PDF is drawn by Android's renderer, which needs a file: the decrypted PDF sits in
  the app's private cache (closed to other apps) while its pages are drawn, then is overwritten
  and deleted, and a leftover is wiped at the next start. Nothing is handed to another app.
  Residual risk: the renderer is Android's code, run on whatever PDF was attached.
- **The phone in the recent apps view** shows no picture of the app's screen (Android 13+
  turns it off for the app; before that, the secure flag is set while the app is in the
  background), so an open vault isn't on show to someone who looks over the app switcher,
  whether or not screenshots are allowed.
- **Sensitive changes on an unlocked phone** (adding or removing a device, stopping sync,
  removing the backup server, removing the vault from the phone) ask for the master password
  again, checked against the vault file: someone who picks up the phone while the vault is
  open can read it until it locks, but can't change who syncs it.
- **SSH keys with a passphrase** are opened once, with the passphrase typed in the app (a
  secure field, never kept), and kept without it, as other managers keep them: the vault is
  their protection, and a key copied out of the app works without a passphrase. Whoever
  opens the vault can use the key, as with any password in it; the item lock can guard it.
- **Generated passwords** come from the app's generator, never from the page or the
  extension. A password the person used is kept in the app's history, sealed with the vault
  key on this computer and shown behind the item lock; "Clear history" deletes it. Copying is
  done by the app, so the clipboard copy stays out of Windows clipboard history. The phone
  keeps its own history the same way (sealed with the vault key next to its copy, masked
  until shown, the last 50).
- **Tray mode** keeps an unlocked vault in memory while the window is hidden; the idle lock
  still applies, and the tray menu locks at once, also while a background job holds the vault.
- **Background jobs** (unlock, password hashing, export, a check of the item lock): each
  result is bound to the session and the vault file it was started for. Locking, or choosing
  another vault, drops it and wipes its keys, so a late result never reopens a vault or writes
  one vault over another; the vault chooser is off while a job runs.
- **The `.vault` file type** is registered for the signed-in user (`HKEY_CURRENT_USER`), so a
  double-click opens the file in the app. A program running as the same user could point it
  at another program, as it could replace the app's shortcut; the file itself stays
  encrypted, and the app only ever asks for the master password in its own window. The
  extension is taken only when no other program has it.
- **Saving while the vault is locked**: a login the person saves from the browser is sealed to
  a public key (libsodium sealed box) whose private key only the open vault reads, and added
  at the next unlock (for a site and username already saved, it updates that login, the old
  password going to its history; behind the closed item lock it waits in the file until the
  lock opens: nothing the browser was told is kept is dropped unread). Nothing is asked for (no PIN, no Windows Hello) and the locked app can't
  read back what it wrote, so the file reveals nothing to someone who copies it. A program
  running as the same user could replace the public key and read later saves; it would
  already see those passwords in the browser as they are typed.
- **Filling while the vault is locked** (setting, on by default; needs the item lock's
  Windows Hello): the passwords of logins sit in a file of their own, under a key that only
  Windows Hello opens (TPM signature after the person is verified), so a locked vault can fill
  one login at a time with the person's face, fingerprint or Windows PIN. The item lock's PIN
  does not open it: a copied file could be tried against every PIN offline, a TPM-backed
  signature can't. The password of a login behind the item lock is sealed to a key only that
  Windows Hello secret opens, so the vault's own key is not a way round it, and each entry is
  bound to the version of the login it was sealed for: a login that changed since fills
  nothing until the vault is opened again. What changes: names, usernames and websites of logins are readable to
  malware running as the same Windows user (DPAPI), as are the extension's connection key
  and the browser's own data; passwords still need Windows Hello. Turning the setting off
  deletes the file.
- **Requests are checked against replay** by counter: the sender's clock in ms × 1000 plus a
  random part; each counter is accepted once and only within two minutes of the app's clock.
  The extension never forgets its connection key by itself; it offers to connect again only
  when the app keeps refusing it.

**Files with secrets outside the vault** (each a deliberate, visible choice):
- Printed emergency kit: the temporary PDF lives in `<app dir>/print` and is overwritten and
  deleted on lock, on exit and at the next start. A kit saved elsewhere with "Save as PDF" is the
  user's file. A filled kit also carries the Secret Key and each recovery part as a QR code
  (black squares in the PDF, no picture), for the phone's scanner: whoever can photograph a
  page could already read the same key printed above its code. A kit with empty boxes, to be
  filled by hand, has no codes.
- Recovery on the phone: the parts are typed or scanned (Google's scanner, as for an invite:
  the text passes through Play services) into secure fields, never into the screen's text.
  With all three parts the vault gets a new master password and a new Secret Key (shown once,
  before it opens), the parts used stop working, and the phone's fingerprint unlock goes, as
  on the desktop.
- Imports: the app offers to overwrite and delete the plain-text export right after importing.
- Unencrypted export: only after re-checking the master password, with a warning; the encrypted
  backup copy is offered first. The phone does the same (master password checked against the
  file, a confirmation, refused while items are behind the item lock), and offers the protected
  export first.

> **Honest limit:** malware running as the user while the vault is unlocked can, in theory, read
> whatever the app decrypts. Complementary defenses outside the vault: passkeys or 2FA on important
> accounts (so a stolen password is not enough) and general system hygiene.

## 4. Out of scope

- OS compromise at administrator/kernel or firmware level (A9).
- Physical coercion of the user.
- Hardware side-channel attacks (Spectre, etc.) beyond what the libraries mitigate.
- Undetected build supply-chain compromise: mitigated (reproducible builds, signed releases,
  dependency auditing) but not eliminated.

## 5. Derived principles

1. **No home-made cryptography**: only standardized primitives from audited libraries.
2. **Encrypt everything**, including titles, URLs, tags and sizes (padding). Metadata leaks information.
3. **Integrity of the whole vault**, not just per field: prevents swapping, removing, reordering
   or rolling back items.
4. **No downgrades**: minimum KDF and algorithm parameters are hard-coded in the client; no legacy modes.
5. **Untrusted server**: it only stores encrypted blobs and never dictates cryptographic parameters.
6. **Biometrics never derive keys**: they only authorize the hardware (TPM/StrongBox) to release a key.
7. **Confirmation out of the page's reach**: no clickable UI injected into the DOM.
8. **Explicit recovery**: a printed emergency kit, its recovery split into three parts kept
   apart (two bring back the Secret Key, three replace the master password, one opens
   nothing). No server-side backdoor.
9. **Network only when asked**: the app contacts nothing by default. Website icons and the leak
   check are opt-in, per action. The leak check is k-anonymous: only 5 hex characters of each
   password's SHA-1 are sent to Have I Been Pwned, with padded answers; matching happens on the
   device. Reading a browser's own password store (the infostealer technique) happens only when
   the user clicks for it, for the signed-in Windows user, in memory; otherwise the user exports
   a file and the app offers to wipe it afterwards. Icons are asked of each site directly, over
   HTTPS, on the site's own port. A site whose certificate isn't trusted (self-signed, as on
   routers and NAS boxes, expired, or for another name) gives no picture: the app only checks
   that it answers without the certificate check, uses nothing it sends, and shows a globe with
   a warning mark. Every image taken (SVG included, drawn without fetching anything it links
   to) is size-limited and decoded by pure-Rust decoders. A site on the internet can't steer
   the fetch into the local network (A11). The leak check follows no redirect.
   Updates: the desktop app and the phone ask GitHub for the newest release every hour while
   they run, and when **Check for updates** is pressed (one anonymous request, no redirect
   followed; nothing about the vault or the device in it, only that someone runs the app at
   that address; a switch beside the button turns the hourly look off). The desktop app
   downloads nothing; the person replaces the program. The phone takes a package from GitHub
   only from github.com and its file store over HTTPS, only when its size and SHA-256 match
   what the release lists, and checks it is this app, newer and signed with the same
   certificate before Android asks to install it; it may take its updates from its sync
   server instead. A sync server follows the releases only when its owner turns it on
   (`--app-updates`): it takes a phone app package only from github.com, only when its size
   and SHA-256 match what GitHub lists, and the phone still checks the package is this app,
   newer and signed with the same certificate before Android asks to install it. GitHub (or
   whoever took the server over) can withhold an update or offer an old one, never one
   signed with another key.
