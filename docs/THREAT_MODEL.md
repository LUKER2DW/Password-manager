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
| A4 | Malicious website / phishing | Fake pages, iframes, clickjacking, DOM manipulation | **Yes**: autofill bound to the exact origin, confirmation outside the page DOM; on the phone nothing offered in a frame of another site than the page, nor in a sandboxed one; warnings for pages that only look like a saved site and for a password given to the wrong site, and the emergency kit's keys refused in every page (§3) |
| A5 | Malicious Android app | WebView hosting a third-party login (AutoSpill) | **Yes**: app package and signature validation |
| A6 | Physical access to a **locked** device | Stolen PC or phone | **Yes**: vault encrypted; quick unlock rate-limited by hardware (TPM/StrongBox) |
| A7 | Malware while the vault is **locked** | Reads disk, keylogger | **Partially**, see §3 |
| A8 | Malware while the vault is **unlocked**, running as the user | Reads process memory, screen, clipboard | **Mitigated only**, see §3 |
| A9 | Malware with administrator/kernel privileges | Full control of the machine | **No**, no software can defend against this |
| A10 | Someone on the network who reaches the sync server, with no device key | Floods it, opens connections and never finishes a request, sends huge or slow requests, guesses invites, races requests, uses a leaked admin invite | **Yes**: unsigned requests and failures are rate-limited per address (an IPv6 /64 counts as one), a copy is read only once its whole signature is checked (64 KiB for any other body), open connections are capped in all and per address and closed when the headers or the reading of an answer stall, requests in flight and their time are capped, invites are 128 random bits used once under one lock, an admin invite only starts a new vault, an enrolled device's place can't be taken by another enrollment (docs/SERVER.md, "How it holds up") |
| A11 | A website saved in the vault, with the website icons on | Its page links to, or redirects to, this computer or the local network (a router's page, a service on localhost) | **Yes**: a site on the internet makes the icon fetcher reach public addresses only, checked at each name lookup; a site saved with a local address is asked only where its name pointed when the fetch began |

### 2.1 A hostile sync place (A2, A3), as tested

A sync folder, a WebDAV host or the person's own server sees only sealed copies, one per
device, and is never trusted with anything that opens or changes the vault. The tests of M10
S14 play such a place from the device's side (SYNC.md §9 lists them): every byte of a copy
altered, copies cut short, empty, garbage, another vault's, an older one served again, one
under another device's name, a removed device's; a server that lies in its listing, answers
what doesn't fit, sends the device elsewhere, hands out an invite that isn't one, never
finishes answering or sends more than any copy can be; a WebDAV host whose listing and files
disagree; a write that fails half-way. They show that:

- nothing is merged from a copy this vault's key didn't seal, nor from a copy found under
  another device's name; a copy older than one already merged from its device is refused as a
  rollback, and an old copy never seen past takes back nothing that changed since;
- the vault file is left byte for byte as it was after a refused copy, the vault in memory
  too, and an honest round afterwards still works;
- each refusal ends in an error that says what happened, never a panic or a hang: every
  request ends after 90 seconds in all, a round reads at most 64 copies and 256 MiB, nothing
  bigger than a copy is read, no redirect is followed and plain `http://` goes only where it
  may, so a WebDAV password never reaches another host.

What a hostile place keeps (SYNC.md §4.6): it can withhold, delay or delete copies, list ones
it won't hand over, keep a device reading every copy each round (a long-poll is asked at most
once a second), and, by altering a copy, make the apps say the vault key may have been renewed
on another device, which takes nothing without the master password and a typed Secret Key.
That is denial of service, out of scope (§4). Found by these tests: the phone app doesn't say
when it refuses a copy, and neither app names a copy it couldn't read (only the device's last
sync shows it).

## 3. Malware: the most realistic scenario

Common infostealers mainly steal **passwords saved in the browser** and **session cookies**.
Moving passwords out of the browser into a well-designed vault already removes most of that risk.
On top of that:

**Vault locked (A7)**
- Nothing in plaintext on disk; no password cache.
- A keylogger may capture the master password, **but it cannot open the vault on its own**: it
  also needs the Secret Key (protected by the OS) and, if configured, the hardware key with a
  physical touch.
- **The Secret Key on Windows** is kept under a key in the computer's TPM where it has one
  (CRYPTO.md §2.2.1): an RSA key made in the chip, which can't be exported, wraps the key that
  seals it. What it protects and what it doesn't:
  - A copy of the disk, of the user's profile or of Credential Manager (what an infostealer
    usually takes, or a backup) no longer carries it: opened anywhere but in this computer's
    chip it is useless, even with the user's Windows password or a domain's DPAPI backup key.
    Before, DPAPI alone protected it, and a copied profile opened with the Windows password.
  - Malware running as the same Windows user while the computer is on can still ask the chip
    to decrypt it, without a prompt, as it could ask DPAPI; with the master password caught by
    a keylogger, it opens the vault there. The chip makes it work on this computer only, not
    for this program only.
  - Without a TPM (older PCs, virtual machines without one, a TPM turned off) or with one that
    refuses the key, the Secret Key stays with DPAPI alone, and Settings → Security says this is
    weaker. A chip cleared or replaced (Clear TPM, a firmware update that resets a firmware TPM,
    a new motherboard) makes the kept key useless: the unlock says so and asks once for the
    Secret Key from the emergency kit, which is then kept again under a new chip key. An error
    that may pass (the chip busy) deletes nothing.
  - The credential store's entries are kept on this computer only, never in a domain's roaming
    profile.
- Quick unlock (Windows Hello / biometrics) avoids typing the master password day to day, which
  reduces keylogger exposure. What it does and doesn't protect:
  - The file it keeps (`quick-unlock-*.bin`) is useless when copied: it needs this PC's TPM.
  - Malware running as the user *can* ask Windows Hello for the same signature, but Windows then
    shows its prompt and the user must pass it; an unexpected Hello prompt is a warning sign.
  - **Anyone who knows the Windows PIN can open the vault on this PC.** The TPM limits guesses,
    the master password is still required every 14 days, and changing the master password
    revokes it. Users who share or reuse their PIN should leave quick unlock off.

**Vault unlocked (A8)**: shrink the window and the attack surface.
- Aggressive auto-lock: after 1–60 minutes without interaction and, on by default, when
  Windows locks the session, switches user, signs out, sleeps or hibernates (the vault is
  locked before Windows is answered, within the two seconds a suspend allows:
  `session_watch.rs`); on the phone, on leaving the app.
- Secrets stay encrypted **per item** in memory; only the item in use is decrypted, and it is
  wiped right after (`zeroize`).
- What is typed into the app's secret fields (master password, PIN, Secret Key, recovery
  parts) stays in one area of memory the app locks into RAM once (`VirtualLock`: never
  written to the pagefile) and leaves out of crash reports, and is wiped after use (lesson
  from KeePass CVE-2023-32784; `secure_memory.rs`).
- The keys an open vault keeps in memory are kept encrypted between uses on Windows
  (`CryptProtectMemory`, under a key the system holds for this process): the vault key, the
  item guard key, and the Secret Key and keyfile the vault was opened with (needed again to
  check the master password, rewrite a key slot or show the kit), from the moment each is
  made or read. Each is opened into a copy that is wiped right after, for the moment it is
  used, and the stack the hashing of a key used is cleared after it: a dump of the process,
  the pagefile or a crash report holds them only encrypted. An administrator, or code
  running inside the process, can still have Windows decrypt them.
- Every block of the app's own heap is wiped before it is freed (a global allocator, in the
  desktop app, the CLI and the phone app), so what was decrypted or shown and then dropped
  (an item, a revealed password in the UI's strings, a buffer of a dependency) isn't left
  behind; and the stack the key work used is cleared when the vault locks. A test reads the
  whole memory of a running copy of the app (`apps/desktop/tests/memory.rs`, in CI), whole
  values and 16-byte pieces, in UTF-8 and UTF-16, while a password is shown, once it is
  hidden, while the kit is shown, once it is hidden, and after the lock. The master
  password, the Secret Key's bytes, the keyfile and the vault and guard keys are never
  found; the Secret Key's text only while the kit shows it; an item's password only while
  it is shown; after the lock, nothing at all (item password, one-time code secret and notes
  included). Before these changes the revealed password was still in two dozen places of
  the heap, and copies of the Secret Key and of both keys on the stack.
- What this doesn't cover: while the vault is open, the item in use and what the window
  shows are in memory as they are (wiped when hidden, and at the lock); memory C code
  allocates for itself is freed but not wiped (the renderer drawing a revealed password,
  the strings UI Automation hands out, a credential Windows returns, the key the TPM
  unwraps for the Secret Key inside NCrypt); the phone has the wiping allocator and the
  cleared stack but no key shield and no locked area, so its keys
  and the Secret Key are in memory as they are while the vault is open (Android doesn't swap
  memory to disk, and the app locks on leaving it); and nothing keeps memory out of
  the hibernation file: that is why the vault locks, and its keys are wiped, before Windows
  sleeps or hibernates.
- A custom master-password input that does not leave copies of the string in memory.
- Window excluded from screen capture (`WDA_EXCLUDEFROMCAPTURE` on Windows, `FLAG_SECURE` on Android).
- What the window shows is also read through the accessibility tree (UI Automation), by
  screen readers and by any program of the same user. A revealed password, PIN or private
  key, a sensitive field, one-time and recovery codes, notes, a generated password, the
  kit's keys and its files' password are drawn but kept out of it: their element names what
  it is ("Password: shown
  on screen, not read aloud"), never the value. The phone's toolkit exposes no accessibility
  tree on Android at all.
- A memory bug is harder to turn into control of the app: the Windows programs have ASLR with
  a high-entropy address space, DEP and Control Flow Guard (an indirect call to anywhere but
  the start of a function stops the program; `.cargo/config.toml`), and every release checks
  each exe for them (`apps/desktop/check-exe.ps1`). Control Flow Guard covers our code and the
  C compiled with it (ring, SQLite), not the standard library or Skia, which come
  precompiled. Most of the code is safe Rust, where such bugs can't happen to begin with.
- A DLL dropped next to the exe never loads: the desktop app is one exe often run from
  Downloads, and Windows looks there first. The DLLs each program imports are looked for in
  System32 only (`/DEPENDENTLOADFLAG:0x800`, checked in every release by `check-exe.ps1`),
  and so are those loaded later by name (`SetDefaultDllDirectories` first thing in `main`,
  `vault_platform::process`). Tested by hand: with a junk `VCRUNTIME140.dll` beside it, an exe
  built without the flag fails to start, one built with it runs.
- Other programs of the same user can't reach into the app: in release builds the process and
  each of its threads carry an access list that lets them only see it run, wait for it and
  end it, from the first line of `main` (also in the browser host's mode, and in the CLI). No
  reading or writing its memory, no thread started in it, no handle taken, no thread
  suspended or steered, and no rewriting the list: an OWNER RIGHTS entry takes from the owner
  the right owners otherwise keep (a list without it is undone in two calls). Threads get the
  list as they start (a TLS callback) and from a sweep now and then. DLLs from a network share
  or a low-integrity folder are refused, the legacy extension points (AppInit DLLs, global
  hooks' DLLs) closed unless a legacy input method needs them, and crash reports carry no
  heap. Limits: the program that started the app keeps the handle it was given (Explorer, the
  browser for its host, or malware that launched it); an administrator reaches everything; a
  hook aimed at the window's own thread, a keylogger and UI Automation are other matters.
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
  extension and the app agree on a key by ECDH, so the key never travels; both show an
  eight-character code computed from the exchange, and the person connects in the app with
  the master password only when the two codes are the same. A program in between gets two
  different codes and can't steer them (CRYPTO.md §3.9). A program that merely asks the app to
  connect makes it show a code the extension doesn't show: the dialog says to refuse then, and
  says so again when a second request replaces the one waiting. This rests on the person
  comparing; the earlier way (a key handed to the extension, its code typed into the app)
  went with the extensions that used it (the version floor, below).
  The browsers find the app's host through a per-user registry value and a manifest file,
  which another program of this user could point at a host of its own, sitting between the
  browser and the app. Every request and every answer is sealed (AES-256-GCM, CRYPTO.md
  §3.9) and each answer is bound to its request, so such a relay reads nothing (not the
  logins, not a password being filled or saved, not the PIN typed for a locked login) and
  can't forge an answer (a password it knows, a passkey of its own, a list of logins). Nor
  can it take the key at the next connection: it would have to agree on one key with each
  side, and the two codes the person compares then differ (the extension commits to its key
  first, so the relay can't pick keys that make the codes agree; one chance in 56^8, about
  10^14, per attempt). While the link runs the app also checks the registration every few
  seconds, puts it back when it changed, refuses that message and says so.
  **A version floor** (M10 S25): the extension names its version (its manifest's) when it
  connects and inside every sealed request, and the app connects and answers only one of
  `MIN_EXTENSION_VERSION` or later (`crates/browser/src/protocol.rs`); an older one hears
  `outdated_extension` and nothing else, and the app says so once. Someone who already runs
  as the person could put back the files of an old release with a known fault in the
  extension's folder (each release's files are genuine, so a signature on them wouldn't
  tell); that copy gets nothing from the vault. The extensions released before the sealed
  link (up to 0.4.7) sign their requests with the key itself and were handed that key when
  they connected, so a relay read their traffic: they name no version and are refused,
  connecting included, and that path is gone from the app. The floor is raised when a
  release fixes a fault in the extension that must not stay reachable. A copy loaded from
  the app's folder hears the version the app carries in the refusal and reloads itself into
  it; one loaded from elsewhere says to update it (Settings → Browser extension → Add to a
  browser writes the newest). What it doesn't stop: a program of the person's that edits
  the extension's files can write any version into them (the app puts back files changed in
  its folder every five minutes, and the code the person compares at connecting is still the
  defence against a program in the extension's place).
  **The native host's parent process is not checked** (it would be the browser, with a valid
  Authenticode signature): Chrome and Edge start the host through `cmd.exe` (`COMSPEC`), so the
  parent is the command prompt and the browser its parent in turn, by process ids that can be
  reused; and a program of the same user can start the host with any process it can open as
  its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), the browser included. The check would
  stop no one it is meant for, and the host is a relay that reads nothing: the sealed link is
  what keeps a host in between from reading or forging anything.
  Known limit: a program already running as the same Windows user can copy the browser's
  stored data, pairing key included, and then ask like the extension does. It gets nothing
  while the vault is locked. By default (Settings → Browser extension, "Ask … every time")
  every password, one-time code, fill, copy and passkey asks for Windows Hello or the item
  lock's PIN or password in that very request, so the copied key alone gets titles,
  usernames and sites, not secrets: Windows Hello's prompt can't be answered by a program,
  and a PIN typed in the extension's window is counted with the app's wrong tries. Turned
  off, it gets every login outside the item lock while the vault is unlocked (each one shows a
  notice in the app). The same program could already read an unlocked vault's memory (S3
  closes the easy way to), so the link adds no new reach; asking every time keeps the link
  from being the easy way.
- **The frame shown inside pages** (since extension 0.2) brings back the risk the extension's
  own window avoided: a page can draw over it, make it see-through or move it under the
  pointer (extension clickjacking). What limits it: the frame is the extension's page in a
  cross-origin iframe, so the page can't read or script it; a click counts only once the
  browser has reported the frame fully visible, with nothing over it, for 400 ms
  (IntersectionObserver v2), and a mouse click only once the pointer has rested on the card
  for 150 ms (a frame slid under the pointer takes no click meant for the page); the card
  shows nothing inside a frame of the page (an advert, a widget), only directly in the page
  whose logins it lists; it shows usernames, never passwords; a document the site sandboxed
  (a `sandbox` frame, a `Content-Security-Policy: sandbox` header, a pop-up that inherited
  one: its own origin is opaque while its address names the site) is not the site, so
  nothing is offered, read, filled or saved there and its passkey requests stay with the
  browser (the class of CVE-2025-65203); a fill goes only into the
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
  **The frame's address** (M10 S24) is the browser's for this session
  (`use_dynamic_url`, Chrome 130 and later): the frame's `src` doesn't carry the extension's
  fixed id, and a page can't load `chrome-extension://<id>/inline.html` to learn, without the
  person doing anything, that Vault is installed. Chrome serves that address from the
  extension's own, which is what the worker sees as the frame's (`isFrameUrl`). Limits: a page
  where the card appears sees an extension's frame there (and that session's address, the same
  on every site until the browser restarts), and a page can still tell Vault is there from
  `navigator.credentials`, which the passkeys script stands in front of; another extension's
  redirect rules have been shown to reveal a dynamic address (Chromium issue 513184498).
  Firefox ignores the key (a warning on `about:debugging`); its extension address is already a
  random id per profile, and it shows no card in pages anyway. Chrome 127 to 129 ignore it too.
  **Tabs driven by an AI agent** (M10 S28): an agent that drives the browser through its
  debugging protocol sends input the browser marks as trusted and can wait out the click
  check, a login filled into a page stays in its fields within the agent's reach, and a page
  can carry instructions for the agent (prompt injection; agentic browsers have filled saved
  data into fake shops and helped fill phishing pages). So while the browser says a program
  drives it (`navigator.webdriver`: WebDriver, Marionette and BiDi, a headless browser, Chrome
  started with `--enable-automation`, `--remote-debugging-pipe` or `--remote-debugging-port=0`),
  or the person turns on "An AI agent or a program is using this browser" in the extension's
  window, nothing is shown in pages: no card under fields, no save card, no passkeys in a
  field's suggestions (`apps/extension/agent.js`). The extension's window still fills, saves
  and copies with its usual checks, and Vault's passkey window still answers a site's
  request. Three places hold it: the content script draws nothing (and takes away what it
  drew), the frame takes no click, and the worker answers no frame while the person's choice
  is on. Limits: no other standard signal of agentic browsing exists (browsers built around an
  agent say nothing a page or an extension can read, and a user-agent string is anyone's
  claim), and an agent can hide `navigator.webdriver` (a fixed debugging port, a flag that
  turns it off, an extension driving the browser through `chrome.debugger`): the person's
  choice covers those. An agent can still use the extension's own window like a person.
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
  and a login behind the item lock asks for its check there too. The answer tells the site
  "user verified" only after Windows Hello or the item lock's PIN or password in that very
  request, as the site asks (`userVerification`), never because the vault happens to be open:
  a site that trusts the flag as a second factor isn't misled. The window names the page
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
  A page's request for a field's suggestions (`mediation: "conditional"`) opens no window:
  Vault takes it only when it has a passkey for that site (the app lists it, as for the
  window), and the request then waits in the document that asked. The
  passkeys are listed in the frame under a sign-in field, which is the frame above, with its
  click check: names only, never a key. A pick there is signed by the same path as a pick in
  the window (the app checks the site; the very document that asked must still wait for that
  request, before the app signs and again before the answer goes back, and the answer goes to
  that document alone, by the browser's id for it); a login behind the item lock needs Windows
  Hello or the PIN typed in the extension's window. The page aborting, leaving, asking for
  another passkey, or passkeys turned off end the request. What this adds: a clickjacked pick
  (one the frame's check didn't catch) signs in to the page that asked with the person's
  passkey, as a clickjacked fill types a password into it; such a page could already ask for
  the passkey in the window. Since the background worker may be stopped while a page waits,
  the document tells it the request again when a field is focused; a request named that way
  but that the document doesn't hold is never answered (the document is asked first).
- **The extension's folder** (Settings → Browser extension → Add to a browser): the desktop app
  writes the extension's files into `<app dir>/browser-extension`, which the person loads in the
  browser (Developer mode and Load unpacked; in Firefox a temporary add-on). No browser lets a
  program add an extension from outside its store by itself on a normal Windows computer, which
  is why the person does it. An extension loaded that way runs whatever the folder holds, read
  again at each browser start and each reload, so a program that rewrites it would run its code
  inside the browser, with the extension's access to every https page. What the app does: it
  makes the folder itself, writes each file whole (a new file renamed into place) and never
  through a link (a link or junction in the folder's place, or a file's, is removed, never
  followed), removes anything that isn't one of its files, and while the browser link runs
  compares the folder with its own copy (when the link starts and every five minutes): what
  differs is put back, and when the folder already held this version it says so in a notice
  (another program changed the extension's code). A read-only mark set on a changed file doesn't
  keep it there, and a folder the app can't put right on two checks in a row (a file held open,
  say) is said too. Where the files come from: by default the newest GitHub release's
  `vault-extension-<version>.zip`, downloaded with the app's own updates (the same release list,
  over HTTPS; nothing else is sent) and taken only when its SHA-256 is the one that list gives
  for it, which catches a download changed on the way or a file swapped on GitHub's storage, but
  not a release made by whoever controls the project's GitHub account (the same trust as the
  apps' updates, until the stores sign the extension). The zip is read strictly: nothing named
  outside the folder, no links, no ZIP64 or encryption, every entry's size and CRC checked, a
  few megabytes at most. The copy built into the app is used when it is newer or nothing was
  downloaded. The person may choose a folder of theirs instead: it is read with the same rules,
  and the app follows the changes made to it, so whatever writes into that folder writes the
  extension, as when it is loaded unpacked from there. The extension updates itself from the
  app's folder only when the app says, in its sealed answers (`status`, `logins`), that it has a
  newer version in use, and then only by reloading that folder: the extension itself downloads
  nothing. What this doesn't cover: a program running as the same Windows user can rewrite the
  folder between two checks (the browser may load that code meanwhile, and keeps running it
  until it reloads the extension: the notice says to restart the browser), change the browser or
  its profile, or load an extension of its own; that program could already do all of this to any
  extension and any browser. A copy loaded from anywhere else (the project's folder, the
  release's zip) is not watched. Unpacked extensions get none of the stores' review or signature
  checks; the extension in the stores (F12) will.
- **An older copy of the apps put back** (M10 S25): a program running as the person could put an
  old release's `vault-desktop.exe` or `vault.exe` (genuine, signed once S15 signs them) in place
  of the newest, one with a fault fixed since. The device state (`state.json`) keeps, for each
  vault, the newest version of the apps that opened it on this computer (the desktop app and
  the CLI are released together, at one version), never lowered. An older one still opens the
  vault (the person must reach it; refusing would also lock out someone who went back on
  purpose), and says so: the desktop app in a notice after the unlock, the CLI on stderr, every
  time, with how to get the newest. It is a warning, not a lock: the program that swapped the
  exe can also edit `state.json`. On a phone, Android refuses to install a lower `versionCode`
  over the installed app (docs/MOBILE.md).
- **Firefox**: the same extension and host. Firefox doesn't report whether
  a frame in a page is covered (no IntersectionObserver v2), so there the extension draws
  nothing inside pages (no card under fields, no save card, no warning): filling and saving
  happen in the extension's own window, and the toolbar button marks a login waiting to be
  saved. A
  page therefore has nothing of Vault's to cover or click in Firefox, and never learns the
  extension's per-install address (`moz-extension://…`, which a frame's address would show
  and which could serve to recognise the browser). The warnings below aren't drawn in pages
  there either: the toolbar button shows "!" for the tab, and the extension's window says what
  it was about. Passkeys go through the window as in
  Chrome; a field's suggestions stay Firefox's own. Firefox starts the host with the path of
  its manifest and the extension's add-on id, which the host's manifest for Firefox
  (`allowed_extensions`) names alone. That id, like the Chrome id fixed by the manifest's
  public key, is no secret: a temporary add-on loaded in `about:debugging` (someone at the
  keyboard, or a program already running as the user) can claim it, as an unpacked copy can
  claim the Chrome id. It then still has to be connected in the app (the code and the master
  password), which is what the app checks on every request.
- **What a page sends when a form is submitted**: the content script reads the typed username
  and password (in the extension's isolated world) and passes them to the background worker,
  which keeps them in `chrome.storage.session` (memory only, closed to content scripts) for
  at most two minutes, until the person answers "Save this login?". The password reaches the
  app to be kept only if the person says Save (before that only to be compared with the other
  sites' and dropped, while the app's warnings are on: below); a page can't trigger the save
  by itself (same visibility check). Only
  the form the person sent is read (a help link, an eye button or a button of another form
  reads nothing), and only after the person's own act in that form: a made-up click or key
  press is ignored, and a form's `submit`, which the browser reports as the person's even when
  a page script asks for it (`requestSubmit()`), counts only within a few seconds after the
  person's click or Enter in that same form, one submit per act. Save acts on the one offer its card
  shows, for the site it was typed on, and an update only for the version of the login the
  app compared and its username (a login changed since is not overwritten). Turned off in the
  extension's Settings, nothing typed is kept or offered; with the app's warnings about other
  sites off as well, nothing typed is read or compared at all (with them on, what was sent is
  compared by the app and dropped, below). A save or an update is answered as done only once the vault file
  is written: when it can't be (the file changed elsewhere, the disk refused it), the app puts
  the open vault back as it was and says "not saved".
- **Warnings about the wrong site** (M10 S16, S21, S17). Filling only on the exact site stops
  a phishing page from being filled; what such a page counts on next is the person copying
  the password from the app and pasting it, or typing it. Three warnings, all decided by the
  app or by a fixed rule, none needing a list from anywhere or a secret in the extension:
  - *A password given to the wrong site* (S16; Settings → Browser extension, "Warn when a page
    isn't the site a password belongs to", on by default). When a password is pasted into a
    password field, or sent from a sign-in form, the content script hands it to the worker,
    which asks the app (`elsewhere`) whether it is the password of a login saved for another
    site. The app compares it with each login outside the item lock and answers with that
    site's name at most (its registrable domain), never which login: nothing when a login of
    the page's own owner has it (`mail.example.com` and `example.com` are one owner), when the
    page's owner has a login behind the item lock (its password may well be that one: such
    logins are never compared), or when it is shorter than six characters (a PIN matches by
    chance). Neither the worker nor the app keeps it. The frame then names that site, under
    the field after a paste, in the corner after a sign-in (in Firefox: the toolbar button's
    "!" and the extension's window), and a sign-in that sent another site's password is not
    offered to save. Its buttons take only clicks the browser vouches were on a fully visible
    frame, as the other cards do, so a page can't have the warning dismissed by a click meant
    for the page. The page sees whether a frame appears: it learns
    that the password it was just given is the one of some other login in the vault, not of
    which; it had the password already. Only the person's own paste counts (a paste a page
    script makes up carries nothing the browser vouches for), so a page that wants to try
    guesses must put each one on the clipboard and get the person to paste it, one bit each.
    Residual risk: the warning comes after the paste or the sign-in, and a page that reads
    every key press or the field has the password by then; what the warning buys is the
    person not sending it, or changing it on the real site at once.
  - *A page that only looks like a saved site* (S21; the same setting). The app compares the
    page's registrable domain with those of the vault's own sites (`crates/browser/src/
    lookalike.rs`): the same reading once accents are dropped and letters of other scripts
    that look Latin, `0`, `1`, `rn` and `vv` are read as the Latin letters they look like
    (`paypa1.com`, `pаypal.com` with a Cyrillic `а`, `rnicrosoft.com`); one letter off (two
    for names of ten or more) for names of five letters or more; the same name under a
    mistyped suffix or a hosting company's (`paypal.co`, `paypal.github.io`); or the saved
    site in the page's name or subdomains (`paypal-login.com`, `paypal.com.evil.example`). A
    page of a saved site's owner is never one. Such a page with no login of its own gets the
    warning under its first sign-in field, and in the extension's window, naming both, before
    anything could be pasted; a login sent there is offered to save with that said on the card.
    The page's host is shown in its ASCII form (`xn--…`) when its name mixes scripts or is made
    only of letters that look Latin, as browsers do in the address bar. Residual risk: a
    phishing site whose name is unlike every saved site's (a different domain altogether, the
    common case) gets no such warning, only the refusal to fill; and an ordinary site one
    letter from a saved one gets a warning it doesn't deserve.
  - *The emergency kit's keys* (S17; no setting, no site excepted). A script of its own
    (`kit.js`), in every https document, frames too, ahead of the page's own scripts,
    recognises the Secret Key, the recovery parts and the Recovery Key of older kits by their
    printed shape (a prefix and Crockford Base32 groups: no secret is needed) and stops a
    paste or a drop of one before the page's listeners hear of it; one typed by hand is taken
    out of the field as its last character comes. The page's frame then says that Vault never
    asks for them in a page. The app checks the same shape in whatever a page sends it (a
    login to save, a password to compare) and never saves, compares or keeps one
    (`crates/browser/src/kit.rs`). Residual risk: a page that reads key presses has a key
    typed by hand by the time it is taken out; one asked for in pieces, or read off a photo of
    the kit, is not recognised.
- **The phone's QR code scanner** is Google's (Play services' code scanner): the camera
  screen runs in Play services, the app has no camera permission and gets back only the
  code's text. That text (the invite) passes through Play services on the phone; it opens
  nothing by itself. What is read is treated like a pasted line: an invite works once,
  within an hour, and the phone still needs the master password and the Secret Key. Residual risk: someone who films the computer's screen while
  the invite is shown can use it within the hour to enroll a device, which then still can't
  open the vault without the master password and the Secret Key. A one-time code's setup key
  scanned the same way passes through Play services too, as it would through any authenticator
  app's scanner.
- **Unlocking the phone app with the phone's screen lock** (when the person turns on unlock
  with the phone): the Keystore key that opens the vault answers to a strong
  fingerprint or face, or to the phone's PIN, pattern or password. Someone who knows that PIN
  and has the phone in hand can open the vault, for up to 14 days after the
  last master password (turning fingerprint unlock off and on again doesn't start them anew,
  and a clock moved back counts as too long ago); guesses are rate-limited by the phone's secure hardware, but a 4-digit
  PIN is weaker than a master password. It is the person's choice in Settings, Security, and
  the master password always works.
- **Every use asks on the phone** (Settings, Security, "Ask for the fingerprint or screen lock
  every time", on by default): while the vault is open, each password shown or copied, each
  one-time code shown or copied (a code shows only until it runs out, then goes back to
  dots), a card's number or security code, a secure note, an attached file, the editor (which
  shows every field) and the generator's history ask Android's own prompt (a strong
  fingerprint or face, or the screen lock) in that action, with nothing remembered between
  two uses. What it protects: someone who picks up the unlocked phone, or is handed it with
  the app open, sees titles, usernames and sites, and gets no password, code, card or note
  without passing the phone's check once for each; a cancelled or failed check shows and
  copies nothing. A phone with no screen lock asks the item lock's PIN or password instead
  (for that use only); with neither, nothing shows. What it doesn't: anyone who knows the
  phone's PIN or pattern passes it (it is the same check as unlocking the phone; guesses are
  rate-limited by Android); a code shown stays readable until it runs out (its period,
  usually 30 seconds; a counter-based one until Next), and a secret already shown stays on
  screen until hidden or the item is left, as one copied stays on the clipboard until it is
  cleared; the item lock's own PIN still guards the items it covers (the phone's check never
  opens it); malware with root or a debugger reads the open vault's memory, which this prompt
  doesn't change. It is the system's prompt, not a Keystore key: the secrets are already
  decrypted in the open vault, so a key would release nothing the app needs, and the
  prompt's answer comes from Android, which another app can't forge.
- **Passkeys on the phone** (Android 14+, once the person turns Vault on as a passkey
  provider in the phone's settings): Android's Credential Manager asks the app, and the app
  answers only after a fingerprint or the phone's lock. A web page's origin counts only when
  Android vouches for it to a browser this app lists by its release certificate (the same list
  autofill trusts); the site a passkey is used or made for must then be that page's host or a
  domain above it that isn't a public suffix, as in a browser. Any other app answers for
  itself: the signed client data names the app's own origin (`android:apk-key-hash:` and its
  certificate), which the site checks against the apps it trusts, so an app that asks for
  another site's passkey gets an answer that site refuses. Residual risk: a site that doesn't
  check the origin of an answer (a broken site) would take such an answer; Digital Asset Links
  can't be checked offline. With the vault locked, the fingerprint opens the vault file for
  that one request: the passkeys it finds stay in the app's memory for a minute at most, for
  that caller only, and a passkey made then is written into the vault file only if the file is
  still the one read. Passkeys behind the item lock are never offered.
- **Previews of attached files on the phone**: pictures and text are decoded in the app's own
  memory. A PDF is drawn by Android's renderer, which needs a file: the decrypted PDF sits in
  the app's private cache (closed to other apps) while its pages are drawn, then is overwritten
  and deleted, and a leftover is wiped at the next start. Nothing is handed to another app.
  Residual risk: the renderer is Android's code, run on whatever PDF was attached.
- **The phone's keyboard** sees every key typed in any field it serves, as in any app. The app
  asks it, in every field, not to learn what is typed (`IME_FLAG_NO_PERSONALIZED_LEARNING`),
  and asks for a password keyboard in the secret fields, so a keyboard that follows Android's
  rules keeps no titles, usernames, notes, card numbers or codes to suggest elsewhere.
  Residual risk: a keyboard app that ignores the flags, or sends what is typed away, gets it
  all; the item lock's PIN is typed on the app's own pad, never the keyboard.
- **Other apps on the phone** (installed by the person, with no root): one with the "display
  over other apps" permission can't draw over the app's windows (Android hides every such
  overlay while they show), so it can't lay a false unlock screen or button over them or pass
  taps through; Android 12 and later, the only versions the app installs on, block taps
  through another app's window by themselves too. No task affinity: another app's activity
  can't be slipped into the app's task to look like it (task hijacking). Nothing of the app is
  in Android's cloud backup or its copy to a new phone. On Android 14 and later, accessibility
  services other than accessibility tools can't read the app's windows or act in them.
  Residual risk: an accessibility tool the person turned on (a screen reader) sees what the
  app shows, as it must; a toast or a notification another app shows is still drawn; a phone
  with root is out of scope (§4).
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
- **Starting at sign-in** (off by default) is one value in this user's `Run` key, listed in
  Task Manager's Startup apps; the app starts locked, and nothing is unlocked by itself. When
  it starts hidden, its window is still made at once and kept out of screen captures before
  it is ever shown. A program running as the same user could point that value at another
  program, as it could replace the app itself or its shortcut; the setting adds no access it
  didn't have. The next time the app runs it points the value back at itself and says which
  program it found there.
- **One running copy**: the app started again shows the running copy's window and ends (a
  named event in the sign-in session). Same-user malware could take that name first and keep
  the app from opening, which it could also do by ending the app; nothing crosses the event
  but "show yourself".
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
  deleted on lock, on exit and at the next start; a kit with keys in it is protected by the
  kit's PDF password (below), which the viewer asks for before it shows or prints it. A kit
  saved with "Save as PDF" holds the
  Secret Key only: infostealers sweep PDFs from Documents and the Desktop, and the three
  recovery parts together open the vault without the master password. The parts go on paper,
  or each to a PDF of its own with "Save each part apart", in different folders (the app
  refuses a folder another part went to). Neither is written to a folder a cloud copies away
  (OneDrive, its backed-up Documents and Desktop included, Dropbox, Google Drive, iCloud
  Drive: `files::cloud_folder`). A saved file is then the user's. A filled kit also carries the Secret Key and each recovery part as a QR code
  (black squares in the PDF, no picture), for the phone's scanner: whoever can photograph a
  page could already read the same key printed above its code. A kit with empty boxes, to be
  filled by hand, has no codes.
- **The kit's PDF files are protected by a password**: the printed kit's temporary PDF, "Save
  as PDF", "Save each part apart" and `vault kit --pdf` are encrypted with AES-256 by the PDF's
  own standard encryption (revision 6, which every viewer opens; CRYPTO.md §3.10). The PDF is
  for printing and may sit on the computer for a while; the paper is the kit. The password is
  four words the app derives from the vault key, the Secret Key and the kit, never stores and
  never prints, and shows on the kit page next to the print and save actions: dots until shown
  for 15 seconds, copyable, and behind the item lock's check (PIN, password, master password or
  Windows Hello) when one is in use, as the kit's keys are (`vault kit --pdf-password` after the
  master password). What it stops: a copy of the file (taken by an infostealer, synced by a
  folder, left in Downloads) or the file opened by someone while the person is away from the
  computer shows nothing. What it doesn't stop: four words are about 51.7 bits and the PDF's
  own password hash is quick, so someone who sets a large GPU farm on one file for a long time
  could find it (a bulk sweep won't); someone who has the password; a program that reads the
  screen while the password shows, or the open vault's memory (it could derive it, and read
  the Secret Key itself); and files made before this protection, which are plain. A new kit
  (new parts, a new Secret Key, a renewed vault key) has a new password; files made before keep
  theirs. The permissions written in the file (print and copy, no changes) are advisory. A
  kit of empty boxes holds no key and is not protected.
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
- Denial of service by a sync place or the network (A2, A3): withholding, delaying or deleting
  copies, or keeping a device busy. Every device keeps the whole vault and works offline; the
  apps show each device's last sync (§2.1, SYNC.md §4.6).
- Physical coercion of the user.
- Hardware side-channel attacks (Spectre, etc.) beyond what the libraries mitigate.
- Undetected build supply-chain compromise: reduced, not eliminated. Dependencies are
  audited (`cargo-deny`, no advisory ignored), the workflows' actions pinned, and GitHub
  attests where every released file was built; the APK is signed with a release key of its
  own. Builds aren't reproducible yet and the Windows exes aren't Authenticode-signed
  (M10 S15).

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
