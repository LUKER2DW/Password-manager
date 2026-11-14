# Threat Model

> Status: **draft** (research phase). This document defines what the project protects against
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
  Requests are accepted only from the extension the person connected (pairing, with a code
  allowed in the app), and a locked login needs Windows Hello or the item lock's PIN for
  each fill.
  Known limit: a program already running as the same Windows user can copy the browser's
  stored data, pairing key included, and then ask like the extension does. It gets nothing while the vault is locked and
  nothing behind the item lock, and it must name the exact site of a login to get it; the
  notice in the app makes it visible. The same program could already read an unlocked
  vault's memory, so the link adds no new reach, but it is one more reason for the item lock.
- **The frame shown inside pages** (since extension 0.2) brings back the risk the extension's
  own window avoided: a page can draw over it, make it see-through or move it under the
  pointer (extension clickjacking). What limits it: the frame is the extension's page in a
  cross-origin iframe, so the page can't read or script it; a click counts only once the
  browser has reported the frame fully visible, with nothing over it, for 400 ms
  (IntersectionObserver v2); it shows usernames, never passwords; a fill goes only into the
  site the login is saved for, top frame only; and a locked login still needs Windows Hello
  (the system's own prompt, which a page can't click) or the PIN, typed in the extension's
  window. New vaults lock every item by default for that reason. The site's icon in the frame
  comes from the browser's own cache (`favicon` permission): nothing is fetched for it.
  The card is drawn half see-through inside the frame, with no blur: a blur, clip or opacity
  on the frame itself would make the browser stop vouching for its visibility (checked:
  `isVisible` turns false), and the click check would refuse every click. Residual risk: a site with
  an XSS flaw can read what is filled into its own page, as it can read what the person types.
- **What a page sends when a form is submitted**: the content script reads the typed username
  and password (in the extension's isolated world) and passes them to the background worker,
  which keeps them in `chrome.storage.session` (memory only, closed to content scripts) for
  at most two minutes, until the person answers "Save this login?". They reach the app only if
  the person says Save; a page can't trigger the save by itself (same visibility check).
- **Generated passwords** come from the app's generator, never from the page or the
  extension. A password the person used is kept in the app's history, sealed with the vault
  key on this computer and shown behind the item lock; "Clear history" deletes it. Copying is
  done by the app, so the clipboard copy stays out of Windows clipboard history.
- **Tray mode** keeps an unlocked vault in memory while the window is hidden; the idle lock
  still applies, and the tray menu locks at once.
- **Saving while the vault is locked**: a login the person saves from the browser is sealed to
  a public key (libsodium sealed box) whose private key only the open vault reads, and added
  at the next unlock. Nothing is asked for (no PIN, no Windows Hello) and the locked app can't
  read back what it wrote, so the file reveals nothing to someone who copies it. A program
  running as the same user could replace the public key and read later saves; it would
  already see those passwords in the browser as they are typed.
- **Filling while the vault is locked** (setting, on by default; needs the item lock's
  Windows Hello): the passwords of logins sit in a file of their own, under a key that only
  Windows Hello opens (TPM signature after the person is verified), so a locked vault can fill
  one login at a time with the person's face, fingerprint or Windows PIN. The item lock's PIN
  does not open it: a copied file could be tried against every PIN offline, a TPM-backed
  signature can't. What changes: names, usernames and websites of logins are readable to
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
  user's file.
- Imports: the app offers to overwrite and delete the plain-text export right after importing.
- Unencrypted export: only after re-checking the master password, with a warning; the encrypted
  backup copy is offered first.

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
8. **Explicit recovery**: a printed emergency kit. No server-side backdoor.
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
   to) is size-limited and decoded by pure-Rust decoders.
