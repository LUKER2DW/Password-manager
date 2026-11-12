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
  reduces keylogger exposure.

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
  (Hello, biometrics or a hardware-key touch) on every use.
- The browser extension stores no secrets; it asks the native app for each credential, and the
  app confirms.

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
