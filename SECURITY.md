# Security policy

## Status

This project is an **alpha**: the apps are usable and were designed with security first, but
there is no stable release and **nothing has had an independent audit yet**. Only the latest
commit of `main` gets fixes. If you store real passwords in it, keep a copy elsewhere and keep
the emergency kit.

## Reporting a vulnerability

Please report security issues **privately**, through the repository host's private
vulnerability reporting (on GitHub: the **Security** tab → **Report a vulnerability**). Do not
open a public issue, pull request or discussion for a vulnerability.

Include what you can:

- the affected component (`core`, `platform`, `import`, `browser`, `sync-wire`, or the
  `cli`, `desktop`, `mobile`, `extension` or `server` app) and commit;
- what an attacker needs (a copy of the vault file, code running as the user, network
  position…) and what they gain;
- steps or a proof of concept, ideally with a test vault and test values only.

Never send real vaults, real keys or real passwords. Reports are acknowledged as soon as
possible; a fix, a regression test and, once fixed, a public advisory follow. Credit is given
unless you ask otherwise.

## What we protect against

The full model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In short:

| Attacker | Expected result |
|---|---|
| Has a copy of the vault file (stolen backup, cloud leak, infostealer grabbing files) | Learns nothing: the key needs the master password **and** the 128-bit Secret Key, which is not in the file; the body hides item count and sizes |
| Can modify or replace the vault file | Detected: every part is authenticated (header in the body AAD, items bound to id and revision), KDF downgrades are refused, older copies are flagged (rollback) |
| Brute-forces the master password from a stolen file | Infeasible without the Secret Key; with it, Argon2id (256 MiB by default, up to 1 GiB if the user picks a stronger level, a hard floor of 64 MiB) slows every guess |
| Reads the clipboard history or cloud clipboard | Copied secrets are excluded from Windows clipboard history and cloud sync, and cleared after a delay |
| Captures the screen | The desktop window asks Windows to exclude it from screen capture |
| Watches the network | Sees nothing by default: the app contacts no server unless the user turns on website icons or the leak watch, runs the leak check or sets up sync; the leak check (and the watch, once a day) sends only 5 hex characters of each password's SHA-1, with padded answers |
| Runs or takes over the sync server | Gets sealed copies and device public keys only: no password, hash or key that opens the vault. Older copies, forks and other vaults' copies are refused by every device ([docs/SERVER.md](docs/SERVER.md)) |
| Leaks a website's password database | The health page flags weak, reused and leaked passwords so they get changed; with the leak watch on, a password that turns up in a new breach is told within a day |

Out of scope (see the threat model): an attacker with administrator or kernel control of a
running, unlocked computer; physical coercion; hardware side channels beyond what the
libraries mitigate.

## Design choices that matter for security

- **Cryptography** ([docs/spec/CRYPTO.md](docs/spec/CRYPTO.md)): Argon2id, HKDF-SHA-256,
  XChaCha20-Poly1305 made key-committing, a random vault key wrapped by key slots, a fresh key
  per item revision, length-hiding padding. Only audited RustCrypto crates; no home-made
  primitives.
- **Two secrets to open a vault:** the master password and the Secret Key (stored in the OS
  credential store on enrolled devices and printed on the emergency kit). The kit also has
  three recovery parts for different places: any two bring back the Secret Key, all three
  open the vault so a new master password can be set, one alone opens nothing, and each set
  works once.
- **Keyfile (optional):** a third factor mixed into the password key. The device stores only
  where the file is; kept on removable storage, a stolen vault file, master password and
  Secret Key still open nothing.
- **Item lock:** with the vault open, passwords, codes and hidden fields can stay closed
  until a second check (master password, PIN or another password), for every item or chosen
  ones; five wrong tries lock the vault. With a PIN or another password the locked secrets
  are also encrypted under a key only it opens, so a program that takes an unlocked vault
  from memory still cannot read locked items. Limits: a 4-digit PIN can be tried exhaustively
  offline by whoever holds the vault key (use 6–8 digits or a password), and secrets are
  readable while open. With the master password as the check it is a rule, not encryption.
- **Browser extension:** off until turned on. The extension keeps no passwords and can't see
  any page until its button is clicked; logins are offered only for the exact https origin
  saved in them and chosen in the extension's own window, so a page has nothing to click on
  your behalf. Only an extension you connected (a code you allow in the app) is answered, and
  logins behind the item lock ask for Windows Hello or the PIN on every fill. In Firefox, which
  can't tell the extension whether something covers its frame in a page, nothing is drawn
  inside pages: logins are filled and saved from the extension's own window. Not a defence against malware already running as your Windows user while the
  vault is open (see the threat model).
- **Password hashing:** Argon2id by default. scrypt and PBKDF2-SHA-256 can be chosen and are
  weaker; the app says so where they are offered.
- **Windows Hello** quick unlock wraps the vault key with a TPM-backed key that only works on
  that computer after Windows verifies the user; changing the master password revokes it, and
  the master password is required again every 14 days.
- **Memory hygiene:** keys and decrypted data are wiped on drop; typed secrets go from the
  keyboard straight into locked Rust buffers, never into UI strings.
- **No `unsafe`** in the core, import and CLI crates; OS calls in the platform and desktop
  crates are isolated and documented.
- **Fail closed:** unknown versions, out-of-range parameters, duplicates and authentication
  failures are errors with no fallback.
- **Opening websites:** only `http` and `https` links reach the operating system's "open",
  so a crafted URL in an imported item can't launch a program or a `file:` path.
- **Imports:** reading a browser's own password store (the same access an infostealer uses)
  happens only when the user clicks for it, in memory; plain-text export files can be wiped
  securely after import. Unencrypted export requires the master password again.
- **Saving:** atomic writes with a backup copy, and a refusal to overwrite a vault file that
  something else changed since it was read.
- **Sync:** each device writes only its own sealed copy and merges the others with the key it
  already holds; the target never supplies a key or a hashing parameter. Server requests are
  signed per device (Ed25519), the body's SHA-256 included, so an upload is checked before
  it is read; plain `http://` is allowed only to this computer or a Tailscale address. The
  server caps open connections, handshakes, header and write times, and copies served at
  once, per address and in all.
- **What reaches the network:** website icons reach public sites only at public addresses
  (checked at every name lookup, redirects included), the leak check follows no redirect and
  reads a bounded answer, and a sync round reads a bounded number and size of copies.
- **Phone:** typed secrets go to the same locked buffers through a keyboard input that only
  holds stand-ins; the Secret Key is kept under an Android Keystore key; copied secrets are
  marked sensitive; the screens stay out of screenshots unless allowed. Fingerprint unlock
  opens a device secret sealed by a Keystore key that needs a strong biometric for each use.
  Autofill offers only the logins saved for the exact site or app, and asks for a fingerprint
  or the phone's lock before every fill.

## Known limitations

- Not audited. Fuzzed every day in CI, but only for minutes at a time so far.
- Windows and Android only: Linux and macOS are not supported yet (the server aside).
- Memory wiping is best-effort: the OS, the allocator or the UI toolkit may keep copies of data
  shown on screen.
- A computer already compromised while the vault is unlocked can read what is unlocked.
- Windows Hello security depends on the Windows PIN or biometrics of that account.
- Website icons, chosen icon pictures, the leak check and sync reveal, to someone watching
  the network, that requests were made; all are off until the user asks for them.
- On a phone, the keyboard app sees the keys of every field it serves, secret ones included.

## Development practices

Known-answer tests for every vault format version, tamper and rollback tests, tests against a
hostile sync folder, WebDAV host and server (docs/THREAT_MODEL.md §2.1), headless end-to-end
tests of the desktop and phone apps, a real server with two devices in the server's tests,
`cargo clippy -D warnings`, and no known vulnerability in any dependency
(`cargo deny check advisories` against the RustSec database, with nothing ignored in
[deny.toml](deny.toml)).

On every push ([.github/workflows](.github/workflows)): the format, clippy and every test on
Windows; the core libraries' tests and the server's Docker image on Linux; the extension's
tests; the dependency advisories (also once a day); gitleaks over the whole history
([.gitleaks.toml](.gitleaks.toml) lists the test keys and values it allows); zizmor over the
workflows; CodeQL over the Rust, JavaScript, Java and the workflows; and OpenSSF Scorecard.
Actions are pinned to full commits, every job's token can only read, and Dependabot keeps
dependencies and actions current.

Every day: each fuzz target ([fuzz/](fuzz/README.md): the vault file and sync copies, the sync
protocol, the extension's messages and release zip, imports, invite lines, one-time code links,
the part C picture) for five minutes, on Linux with AddressSanitizer.

Planned: reproducible builds and an independent audit before any stable release.
