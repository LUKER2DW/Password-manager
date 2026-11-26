# Changelog

What each release brought, newest first. A version's section is the text of its GitHub
release (`.github/workflows/release.yml`), so write it for the people who install it. Alpha:
never use the apps with real passwords yet.

## [0.4.3] - 2026-11-26

Updates that find their own way: the sync server follows the releases and hands each new phone
app to your phones, and the desktop app is one file that checks for a newer one when you ask.

### Added
- **The sync server follows the releases** (`--app-updates LUKER2DW/Password-manager`, set in
  `apps/server/compose.yaml`): every 6 hours it asks GitHub for the newest release, downloads a
  newer phone app, checks it against the SHA-256 GitHub lists and offers it to the phones
  (Settings → Updates). Its log says when a newer server is out. `vault-server fetch-app` does
  it once, now.
- **Check for updates** in the desktop app (Settings → About): asks GitHub only when you press
  it, says whether a newer version is out and opens its page.
- **The sync server is released too:** an image on GitHub Packages
  (`ghcr.io/luker2dw/vault-server`, amd64 and arm64, so a Raspberry Pi as well) and programs
  for Linux (x64, arm64) and Windows. `compose.yaml` runs the image; `pull` then `up -d`
  updates it.

### Changed
- **The desktop app is one file**, `vault-desktop.exe`: the browsers start it as the
  extension's helper, so `vault-browser-host.exe` is gone. After updating, open the app once
  with the browser extension on, so the browsers point at the new file.
- Releases list each file on its own, with the SHA-256 GitHub shows next to it.

## [0.4.2] - 2026-11-26

The first release with every app built, signed and published by GitHub Actions: the desktop
app for Windows, the browser extension and the phone app, from the same commit.

### Added
- **Renewing the vault key.** The emergency kit page renews the vault key and prints a new
  kit; other devices take the renewed key once with the new Secret Key and the master
  password (desktop: Sync; phone: the sync settings; CLI: `vault renew-key`,
  `vault sync --take-new-key`). Copies sealed under the old key are told apart.
- The desktop app in Brazilian Portuguese, every text.
- Releases: the APK signed with the app's own release key, checked against its certificate,
  with build provenance and `SHA256SUMS` for every file.

### Changed
- Android autofill ties a login saved from an app to that app's signing certificate, not only
  its package name; a login saved before this is filled again once you save it from the app
  (Android shows the certificate first).
- The phone app is signed with a release key of its own: uninstall a copy signed with the
  debug key once (sync or export the vault first), then install this one. Later versions
  install over it.
- Every app carries the same version number.

### Fixed
- Sync: failed reads count toward a round's limit, and copies known and unchanged past the
  limit keep their place, so they aren't downloaded again.
- Fixes from the security audit of 2026-11-25 across the core, sync, the server, the browser
  link, import and the apps: the item lock follows an item across devices, WebDAV only over
  https, stricter wildcard sites in the extension, checked atomic writes.

### Security
- Dependencies on their newest releases, none with a known advisory (`cargo deny`).
- Code scanning no longer reports the made-up passwords in test code.

## [0.4.1] - 2026-11-24

Phone app only: passwords evenly spaced, the Secret Key two groups to a line, a recovery part
read from its picture, updates offered as soon as the server has them, languages with flags.
