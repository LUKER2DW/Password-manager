# Privacy policy

**The apps collect nothing about you.** There is no account with the project, no telemetry, no
analytics, no crash reports and no advertising, and the project runs no server of its own. Your
vault is one encrypted file on your devices; it goes only where you sync it, and it opens only
with your master password and your Secret Key, which never leave your devices.

What does leave a device is listed below, all of it: where it goes, when, and how to turn it
off. Anything not listed here is not sent.

## The desktop app (Windows)

| What is sent | To | When | On or off |
|---|---|---|---|
| A request for the project's newest release, then that release's `manifest.json` and its signature; when the release has a newer browser extension than the app's, its zip; when the release is newer than the app, its program (`vault-desktop.exe`), which installs itself | GitHub (`api.github.com`, `github.com` and GitHub's file store) | Half a minute after the app starts, then once an hour while it runs, and when you press **Check for updates** | **On by default**, so a fix reaches every computer soon after it is released. The first screen of a new vault says so, with the switch; later, **Settings → About → Look for updates by itself**; **Install updates by itself** (on by default) off, the program is downloaded only when you press **Install now**. The button always works |
| The leak check: the first 5 characters (hex) of each password's SHA-1 fingerprint, never a password; the answers are padded so their size says nothing | Have I Been Pwned (`api.pwnedpasswords.com`) | When you press **Check** on Password health; once a day with the leak watch on | Off until you ask; the leak watch is off by default |
| Website icons: a request for each saved website's icon | Each website itself, at its own address over HTTPS (never a third-party icon service) | While website icons are on | Off by default (**Settings → Privacy**) |
| An icon or picture link you choose for an item or folder | That address | When you choose it | Only when you do |
| Your vault, sealed (the same encrypted file, never your keys) | Your own folder, WebDAV host or sync server | When the vault opens, after each save, every 5 minutes and when you press **Sync now** | Off until you set sync up (**Settings → Sync**) |

The browser extension's link to the app is a local pipe on your computer, off by default.
Links the app opens (a release page, a website) open in your browser when you click them.

## The phone app (Android)

| What is sent | To | When | On or off |
|---|---|---|---|
| A request for the project's newest release and its manifest and signature; the new app when you install it | GitHub, or your own sync server if you choose it | While a vault is open: when it opens and then once an hour (from your server: after syncing), and when you press **Check for updates** | **On by default**. The first screen says so, with the switch; later, **Settings → About and updates** (where updates can come from your server instead) |
| The leak check and the leak watch, as on the desktop | Have I Been Pwned | When you ask; once a day with the leak watch on | Off until you ask; the leak watch is off by default |
| Website icons, as on the desktop | Each website itself | While website icons are on | Off by default (**Settings → Appearance**) |
| Your vault, sealed | Your own folder, WebDAV host or sync server | When the vault opens, after each save and every few minutes | Off until you set sync up |

Filling logins and passkeys into other apps and websites happens on the phone, between the app
and Android: nothing is sent for it.

## The browser extension

It talks only to the desktop app on the same computer (the browser's native messaging, then a
local pipe), and only on pages you open. It sends nothing to the internet itself and downloads
nothing: a newer version comes from the desktop app's own folder.

## The sync server (yours)

The server is a program you run yourself, for your own devices; the project never sees it.
It keeps each device's sealed copy of the vault, the devices' names and public keys, and the
invites' digests ([SERVER.md](SERVER.md)), and sees what any server sees of a request (the
address it came from, its time and size). It sends nothing anywhere unless you start it with
`--app-updates`: then it asks GitHub for the project's newest release every 6 hours, and
downloads its manifest and the new phone app when there is one.

## The command line (`vault`)

It syncs when you ask it to (`vault sync`), to the place you set up, and sends nothing else.

## What GitHub and Have I Been Pwned see

Each request shows them the address it comes from and its time, as any website sees. An update
check carries nothing about you, your vault or your device: a general program name and no
version, cookie or identifier. The leak check carries the five characters above. Their own
privacy policies apply to what they keep.

## Questions

Report a problem with what an app sends as [SECURITY.md](../SECURITY.md) describes.
