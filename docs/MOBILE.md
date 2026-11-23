# Mobile app

> Status: **early, runs on Android**. The screens and their controller (`apps/mobile`) run
> as an APK (`apps/mobile-android`), in a phone-sized window on the desktop and in a web page
> (`apps/mobile-web`). This document is the plan: what the app is, how it is built, the order
> of the work, what we chose after looking into the keyboard, fonts and moving the vault over
> (§6), and what is still open.

## 1. What it is

The same vault on a phone: Android first (ROADMAP Phase 5). One person's passwords, cards,
notes and one-time codes, opened with the master password or the phone's biometrics, filled
into apps and websites by Android itself.

It is not a second product. It reads and writes the same vault file with the same core, shows
the same design, and follows the same rules (AGENTS.md §4).

**The phone opens a vault; it never makes one.** A vault is created on the computer, where
the emergency kit is printed. The phone keeps a copy of that file (§6.3).

## 2. How it is built

```
┌──────────────────────────── Android app (one APK) ────────────────────────────┐
│  Java shell (apps/mobile-android/java)   Rust (one shared library)            │
│  ─ VaultActivity: NativeActivity that    ─ vault-mobile: screens + controller │
│    hosts the Slint UI, file picker,      ─ vault-core: keys, format, items    │
│    "save as", Back                       ─ vault-platform: Keystore, storage  │
│  ─ later: AutofillService,                                                    │
│    CredentialProviderService (14+),      JNI bridge: a few narrow functions   │
│    BiometricPrompt, Keystore/StrongBox   (apps/mobile-android/src/shell.rs)   │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **Screens: Slint**, like the desktop app. `apps/mobile/ui` imports the desktop's tokens,
  widgets and icons (`apps/desktop/ui/theme.slint`, `widgets.slint`, `icons.slint`), so the
  two apps can't drift apart. `Theme.touch` makes text a step larger and controls 48 px tall.
- **Logic: Rust.** `vault-mobile` has its own small controller: a phone shows one thing at a
  time, so it shares the core and the widgets with the desktop, not its window logic.
- **System services: the shell.** Autofill, Credential Manager, biometrics and the Keystore
  are Android APIs with no Rust equivalent. The shell is plain Java for now (one small class
  needs no Kotlin compiler or Gradle); its services call the Rust core through a narrow JNI
  bridge and never hold a decrypted vault of their own.
- **Network only for sync and opt-in website icons.** `INTERNET` is the only permission.

### Why not a web view or a second UI toolkit

Typed secrets must stay out of memory we don't control (rule 4.1.3). A web view or a
Compose `TextField` keeps typed text in strings owned by the toolkit and the keyboard's
history. With Slint the master password goes key by key into a locked, wiped buffer, as on
the desktop.

## 3. Screens

One column, 360–430 px wide, portrait first. Four places at the bottom, one page on top of
them when an item is open.

```
 Unlock            Vault               Item                Codes
┌──────────┐     ┌──────────┐       ┌──────────┐       ┌──────────┐
│   logo   │     │ Name   + │       │ ‹ Vault  │       │ Codes    │
│  Name    │     │ [search] │       │ ▢ GitHub │       │ ▢ GitHub │
│          │     │ All Fav… │       │ Username │       │  123 456 │
│ [······] │     │ ▢ GitHub │       │ Password │       │ ▬▬▬▬──── │
│ [ Open ] │     │ ▢ Bank   │       │ Code     │       │ ▢ Mail   │
│          │     │ ▢ Visa   │       │ Website  │       │  987 654 │
│          │     ├──────────┤       │ Notes    │       ├──────────┤
└──────────┘     │ V  C  G S│       └──────────┘       │ V  C  G S│
                 └──────────┘                          └──────────┘
```

| Screen | What it does | State |
|---|---|---|
| Start | No vault on this phone: choose its file, or set it up from the server | ✅ (the system's file picker on Android) |
| Unlock | Master password (and the Secret Key the first time on this phone); a chosen file waits here until it opens | ✅; ⬜ biometrics |
| Vault | Search, filters (all, favourites, logins, cards, notes, SSH keys), the list | ✅; ⬜ several vaults |
| Item | Every field with Copy; password and code hidden until asked; item lock; files | ✅ |
| Editor | New login, card, note, authenticator item or SSH key, edit, delete, attach files | ✅; ⬜ custom fields |
| Codes | One-time codes with their countdown; tap to copy; Add | ✅; ⬜ scan a QR code |
| Generator | Characters or words, length, Advanced options, strength; copy | ✅ |
| Settings | Theme, lock, clipboard, backdrop, website icons, sync, master password, a copy of the vault | ✅; ⬜ groups, biometrics, autofill, updates |
| Autofill sheet | Android's own picker over another app | ⬜ (Kotlin) |

Rules carried over from DESIGN.md: one yellow thing per screen (the main button), hand-drawn
only for small details (the stroke under the chosen place), sentence case, words that say
what happens. Added for touch: targets at least 48 px, the main action within reach of a
thumb (bottom of the form, not the top bar), nothing that needs hover.

## 4. Security on a phone

| Topic | Decision |
|---|---|
| Secret Key at rest | Android Keystore (StrongBox when the phone has it), wrapped key in app-private storage |
| Quick unlock | ✅ `BiometricPrompt` Class 3 releasing a Keystore key that opens a device secret, which unwraps the vault key (CRYPTO.md §3.1.1, as Windows Hello does on the desktop); master password again every 14 days and after it changes; a new fingerprint retires the key |
| Screen | ✅ `FLAG_SECURE` unless "Allow screenshots" is turned on: no screenshots, blank in the app switcher |
| Clipboard | Marked sensitive (`EXTRA_IS_SENSITIVE`, Android 13+), cleared after the timeout |
| Background | Locks when the app leaves the screen for longer than the auto-lock time; at once with "Lock as soon as I leave the app" |
| Autofill | ✅ Offers only the logins saved for the website's exact domain (or under a saved `*.example.com`), or for an app by the `androidapp://<package>` saved in the login; none behind the item lock; every fill asks for a fingerprint or the phone's lock first; a phone with no screen lock gets nothing. ⬜ checking the app's signing certificate |
| Typed secrets | Slint secure field → locked buffer in Rust, through an input connection that keeps no text (§6.1); the keyboard is told the field is a password (no suggestions, no learning) |
| Backups | The vault file is excluded from Android cloud backup; the wrapped keys never leave the phone |
| Root / debugger | Not defended against beyond what the Keystore gives: stated in THREAT_MODEL.md |

## 5. Milestones (M7)

| # | Milestone | Done when |
|---|---|---|
| M7.0 | **Base** — crate, screens, controller, off-screen screenshots, headless test | ✅ |
| M7.1 | **Runs on a phone** — NDK build (cargo-apk, §7.2), Slint Android backend, the system keyboard for secret fields (§6.1, §7.2), bundled fonts (§6.2), Back | ✅ an APK opens a test vault on a device; ⬜ fonts |
| M7.2 | **Phone storage** — Keystore-backed Secret Key, app-private vault path, the system file picker and "open with" for `.vault` files (§6.3), `FLAG_SECURE`, sensitive clipboard | ✅ a vault made on Windows opens on the phone; ✅ `FLAG_SECURE`; ⬜ "open with" |
| M7.3 | **Biometrics** — Class 3 prompt, key invalidated when biometrics change; an app lock | ✅ built (CRYPTO.md §3.1.1); ⬜ tried on a device |
| M7.4 | **Autofill** — `AutofillService` with app and origin matching, save prompt | ✅ built: offers, a confirmation on every fill, "Save to Vault?", a strong password suggested; ⬜ tried on a device |
| M7.5 | **Passkeys and Credential Manager** (Android 14+) | ⬜ Depends on passkeys in the core |
| M7.6 | **Sync** with the self-hosted server or WebDAV (M6) | ✅ The same vault on both devices without copying a file |
| M7.7 | Cards, authenticator items, SSH keys and files (✅); custom fields, folders, health, import, translations (⬜) | Parity with what the desktop edits |

## 6. Researched choices

### 6.1 The soft keyboard and the secure field

**What Slint does on Android.** Slint 1.18's Android backend shows the keyboard only for a
`TextInput`. Its Java side keeps the field's whole text in an editable buffer
(`SlintEditable`, a `SpannableStringBuilder`). On every change it hands the full text to Rust
as a new Java `String`. A `TextInput { input-type: password; }` does set
`TYPE_TEXT_VARIATION_PASSWORD | TYPE_TEXT_FLAG_NO_SUGGESTIONS`, so the keyboard learns
nothing. But the password would sit in Java strings the app can't wipe, one copy per
keystroke, plus a Slint string: that breaks rule 4.1.3. Our `SecretField` is a `FocusScope`,
not a `TextInput`, so as it stands no keyboard opens for it at all.

| Option | Secret in memory we don't control | Keyboard apps see the keys | Effort |
|---|---|---|---|
| A. `TextInput` with `input-type: password` | Yes: Java strings and a Slint string | Yes | None |
| B. **Our own input view** in the Kotlin shell (chosen) | One character at a time, never the whole secret | Yes | Small |
| C. A keyboard drawn by the app | No | No | Large; accessibility and languages suffer |

**Chosen: B, with C for the item PIN.** **Built first: C for every secret field** (M7.1,
§7.2): it needs no Java shell and no keyboard app sees anything. **Then, for now: A with
stand-ins** (the list in §7.2), the system keyboard after all: the field's input
holds stand-ins, never the secret, but each edit crosses a Java and a Slint string. B is
still the goal now that the Java shell exists.

- **The view.** The shell adds `SecretInputView`, a plain `View` whose
  `onCreateInputConnection` returns a connection that holds no text:
  - `EditorInfo.inputType = TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD`;
  - `imeOptions = IME_FLAG_NO_PERSONALIZED_LEARNING | IME_FLAG_NO_EXTRACT_UI | IME_ACTION_DONE`.
- **Typed text.** `commitText` passes each character straight to Rust over JNI
  (`Secrets.insert`). `deleteSurroundingText` and a `KEYCODE_DEL` key event become
  `Secrets.backspace`. `performEditorAction` becomes `accepted`.
- **What the keyboard is shown.** `getTextBeforeCursor` returns as many `•` as the field holds,
  so the keyboard knows there is something to delete without seeing it.
- **Opening and closing the keyboard.** `SecretField`'s focus changes call the shell
  (`Secrets.focused(field, bool)`). The shell focuses the view and asks the
  `InputMethodManager` to show or hide the keyboard.
- **The PIN.** The item PIN is digits only, so the app draws a 3 × 4 pad for it. No keyboard
  app sees the PIN at all.
- **Later.** A setting, off by default, could offer the same drawn keyboard for the master
  password, for people who don't trust their keyboard app.

The remaining risk is the keyboard app itself: it sees the keys of any field it serves. This
goes in THREAT_MODEL.md, next to the clipboard.

### 6.2 Fonts the app may carry

| Role | Desktop (Windows) | Phone | Licence |
|---|---|---|---|
| Interface | Bahnschrift (ships with Windows, may not be redistributed) | **Barlow**: a slightly rounded DIN-like grotesk with weights 100–900, so the 300/400/600 the design uses are all there | SIL OFL 1.1 |
| Codes, keys, passwords | Cascadia Mono | **Cascadia Mono**, the same font | SIL OFL 1.1, Microsoft; "Cascadia Code" is a reserved name, so it ships unmodified |

Other candidates we looked at:
- **D-DIN** is closer to DIN but has only two weights.
- **Sofia Sans** and **Saira** have a width axis like Bahnschrift.

Barlow wins on weights and on how it reads at small sizes.

How the fonts get in:
- `import "fonts/Barlow-Regular.ttf";` (and the Light, SemiBold and Cascadia Mono files) in
  `apps/mobile/ui/app.slint`. Slint compiles the files into the binary, a few hundred KB in
  all.
- `Theme.ui-font` and `Theme.mono-font` become `in-out`, and the phone sets them to `"Barlow"`
  and `"Cascadia Mono"`.
- The `.ttf` files and their `OFL.txt` go in `apps/mobile/ui/fonts/`.
- Without them the phone falls back to Roboto, which works but loses the look.

Linux (ROADMAP) has the same problem, so the same two fonts could serve it. Whether the
Windows app keeps Bahnschrift or moves to Barlow too is a design decision for later.

### 6.3 Getting the vault onto the phone before sync

The file is safe to carry over any channel: without the master password and the Secret Key
it opens nothing (zero-knowledge). What matters is that the person can do it with what they
already have, and that a wrong or old file can't replace the phone's copy.

**Now (built): the phone keeps its own copy.**
- The start screen's "Choose the vault file" goes to the shell's picker. On Android that is
  `ACTION_OPEN_DOCUMENT` from the Storage Access Framework, which covers Download, a USB stick
  (OTG), Drive and any other document provider.
- An intent filter makes `.vault` files shared or opened from other apps land in the same
  place: Quick Share from Windows, Bluetooth, a mail attachment.
- `Controller::bring_vault(bytes)` only reads the file. The phone's copy, in app-private
  storage, is replaced once the file:
  1. opened with the person's keys, and
  2. is no older than the revision this phone saw.

  The old copy stays as `.bak`.
- An older file is refused with "Bring the newest copy". "Cancel" goes back to the phone's own
  copy.
- Settings has "Bring a newer copy" for the same thing later.
- Saving on the phone writes to its own copy. Until sync, changes made on both sides diverge:
  Settings says so.

**Considered and set aside for now:**
- **Open in place** (keep the SAF document and write back to it, as KeePass-style apps do).
  The file can then be swapped under the app by the provider or another app, and it doesn't
  work offline. Worth reconsidering for a person who already syncs a folder (Syncthing), as an
  option.
- **Straight from the desktop over Wi-Fi.** The desktop shows a QR code with its address and a
  one-time key; the phone fetches the file sealed under that key. It is convenient but needs
  the `INTERNET` permission and an open port on the PC (a Windows firewall prompt). It belongs
  with sync (M7.6), which needs both anyway.
- **An animated QR stream** (the file in many QR frames). It is fully offline, but slow for a
  vault with pictures, and it needs the camera.

**The Secret Key.** It is typed once from the emergency kit (`S0-` and 26 characters in Crockford
Base32, which accepts small letters and reads O as 0, I and L as 1). It is then kept in the Keystore. Scanning it is a
later convenience: a QR on the desktop's kit page, read by CameraX and decoded in Rust
(`rxing`). The QR is shown only on request, never printed by default.

### 6.4 Still open

1. **One activity or two.** Autofill needs a way to unlock without opening the whole app: a
   small unlock sheet in the same process, sharing the open vault with the main activity.
2. **iOS** is not planned. Nothing here rules it out: the Rust part is the same, the shell
   would be Swift.

## 7. Working on it

```bash
# The app in a phone-sized window. VAULT_FILE is where the "phone" keeps its copy (default:
# <app dir>/phone/vault.vault); "Choose the vault file" opens the computer's file dialog.
VAULT_FILE=target/phone-test.vault cargo run -p vault-mobile

# Every screen as a PNG, off-screen (fake data), with an index.html gallery:
cargo run -p vault-mobile --example phone_screens -- target/phone-screens

cargo test -p vault-mobile
```

### 7.1 In a browser

`apps/mobile-web` compiles the same app to WebAssembly and draws it on a canvas in a web
page, with a demo vault made in the page (fake data, master password shown beside the phone).
It is for trying the app with a mouse and keyboard; nothing leaves the page and nothing is
kept.

```powershell
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
./apps/mobile-web/build.ps1
python -m http.server 8080 --bind 127.0.0.1 --directory target/mobile-web   # then open http://127.0.0.1:8080
```

What a browser can't give, `src/platform/web.rs` stands in for: files, the remembered Secret
Key and the clipboard live in the page's memory (the page's Copy button puts the demo
password there, so Ctrl+V works in the app), and device state only remembers revisions. The
vault code is the same: the core uses the browser's clock (`web-time`) and its random numbers
(`crypto.getRandomValues`), and Argon2 runs on one thread.

### 7.2 On Android

`apps/mobile-android` is the APK's native library: `android_main` points the app folder
at the app's private storage, starts Slint's Android backend and opens the same screens and
controller. `cargo-apk` packages it. The activity is `VaultActivity`
(`apps/mobile-android/java/`), Android's `NativeActivity` plus the system's file picker:
it opens a document (`ACTION_OPEN_DOCUMENT`) or asks where to save one
(`ACTION_CREATE_DOCUMENT`), reads and writes it through the content resolver off the main
thread, and hands the bytes to the native library (`src/shell.rs`, JNI). `build.ps1`
compiles it with the JDK's `javac` and the SDK's `d8`, adds `classes.dex` to the APK
cargo-apk made, then aligns and signs it again. The launcher icon (`res/`) is the desktop's
safe, as an adaptive icon. It is plain Java, not Kotlin: one small class needs no Kotlin
compiler or Gradle in the build.

```powershell
# Once: the NDK and platform 35 (sdkmanager), Rust's Android targets, cargo-apk.
sdkmanager "ndk;28.2.13676358" "platforms;android-35"
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-apk --locked

./apps/mobile-android/build.ps1          # target/release/apk/vault-mobile-android.apk
adb install -r target/release/apk/vault-mobile-android.apk
```

The APK is signed with the Android debug key: for trying it, never for publishing it.

What is in this first build (M7.1):
- **Secret fields take the system keyboard, asked for a password** (no learning, no
  suggestions). An unseen `TextInput` lies over the field and only ever holds stand-ins:
  each edit goes to `Secrets.typed`, which puts what was typed in the secure buffer and
  hands back a stand-in for each character, as long in UTF-8 and UTF-16 as that character
  (Slint then puts the keyboard's cursor at an offset into what it typed; inside a
  character, its password mask panics). The cursor stays at the end and a selection is all
  of it, as on the desktop. A long press opens the system's menu: Paste goes through the
  same path. Each keystroke still passes through a Java string and a Slint string on the
  way (§6.1, option A); the stand-ins replace it at once.
- **The start screen offers both ways:** choose the `.vault` file (the system's picker; it
  then works offline, and sync can be turned on later in Settings, server or WebDAV), or
  paste the `vaultsync:` line from a computer's Add a device to set it up from the server.
  "Bring a newer copy" takes a file too.
- **Settings:** change the master password (the current one is checked against the file;
  saved and synced), and save a copy of the vault: the copy is read back, compared byte for
  byte and opened with the vault's key before it is called a backup; one that fails is
  deleted.
- **The credential store** is SharedPreferences encrypted with a key in the Android Keystore
  (`android-native-keyring-store`); **the clipboard** is the system's `ClipboardManager`
  over JNI, with copied secrets marked sensitive.
- `INTERNET` is the only permission. Android lets plain http through only so a Tailscale
  address works; the app itself refuses `http://` to anything else.
- **Back** goes one step back: an item or the editor closes, another place goes back to the
  Vault. At the top the app goes to the background (`moveTaskToBack`), never closed by
  mistake. A focus scope around the window takes Back before any field does.
- **Items:** logins, cards (number checked, expiry, security code, PIN kept as the item's
  secret), notes, and authenticator items (a setup key; the name comes from the key's
  issuer when none is typed), as on the desktop. The Codes page has Add.
- **Settings of its own** (`settings.json` next to the vault copy; nothing secret): theme,
  lock time, clipboard time, the doodle backdrop, website icons (off until turned on; the
  desktop's fetcher and sealed cache), the generator's options (Advanced: at least N of each
  kind, look-alikes, characters added or left out; words: case, separator, a digit).
- **An eye** on the master password, the Secret Key (also in boxes, as printed) and the
  password change fields.
- **SSH keys and files:** a new Ed25519 key, one pasted or read from a file through the
  system's picker; files attached to any item, saved through the system's "save as" and read
  back before they are called saved.

- **Settings in groups** (Security, Autofill, Vault, Import and export, Sync, Appearance,
  Updates, About). **Several vaults:** the vault's name on top of the list opens a card with
  every vault on the phone (open or locked, where each syncs), Add a vault, Manage vaults.
- **Fingerprint unlock** (CRYPTO.md §3.1.1), **Lock as soon as I leave the app**, **Allow
  screenshots** (off: `FLAG_SECURE`).
- **Autofill** (`VaultAutofillService`, `AutofillActivity`, `src/autofill.rs` in vault-mobile):
  the logins for exactly the website or app asking; a fingerprint or the phone's lock before
  every fill; "Use a strong password" on password fields; "Save to Vault?" after a sign-in,
  into the open vault or, while it is locked, its drop box (CRYPTO.md §3.5). cargo-apk can't
  declare a service, so `build.ps1` packages the APK again with them added to its manifest.
- **Sync as on a computer:** Add a device (QR code and line), change the server's address,
  add or remove a backup server, the devices (remove one), how many copies the server keeps.
- **Updates** from the vault server (docs/SERVER.md, "Updates of the phone app").
- **Import** of another manager's export, and **Check this password** (strength, leak check)
  on the item page. **The leak watch** (Security, off until turned on): every login checked
  once a day while open; a new leak is told and marked in the list.

Not yet: scanning QR codes, the bundled fonts (Roboto stands in), checking an app's signing
certificate before filling it, passkeys.
