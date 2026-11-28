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
- **Network only for sync and opt-in website icons.** `INTERNET` is the only permission that
  reaches out. The app has no camera permission: Google's code scanner reads QR codes.

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
| Start | No vault on this phone: scan the computer's QR code (or paste its line) to set it up from the server, or choose its file | ✅ (Google's code scanner, the system's file picker on Android) |
| Unlock | Master password (and the Secret Key the first time on this phone, typed or scanned from the kit's QR code), or the phone's unlock (fingerprint, face or screen lock); a chooser for the vaults this phone keeps; under the form the open vault's doodles fade in, with "Forgot your master password?" and, the first time, "No Secret Key? Use two recovery parts" | ✅ |
| Recovery | With the emergency kit: all three recovery parts and a new master password (the vault gets a new Secret Key too, shown before it opens, and the parts used stop working, as on the desktop), or two parts that bring back a Secret Key the phone doesn't have (the parts stop working first, written over the file they were checked against, and only then is the key kept; if the file changed meanwhile or can't be written, nothing is kept and the parts still work); a vault file older than one this phone already opened or wrote is refused before anything is written, with two parts or three; each part typed or scanned from its QR code. Parts are retired in the current file only: older copies (the `.bak`, a server's copies, other devices until they sync, backups) still take them. A recovery doesn't change the vault key (CRYPTO.md §3), so whoever opens an older copy, with its kit or its factors, also holds the key to newer copies until the vault key is renewed. Renewing is done on a computer, where the new kit is printed (CRYPTO.md §3.8); the phone then takes the new key in Settings → Sync | ✅ |
| Vault | Search, filters (all, favourites, logins, cards, notes, SSH keys), the list; the Folders button opens every folder (those inside a folder under it) with its count, and an x leaves the folder; under All, the folders follow the items after a divider; swipe between the four places | ✅ |
| Item | Every field with Copy; password, card number, CVV, PIN and code hidden until asked (and, by default, each show or copy of a secret asks for the fingerprint or screen lock first); item lock; open the website; notes in Markdown; created and last edited; previews of attached pictures, text and PDFs; an SSH key's type and fingerprint | ✅ |
| Editor | New login, card, note, authenticator item or SSH key, edit, delete, attach files; a folder (from a list) and an icon (the site's, or a preset line icon in colours of its own, behind Choose); the setup key scanned from a QR code (the kind of code under Advanced options); "Make a strong one" opens the generator and Use brings it back; an SSH key made here, pasted or read from a file in any common form, its passphrase asked once | ✅; ⬜ custom fields |
| Codes | One-time codes with a countdown pie and its seconds, green to yellow to red; tap a card to copy, or drag it to the left (Copy shows under it, and "Copied" on the card); drag it to the right to edit it (the page doesn't change place there); hold a card, then drag it up or down to put it elsewhere (the order is kept on this phone, per vault); Next for counter-based ones; Add | ✅ |
| Generator | Characters or words, length (a held slider keeps the finger), Advanced options, strength, the password in a box as tall as it needs; copy; "New login with it"; the history of copied passwords (masked, with the date and time, those an item already uses leave it for good, and while an item's secrets are behind the item lock the list stays masked and nothing in it can be copied (checked again after every sync that brings items); each deletable after a confirmation, the list cleared after one) | ✅ |
| Settings | Security, autofill, vaults (its name, kept in the vault; an icon and its colours on this phone), import and export, sync (a device without a copy where the vault syncs now says so; a vault key renewed on a computer is taken once with the new Secret Key and the master password), appearance, about and updates (with short notes for each version; updates from GitHub, looked for every hour while a vault is open, or from the vault's servers, asked after syncing; what was found is said), password health (a ring with the share of logins that are fine, what to do first, counts that filter the list, each login's problems as tags, the leak watch's switch, what the words mean), folders (inside other folders, with an icon and a colour) | ✅ |
| Autofill sheet | Android's own picker over another app | ✅ (Java) |

Every page scrolls on its own (`Scroller` in app.slint: one per page and a thin bar while it
moves). Past either end a page overscrolls like a rubber band: a pull moves it about half the
finger's travel at first and less and less after (never more than 96 px), and it springs back
to the end as soon as the finger lets go (or holds still); a fling that runs into an end goes
a little past it and springs back the same way. The Flickable reports a finger's moves
(`flicked`), so a quiet moment means let go. (A Slint `Timer` that was never started ignores
`restart()`, which is why each timer there is set running first; before that, the spring
never started.) A slider being dragged holds the finger (`Gesture.holding`): Slint's
Flickable otherwise takes any drag that moves 8 px up or down in its first half second.
Slint measures wrapped text that an `if` or `for` shows inside a card as if its lines were one,
so such blocks are written out or shown through `Fold` (a height limit instead of `if`), and
each page keeps 56 px of room at its end.
Sensitive actions (removing a vault or a device, adding a device, stopping sync, removing the
backup server, deleting an item, a folder or the generator's history) ask first in a sheet at
the bottom; the changes to sync and to the vaults on the phone also ask for the master password
there, checked against the vault file. A password an action needs is typed in that same
sheet, not on the page: the master password (and the export's own) for an export, a file's
password when the chosen file turns out to have one, a new master password, the item lock's
check, an SSH key's passphrase. The sheet stays open while the password is checked and says
there what went wrong; it closes once the action is done, and its fields are wiped when it
closes either way.

Secret fields have a cursor: on the phone the field's own input (stand-ins only, §7.2) draws
the dots and the system's cursor, so a tap places it and a long press selects and pastes;
`Secrets.typed` gets each edit with where the cursor is, and the buffer is edited there. With
the text shown, or with the app's own keyboard, the field draws one cell per character and a
tap or the arrows move the cursor (`Secrets.carets`, kept in Rust). A long password scrolls
inside the field instead of widening the page.

Rules carried over from DESIGN.md: one yellow thing per screen (the main button), hand-drawn
only for small details (the stroke under the chosen place), sentence case, words that say
what happens. Added for touch: targets at least 48 px, the main action within reach of a
thumb (bottom of the form, not the top bar), nothing that needs hover.

## 4. Security on a phone

| Topic | Decision |
|---|---|
| Secret Key at rest | Android Keystore (StrongBox when the phone has it), wrapped key in app-private storage |
| Quick unlock | ✅ `BiometricPrompt` releasing a Keystore key that opens a device secret, which unwraps the vault key (CRYPTO.md §3.1.1, as Windows Hello does on the desktop): a Class 3 fingerprint or face, or the phone's screen lock (PIN, pattern or password); master password again every 14 days and after it changes (turning fingerprint unlock off and on again doesn't renew the 14 days, and a clock moved back counts as too long ago); a new fingerprint retires the key; taking a renewed vault key turns fingerprint unlock off (its sealed copy of the vault key opens nothing then) until it is turned on again |
| Each use | ✅ Settings → Security, "Ask for the fingerprint or screen lock every time", on by default: showing or copying a password (a card's PIN, an SSH private key), showing or copying a one-time code, showing or copying a card's number or security code, showing a secure note, viewing or saving an attached file, opening an item in the editor and showing or copying the generator's history each ask Android's own prompt first (`BiometricPrompt` with `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL`, `Biometrics.confirm`, through `System::check_person`), in that very action: no grace period, the next use asks again, a cancelled or failed check shows and copies nothing, an answer that comes after the item was left or the vault locked does nothing (`controller/each_use.rs`). One-time codes are dots with an eye, on the item page and on each row of the Codes page; the eye asks for that code only, which then shows with its countdown until it runs out (its time step passes, or Next makes a counter-based one), and goes back to dots by itself, never asking again on its own; leaving the item or locking hides it too, and hiding never asks. With the setting off, codes show as before. A phone with no screen lock can't ask it: the item lock's PIN or password is asked instead, in a sheet, for that use only (it opens the lock just for it); with no item lock either, nothing shows until a screen lock is set or the setting is turned off, and Settings says which of these holds. The item lock works as before: "Show the secrets" asks its own check (never the phone's instead) and then shows them (its code included), so one action asks once; every later use asks the phone. A bare prompt and not a Keystore key: the open vault already holds the secrets in the app's memory, so a key would release nothing the app needs (the prompt's answer comes from the system, which another app can't give), and a key the screen lock opens must not stand in for the item lock's PIN. Autofill and passkeys asked for every use already, setting or not |
| Previews | ✅ Pictures and text are decoded in Rust from memory. A PDF is drawn by Android's `PdfRenderer`, which reads a file descriptor: memory with no name (`memfd`), so the decrypted PDF touches no storage; where the kernel has none, a file in the app's private cache whose name is deleted as soon as it is open. Either way it is overwritten over its full length and every descriptor closed when drawing ends, whatever failed (`PdfPreview.java`, `Wipe.java`); a leftover of an older version is wiped at the next start. At most 40 pages, each at most 1080 × 4096 pixels, 96 MiB together, decided before any pixel is asked for (`system::PageBudget`, held to again in Java): many pages are drawn smaller, and a PDF that doesn't fit ends there and says how many pages are shown. Nothing is handed to another app |
| Exports | ✅ The master password again (checked against the file), in the confirmation sheet; refused while items are behind the item lock. The protected export (`.vaultx`) is sealed under a password of its own; a plain JSON or CSV export says it holds every password in plain text; before the file is made, the sheet shows what the chosen format leaves out and what it writes in plain text (`vault_import::export_report`), counted again if the vault changed before confirming; an import shows its first warnings (and how many more) before its sheet closes |
| Generated passwords | ✅ The last 50 copied, sealed with the vault key next to the phone's copy (`generated-<vault id>.history`), masked until shown; those an item already uses leave the list for good, and while some item's secrets are behind the item lock the list stays masked and can't be copied from |
| Screen | ✅ `FLAG_SECURE` unless "Allow screenshots" is turned on: no screenshots, blank in the app switcher |
| Clipboard | Marked sensitive (`EXTRA_IS_SENSITIVE`, Android 13+), cleared after the timeout |
| Background | Locks when the app leaves the screen for longer than the auto-lock time; at once with "Lock as soon as I leave the app" |
| Autofill | ✅ Offers only the logins saved for the website's exact domain (or under a saved `*.example.com`, never one over a public suffix such as `*.co.uk` or `*.github.io`; a `*` only in an address's path is no rule), or for an app by the `androidapp://<SHA-256 certificate>@<package>` saved in the login. Who would receive a login is worked out from the fields that get it (`Place.java`, `autofill::Recipient`): a website only when a browser known by its package and signing certificate names it, over https, for fields under the same web view; else the app itself, by its package and Android-verified signing lineage. A facet for an earlier signer remains valid only while Android includes it in that app's verified rotation history. A differently signed app with the same package, an app with ambiguous or unavailable signer data, any other browser, an app under a known browser's name, and pages that aren't https get nothing; a domain given by any other app counts for nothing (Digital Asset Links can't be checked offline). The cases of AutoFail (USENIX Security 2026): a sandboxed frame or another opaque origin, which a browser names "null", is nobody's site (never one bucket for all of them); fields of another frame's origin are never one form with the page's, so a login goes only into the fields of the origin it is for; a form in a frame of another site than the page around it (not the same registrable domain) gets no offer and saves nothing, since the person sees the page, not the frame (`Fields.framedByAnotherSite`, `autofill::same_site`); and the list of offers tells no app which sites have logins: an app that isn't a browser known by its certificate sees only its own logins, whatever domain it claims, and a locked vault shows one "Unlock" line for everyone. Saving follows the same rule, for the page the offer was made for. A legacy package-only app facet is never filled; Android's explicit save confirmation shows the current signer and is the only path that rebinds it. None behind the item lock is offered or changed: a new password for one is kept as a login of its own, behind the lock. Every fill asks for a fingerprint or the phone's lock first; a phone with no screen lock gets nothing |
| Typed secrets | Slint secure field → locked buffer in Rust, through an input connection that keeps no text (§6.1); the keyboard is told the field is a password (no suggestions, no learning) |
| Keyboard | ✅ Every text field asks the keyboard not to learn what is typed (`IME_FLAG_NO_PERSONALIZED_LEARNING`, the flag Gboard's incognito mode follows): titles, usernames, notes, card numbers, recovery codes and searches never come back as suggestions in other apps. Slint's Java side sets no such flag and the app can't reach it, so the APK builds Slint's Android backend from `vendor/` with that one line added (`vendor/README.md`; a test fails if a Slint update leaves the copy behind). The secret fields ask for a password keyboard, which learns nothing anyway. A keyboard app that ignores the flag still sees and may keep what it is handed: that is the keyboard's choice (THREAT_MODEL.md) |
| Backups | ✅ Nothing of the app goes into Android's cloud backup or its copy to a new phone: `allowBackup` is off (which, since Android 12, stops the cloud backup only) and `data_extraction_rules.xml` leaves every storage domain out of both. A vault moves by sync or an export; the Keystore keys never leave the phone |
| Other apps' windows | ✅ No other app's overlay ("display over other apps") is drawn over the app's windows while they show (`Window.setHideOverlayWindows`, `Shield.java`; the system's own windows still show): no false unlock screen or button laid over the app's, and no taps through such a window. The app's screen is one surface drawn by its Rust library, whose touches never pass through Android's views, so `filterTouchesWhenObscured` can't apply; Android 12 and later also block taps through another app's window by themselves. On Android 14, only accessibility tools (a screen reader) may read the windows or act in them (`setAccessibilityDataSensitive`) |
| Task | ✅ No task affinity (`android:taskAffinity=""`): another app's activity can't be slipped into the app's task, over its screens, when it is opened from the launcher (task hijacking); the variant only a system update stops is fixed in Android 12, the oldest the app installs on |
| Release check | ✅ The built APK's manifest, as Android reads it after Gradle merged in the libraries', is checked before a release publishes it (`check-manifest.ps1`, in `build.ps1` too): those protections, Android 12 at least, no plain http, no permission but those listed, and no part open to other apps but the launcher screen, the autofill and passkey services (only Android may bind to them) and AndroidX's profile receiver (only adb) |
| Root / debugger | Not defended against beyond what the Keystore gives: stated in THREAT_MODEL.md |

## 5. Milestones (M7)

| # | Milestone | Done when |
|---|---|---|
| M7.0 | **Base** — crate, screens, controller, off-screen screenshots, headless test | ✅ |
| M7.1 | **Runs on a phone** — NDK build (cargo + Gradle, §7.2), Slint Android backend, the system keyboard for secret fields (§6.1, §7.2), bundled fonts (§6.2), Back | ✅ an APK opens a test vault on a device; ⬜ fonts |
| M7.2 | **Phone storage** — Keystore-backed Secret Key, app-private vault path, the system file picker and "open with" for `.vault` files (§6.3), `FLAG_SECURE`, sensitive clipboard | ✅ a vault made on Windows opens on the phone; ✅ `FLAG_SECURE`; ⬜ "open with" |
| M7.3 | **Biometrics** — Class 3 prompt, key invalidated when biometrics change; an app lock | ✅ built (CRYPTO.md §3.1.1); ⬜ tried on a device |
| M7.4 | **Autofill** — `AutofillService` with app and origin matching, save prompt | ✅ built: offers, a confirmation on every fill, "Save to Vault?", a strong password suggested; ⬜ tried on a device |
| M7.5 | **Passkeys and Credential Manager** (Android 14+) | ✅ built: sign-in and new passkeys for browsers and apps, a fingerprint or the phone's lock first, the vault file opened with the fingerprint while locked (THREAT_MODEL.md); ⬜ tried on a device |
| M7.6 | **Sync** with the self-hosted server or WebDAV (M6) | ✅ The same vault on both devices without copying a file |
| M7.7 | Cards, authenticator items (time- and counter-based), SSH keys, files and their previews, folders, password health, import and export, the generator's history, Brazilian Portuguese (✅); custom fields (⬜) | Parity with what the desktop edits |

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
| Codes, keys, passwords | **JetBrains Mono**, built in | **JetBrains Mono**, the same files | SIL OFL 1.1 (`apps/desktop/ui/fonts/OFL.txt`), shipped unmodified |

Other candidates we looked at:
- **D-DIN** is closer to DIN but has only two weights.
- **Sofia Sans** and **Saira** have a width axis like Bahnschrift.

Barlow wins on weights and on how it reads at small sizes.

How the fonts get in:
- Done for the monospace one: `JetBrainsMono-Regular.ttf` and `-SemiBold.ttf` are in
  `apps/desktop/ui/fonts/` with their `OFL.txt`, imported by both apps' `app.slint`, so Slint
  compiles them into the binaries (about 550 KB). Without them the phone fell back to its
  proportional sans-serif, and a shown password, drawn one character to a box, came out with
  wide letters running into their neighbours and gaps after narrow ones.
- Still to do for the interface: `import "fonts/Barlow-Regular.ttf";` (and the Light and
  SemiBold files) in `apps/mobile/ui/app.slint`, with `Theme.ui-font` set to `"Barlow"` on the
  phone. Until then the phone uses Roboto, which works but loses the look.

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

# The same screens in Brazilian Portuguese (English otherwise, whatever the computer's language):
VAULT_LANG=pt-BR cargo run -p vault-mobile --example phone_screens -- target/phone-screens-pt

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
controller. The activity is `VaultActivity`
(`apps/mobile-android/java/`), Android's `NativeActivity` plus the system's file picker:
it opens a document (`ACTION_OPEN_DOCUMENT`) or asks where to save one
(`ACTION_CREATE_DOCUMENT`), reads and writes it through the content resolver off the main
thread, and hands the bytes to the native library (`src/shell.rs`, JNI). The launcher icon (`res/`)
is the desktop's safe, as an adaptive icon. It is plain Java, not Kotlin.

`build.ps1` builds it in two steps: cargo builds the native library with the NDK's linker
(in `target/android`, apart from the computer's builds, so both can build at once), then
Gradle (`gradlew`, `build.gradle`, `AndroidManifest.xml`) packages it with the Java shell,
`res/` and the one library the Java side uses, Google's code scanner, and signs the APK.
The library is built with the `fast` profile (optimized, parallel, incremental: a rebuild
after a change takes a fraction of a full one); `build.ps1 -Release` uses the release
profile (one codegen unit and LTO). The first build fetches Gradle and the scanner's
libraries from Google's Maven repository; later builds use Gradle's cache.

```powershell
# Once: the NDK and platform 35 (sdkmanager), Rust's Android targets. Gradle runs on
# Android Studio's Java (JAVA_HOME, or its jbr folder).
sdkmanager "ndk;30.0.16248370" "platforms;android-35"
rustup target add aarch64-linux-android x86_64-linux-android

./apps/mobile-android/build.ps1          # target/release/apk/vault-mobile-android.apk
adb install -r target/release/apk/vault-mobile-android.apk
```

The APK is signed with the release key when there is one, else with the Android debug key
(for trying it, never for publishing it). The release key is made once with
`./apps/mobile-android/make-release-key.ps1`: a 4096-bit RSA key in
`%APPDATA%\PasswordVault\signing\release.p12`, outside the repository, its password sealed
for this Windows user (DPAPI) so `build.ps1` signs without asking. Android installs an update
only when it carries the same key as the app on the phone, so back the key and its password up
offline: lost, no update installs over the app again; copied, whoever has it can sign an
"update". The first APK signed with it doesn't install over one signed with the debug key: sync
or export the vault, uninstall once, install again. Gradle needs a Java it supports (JDK 17 or
21 in `JAVA_HOME`; a newer Android Studio's own Java may be too new for it).
The key's place and password may be given in the repository's `.env` instead (git-ignored;
`.env.example` names the two variables), which `build.ps1` reads first.

**Releases on GitHub.** `.github/workflows/release.yml` builds the same APK on GitHub from
`main` whenever an app or what it is built from changes, together with the desktop app, the
server and the browser extension, checks its manifest (`check-manifest.ps1`) and, in a run that
publishes, signs it with the release key and checks it came out signed with the release
certificate alone (its SHA-256 is written in the workflow). When the version
every app carries has no release yet, it publishes `v<version>`: the notes are that version's
section of `CHANGELOG.md`, and every file has a provenance attestation. To release, bump the
version in each app (the workflow's comment lists the files), add the notes shown in About and
write the changelog section. The phones find the new APK by themselves within the hour, on
GitHub or, when they take updates from it, on a sync server that follows the releases
(`--app-updates`, docs/SERVER.md).
The key and its password are secrets of the `android-release` environment
(`ANDROID_SIGNING_STORE`, the `.p12` in base64; `ANDROID_SIGNING_PASSWORD`), handed only to a
run for `main` that publishes, and only once the maintainer approved it (the environment's
required reviewer, admins included); any other run builds the same APK with a key made for
it. GitHub keeps them write-only: they are not a backup of the key.

What is in this first build (M7.1):
- **Secret fields take the system keyboard, asked for a password** (no learning, no
  suggestions). The field's `TextInput` only ever holds stand-ins, drawn as its password
  dots with the system's cursor: each edit goes to `Secrets.typed` with where the cursor is,
  which puts what was typed in the secure buffer at that place (the stand-ins missing were
  deleted there) and hands back a stand-in for each character, as long in UTF-8 and UTF-16
  as that character (Slint's password mask panics on a cursor inside a character). A tap
  places the cursor, a selection can be typed over, and a long press opens the system's
  menu: Paste goes through the same path. Each keystroke still passes through a Java string
  and a Slint string on the way (§6.1, option A); the stand-ins replace it at once.
- **The recent apps view never shows the app's screen** (`setRecentsScreenshotEnabled(false)`
  from Android 13; before it, the secure flag while the app is in the background), with
  screenshots allowed or not.
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
- `INTERNET` is the only permission that reaches out. The Java side may use no plain http
  (`usesCleartextTraffic="false"`); the app's own connections, made by its Rust library,
  refuse `http://` except to the phone itself or a Tailscale address (and for WebDAV, which
  sends its password with every request, anything but the phone itself).
- **Scan the QR code** (the start screen and Settings → Sync) reads the invite a computer
  shows under Add a device with Google's code scanner (`play-services-code-scanner`, the
  same as Sentinela's): the camera screen is Play services' own, so the app has no camera
  permission and gets back only the code's text, which is used as a pasted line. A phone
  without Play services gets a message to paste the line instead.
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
- **SSH keys and files:** a new Ed25519 key, or one pasted or read from a file through the
  system's picker in any common form (OpenSSH's, PKCS#8, PKCS#1, SEC1; a passphrase asked
  once in the sheet, the key kept without it, as `vault_core::ssh` says); files attached to
  any item, saved through the system's "save as" and read back before they are called saved.
- **The APK's size:** the Rust library is stripped (`llvm-strip`, its symbols only; the
  phone never shows a backtrace) and compressed in the APK (`useLegacyPackaging`), as
  cargo-apk did: a release build is about a third of the uncompressed one.

- **Settings in groups** (Security, Autofill, Vault, Import and export, Sync, Appearance,
  Updates, About). **Several vaults:** the vault's name on top of the list opens a card with
  every vault on the phone (open or locked, where each syncs), Add a vault, Manage vaults.
- **Fingerprint unlock** (CRYPTO.md §3.1.1), **Lock as soon as I leave the app**, **Allow
  screenshots** (off: `FLAG_SECURE`).
- **Autofill** (`VaultAutofillService`, `AutofillActivity`, `src/autofill.rs` in vault-mobile):
  the logins for exactly the website or app asking; a fingerprint or the phone's lock before
  every fill; "Use a strong password" on password fields; "Save to Vault?" after a sign-in,
  into the open vault or, while it is locked, its drop box (CRYPTO.md §3.5). The service and
  its activity are declared in `AndroidManifest.xml`.
- **Sync as on a computer:** Add a device (QR code and line), change the server's address,
  add or remove a backup server, the devices (remove one), how many copies the server keeps.
- **A renewed vault key** (SYNC.md §4.7): when the key was renewed on a computer, Settings →
  Sync says so and its sheet asks once for the new Secret Key (from the new kit) and the
  master password; the phone then keeps the new Secret Key in the Keystore, syncs again and
  turns fingerprint unlock off. The phone doesn't renew the key itself: the new kit has to be
  printed, so that is done on a computer (the desktop app or `vault renew-key`).
- **Updates** from the project's releases on GitHub (the default: looked for every hour while
  a vault is open, the package taken only as the release lists it) or from the vault server
  (docs/SERVER.md, "Updates of the phone app"); Settings → About and updates chooses, and
  turns the looks on their own off.
- **Import** of another manager's export, and **Check this password** (strength, leak check)
  on the item page. **The leak watch** (Security, off until turned on): every login checked
  once a day while open; a new leak is told and marked in the list.

Not yet: scanning a one-time code's QR code, the bundled fonts (Roboto stands in), passkeys.

**Updates** take only this app, newer and signed with the same certificate, checked before
Android's installer gets it; the installer's answer comes to a receiver no other app can reach
(`Updates.java`, `InstallReceiver.java`). The APKs are signed with the release key that
`make-release-key.ps1` makes (see below), the only key updates are taken from.

### 7.3 Languages

Every text of the phone is written in English in the `.slint` files, inside `@tr(...)`, and
Brazilian Portuguese is compiled in from `apps/mobile/translations/` (gettext, as the desktop's;
see its README). Settings → Appearance chooses "the phone's" (the phone's language, the
computer's, or the browser's in the web preview), English or Português, and the words change at
once. The catalogue is checked by `cargo test -p vault-mobile i18n`: the template lists every
text of the sources, and every text has a Portuguese one with the same placeholders.
