# Mobile app

> Status: **started**. The screens and their controller exist (`crates/mobile`) and run in a
> phone-sized window on the desktop; nothing is packaged for Android yet. This document is the
> plan: what the app is, how it is built, the order of the work, and what is still open.

## 1. What it is

The same vault on a phone: Android first (ROADMAP Phase 5). One person's passwords, cards,
notes and one-time codes, opened with the master password or the phone's biometrics, filled
into apps and websites by Android itself.

It is not a second product. It reads and writes the same vault file with the same core, shows
the same design, and follows the same rules (AGENTS.md §4).

## 2. How it is built

```
┌──────────────────────────── Android app (one APK) ────────────────────────────┐
│  Kotlin shell (android/)                 Rust (one shared library)            │
│  ─ activity that hosts the Slint UI      ─ vault-mobile: screens + controller │
│  ─ AutofillService                       ─ vault-core: keys, format, items    │
│  ─ CredentialProviderService (14+)       ─ vault-platform: Keystore, storage  │
│  ─ BiometricPrompt, Keystore/StrongBox                                        │
│  ─ file picker, share sheet, lifecycle   JNI bridge: a few narrow functions   │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **Screens: Slint**, like the desktop app. `crates/mobile/ui` imports the desktop's tokens,
  widgets and icons (`crates/desktop/ui/theme.slint`, `widgets.slint`, `icons.slint`), so the
  two apps can't drift apart. `Theme.touch` makes text a step larger and controls 48 px tall.
- **Logic: Rust.** `vault-mobile` has its own small controller: a phone shows one thing at a
  time, so it shares the core and the widgets with the desktop, not its window logic.
- **System services: Kotlin.** Autofill, Credential Manager, biometrics and the Keystore are
  Android APIs with no Rust equivalent. They call the Rust core through a narrow JNI bridge
  and never hold a decrypted vault of their own.
- **No network** until sync exists (§6). The app asks for no `INTERNET` permission before.

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
| Welcome | No vault on this phone: create one, or bring one from another device | ✅ create; ⬜ bring |
| New vault | Master password twice, then the Secret Key and Recovery Key to write down | ✅ |
| Unlock | Master password (and the Secret Key the first time on this phone) | ✅; ⬜ biometrics |
| Vault | Search, filters (all, favourites, logins, cards, notes), the list | ✅ |
| Item | Every field with Copy; password and code hidden until asked; item lock | ✅ |
| Editor | New login or note, edit, delete | ✅ logins and notes; ⬜ cards, custom fields |
| Codes | One-time codes with their countdown; tap to copy | ✅ |
| Generator | Characters or words, length, strength; copy | ✅ |
| Settings | Theme, auto-lock, about, lock now | ✅; ⬜ biometrics, autofill, sync |
| Autofill sheet | Android's own picker over another app | ⬜ (Kotlin) |

Rules carried over from DESIGN.md: one yellow thing per screen (the main button), hand-drawn
only for small details (the stroke under the chosen place), sentence case, words that say
what happens. Added for touch: targets at least 48 px, the main action within reach of a
thumb (bottom of the form, not the top bar), nothing that needs hover.

## 4. Security on a phone

| Topic | Decision |
|---|---|
| Secret Key at rest | Android Keystore (StrongBox when the phone has it), wrapped key in app-private storage |
| Quick unlock | `BiometricPrompt` Class 3 releasing a Keystore key that unwraps the vault key (as Windows Hello does on the desktop); master password again after a restart and every N days |
| Screen | `FLAG_SECURE` on every window: no screenshots, blank in the app switcher |
| Clipboard | Marked sensitive (`EXTRA_IS_SENSITIVE`, Android 13+), cleared after the timeout |
| Background | Locks when the app leaves the screen for longer than the auto-lock time; at once when the screen turns off |
| Autofill | Answers only for the app's verified package and signing certificate, or the website's exact origin; never fills a field of another app on its word alone |
| Typed secrets | Slint secure field → locked buffer in Rust; the system keyboard is told the field is a password (no suggestions, no learning) |
| Backups | The vault file is excluded from Android cloud backup; the wrapped keys never leave the phone |
| Root / debugger | Not defended against beyond what the Keystore gives: stated in THREAT_MODEL.md |

## 5. Milestones (M7)

| # | Milestone | Done when |
|---|---|---|
| M7.0 | **Base** — crate, screens, controller, off-screen screenshots, headless test | ✅ this document's first commit |
| M7.1 | **Runs on a phone** — NDK and `cargo-apk`/Gradle build, Slint Android backend, bundled font, back button, soft keyboard for the secure field | An APK opens a test vault on a device |
| M7.2 | **Phone storage** — Keystore-backed Secret Key, app-private vault path, file picker to bring a vault in, `FLAG_SECURE`, sensitive clipboard | A vault made on Windows opens on the phone |
| M7.3 | **Biometrics** — Class 3 prompt, key invalidated when biometrics change | Unlock with a fingerprint after one password unlock |
| M7.4 | **Autofill** — `AutofillService` with app and origin matching, save prompt | A login fills into a browser and an app |
| M7.5 | **Passkeys and Credential Manager** (Android 14+) | Depends on passkeys in the core |
| M7.6 | **Sync** with the self-hosted server (M6) | The same vault on both devices without copying a file |
| M7.7 | Cards and custom fields in the editor, folders, health, import, translations | Parity with what the desktop edits |

## 6. Open questions

1. **The keyboard.** The secure field takes key events; Android's soft keyboard talks to an
   input connection instead. Either the Slint Android backend forwards committed text as key
   events for a password-type field (to check on a device), or the Kotlin shell owns a small
   hidden input that forwards each character to Rust. An in-app keyboard is the last resort.
2. **Fonts.** Bahnschrift and Cascadia Mono ship with Windows only. The app needs two fonts
   it may bundle (a DIN-like sans and a mono, both under the OFL).
3. **How the vault gets onto the phone before sync exists**: the file picker (M7.2). The
   Secret Key is typed once from the emergency kit, or scanned from the kit's QR code later.
4. **One activity or two.** Autofill needs a way to unlock without opening the whole app: a
   small unlock sheet in the same process, sharing the open vault with the main activity.
5. **iOS** is not planned. Nothing here rules it out: the Rust part is the same, the shell
   would be Swift.

## 7. Working on it

```bash
# The app in a phone-sized window, against a test vault:
VAULT_FILE=target/phone-test.vault cargo run -p vault-mobile

# Every screen as a PNG, off-screen (fake data), with an index.html gallery:
cargo run -p vault-mobile --example phone_screens -- target/phone-screens

cargo test -p vault-mobile
```
