# vendor/

Third-party code the workspace builds from here instead of from crates.io, each with the one
change the app needs. The root `Cargo.toml` points cargo at it (`[patch.crates-io]`) and keeps
it out of the workspace (`exclude`). Nothing else is changed in these copies: their licences
are their own (each keeps its `LICENSES/`).

## i-slint-backend-android-activity

Slint's Android backend, as published on crates.io (GPL-3.0-only, among its licences; the
app is GPL-3.0-or-later). The change, in `java/SlintAndroidJavaHelper.java`
(`onCreateInputConnection`): every text field the system keyboard serves asks it not to learn
what is typed (`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`, the flag Gboard's incognito
mode follows), not only the password fields. Without it the keyboard would learn the vault's
titles, usernames, notes, card numbers and recovery codes, and suggest them later in any app
(M10 S23). The secret fields already ask for a password keyboard, which learns nothing.

Slint's Java side has no way to set that flag from the app, so the change can't live in the
app's own code. A Slint update needs the copy made again, with the change:
`vendor/update-slint-android.ps1 -Version <version>` (its comment has the steps). Until then
cargo would quietly build the published crate instead of this one: `apps/mobile`'s tests fail
when the lock file doesn't take this copy, or when the copy lacks the flag.
