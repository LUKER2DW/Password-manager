# Translations

Every word the desktop app shows is written in English in the `.slint` files, inside
`@tr(...)`. Rust sends codes, never sentences (see `ui/model.slint` → `Messages`). This folder
holds the translations of those words as gettext catalogues; `ui/build.rs` compiles them into
the app and `src/i18n.rs` picks one at run time (Settings → Appearance → Language, or the
Windows language; `VAULT_LANG=pt_BR` overrides both).

```
vault-desktop-ui.pot                      every text to translate (generated, do not edit)
pt_BR/LC_MESSAGES/vault-desktop-ui.po     Brazilian Portuguese
```

A text missing from a catalogue shows in English, so a language can be translated a piece at
a time.

## Updating the template after changing a `.slint` file

```bash
cargo install slint-tr-extractor --version 1.18.1 --locked
cd apps/desktop
slint-tr-extractor ui/*.slint -d vault-desktop-ui --package-name vault-desktop-ui -o translations/vault-desktop-ui.pot
```

Then bring each catalogue up to date with gettext's `msgmerge` (or Poedit → Update from POT):

```bash
msgmerge --update --backup=none translations/pt_BR/LC_MESSAGES/vault-desktop-ui.po translations/vault-desktop-ui.pot
```

Each entry's `msgctxt` is the Slint component the text is written in (`TrayMenu`,
`SettingsPage`, `Messages`…): the same English word may be translated differently in two
places. Placeholders (`{}`, `{n}`, `{0}`) must stay as they are; plurals use the
`Plural-Forms` line of the catalogue's header.

## Adding a language

1. Copy the template to `<language>/LC_MESSAGES/vault-desktop-ui.po` (`es`, `fr`, `de`…),
   set `Language:` and `Plural-Forms:` in its header, and translate.
2. Add it to `LANGUAGES` and `catalogue_for` in `src/i18n.rs`, and to the Language list in
   `ui/pages.slint` (Settings → Appearance), named in its own language.

The browser extension has its own catalogues in `apps/extension/_locales/<language>/messages.json`
(Chrome's format); `en` is the default.
