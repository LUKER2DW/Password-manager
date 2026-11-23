# Translations

Every word the phone app shows is written in English in the `.slint` files, inside `@tr(...)`.
Rust sends codes, never sentences (see `ui/app.slint` → `Words`). This folder holds the
translations as gettext catalogues: `build.rs` compiles them into the app, and `src/i18n.rs`
picks one at run time (Settings → Appearance: "the phone's", English or Português; the phone's
own language when it is Brazilian Portuguese).

```
vault-mobile.pot                          every text the phone's build compiles (generated, do not edit)
pt_BR/LC_MESSAGES/vault-mobile.po         Brazilian Portuguese (complete)
```

The phone compiles `ui/app.slint` and the desktop's `theme`, `widgets`, `icons`, `strength` and
`model` (`apps/desktop/ui`), so their texts are in the template too. The desktop has its own
catalogue (`apps/desktop/translations`); the phone's is complete on its own. Terms are kept the
same where they overlap: cofre, chave secreta, sincronização…

A text missing from a catalogue shows in English, so a language can be finished a piece at a time.

## Updating the template after changing a `.slint` file

```powershell
cargo install slint-tr-extractor --version 1.18.1 --locked
cd apps/mobile
slint-tr-extractor ui/app.slint ../desktop/ui/theme.slint ../desktop/ui/widgets.slint ../desktop/ui/icons.slint ../desktop/ui/strength.slint ../desktop/ui/model.slint -d vault-mobile --package-name vault-mobile -o translations/vault-mobile.pot
```

Then translate the new entries in `pt_BR/LC_MESSAGES/vault-mobile.po` (gettext's `msgmerge`, or
Poedit → Update from POT, keeps the old ones).

Each entry's `msgctxt` is the Slint component the text is written in (`PhoneWindow`, `Words`,
`Messages`…): the same English word may be translated differently in two places. Placeholders
(`{}`, `{n}`) must stay as they are; plurals use the `Plural-Forms` line of the header.

`cargo test -p vault-mobile i18n` checks both ways: that the template lists every text of the
sources (so it was regenerated after a change), and that every text has a Portuguese one with the
same placeholders. It names each text that is missing.

## Adding a language

1. Copy the template to `<language>/LC_MESSAGES/vault-mobile.po` (`es`, `fr`…), set `Language:`
   and `Plural-Forms:` in its header, and translate.
2. Add it to `catalogue_for`, `choice_of` and `setting_of` in `src/i18n.rs`, to the Language
   list in `ui/app.slint` (Settings → Appearance), named in its own language, and give it the
   same two checks as Portuguese in `src/i18n.rs`'s tests.
