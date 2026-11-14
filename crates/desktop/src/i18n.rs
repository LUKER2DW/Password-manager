//! The app's language.
//!
//! Every word on screen is written in English in the `.slint` files, inside `@tr(…)`. The
//! translations are gettext catalogues in `translations/<language>/LC_MESSAGES/` (see
//! `translations/README.md`), compiled into the app by `ui/build.rs`; nothing is read from disk
//! at run time. Rust never builds a sentence: it sends codes, and the words live in
//! `ui/model.slint`, so changing the language here changes every screen at once, including
//! the open one.
//!
//! The language is chosen in Settings → Appearance and kept per computer (`Settings::language`);
//! left empty it follows Windows. `VAULT_LANG` overrides both (for screenshots and tests).

/// The languages the app can show: the code of its catalogue ("" for the English written in
/// the `.slint` files) and its name, written in that language.
pub const LANGUAGES: [(&str, &str); 2] = [("", "English"), ("pt_BR", "Português (Brasil)")];

/// The catalogue for a language tag (`pt-BR`, `pt_BR.UTF-8`, `en-US`), or `None` when the app
/// has no translation for it. Any Portuguese gets the Brazilian one, the only one so far.
pub fn catalogue_for(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().to_ascii_lowercase().replace('-', "_");
    let language = tag.split(['_', '.', '@']).next().unwrap_or_default();
    match language {
        "en" => Some(""),
        "pt" => Some("pt_BR"),
        _ => None,
    }
}

/// The catalogue to show: `VAULT_LANG`, else the saved choice, else the system's language,
/// else English.
pub fn resolve(env: Option<&str>, setting: &str, system: Option<&str>) -> &'static str {
    [env, Some(setting), system]
        .into_iter()
        .flatten()
        .filter(|tag| !tag.trim().is_empty())
        .find_map(catalogue_for)
        .unwrap_or("")
}

/// Shows the app in the language `setting` asks for (see [`resolve`]). Call after the first
/// window exists: the catalogues come with it.
pub fn apply(setting: &str) {
    let env = std::env::var("VAULT_LANG").ok();
    let system = vault_platform::locale::system_language();
    let catalogue = resolve(env.as_deref(), setting, system.as_deref());
    // A catalogue missing from the build (none compiled in) leaves the English text.
    let _ = slint::select_bundled_translation(catalogue);
}

/// The Settings choice for a saved setting: 0 follows the system, then [`LANGUAGES`] in order.
pub fn choice_of(setting: &str) -> i32 {
    if setting.is_empty() {
        return 0;
    }
    LANGUAGES
        .iter()
        .position(|(code, _)| Some(*code) == catalogue_for(setting))
        .map_or(0, |i| i32::try_from(i + 1).unwrap_or(0))
}

/// The setting saved for a Settings choice (see [`choice_of`]).
pub fn setting_of(choice: i32) -> String {
    match usize::try_from(choice - 1)
        .ok()
        .and_then(|i| LANGUAGES.get(i))
    {
        // English is saved as "en", so it doesn't read as "follow the system".
        Some(("", _)) => "en".to_owned(),
        Some((code, _)) => (*code).to_owned(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_find_their_catalogue() {
        assert_eq!(catalogue_for("pt-BR"), Some("pt_BR"));
        assert_eq!(catalogue_for("pt_PT.UTF-8"), Some("pt_BR"));
        assert_eq!(catalogue_for("en-US"), Some(""));
        assert_eq!(catalogue_for("de-DE"), None);
    }

    #[test]
    fn the_override_then_the_setting_then_the_system() {
        assert_eq!(resolve(Some("en"), "pt_BR", Some("pt-BR")), "");
        assert_eq!(resolve(None, "pt_BR", Some("en-US")), "pt_BR");
        assert_eq!(resolve(None, "", Some("pt-BR")), "pt_BR");
        assert_eq!(
            resolve(None, "", Some("de-DE")),
            "",
            "no German yet: English"
        );
        assert_eq!(resolve(Some(""), "", None), "");
    }

    #[test]
    fn settings_choices_round_trip() {
        assert_eq!(choice_of(""), 0);
        assert_eq!(setting_of(0), "");
        for choice in 1..=i32::try_from(LANGUAGES.len()).unwrap() {
            assert_eq!(choice_of(&setting_of(choice)), choice);
        }
        assert_eq!(setting_of(1), "en");
        assert_eq!(setting_of(2), "pt_BR");
    }
}
