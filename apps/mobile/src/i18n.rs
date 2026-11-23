//! The phone's language.
//!
//! Every word on screen is written in English in the `.slint` files, inside `@tr(…)`. The
//! Brazilian Portuguese is a gettext catalogue in `translations/pt_BR/LC_MESSAGES/` (see
//! `translations/README.md`), compiled into the app by `build.rs`; nothing is read from disk at
//! run time. Rust never builds a sentence: it sends codes, and the words live in
//! `ui/model.slint` and `ui/app.slint`, so a language change shows on every screen at once.
//!
//! Settings → Appearance keeps the choice in `prefs.language`: "" follows the phone, "en" is
//! English, "pt-BR" is Portuguese. The phone's own language comes from Android
//! (`System::language`), or from the computer's or the browser's where there is no Android.

/// The catalogue for a language tag (`pt-BR`, `pt_BR.UTF-8`, `en-US`), or `None` when the app
/// has no translation for it: "" for the English written in the `.slint` files, "pt_BR" for
/// Brazilian Portuguese (any Portuguese gets it, the only one so far).
pub fn catalogue_for(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().to_ascii_lowercase().replace('-', "_");
    let language = tag.split(['_', '.', '@']).next().unwrap_or_default();
    match language {
        "en" => Some(""),
        "pt" => Some("pt_BR"),
        _ => None,
    }
}

/// The catalogue to show: the saved choice, else the phone's language, else English.
pub fn resolve(setting: &str, system: Option<&str>) -> &'static str {
    [Some(setting), system]
        .into_iter()
        .flatten()
        .filter(|tag| !tag.trim().is_empty())
        .find_map(catalogue_for)
        .unwrap_or("")
}

/// Shows the app in the language `setting` asks for (see [`resolve`]). The catalogues come
/// with the first window, so call this once it exists. Without a compiled-in catalogue the
/// English text stays.
pub fn apply(setting: &str, system: Option<&str>) {
    let _ = slint::select_bundled_translation(resolve(setting, system));
}

/// The Settings choice for a saved setting: 0 is "the phone's", then English and Portuguese.
pub fn choice_of(setting: &str) -> i32 {
    if setting.trim().is_empty() {
        return 0;
    }
    match catalogue_for(setting) {
        Some("") => 1,
        Some(_) => 2,
        None => 0,
    }
}

/// The setting saved for a Settings choice (see [`choice_of`]).
pub fn setting_of(choice: i32) -> &'static str {
    match choice {
        1 => "en",
        2 => "pt-BR",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn tags_find_their_catalogue() {
        assert_eq!(catalogue_for("pt-BR"), Some("pt_BR"));
        assert_eq!(catalogue_for("pt_PT.UTF-8"), Some("pt_BR"));
        assert_eq!(catalogue_for("en-US"), Some(""));
        assert_eq!(catalogue_for("de-DE"), None);
    }

    #[test]
    fn the_setting_then_the_phones_language() {
        assert_eq!(resolve("pt-BR", Some("en-US")), "pt_BR");
        assert_eq!(resolve("en", Some("pt-BR")), "", "English chosen");
        assert_eq!(resolve("", Some("pt-BR")), "pt_BR", "the phone's");
        assert_eq!(resolve("", Some("de-DE")), "", "no German yet: English");
        assert_eq!(resolve("", None), "");
    }

    #[test]
    fn settings_choices_round_trip() {
        assert_eq!(choice_of(""), 0);
        assert_eq!(setting_of(0), "");
        for choice in 1..=2 {
            assert_eq!(choice_of(setting_of(choice)), choice);
        }
        assert_eq!(setting_of(1), "en");
        assert_eq!(setting_of(2), "pt-BR");
        assert_eq!(choice_of("pt_BR"), 2, "the catalogue's own name");
    }

    // ---- the catalogue against the Slint sources ----

    /// The Slint files the phone compiles: its own and the desktop's it imports, directly or
    /// through another of them (`strength.slint` imports `model.slint`). Keep this list and
    /// `translations/README.md` in step.
    const SOURCES: [(&str, &str); 6] = [
        ("ui/app.slint", include_str!("../ui/app.slint")),
        (
            "../desktop/ui/theme.slint",
            include_str!("../../desktop/ui/theme.slint"),
        ),
        (
            "../desktop/ui/widgets.slint",
            include_str!("../../desktop/ui/widgets.slint"),
        ),
        (
            "../desktop/ui/icons.slint",
            include_str!("../../desktop/ui/icons.slint"),
        ),
        (
            "../desktop/ui/strength.slint",
            include_str!("../../desktop/ui/strength.slint"),
        ),
        (
            "../desktop/ui/model.slint",
            include_str!("../../desktop/ui/model.slint"),
        ),
    ];

    /// The template (`slint-tr-extractor`'s output for [`SOURCES`]) and the Brazilian
    /// Portuguese catalogue.
    const TEMPLATE: &str = include_str!("../translations/vault-mobile.pot");
    const PORTUGUESE: &str = include_str!("../translations/pt_BR/LC_MESSAGES/vault-mobile.po");

    /// One `@tr(...)`: the component it is written in (its context), the English text and
    /// the plural form, when there is one.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Text {
        context: String,
        text: String,
        plural: Option<String>,
    }

    /// Reads a Slint string literal that starts at `chars[i]` (a `"`): its text, and the index
    /// after its closing quote.
    fn string_at(chars: &[char], mut i: usize) -> (String, usize) {
        i += 1;
        let mut text = String::new();
        while i < chars.len() && chars[i] != '"' {
            if chars[i] == '\\' && i + 1 < chars.len() {
                i += 1;
                text.push(match chars[i] {
                    'n' => '\n',
                    other => other,
                });
            } else {
                text.push(chars[i]);
            }
            i += 1;
        }
        (text, i + 1)
    }

    fn skip_spaces(chars: &[char], mut i: usize) -> usize {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        i
    }

    fn starts_with(chars: &[char], i: usize, word: &str) -> bool {
        word.chars()
            .enumerate()
            .all(|(k, c)| chars.get(i + k) == Some(&c))
    }

    /// Every `@tr(...)` of a Slint file, in the order written, with its context: the
    /// `"context" => ` given, else the component or global it is written in.
    fn texts_in(source: &str) -> Vec<Text> {
        let chars: Vec<char> = source.chars().collect();
        let mut found = Vec::new();
        let mut component = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            } else if c == '"' {
                i = string_at(&chars, i).1;
            } else if c == '@' && starts_with(&chars, i, "@tr") {
                let open = skip_spaces(&chars, i + 3);
                if chars.get(open) != Some(&'(') {
                    i += 3;
                    continue;
                }
                let mut j = skip_spaces(&chars, open + 1);
                let (first, after) = string_at(&chars, j);
                j = skip_spaces(&chars, after);
                let (context, text) = if starts_with(&chars, j, "=>") {
                    j = skip_spaces(&chars, j + 2);
                    let (text, after) = string_at(&chars, j);
                    j = after;
                    (Some(first), text)
                } else {
                    (None, first)
                };
                j = skip_spaces(&chars, j);
                let plural = if chars.get(j) == Some(&'|') {
                    j = skip_spaces(&chars, j + 1);
                    let (plural, after) = string_at(&chars, j);
                    j = after;
                    Some(plural)
                } else {
                    None
                };
                // The rest of the call: a `% n` or formatting arguments, up to its `)`.
                let mut depth = 0;
                while j < chars.len() {
                    match chars[j] {
                        '"' => {
                            j = string_at(&chars, j).1;
                            continue;
                        }
                        '(' => depth += 1,
                        ')' if depth == 0 => break,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                found.push(Text {
                    context: context.unwrap_or_else(|| component.clone()),
                    text,
                    plural,
                });
                i = j + 1;
            } else if c.is_alphabetic() || c == '_' {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "component" || word == "global" {
                    let name = skip_spaces(&chars, i);
                    let end = (name..chars.len())
                        .find(|&k| !(chars[k].is_alphanumeric() || chars[k] == '_'))
                        .unwrap_or(chars.len());
                    component = chars[name..end].iter().collect();
                    i = end;
                }
            } else {
                i += 1;
            }
        }
        found
    }

    /// One entry of a gettext catalogue.
    #[derive(Debug)]
    struct Entry {
        context: String,
        text: String,
        plural: Option<String>,
        msgstr: Vec<String>,
    }

    /// The entries of a `.po` or `.pot` file (its header left out).
    fn entries_of(po: &str) -> Vec<Entry> {
        let mut entries = Vec::new();
        // A Windows checkout has CRLF line ends: entries are still apart by an empty line.
        let po = po.replace("\r\n", "\n");
        for block in po.split("\n\n") {
            let mut context = None;
            let mut text = None;
            let mut plural = None;
            let mut msgstr: Vec<String> = Vec::new();
            // The field the next continuation line ("…") adds to.
            let mut field: Option<&str> = None;
            for line in block.lines() {
                let line = line.trim_end();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if line.starts_with('"') {
                    // A continuation of the field above.
                    let rest = unquote(line);
                    match field {
                        Some("msgctxt") => context.get_or_insert_with(String::new).push_str(&rest),
                        Some("msgid") => text.get_or_insert_with(String::new).push_str(&rest),
                        Some("msgid_plural") => {
                            plural.get_or_insert_with(String::new).push_str(&rest);
                        }
                        _ => {
                            if let Some(last) = msgstr.last_mut() {
                                last.push_str(&rest);
                            }
                        }
                    }
                    continue;
                }
                let Some((key, value)) = line.split_once(' ') else {
                    continue;
                };
                let value = unquote(value);
                match key {
                    "msgctxt" => {
                        context = Some(value);
                        field = Some("msgctxt");
                    }
                    "msgid" => {
                        text = Some(value);
                        field = Some("msgid");
                    }
                    "msgid_plural" => {
                        plural = Some(value);
                        field = Some("msgid_plural");
                    }
                    _ if key.starts_with("msgstr") => {
                        msgstr.push(value);
                        field = None;
                    }
                    _ => {}
                }
            }
            let Some(text) = text.filter(|text| !text.is_empty()) else {
                continue;
            };
            entries.push(Entry {
                context: context.unwrap_or_default(),
                text,
                plural,
                msgstr,
            });
        }
        entries
    }

    /// A quoted `.po` string (or a bare one), unescaped.
    fn unquote(value: &str) -> String {
        let value = value.trim();
        let inner = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some(other) => out.push(other),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The placeholders of a text (`{}`, `{n}`…), in order.
    fn placeholders(text: &str) -> Vec<&str> {
        let mut found = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            let Some(len) = rest[start..].find('}') else {
                break;
            };
            found.push(&rest[start..start + len + 1]);
            rest = &rest[start + len + 1..];
        }
        found
    }

    fn sources_texts() -> BTreeSet<Text> {
        SOURCES
            .iter()
            .flat_map(|(_, source)| texts_in(source))
            .collect()
    }

    #[test]
    fn the_template_lists_every_text_of_the_sources() {
        // The same list `slint-tr-extractor` writes for these files (translations/README.md).
        let template: BTreeSet<Text> = entries_of(TEMPLATE)
            .into_iter()
            .map(|entry| Text {
                context: entry.context,
                text: entry.text,
                plural: entry.plural,
            })
            .collect();
        let sources = sources_texts();
        let missing: Vec<&Text> = sources.difference(&template).collect();
        let stale: Vec<&Text> = template.difference(&sources).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "translations/vault-mobile.pot is out of date (regenerate it, see \
             translations/README.md). Missing: {missing:#?}\nStale: {stale:#?}"
        );
    }

    #[test]
    fn every_text_has_a_portuguese_translation() {
        let catalogue: BTreeMap<(String, String), Entry> = entries_of(PORTUGUESE)
            .into_iter()
            .map(|entry| ((entry.context.clone(), entry.text.clone()), entry))
            .collect();
        let mut problems = Vec::new();
        for text in sources_texts() {
            let Some(entry) = catalogue.get(&(text.context.clone(), text.text.clone())) else {
                problems.push(format!("no translation for {text:?}"));
                continue;
            };
            let expected = if text.plural.is_some() { 2 } else { 1 };
            if entry.msgstr.len() != expected || entry.msgstr.iter().any(|s| s.is_empty()) {
                problems.push(format!("empty or missing translation for {text:?}"));
                continue;
            }
            if entry.plural != text.plural {
                problems.push(format!("the plural form differs for {text:?}"));
            }
            for translated in &entry.msgstr {
                if placeholders(translated) != placeholders(&text.text) {
                    problems.push(format!(
                        "the placeholders differ for {text:?}: {translated:?}"
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn the_scanner_reads_what_the_compiler_reads() {
        let sample = r#"
            // @tr("in a comment") is not a text.
            export component Sample inherits Window {
                text: @tr("Plain text");
                text: @tr("ctx" => "With context");
                text: @tr("{n} item" | "{n} items" % n);
                text: @tr("Read {} from \"quotes\"", value);
            }
            export global Words {
                pure public function error() -> string { return @tr("In a global"); }
            }
        "#;
        let texts = texts_in(sample);
        let found: Vec<(&str, &str, Option<&str>)> = texts
            .iter()
            .map(|t| (t.context.as_str(), t.text.as_str(), t.plural.as_deref()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("Sample", "Plain text", None),
                ("ctx", "With context", None),
                ("Sample", "{n} item", Some("{n} items")),
                ("Sample", "Read {} from \"quotes\"", None),
                ("Words", "In a global", None),
            ]
        );
    }
}
