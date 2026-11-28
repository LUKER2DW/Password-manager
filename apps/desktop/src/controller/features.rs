//! Generator options and word lists, password history, password health and the leak check,
//! the import review, vault settings. Split from `controller.rs`; same `Controller`.

use std::sync::Arc;

use slint::{Model, ModelRc, SharedString, VecModel};
use vault_core::{
    GuardCheck, ItemData, ItemId, ItemKind, KdfMethod, KdfStrength, PasswordKdf, Unlock, Vault,
    VaultSettings,
    card::{self, CardDetails},
    generator::{self, PassphraseOptions, PasswordOptions, WordCase, Wordlist},
    health::{self, BreachQuery},
};
use vault_import::{FolderTarget, Source};
use vault_platform::{browsers::Browser, device::GeneratorPrefs, paths};
use zeroize::Zeroizing;

use super::{Controller, JobResult, Panel, Runner, error, field, notice, view};
use crate::ui::{HealthRow, HistoryRow, ImportRow, SourceRow};

/// A word list the user added, kept in the app's word list folder.
pub(super) struct UserWordlist {
    pub(super) file: String,
    pub(super) list: Arc<Wordlist>,
}

/// (group, item, detail, weakness, (age unit, age amount)) for one health problem.
type HealthEntry = (i32, ItemId, String, i32, (i32, i32));

/// One import source as `Source::ALL` lists them, with the browser it maps to (if any).
fn browser_of(source: Source) -> Option<Browser> {
    match source {
        Source::Chrome => Some(Browser::Chrome),
        Source::Edge => Some(Browser::Edge),
        Source::Firefox => Some(Browser::Firefox),
        Source::Brave => Some(Browser::Brave),
        Source::Opera => Some(Browser::Opera),
        Source::OperaGx => Some(Browser::OperaGx),
        Source::Vivaldi => Some(Browser::Vivaldi),
        _ => None,
    }
}

impl Controller {
    // -----------------------------------------------------------------------------------------
    // Generator
    // -----------------------------------------------------------------------------------------

    /// Puts the saved generator options on screen (once, at startup).
    pub(super) fn load_generator_prefs(&self) {
        let prefs = self.state.borrow().settings.generator.clone();
        let app = self.app();
        app.set_gen_mode(i32::from(prefs.mode.min(1)));
        app.set_gen_length(i32::try_from(prefs.length.clamp(4, 128)).unwrap_or(24));
        app.set_gen_words(i32::try_from(prefs.words.clamp(3, 20)).unwrap_or(6));
        app.set_gen_lowercase(prefs.lowercase);
        app.set_gen_uppercase(prefs.uppercase);
        app.set_gen_digits(prefs.digits);
        app.set_gen_symbols(prefs.symbols);
        app.set_gen_extended(prefs.extended_ascii);
        app.set_gen_avoid_ambiguous(prefs.avoid_ambiguous);
        app.set_gen_also_use(SharedString::from(prefs.also_use.as_str()));
        app.set_gen_never_use(SharedString::from(prefs.never_use.as_str()));
        app.set_gen_word_case(i32::from(prefs.word_case.min(3)));
        app.set_gen_number(prefs.add_digit);
        app.set_gen_separator(SharedString::from(prefs.separator.as_str()));
        let minimum = |n: u32| i32::try_from(n.min(128)).unwrap_or(0);
        app.set_gen_min_lowercase(minimum(prefs.min_lowercase));
        app.set_gen_min_uppercase(minimum(prefs.min_uppercase));
        app.set_gen_min_digits(minimum(prefs.min_digits));
        app.set_gen_min_symbols(minimum(prefs.min_symbols));
        self.load_wordlists();
        let index = self
            .state
            .borrow()
            .wordlists
            .iter()
            .position(|w| w.file == prefs.wordlist)
            .map_or(0, |i| i + 1);
        app.set_gen_wordlist(i32::try_from(index).unwrap_or(0));
        self.show_wordlists();
    }

    pub(super) fn current_generator_prefs(&self) -> GeneratorPrefs {
        let app = self.app();
        let wordlist = usize::try_from(app.get_gen_wordlist() - 1)
            .ok()
            .and_then(|i| self.state.borrow().wordlists.get(i).map(|w| w.file.clone()))
            .unwrap_or_default();
        GeneratorPrefs {
            mode: u8::try_from(app.get_gen_mode().clamp(0, 1)).unwrap_or(0),
            length: u32::try_from(app.get_gen_length().clamp(4, 128)).unwrap_or(24),
            words: u32::try_from(app.get_gen_words().clamp(3, 20)).unwrap_or(6),
            lowercase: app.get_gen_lowercase(),
            uppercase: app.get_gen_uppercase(),
            digits: app.get_gen_digits(),
            symbols: app.get_gen_symbols(),
            extended_ascii: app.get_gen_extended(),
            avoid_ambiguous: app.get_gen_avoid_ambiguous(),
            also_use: app.get_gen_also_use().chars().take(128).collect(),
            never_use: app.get_gen_never_use().chars().take(128).collect(),
            word_case: u8::try_from(app.get_gen_word_case().clamp(0, 3)).unwrap_or(0),
            add_digit: app.get_gen_number(),
            separator: app.get_gen_separator().chars().take(3).collect(),
            wordlist,
            min_lowercase: u32::try_from(app.get_gen_min_lowercase().clamp(0, 128)).unwrap_or(0),
            min_uppercase: u32::try_from(app.get_gen_min_uppercase().clamp(0, 128)).unwrap_or(0),
            min_digits: u32::try_from(app.get_gen_min_digits().clamp(0, 128)).unwrap_or(0),
            min_symbols: u32::try_from(app.get_gen_min_symbols().clamp(0, 128)).unwrap_or(0),
        }
    }

    /// Saves the generator options when they changed (the file is small; the slider calls this
    /// at every step, so unchanged options are not written again).
    pub(super) fn remember_generator_prefs(&self, prefs: GeneratorPrefs) {
        if self.state.borrow().settings.generator == prefs {
            return;
        }
        self.state.borrow_mut().settings.generator = prefs.clone();
        if self.state.borrow().runner == Runner::Inline {
            return; // tests and screenshots leave the device state alone
        }
        if let Ok(mut device_state) = vault_platform::DeviceState::load() {
            device_state.settings.generator = prefs;
            let _ = device_state.save();
        }
    }

    pub(super) fn generate(&self) -> Option<Zeroizing<String>> {
        let app = self.app();
        self.wordlist_changed();
        let prefs = self.current_generator_prefs();
        let result = if prefs.mode == 1 {
            let wordlist = usize::try_from(app.get_gen_wordlist() - 1)
                .ok()
                .and_then(|i| self.state.borrow().wordlists.get(i).map(|w| w.list.clone()));
            let options = PassphraseOptions {
                words: prefs.words as usize,
                separator: prefs.separator.clone(),
                case: match prefs.word_case {
                    1 => WordCase::Upper,
                    2 => WordCase::Title,
                    3 => WordCase::Mixed,
                    _ => WordCase::Lower,
                },
                include_number: prefs.add_digit,
                wordlist,
            };
            super::set_strength(&app, options.entropy_bits());
            generator::generate_passphrase(&options)
        } else {
            let mut options = PasswordOptions {
                length: prefs.length as usize,
                lowercase: prefs.lowercase,
                uppercase: prefs.uppercase,
                digits: prefs.digits,
                symbols: prefs.symbols,
                extended_ascii: prefs.extended_ascii,
                avoid_ambiguous: prefs.avoid_ambiguous,
                also_use: prefs.also_use.clone(),
                never_use: prefs.never_use.clone(),
                min_lowercase: prefs.min_lowercase as usize,
                min_uppercase: prefs.min_uppercase as usize,
                min_digits: prefs.min_digits as usize,
                min_symbols: prefs.min_symbols as usize,
            };
            // Minimums that need more characters than the length: the length grows.
            if options.required() > options.length {
                options.length = options.required().min(128);
                app.set_gen_length(i32::try_from(options.length).unwrap_or(24));
            }
            if options.alphabet_size() == 0 {
                // Nothing left to draw from: fall back to lowercase letters.
                options.lowercase = true;
                options.never_use.clear();
                app.set_gen_lowercase(true);
                app.set_gen_never_use(SharedString::new());
            }
            app.set_gen_alphabet(i32::try_from(options.alphabet_size()).unwrap_or(0));
            super::set_strength(&app, options.entropy_bits());
            generator::generate_password(&options)
        };
        self.remember_generator_prefs(self.current_generator_prefs());
        result.ok()
    }

    /// Reads the user's word lists from the app folder (unreadable or too short ones skipped).
    fn load_wordlists(&self) {
        let mut lists = Vec::new();
        if let Ok(dir) = paths::wordlists_dir()
            && let Ok(entries) = std::fs::read_dir(dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
                    && let Ok(text) = std::fs::read_to_string(&path)
                    && let Ok(list) = Wordlist::parse(&text)
                {
                    lists.push(UserWordlist {
                        file: entry.file_name().to_string_lossy().into_owned(),
                        list: Arc::new(list),
                    });
                }
            }
        }
        lists.sort_by_key(|w| w.file.to_lowercase());
        self.state.borrow_mut().wordlists = lists;
    }

    fn show_wordlists(&self) {
        let app = self.app();
        let mut options = vec![SharedString::from(format!(
            "EFF ({} words)",
            generator::Wordlist::eff_large().len()
        ))];
        for list in &self.state.borrow().wordlists {
            let name = list.file.trim_end_matches(".txt");
            options.push(SharedString::from(format!(
                "{name} ({} words)",
                list.list.len()
            )));
        }
        let count = options.len() as i32;
        app.set_gen_wordlists(ModelRc::from(std::rc::Rc::new(VecModel::from(options))));
        if app.get_gen_wordlist() >= count {
            app.set_gen_wordlist(0);
        }
        app.set_gen_wordlist_removable(app.get_gen_wordlist() > 0);
    }

    pub(super) fn add_wordlist(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests: they call add_wordlist_file
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Add a word list")
            .add_filter("Word list", &["txt"])
            .pick_file()
        {
            self.add_wordlist_file(&path);
        }
    }

    /// Copies a word list into the app folder and selects it.
    pub fn add_wordlist_file(&self, path: &std::path::Path) {
        let text = match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(err) => {
                self.set_error(error::WORDLIST, &err.to_string());
                return;
            }
        };
        let list = match Wordlist::parse(&text) {
            Ok(list) => list,
            Err(_) => {
                self.set_error(error::WORDLIST, "");
                return;
            }
        };
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "words".into());
        let stem: String = stem
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
            .take(40)
            .collect();
        let file = format!("{}.txt", if stem.is_empty() { "words" } else { &stem });
        let saved = paths::wordlists_dir().and_then(|dir| {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(&file), text.as_bytes())?;
            Ok(())
        });
        if let Err(err) = saved {
            self.set_error(error::FILE, &err.to_string());
            return;
        }
        self.load_wordlists();
        let index = self
            .state
            .borrow()
            .wordlists
            .iter()
            .position(|w| w.file == file)
            .map_or(0, |i| i + 1);
        let app = self.app();
        app.set_gen_wordlist(i32::try_from(index).unwrap_or(0));
        app.set_gen_mode(1);
        self.show_wordlists();
        self.set_error(error::NONE, "");
        self.notify(
            notice::WORDLIST_ADDED,
            &format!("{} ({} words)", file.trim_end_matches(".txt"), list.len()),
        );
        self.regenerate();
    }

    pub(super) fn remove_wordlist(&self) {
        let app = self.app();
        let Some(file) = usize::try_from(app.get_gen_wordlist() - 1)
            .ok()
            .and_then(|i| self.state.borrow().wordlists.get(i).map(|w| w.file.clone()))
        else {
            return;
        };
        if let Ok(dir) = paths::wordlists_dir() {
            let _ = std::fs::remove_file(dir.join(file));
        }
        app.set_gen_wordlist(0);
        self.load_wordlists();
        self.show_wordlists();
        self.regenerate();
    }

    pub(super) fn wordlist_changed(&self) {
        self.app()
            .set_gen_wordlist_removable(self.app().get_gen_wordlist() > 0);
    }

    // -----------------------------------------------------------------------------------------
    // Item page: password strength, reuse, age and history
    // -----------------------------------------------------------------------------------------

    /// Fills the password health lines and the history count for the item page.
    pub(super) fn show_password_details(&self, id: ItemId, item: &ItemData) {
        let app = self.app();
        let is_login = item.kind == ItemKind::Login && !item.password.is_empty();
        if is_login {
            let words: Vec<&str> = [item.title.as_str(), item.username.as_str()]
                .into_iter()
                .chain(item.urls.iter().map(String::as_str))
                .filter(|w| !w.is_empty())
                .collect();
            let strength = health::strength(&item.password, &words);
            app.set_detail_strength_bits(strength.bits as i32);
            app.set_detail_strength_score(i32::from(strength.score));
            app.set_detail_weakness(if strength.is_weak() {
                view::weakness_code(&strength)
            } else {
                0
            });
            app.set_detail_reused_by(
                i32::try_from(self.reuse_count(id, &item.password)).unwrap_or(0),
            );
            let (unit, amount) = view::ago(item.password_set_at(), view::now_unix());
            app.set_detail_age_unit(unit);
            app.set_detail_age_amount(amount);
        } else {
            app.set_detail_strength_score(0);
            app.set_detail_weakness(0);
            app.set_detail_reused_by(0);
            app.set_detail_age_unit(-1);
        }
        app.set_detail_brand(if item.kind == ItemKind::Card {
            view::brand_mark(card::detect_brand(&CardDetails::from_item(item).number))
        } else {
            0
        });
        app.set_detail_username_is_email(
            item.kind == ItemKind::Login
                && item.username.contains('@')
                && !item.username.contains(' '),
        );
        app.set_detail_history_count(i32::try_from(item.password_history.len()).unwrap_or(0));
        let keep_shown = self.state.borrow().history_shown == Some(id);
        if keep_shown {
            self.fill_history(item);
        } else {
            self.hide_history();
        }
    }

    /// How many other items share this password (compared by SHA-256, never stored).
    fn reuse_count(&self, id: ItemId, password: &str) -> usize {
        use sha2::{Digest, Sha256};
        let target: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return 0;
        };
        session
            .vault
            .item_ids()
            .filter(|other| *other != id)
            .filter_map(|other| session.vault.get_item(&other).ok())
            .filter(|other| {
                other.kind == ItemKind::Login
                    && !other.password.is_empty()
                    && <[u8; 32]>::from(Sha256::digest(other.password.as_bytes())) == target
            })
            .count()
    }

    fn fill_history(&self, item: &ItemData) {
        let revealed = self.state.borrow().history_revealed.clone();
        // Newest first.
        let rows: Vec<HistoryRow> = item
            .password_history
            .iter()
            .rev()
            .enumerate()
            .map(|(i, change)| HistoryRow {
                password: if revealed.contains(&i) {
                    SharedString::from(change.password.as_str())
                } else {
                    SharedString::new()
                },
                date: SharedString::from(view::date(change.replaced_at)),
            })
            .collect();
        let app = self.app();
        app.set_detail_history(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
        app.set_detail_history_shown(true);
    }

    pub(super) fn show_history(&self) {
        let Some((id, item)) = self.selected_item() else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            state.history_shown = Some(id);
            state.history_revealed.clear();
        }
        self.fill_history(&item);
    }

    pub(super) fn hide_history(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.history_shown = None;
            state.history_revealed.clear();
        }
        let app = self.app();
        app.set_detail_history(ModelRc::default());
        app.set_detail_history_shown(false);
    }

    pub(super) fn reveal_history(&self, index: i32) {
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            if let Some(at) = state.history_revealed.iter().position(|&i| i == index) {
                state.history_revealed.remove(at);
            } else {
                state.history_revealed.push(index);
            }
        }
        self.fill_history(&item);
    }

    pub(super) fn copy_history(&self, index: i32) {
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        let value = usize::try_from(index)
            .ok()
            .and_then(|i| item.password_history.iter().rev().nth(i))
            .map(|change| Zeroizing::new(change.password.clone()));
        if let Some(value) = value {
            self.copy(value, true, notice::OLD_PASSWORD_COPIED);
        }
    }

    pub(super) fn clear_history(&self) {
        let Some((id, _)) = self.selected_item() else {
            return;
        };
        if !self.take_confirmed(super::confirm::kind::CLEAR_HISTORY) {
            self.ask_confirm(super::confirm::kind::CLEAR_HISTORY, 0, "");
            return;
        }
        let cleared = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.clear_password_history(&id));
        if matches!(cleared, Some(Ok(()))) && self.save_vault() {
            self.hide_history();
            self.show_detail();
            self.notify(notice::HISTORY_CLEARED, "");
        }
    }

    // -----------------------------------------------------------------------------------------
    // Editor: strength of the password being typed, card network
    // -----------------------------------------------------------------------------------------

    pub(super) fn update_editor_strength(&self) {
        let app = self.app();
        let (bits, weakness) = {
            let state = self.state.borrow();
            let password = state.secrets[field::ITEM_PASSWORD].as_str();
            if password.is_empty() || app.get_ed_kind() != 0 {
                (0.0, 0)
            } else {
                let title = app.get_ed_title();
                let username = app.get_ed_username();
                let url = app.get_ed_url();
                let words: Vec<&str> = [title.as_str(), username.as_str(), url.as_str()]
                    .into_iter()
                    .filter(|w| !w.is_empty())
                    .collect();
                let strength = health::strength(password, &words);
                // Just made by Generate: its entropy is known exactly.
                let generated = state
                    .editor_generated
                    .filter(|(hash, _)| *hash == super::file_hash(password.as_bytes()))
                    .map(|(_, bits)| bits);
                let weakness = if strength.is_weak() && generated.is_none() {
                    view::weakness_code(&strength)
                } else {
                    0
                };
                (
                    strength.bits.max(generated.unwrap_or(0.0)).max(1.0),
                    weakness,
                )
            }
        };
        app.set_ed_strength_bits(bits as i32);
        let (unit, amount) = view::crack_time(bits);
        app.set_ed_crack_unit(unit);
        app.set_ed_crack_amount(amount);
        app.set_ed_weakness(weakness);
        // Reused in the vault, or known leaked (F18): said under the strength.
        self.weigh_editor_soon();
    }

    pub(super) fn card_number_edited(&self, text: &str) {
        let digits = card::digits(text);
        let brand = card::detect_brand(&digits);
        let app = self.app();
        app.set_ed_card_brand(SharedString::from(brand.name()));
        app.set_ed_card_brand_mark(if digits.is_empty() {
            0
        } else {
            view::brand_mark(brand)
        });
    }

    // -----------------------------------------------------------------------------------------
    // Password health
    // -----------------------------------------------------------------------------------------

    pub(super) fn open_health(&self) {
        let app = self.app();
        app.set_panel(Panel::Health);
        self.set_error(error::NONE, "");
        self.refresh_health();
    }

    /// Recomputes the report (strength of every login, reuse, age, expired cards).
    /// Audits every password again. Reading the vault is quick and happens here; estimating
    /// the strength of every password is not, so it runs off the UI thread and the page (and
    /// the count in the index) updates when it is done.
    pub(super) fn refresh_health(&self) {
        let (input, runner, generation) = {
            let mut state = self.state.borrow_mut();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            let input = health::collect(&session.vault, view::now_unix(), view::now_month_year());
            state.health_generation += 1;
            (input, state.runner, state.health_generation)
        };
        let input = match input {
            Ok(input) => input,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        match runner {
            Runner::Inline => self.health_ready(generation, input.analyze()),
            Runner::Thread => {
                std::thread::spawn(move || {
                    let report = input.analyze();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = super::CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.health_ready(generation, report);
                        }
                    });
                });
            }
        }
    }

    /// An audit finished. Dropped when the vault was locked or changed again meanwhile.
    fn health_ready(&self, generation: u64, report: health::HealthReport) {
        {
            let mut state = self.state.borrow_mut();
            if state.session.is_none() || state.health_generation != generation {
                return;
            }
            state.health = Some(report);
        }
        self.show_health();
    }

    pub(super) fn show_health(&self) {
        let app = self.app();
        let filter = app.get_health_filter();
        let now = view::now_unix();
        // (group, item, problem, detail, weakness, age); groups: 0 leaked, 1 weak, 2 reused,
        // 3 old, 4 expired cards. Problems are the group + 1.
        let mut entries: Vec<HealthEntry> = Vec::new();
        let (logins, healthy) = {
            let state = self.state.borrow();
            let Some(report) = state.health.as_ref() else {
                return;
            };
            for login in &report.logins {
                if let Some(&count) = state.leaks.get(&login.id)
                    && count > 0
                {
                    entries.push((0, login.id, format_count(count), 0, (-1, 0)));
                }
            }
            for login in report.weak() {
                entries.push((
                    1,
                    login.id,
                    String::new(),
                    view::weakness_code(&login.strength),
                    (-1, 0),
                ));
            }
            for login in report.reused() {
                entries.push((2, login.id, login.reused_by.to_string(), 0, (-1, 0)));
            }
            for login in report.old() {
                entries.push((3, login.id, String::new(), 0, view::ago(login.set_at, now)));
            }
            for id in &report.expired_cards {
                let expiry = state
                    .session
                    .as_ref()
                    .and_then(|s| s.vault.get_item(id).ok())
                    .map(|item| CardDetails::from_item(&item).expiry)
                    .unwrap_or_default();
                entries.push((4, *id, expiry, 0, (-1, 0)));
            }
            // An expiry date (format v11) past or within 30 days: told apart by `weakness` 1.
            for (id, at) in &report.expiring {
                if !report.expired_cards.contains(id) {
                    entries.push((4, *id, view::date(*at), 1, (-1, 0)));
                }
            }
            let troubled: std::collections::HashSet<ItemId> = entries
                .iter()
                .filter(|(group, ..)| *group < 4)
                .map(|(_, id, ..)| *id)
                .collect();
            let logins = report.logins.len();
            (
                logins,
                logins
                    - report
                        .logins
                        .iter()
                        .filter(|h| troubled.contains(&h.id))
                        .count(),
            )
        };
        let mut counts = [0i32; 5];
        for (group, ..) in &entries {
            counts[*group as usize] += 1;
        }
        let mut ids = Vec::new();
        let mut rows = Vec::new();
        for (group, id, detail, weakness, (age_unit, age_amount)) in entries {
            if filter >= 0 && group != filter {
                continue;
            }
            let summary = {
                let state = self.state.borrow();
                state.summaries.iter().find(|s| s.id == id).map(|s| {
                    (
                        s.title.clone(),
                        view::subtitle(s),
                        s.kind,
                        s.url.clone(),
                        view::brand_mark(s.card_brand),
                        s.icon_url.clone(),
                    )
                })
            };
            let Some((title, subtitle, kind, url, brand, icon_url)) = summary else {
                continue;
            };
            let visual = self.icon_for(kind, &url, &icon_url, &title);
            ids.push(id);
            rows.push(HealthRow {
                title: SharedString::from(title),
                subtitle: SharedString::from(subtitle),
                kind: view::kind_to_int(kind),
                brand,
                icon: visual.image,
                has_icon: visual.has_image,
                initial: visual.initial,
                tint: visual.tint,
                problem: group + 1,
                count: if group == 2 {
                    detail.parse().unwrap_or(0)
                } else {
                    0
                },
                detail: SharedString::from(if group == 2 { String::new() } else { detail }),
                weakness,
                age_unit,
                age_amount,
                has_site: kind == ItemKind::Login
                    && vault_browser::resources::change_password_url(&url).is_some(),
            });
        }
        self.state.borrow_mut().health_ids = ids;
        let score = (healthy * 100).checked_div(logins).unwrap_or(100);
        app.set_health_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
        app.set_health_counts(ModelRc::from(std::rc::Rc::new(VecModel::from(
            counts.to_vec(),
        ))));
        app.set_health_total(counts.iter().sum());
        self.refresh_alerts();
        app.set_health_logins(i32::try_from(logins).unwrap_or(0));
        app.set_health_score(i32::try_from(score).unwrap_or(0));
    }

    pub(super) fn health_open(&self, index: i32) {
        let Some(id) = usize::try_from(index)
            .ok()
            .and_then(|i| self.state.borrow().health_ids.get(i).copied())
        else {
            return;
        };
        let app = self.app();
        app.set_category(0);
        app.set_search_text(SharedString::new());
        app.set_panel(Panel::Detail);
        self.state.borrow_mut().selected = Some(id);
        self.refresh_list();
        self.show_detail();
    }

    /// "Change on the site" on a health warning: the login's page for changing its password.
    pub(super) fn health_change(&self, index: i32) {
        let site = {
            let state = self.state.borrow();
            let Some(id) = usize::try_from(index)
                .ok()
                .and_then(|i| state.health_ids.get(i).copied())
            else {
                return;
            };
            state
                .session
                .as_ref()
                .and_then(|s| s.vault.get_item(&id).ok())
                .and_then(|item| item.urls.first().cloned())
        };
        if let Some(site) = site {
            self.open_change_page(&site);
        }
    }

    /// Asks the breach service about every login's password (k-anonymous; see health.rs).
    pub(super) fn check_leaks(&self) {
        let queries: Vec<(ItemId, BreachQuery)> = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            session
                .vault
                .item_ids()
                .filter_map(|id| {
                    let item = session.vault.get_item(&id).ok()?;
                    (item.kind == ItemKind::Login && !item.password.is_empty())
                        .then(|| (id, BreachQuery::new(&item.password)))
                })
                .collect()
        };
        if queries.is_empty() {
            // Nothing to ask about, but logins behind the item lock may be why.
            let locked = self.locked_logins();
            if locked > 0 {
                self.notify_long(notice::LEAKS_SKIPPED_LOCKED, &locked.to_string());
            }
            return;
        }
        if self.state.borrow().runner == Runner::Inline {
            return; // no network in tests: they call finish_leak_check directly
        }
        self.app().set_leaks_checking(true);
        self.run_job(move || JobResult::LeaksChecked {
            result: vault_platform::leak_check::lookup(&queries),
        });
    }

    /// Logins whose password the item lock keeps closed right now.
    fn locked_logins(&self) -> usize {
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return 0;
        };
        session
            .vault
            .item_ids()
            .filter(|id| {
                session
                    .vault
                    .get_item(id)
                    .is_ok_and(|item| item.kind == ItemKind::Login && item.is_locked())
            })
            .count()
    }

    pub(super) fn finish_leak_check(&self, result: Result<Vec<(ItemId, u64)>, String>) {
        let app = self.app();
        app.set_leaks_checking(false);
        match result {
            Ok(counts) => {
                let found = counts.iter().filter(|(_, c)| *c > 0).count();
                {
                    let mut state = self.state.borrow_mut();
                    state.leaks = counts.into_iter().collect();
                }
                app.set_leaks_checked(true);
                self.refresh_health();
                // Locked logins keep their passwords out of reach, so they weren't asked
                // about: never an all-clear that leaves them out without saying so.
                let locked = self.locked_logins();
                match (found, locked) {
                    (_, 0) => self.notify(notice::LEAKS_CHECKED, &found.to_string()),
                    (0, locked) => {
                        self.notify_long(notice::LEAKS_SKIPPED_LOCKED, &locked.to_string())
                    }
                    (found, _) => {
                        self.notify_long(notice::LEAKS_FOUND_SOME_LOCKED, &found.to_string())
                    }
                }
            }
            Err(detail) => self.set_error(error::LEAK_CHECK, &detail),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Import: where from, review, where to
    // -----------------------------------------------------------------------------------------

    pub(super) fn show_sources(&self) {
        let rows: Vec<SourceRow> = Source::ALL
            .iter()
            .map(|&source| {
                let name = source.name();
                let (r, g, b) = view::tint(ItemKind::Login, name);
                SourceRow {
                    name: SharedString::from(name),
                    browser: source.is_browser(),
                    installed: browser_of(source).is_some_and(|b| b.program().is_some()),
                    initial: SharedString::from(view::initial(name)),
                    tint: slint::Color::from_rgb_u8(r, g, b),
                }
            })
            .collect();
        let names: Vec<SharedString> = std::iter::once(SharedString::new())
            .chain(Source::ALL.iter().map(|s| SharedString::from(s.name())))
            .collect();
        let app = self.app();
        app.set_import_sources(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
        app.set_import_source_names(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
    }

    pub(super) fn pick_source(&self, index: i32) {
        let source = usize::try_from(index)
            .ok()
            .and_then(|i| Source::ALL.get(i).copied());
        let direct = source.is_some_and(vault_import::browser::supports_direct);
        let profiles = match source {
            Some(source) if direct && self.state.borrow().runner == Runner::Thread => {
                vault_import::browser::profiles(source)
            }
            _ => Vec::new(),
        };
        let names: Vec<SharedString> = profiles
            .iter()
            .map(|p| SharedString::from(p.name.as_str()))
            .collect();
        {
            let mut state = self.state.borrow_mut();
            state.import_source = source;
            state.browser_profiles = profiles;
        }
        let app = self.app();
        app.set_import_direct_supported(direct);
        app.set_import_browser_method(0);
        app.set_import_browser_profiles(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
        app.set_import_browser_profile(0);
        self.clear_secret(field::IMPORT);
        self.set_error(error::NONE, "");
    }

    /// Reads the chosen browser profile's own password store (on a worker thread), then shows
    /// the review like any other import.
    pub(super) fn import_direct(&self) {
        let app = self.app();
        let (source, profile) = {
            let state = self.state.borrow();
            let Some(source) = state.import_source else {
                return;
            };
            let index = usize::try_from(app.get_import_browser_profile()).unwrap_or(0);
            let Some(profile) = state.browser_profiles.get(index).cloned() else {
                return;
            };
            (source, profile)
        };
        let password = Zeroizing::new(
            self.state.borrow().secrets[field::IMPORT]
                .as_str()
                .to_owned(),
        );
        app.set_import_file(SharedString::from(format!(
            "{} · {}",
            source.name(),
            profile.name
        )));
        app.set_import_plaintext(false);
        self.state.borrow_mut().pending_import = Some(super::PendingImport {
            path: std::path::PathBuf::new(),
            bytes: Zeroizing::new(Vec::new()),
            format: vault_import::Format::Csv,
            report: None,
        });
        self.run_job(move || {
            match vault_import::browser::read(
                source,
                &profile,
                &password,
                &vault_platform::dpapi::unprotect,
            ) {
                Ok(report) => JobResult::ImportParsed { report },
                Err(err) => JobResult::Failed {
                    code: error::IMPORT,
                    detail: err.to_string(),
                    session: None,
                },
            }
        });
    }

    pub(super) fn open_browser(&self) {
        let Some(source) = self.state.borrow().import_source else {
            return;
        };
        let Some(browser) = browser_of(source) else {
            return;
        };
        match browser.open_passwords_page() {
            Ok(()) => self.notify_long(notice::BROWSER_OPENED, source.name()),
            Err(err) => self.set_error(error::IMPORT, &err.to_string()),
        }
    }

    /// File types for the picker of the chosen source.
    pub(super) fn source_extensions(&self) -> &'static [&'static str] {
        self.state
            .borrow()
            .import_source
            .map_or(&["json", "csv", "kdbx"], Source::extensions)
    }

    /// Fills the review table for a parsed import.
    pub(super) fn show_review(&self, report: &vault_import::ImportReport) -> bool {
        let review = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return false;
            };
            report.review(&session.vault)
        };
        let review = match review {
            Ok(review) => review,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return false;
            }
        };
        let include: Vec<bool> = review.iter().map(|row| !row.duplicate).collect();
        let duplicates = review.iter().filter(|row| row.duplicate).count();
        let rows: Vec<ImportRow> = review
            .into_iter()
            .zip(&include)
            .map(|(row, &include)| ImportRow {
                include,
                title: SharedString::from(row.title.as_str()),
                username: SharedString::from(row.username.as_str()),
                site: SharedString::from(row.site.as_str()),
                folder: SharedString::from(row.folder.as_str()),
                kind: view::kind_to_int(row.kind),
                has_password: row.has_password,
                has_totp: row.has_totp,
                duplicate: row.duplicate,
            })
            .collect();
        let app = self.app();
        app.set_import_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
        app.set_import_duplicates(i32::try_from(duplicates).unwrap_or(0));
        self.state.borrow_mut().import_include = include;
        self.count_selected();

        // Where to put them: the vault's folders for "All in one folder".
        let folders: Vec<SharedString> = std::iter::once(SharedString::new())
            .chain(
                self.state
                    .borrow()
                    .session
                    .as_ref()
                    .map(|s| {
                        s.vault
                            .folders()
                            .iter()
                            .map(|f| SharedString::from(f.name.as_str()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            )
            .collect();
        app.set_import_folders(ModelRc::from(std::rc::Rc::new(VecModel::from(folders))));
        app.set_import_folder(0);
        app.set_import_target(0);
        let suggested = self
            .state
            .borrow()
            .import_source
            .map(|s| format!("From {}", s.name()))
            .unwrap_or_default();
        app.set_import_new_folder(SharedString::from(suggested));
        true
    }

    fn count_selected(&self) {
        let selected = self
            .state
            .borrow()
            .import_include
            .iter()
            .filter(|&&on| on)
            .count();
        self.app()
            .set_import_selected(i32::try_from(selected).unwrap_or(0));
    }

    pub(super) fn import_toggle(&self, index: i32, on: bool) {
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        if let Some(slot) = self.state.borrow_mut().import_include.get_mut(index) {
            *slot = on;
        } else {
            return;
        }
        let rows = self.app().get_import_rows();
        if let Some(mut row) = rows.row_data(index) {
            row.include = on;
            rows.set_row_data(index, row);
        }
        self.count_selected();
    }

    pub(super) fn import_select_all(&self, on: bool) {
        let rows = self.app().get_import_rows();
        let count = self.state.borrow().import_include.len();
        for index in 0..count {
            if let Some(mut row) = rows.row_data(index) {
                // "Select all" leaves out entries already in the vault (they'd be skipped).
                let value = on && !row.duplicate;
                row.include = value;
                rows.set_row_data(index, row);
                self.state.borrow_mut().import_include[index] = value;
            }
        }
        self.count_selected();
    }

    /// Where the reviewed entries go, from the page's choice.
    pub(super) fn import_target(&self) -> FolderTarget {
        let app = self.app();
        match app.get_import_target() {
            1 => FolderTarget::NoFolder,
            2 => {
                let index = app.get_import_folder();
                let existing = usize::try_from(index - 1).ok().and_then(|i| {
                    self.state
                        .borrow()
                        .session
                        .as_ref()
                        .and_then(|s| s.vault.folders().get(i).map(|f| f.id))
                });
                match existing {
                    Some(id) => FolderTarget::Existing(id),
                    None => {
                        let name = app.get_import_new_folder().trim().to_owned();
                        if name.is_empty() {
                            FolderTarget::NoFolder
                        } else {
                            FolderTarget::New(name)
                        }
                    }
                }
            }
            _ => FolderTarget::FromFile,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Folders: name, icon, colour
    // -----------------------------------------------------------------------------------------

    // -----------------------------------------------------------------------------------------
    // Unlock protection (Argon2id cost)
    // -----------------------------------------------------------------------------------------

    /// Rewrites the password slot with the chosen method and level, after checking the current
    /// master password against the file. The new file is opened once before it is written, so
    /// a slot that wouldn't open never reaches the disk; that open is also the timing shown.
    pub(super) fn change_kdf(&self) {
        let app = self.app();
        let Some(level) = usize::try_from(app.get_kdf_level())
            .ok()
            .and_then(|i| KdfStrength::ALL.get(i).copied())
        else {
            return;
        };
        let method = usize::try_from(app.get_kdf_method())
            .ok()
            .and_then(|i| KdfMethod::ALL.get(i).copied())
            .unwrap_or(KdfMethod::Argon2id);
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::KDF_CURRENT]
                .as_str()
                .to_owned(),
        );
        if current.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            app.set_kdf_failed(true);
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
        self.run_job(move || {
            let mut session = session;
            if let Err((code, detail)) = super::verify_current(&path, &current, &session) {
                return JobResult::KdfFailed {
                    code,
                    detail,
                    session,
                    card: 1,
                };
            }
            if !super::file_unchanged(&path, expected) {
                return JobResult::KdfFailed {
                    code: error::CHANGED_OUTSIDE,
                    detail: String::new(),
                    session,
                    card: 1,
                };
            }
            let secret_key = &session.secret_key;
            let keyfile = session.keyfile.as_ref();
            let outcome = session.vault.change_unlock(|vault| {
                let params = PasswordKdf::preset(method, level)?;
                vault.change_password(&current, secret_key, keyfile, &params)?;
                let bytes = vault.to_bytes()?;
                let started = std::time::Instant::now();
                let unlock = match keyfile {
                    Some(keyfile) => Unlock::PasswordAndKeyfile {
                        password: &current,
                        secret_key,
                        keyfile,
                    },
                    None => Unlock::Password {
                        password: &current,
                        secret_key,
                    },
                };
                Vault::open(&bytes, unlock)?;
                let seconds = started.elapsed().as_secs_f64();
                vault_core::storage::write_atomic(&path, &bytes)?;
                Ok(seconds)
            });
            match outcome {
                Ok(seconds) => {
                    let _ = vault_platform::device::record_revision(
                        &session.vault.id_hex(),
                        session.vault.revision(),
                    );
                    JobResult::PasswordChanged {
                        session,
                        kdf_seconds: Some(seconds),
                    }
                }
                Err(err) => JobResult::KdfFailed {
                    code: error::FILE,
                    detail: err.to_string(),
                    session,
                    card: 1,
                },
            }
        });
    }

    // -----------------------------------------------------------------------------------------
    // Vault settings
    // -----------------------------------------------------------------------------------------

    pub(super) fn show_vault_settings(&self) {
        self.show_sync_settings();
        let app = self.app();
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return;
        };
        let settings = session.vault.settings();
        app.set_vault_name_edit(SharedString::from(settings.name.as_str()));
        app.set_history_limit(i32::from(settings.history_limit));
        app.set_vault_folders(i32::try_from(session.vault.folders().len()).unwrap_or(0));
        let kdf = session.vault.kdf_params();
        app.set_kdf_memory(i32::try_from(kdf.memory_mib()).unwrap_or(i32::MAX));
        app.set_kdf_passes(i32::try_from(kdf.rounds()).unwrap_or(i32::MAX));
        let level = kdf
            .strength()
            .and_then(|level| KdfStrength::ALL.iter().position(|l| *l == level))
            .map_or(-1, |i| i32::try_from(i).unwrap_or(-1));
        app.set_kdf_current(level);
        app.set_kdf_level(if level < 0 { 1 } else { level });
        let method = KdfMethod::ALL
            .iter()
            .position(|m| *m == kdf.method())
            .map_or(0, |i| i32::try_from(i).unwrap_or(0));
        app.set_kdf_current_method(method);
        app.set_kdf_method(method);
        app.set_unlock_time(SharedString::from(
            state
                .unlock_seconds
                .map(|s| format!("{s:.1}"))
                .unwrap_or_default(),
        ));
        app.set_vault_recovery(if session.vault.has_recovery_parts() {
            2
        } else {
            i32::from(session.vault.has_recovery_key())
        });
        let guard = session.vault.item_guard();
        let check = super::protection::check_code(guard.check);
        app.set_guard_current_check(check);
        let hello_on = vault_platform::quick_unlock::item_lock_enrolled(&session.vault.id_hex());
        // No item lock yet: the form starts on what is suggested (a PIN on every item, and
        // Windows Hello where this computer has it). Nothing changes until it is saved.
        let unset = !guard.encrypts() && !guard.all_items && guard.check == GuardCheck::Master;
        app.set_guard_all(guard.all_items || unset);
        app.set_guard_check(if unset { 1 } else { check });
        app.set_guard_hello(hello_on || (unset && state.quick_available));
        let keyfile_on = session.vault.needs_keyfile();
        app.set_keyfile_on(keyfile_on);
        app.set_keyfile_path(SharedString::from(
            vault_platform::keyfile::remembered_path(&session.vault.id_hex())
                .filter(|_| keyfile_on)
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        app.set_vault_file_name(SharedString::from(
            state
                .path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ));
    }

    /// The vault's display name (its own setting, else nothing: the index shows "Vault").
    pub(super) fn show_vault_name(&self) {
        let name = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.settings().name.clone())
            .unwrap_or_default();
        self.app().set_vault_name(SharedString::from(name));
        self.show_vault_mark();
    }

    pub(super) fn vault_settings_changed(&self) {
        let app = self.app();
        let settings = VaultSettings {
            name: app.get_vault_name_edit().to_string(),
            history_limit: u16::try_from(app.get_history_limit().clamp(0, 100)).unwrap_or(10),
        };
        let unchanged = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_none_or(|s| *s.vault.settings() == settings);
        if unchanged {
            return;
        }
        let applied = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.set_settings(settings));
        match applied {
            Some(Ok(())) => {
                if self.save_vault() {
                    self.set_error(error::NONE, "");
                    self.show_vault_name();
                    self.show_vault_settings();
                    self.notify(notice::VAULT_SETTINGS_SAVED, "");
                }
            }
            Some(Err(_)) => self.set_error(error::VAULT_NAME, ""),
            None => {}
        }
    }
}

/// "1,234" style grouping for breach counts.
fn format_count(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
