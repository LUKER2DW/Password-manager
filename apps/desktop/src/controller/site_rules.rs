//! Settings → Browser extension → Site rules: what the extension doesn't do on particular sites
//! (`vault_browser::rules`), kept in this device's state. The extension's window changes the
//! rule of the site in front through `site_rule` (`browser.rs`).

use std::rc::Rc;

use slint::{ModelRc, SharedString, VecModel};
use vault_browser::rules;
use vault_platform::device::SiteRule;

use super::{Controller, error, notice};
use crate::ui::SiteRuleRow;

impl Controller {
    /// The rules as Settings lists them, by site.
    pub(super) fn show_site_rules(&self) {
        let rows: Vec<SiteRuleRow> = self
            .state
            .borrow()
            .settings
            .site_rules
            .iter()
            .map(|rule| SiteRuleRow {
                site: SharedString::from(rule.host.as_str()),
                never_save: rule.never_save,
                no_card: rule.no_card,
                never_fill: rule.never_fill,
                no_passkeys: rule.no_passkeys,
                card_frames: SharedString::from(rule.card_frames.join(", ")),
            })
            .collect();
        self.app()
            .set_site_rules(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    /// One switch of a site's rule (`which`: 0 never save, 1 no card, 2 never fill, 3 no
    /// passkeys, 4 every approved card frame taken back). A rule with nothing left on stays
    /// listed until removed, so the person sees what they just turned off.
    pub(super) fn site_rule_toggled(&self, site: &str, which: i32, on: bool) {
        {
            let mut state = self.state.borrow_mut();
            let Some(rule) = state
                .settings
                .site_rules
                .iter_mut()
                .find(|rule| rule.host == site)
            else {
                return;
            };
            match which {
                0 => rule.never_save = on,
                1 => rule.no_card = on,
                2 => rule.never_fill = on,
                3 => rule.no_passkeys = on,
                4 => rule.card_frames.clear(),
                _ => return,
            }
        }
        self.save_settings();
        self.show_site_rules();
    }

    pub(super) fn site_rule_removed(&self, site: &str) {
        self.state
            .borrow_mut()
            .settings
            .site_rules
            .retain(|rule| rule.host != site);
        self.save_settings();
        self.show_site_rules();
    }

    /// "Add a site": a rule with every switch off, for the person to choose in.
    pub(super) fn site_rule_added(&self, typed: &str) {
        let Some(site) = rules::site_key(typed) else {
            self.set_error(error::SITE_RULE_ADDRESS, "");
            return;
        };
        let full = {
            let mut state = self.state.borrow_mut();
            let kept = &mut state.settings.site_rules;
            let full = kept.len() >= rules::MAX_RULES;
            if !full && !kept.iter().any(|rule| rule.host == site) {
                // Every switch off, for the person to choose in: listed until removed.
                kept.push(SiteRule {
                    host: site.clone(),
                    ..SiteRule::default()
                });
                kept.sort_by(|a, b| a.host.cmp(&b.host));
            }
            full
        };
        if full {
            self.set_error(error::SITE_RULE_ADDRESS, "");
            return;
        }
        self.app().set_site_rule_new(SharedString::new());
        self.set_error(error::NONE, "");
        self.save_settings();
        self.show_site_rules();
        self.notify(notice::SITE_RULE_ADDED, &site);
    }
}
