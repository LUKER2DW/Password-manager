//! Settings → Password health: the desktop's check on the phone. Every login's password is
//! rated (zxcvbn), compared with the others and dated, off the UI thread; the logins that
//! need a look are listed, the worst first, with what is wrong in words (Words.health). A tap
//! opens the login. Leaks come from the leak watch (watch.rs), never asked for here.

use slint::{ModelRc, VecModel};
use vault_core::{ItemId, health};

use super::{Controller, icons, initial, tint};
use crate::{
    ui::{HealthRow, Page},
    view,
};

/// One year, in seconds: a password older than this is "old" (the core's rule).
const YEAR: i64 = 365 * 24 * 3600;

impl Controller {
    /// The health page opened (or the vault changed while it shows): checks every login.
    pub(super) fn refresh_health(&self) {
        let input = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            match health::collect(vault, view::now_unix(), view::now_month_year()) {
                Ok(input) => input,
                Err(_) => return,
            }
        };
        self.run_quietly(move || input.analyze(), Controller::health_ready);
    }

    fn health_ready(&self, report: health::HealthReport) {
        let app = self.app();
        let now = view::now_unix();
        let (rows, counts) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let mut found: Vec<(u8, HealthRow, ItemId)> = Vec::new();
            let (mut weak, mut reused, mut old, mut leaked) = (0, 0, 0, 0);
            for login in &report.logins {
                let is_leaked = state.leaked.contains(&login.id);
                let is_weak = login.strength.is_weak();
                weak += i32::from(is_weak);
                reused += i32::from(login.reused_by > 0);
                old += i32::from(login.old);
                leaked += i32::from(is_leaked);
                if !(is_leaked || is_weak || login.reused_by > 0 || login.old) {
                    continue;
                }
                let Ok(item) = vault.get_item(&login.id) else {
                    continue;
                };
                let url = item.urls.first().cloned().unwrap_or_default();
                let (icon, has_icon) = self.picture(&url, &item.icon_url);
                let (glyph, glyph_color, glyph_bg) = icons::look_of(&item.icon_url);
                // The worst first: leaked, weak, reused, then old.
                let rank = if is_leaked {
                    0
                } else if is_weak {
                    1
                } else if login.reused_by > 0 {
                    2
                } else {
                    3
                };
                found.push((
                    rank,
                    HealthRow {
                        title: item.title.as_str().into(),
                        username: item.username.as_str().into(),
                        leaked: is_leaked,
                        weak: is_weak,
                        reused: i32::try_from(login.reused_by).unwrap_or(i32::MAX),
                        old_years: if login.old && login.set_at > 0 {
                            i32::try_from(((now - login.set_at) / YEAR).max(1)).unwrap_or(1)
                        } else {
                            0
                        },
                        icon,
                        has_icon,
                        initial: initial(&item.title),
                        tint: tint(item.kind, if url.is_empty() { &item.title } else { &url }),
                        glyph,
                        glyph_color,
                        glyph_bg,
                    },
                    login.id,
                ));
            }
            found.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
            });
            let rows: Vec<(HealthRow, ItemId)> =
                found.into_iter().map(|(_, row, id)| (row, id)).collect();
            (rows, (weak, reused, old, leaked, report.logins.len()))
        };
        let (weak, reused, old, leaked, logins) = counts;
        let problems = i32::try_from(rows.len()).unwrap_or(i32::MAX);
        app.set_health_logins(i32::try_from(logins).unwrap_or(i32::MAX));
        app.set_health_score(problems);
        app.set_health_problems(problems);
        app.set_health_weak(weak);
        app.set_health_reused(reused);
        app.set_health_old(old);
        app.set_health_leaked(leaked);
        self.state.borrow_mut().health_all = rows;
        self.show_health_rows();
    }

    /// The health page's list: every login that needs a look, or (a count tapped) only those
    /// with that problem: 0 leaked, 1 weak, 2 reused, 3 old.
    pub(super) fn show_health_rows(&self) {
        let app = self.app();
        let filter = app.get_health_filter();
        let (rows, ids): (Vec<HealthRow>, Vec<ItemId>) = {
            let state = self.state.borrow();
            state
                .health_all
                .iter()
                .filter(|(row, _)| match filter {
                    0 => row.leaked,
                    1 => row.weak,
                    2 => row.reused > 0,
                    3 => row.old_years > 0,
                    _ => true,
                })
                .map(|(row, id)| (row.clone(), *id))
                .unzip()
        };
        // A filter that matches nothing any more (all fixed) shows everything again.
        if rows.is_empty() && filter >= 0 && !self.state.borrow().health_all.is_empty() {
            app.set_health_filter(-1);
            return self.show_health_rows();
        }
        app.set_health_rows(ModelRc::new(VecModel::from(rows)));
        self.state.borrow_mut().health_ids = ids;
    }

    /// A login on the health page: its page opens, as from the list.
    pub(super) fn health_open(&self, index: i32) {
        let id = usize::try_from(index)
            .ok()
            .and_then(|index| self.state.borrow().health_ids.get(index).copied());
        let Some(id) = id else {
            return;
        };
        self.open_item_id(id);
    }

    /// Opens the item `id` on its page (from the list, the health page or the codes).
    pub(super) fn open_item_id(&self, id: ItemId) {
        {
            let mut state = self.state.borrow_mut();
            state.selected = Some(id);
            state.show_password = false;
        }
        self.set_error(super::error::NONE, "");
        self.show_item();
        self.app().set_page(Page::Item);
    }
}
