//! "Change password" on a login's page (F19): the app makes a strong password for that login
//! and opens the site's page for changing it. The browser extension, asked for a suggestion on
//! a new-password field of that site, gets that very password (when it fits what the field
//! allows); after the person sends the form, the extension's card offers to update the login,
//! as for any change typed there (the old password goes into the item's history).
//!
//! The password waits in memory only, for one login and its sites, for half an hour at most,
//! and goes when the vault locks; nothing is saved until the person updates the login.

use std::time::{Duration, Instant};

use vault_browser::{
    origin::{Origin, item_matches},
    protocol::{GeneratedPassword, Request, Response, Symbols},
};
use vault_core::{
    ItemId, ItemKind,
    generator::{self, PasswordOptions},
};
use zeroize::Zeroizing;

use super::{Controller, notice};

/// How long a password made for a change waits for the site's page.
const WAITS_FOR: Duration = Duration::from_secs(30 * 60);

/// A password made for changing one login's password on its site.
pub(super) struct PendingChange {
    item: ItemId,
    urls: Vec<String>,
    password: Zeroizing<String>,
    bits: u32,
    at: Instant,
    /// The session it was made in: a lock ends it.
    epoch: u64,
}

impl std::fmt::Debug for PendingChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingChange")
            .field("item", &self.item)
            .finish_non_exhaustive()
    }
}

/// Whether `password` is one a generator asked with these options could have made: no longer
/// than asked, and only of the kinds of characters allowed.
fn fits(
    password: &str,
    length: Option<u32>,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: &Symbols,
) -> bool {
    let short_enough = length
        .and_then(|l| usize::try_from(l).ok())
        .is_none_or(|l| password.chars().count() <= l);
    short_enough
        && password.chars().all(|c| {
            if c.is_ascii_lowercase() {
                lower
            } else if c.is_ascii_uppercase() {
                upper
            } else if c.is_ascii_digit() {
                digits
            } else {
                match symbols {
                    Symbols::Any(on) => *on && c.is_ascii_punctuation(),
                    Symbols::Only(set) => set.contains(c),
                }
            }
        })
}

impl Controller {
    /// The item page's "Change password": a strong password made for the selected login, and
    /// the site's page for changing it opened.
    pub(super) fn start_password_change(&self) {
        let Some((id, item)) = self.selected_item_raw() else {
            return;
        };
        let Some(site) = item
            .urls
            .first()
            .cloned()
            .filter(|_| item.kind == ItemKind::Login)
        else {
            return;
        };
        let options = PasswordOptions {
            length: 20,
            ..PasswordOptions::default()
        };
        let Ok(password) = generator::generate_password(&options) else {
            return;
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bits = options.entropy_bits() as u32;
        {
            let mut state = self.state.borrow_mut();
            let epoch = state.session_epoch;
            state.change_pending = Some(PendingChange {
                item: id,
                urls: item.urls.clone(),
                password,
                bits,
                at: Instant::now(),
                epoch,
            });
        }
        self.open_change_page(&site);
        let browser = self.state.borrow().settings.browser_extension;
        self.notify_long(
            if browser {
                notice::CHANGE_READY
            } else {
                notice::CHANGE_NO_EXTENSION
            },
            &item.title,
        );
    }

    /// The extension's `generate` for a page of the login being changed: the password made
    /// for it, held as any generated password (`keep` adds it to the history), when it fits
    /// what the field allows. `None`: the generator answers as usual.
    pub(super) fn pending_change_answer(
        &self,
        request: &[u8],
        hold: impl FnOnce(&mut super::State, Zeroizing<String>, String) -> String,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let Ok(Request::Generate {
            length,
            lower,
            upper,
            digits,
            symbols,
            words: None,
            url: Some(url),
            ..
        }) = serde_json::from_slice::<Request>(request)
        else {
            return None;
        };
        let origin = Origin::of_page(&url).ok()?;
        let mut state = self.state.borrow_mut();
        let epoch = state.session_epoch;
        let pending = state.change_pending.as_ref()?;
        if pending.epoch != epoch || pending.at.elapsed() > WAITS_FOR || state.session.is_none() {
            state.change_pending = None;
            return None;
        }
        if !item_matches(&pending.urls, &origin)
            || !fits(&pending.password, length, lower, upper, digits, &symbols)
        {
            return None;
        }
        let password = pending.password.clone();
        let bits = pending.bits;
        let id = hold(&mut state, password.clone(), origin.as_str().to_owned());
        let answer = Response::Generated(GeneratedPassword {
            id,
            password: password.to_string(),
            bits,
        });
        serde_json::to_vec(&answer).ok().map(Zeroizing::new)
    }

    /// The password made for a change was used (kept from the extension): it no longer waits.
    pub(super) fn pending_change_used(&self, password: &str) {
        let mut state = self.state.borrow_mut();
        if state
            .change_pending
            .as_ref()
            .is_some_and(|pending| pending.password.as_str() == password)
        {
            state.change_pending = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_made_for_a_change_is_offered_only_where_it_fits() {
        let any = Symbols::Any(true);
        assert!(fits("aB3$xyz", None, true, true, true, &any));
        assert!(fits("aB3$xyz", Some(7), true, true, true, &any));
        assert!(
            !fits("aB3$xyz", Some(6), true, true, true, &any),
            "too long"
        );
        assert!(!fits(
            "aB3$xyz",
            None,
            true,
            true,
            true,
            &Symbols::Any(false)
        ));
        assert!(fits(
            "aB3$xyz",
            None,
            true,
            true,
            true,
            &Symbols::Only("$!".into())
        ));
        assert!(!fits(
            "aB3%xyz",
            None,
            true,
            true,
            true,
            &Symbols::Only("$!".into())
        ));
        assert!(
            !fits("aB3xyz", None, true, true, false, &any),
            "no digits allowed"
        );
    }
}
