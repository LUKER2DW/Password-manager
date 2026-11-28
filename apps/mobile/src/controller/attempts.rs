//! Unlock attempts on this phone (THREAT_MODEL.md, "Unlock attempts"; `vault_core::attempts`):
//! every failed try at a vault (a wrong master password, the fingerprint failing in a way the
//! app sees) is counted in the phone's settings (`Prefs::unlock_attempts`), which a restart
//! doesn't clear. From the fifth failure in a row the next try waits, 30 s and doubling up to
//! 15 min: the unlock screen counts down, and the controller refuses a try before then. The
//! next right unlock says how many failed and since when, once, and the count starts again.
//!
//! A vault that syncs may also choose (Settings, Security; off by default, the master password
//! asked) that this phone's copy goes after [`prefs::REMOVE_AFTER_FAILURES`] failures in a row:
//! the vault file, its fingerprint unlock and the Keystore key behind it, the Secret Key kept
//! here and this phone's sync keys for it. Nothing is sent to the server, whose copies stay.

use web_time::Instant;

use super::{Controller, error, notice, sheet};
use crate::{platform::files, prefs};

impl Controller {
    /// Both clocks: Unix seconds, and the time since the phone started (which nobody sets),
    /// where the system tells it. The tests put their own in its place.
    pub(super) fn clock(&self) -> (i64, Option<i64>) {
        (self.state.borrow().clock)()
    }

    /// Seconds before the next try at vault `vault_id` may start (0: now); the unlock screen
    /// counts down meanwhile. A clock set back starts the wait again from now.
    pub(super) fn unlock_wait(&self, vault_id: &str) -> i64 {
        let (now, uptime) = self.clock();
        let mut attempts = self
            .state
            .borrow()
            .prefs
            .unlock_attempts
            .get(vault_id)
            .copied()
            .unwrap_or_default();
        if attempts.settle_clock(now) {
            self.change_prefs(|prefs| {
                prefs.unlock_attempts.insert(vault_id.to_owned(), attempts);
            });
        }
        let left = attempts.wait_left(now, uptime);
        self.show_unlock_wait(left, attempts.failed);
        left
    }

    fn show_unlock_wait(&self, left: i64, failed: u32) {
        let app = self.app();
        app.set_unlock_wait(i32::try_from(left.max(0)).unwrap_or(i32::MAX));
        app.set_unlock_failed(i32::try_from(failed).unwrap_or(i32::MAX));
        self.state.borrow_mut().unlock_until = (left > 0)
            .then(|| Instant::now() + std::time::Duration::from_secs(left.unsigned_abs()));
    }

    /// Once a second: the countdown on the unlock screen (only what shows; each try asks
    /// [`Controller::unlock_wait`] again).
    pub(super) fn tick_unlock_wait(&self) {
        let Some(until) = self.state.borrow().unlock_until else {
            return;
        };
        let left = until
            .saturating_duration_since(Instant::now())
            .as_secs_f64();
        self.app().set_unlock_wait(left.ceil() as i32);
        if left <= 0.0 {
            self.state.borrow_mut().unlock_until = None;
        }
    }

    /// A try at vault `vault_id` failed: counted, the wait it starts shown, and this phone's
    /// copy removed when the vault chose that and this was the last try it allows. Returns
    /// whether the copy went.
    pub(super) fn unlock_failed(&self, vault_id: &str) -> bool {
        let (now, uptime) = self.clock();
        let mut attempts = self
            .state
            .borrow()
            .prefs
            .unlock_attempts
            .get(vault_id)
            .copied()
            .unwrap_or_default();
        attempts.record_failure(now, uptime);
        self.change_prefs(|prefs| {
            prefs.unlock_attempts.insert(vault_id.to_owned(), attempts);
        });
        let chosen = self
            .state
            .borrow()
            .prefs
            .remove_after_failures
            .contains(vault_id);
        // Only while the vault still syncs: its copies live elsewhere too.
        if chosen && attempts.failed >= prefs::REMOVE_AFTER_FAILURES && Self::syncs(vault_id) {
            self.remove_copy_after_failures(vault_id);
            return true;
        }
        self.show_unlock_wait(attempts.wait_left(now, uptime), attempts.failed);
        false
    }

    /// Vault `vault_id` opened: the failed tries before it are told once (how many, since
    /// when), and the count starts again.
    pub(super) fn tell_failed_unlocks(&self, vault_id: &str) {
        let before = self
            .state
            .borrow()
            .prefs
            .unlock_attempts
            .get(vault_id)
            .copied();
        self.show_unlock_wait(0, 0);
        let Some(before) = before else {
            return;
        };
        self.change_prefs(|prefs| {
            prefs.unlock_attempts.remove(vault_id);
        });
        if before.is_clear() {
            return;
        }
        let since = crate::view::date_time(before.first_at, self.system().utc_offset_minutes());
        self.notify(notice::FAILED_UNLOCKS, &since);
        self.app()
            .set_notice_count(i32::try_from(before.failed).unwrap_or(i32::MAX));
    }

    /// The last failed try a vault allowed on this phone: its copy goes (see the module's
    /// words), and the next vault the phone keeps shows, or the start screen.
    fn remove_copy_after_failures(&self, vault_id: &str) {
        let path = self.state.borrow().path.clone();
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = self
            .state
            .borrow()
            .prefs
            .vaults
            .iter()
            .find(|v| v.file == file)
            .map(|v| v.name.clone())
            .unwrap_or_default();
        self.forget_sync_here(vault_id);
        self.forget_biometrics(vault_id);
        let _ = crate::platform::secret_store::forget(vault_id);
        files::remove(&path);
        files::remove(&super::settings::bak(&path));
        self.state.borrow_mut().incoming = None;
        self.change_prefs(|prefs| {
            prefs.vaults.retain(|v| v.file != file);
            prefs.password_typed_at.remove(vault_id);
            prefs.unlock_attempts.remove(vault_id);
            prefs.remove_after_failures.remove(vault_id);
            prefs.current.clear();
        });
        self.show_unlock_wait(0, 0);
        self.open_next_vault();
        self.notify(notice::COPY_REMOVED, &name);
    }

    /// Settings, Security: whether this vault may remove the phone's copy after failed
    /// unlocks (only while it syncs), and whether it does.
    pub(super) fn refresh_failed_unlocks_setting(&self) {
        let app = self.app();
        let id = self
            .state
            .borrow()
            .vault
            .as_ref()
            .map(vault_core::Vault::id_hex);
        let Some(id) = id else {
            return;
        };
        let syncs = Self::syncs(&id);
        let on = syncs
            && self
                .state
                .borrow()
                .prefs
                .remove_after_failures
                .contains(&id);
        app.set_can_remove_after(syncs);
        app.set_remove_after(on);
    }

    /// The switch: on asks first (the sheet says exactly what goes, and the master password
    /// confirms it); off at once.
    pub(super) fn remove_after_toggled(&self, on: bool) {
        let id = self
            .state
            .borrow()
            .vault
            .as_ref()
            .map(vault_core::Vault::id_hex);
        let Some(id) = id else {
            return;
        };
        if on {
            // Stays off until the master password confirms it.
            self.app().set_remove_after(false);
            if Self::syncs(&id) {
                self.set_error(error::NONE, "");
                self.app().invoke_ask(sheet::REMOVE_AFTER_FAILURES);
            }
            return;
        }
        self.change_prefs(|prefs| {
            prefs.remove_after_failures.remove(&id);
        });
        self.refresh_failed_unlocks_setting();
    }

    /// The master password confirmed the switch.
    pub(super) fn remove_after_confirmed(&self) {
        let id = self
            .state
            .borrow()
            .vault
            .as_ref()
            .map(vault_core::Vault::id_hex);
        if let Some(id) = id
            && Self::syncs(&id)
        {
            self.change_prefs(|prefs| {
                prefs.remove_after_failures.insert(id);
            });
        }
        self.refresh_failed_unlocks_setting();
    }

    /// The tests: this window's clocks from now on.
    #[cfg(test)]
    pub(crate) fn set_clock(&self, clock: fn() -> (i64, Option<i64>)) {
        self.state.borrow_mut().clock = clock;
    }
}

/// Both clocks as the phone reads them.
pub(super) fn clock_default() -> (i64, Option<i64>) {
    (crate::view::now_unix(), crate::platform::uptime_seconds())
}
