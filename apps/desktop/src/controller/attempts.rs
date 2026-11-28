//! Unlock attempts on this computer (THREAT_MODEL.md, "Unlock attempts";
//! `vault_core::attempts`): every failed try at the vault (a wrong master password, a keyfile
//! that doesn't match, Windows Hello failing) is counted in the device state, which a restart
//! doesn't clear. From the fifth failure in a row the next try waits, 30 s and doubling up to
//! 15 min: the unlock screen counts down, and `unlock` and `quick_unlock` refuse a try before
//! then (here, not only on screen). The next right unlock says how many failed and since when,
//! once, and the count starts again. The CLI counts in the same place.

use std::time::{Duration, Instant};

use slint::TimerMode;
use vault_platform::device::{Clock, unlock_attempts};

use super::{Controller, notice};
use crate::view;

impl Controller {
    /// Both clocks, as this window reads them (the tests set their own).
    pub(super) fn clock(&self) -> Clock {
        (self.state.borrow().clock)()
    }

    /// Seconds before the next try at vault `vault_id` may start (0: now); the countdown shows
    /// while there is a wait.
    pub(super) fn unlock_wait(&self, vault_id: &str) -> i64 {
        let left = unlock_attempts::wait(vault_id, self.clock());
        if left > 0 {
            let failed = vault_platform::DeviceState::load_or_set_aside()
                .0
                .unlock_attempts(vault_id)
                .failed;
            self.app()
                .set_unlock_failed(i32::try_from(failed).unwrap_or(i32::MAX));
        }
        self.show_unlock_wait(left);
        left
    }

    /// A try at vault `vault_id` failed: counted, and the wait it starts shown.
    pub(super) fn unlock_failed(&self, vault_id: &str) {
        let clock = self.clock();
        let attempts = unlock_attempts::failed(vault_id, clock);
        self.app()
            .set_unlock_failed(i32::try_from(attempts.failed).unwrap_or(i32::MAX));
        self.show_unlock_wait(attempts.wait_left(clock.now, clock.uptime));
    }

    /// Counts down `left` seconds on the unlock screen (the controller checks again before
    /// each try: this is only what shows).
    fn show_unlock_wait(&self, left: i64) {
        let app = self.app();
        app.set_unlock_wait(i32::try_from(left.max(0)).unwrap_or(i32::MAX));
        if left <= 0 {
            self.timers.unlock_wait.stop();
            return;
        }
        let until = Instant::now() + Duration::from_secs(left.unsigned_abs());
        let weak = self.app.clone();
        self.timers
            .unlock_wait
            .start(TimerMode::Repeated, Duration::from_secs(1), move || {
                if let Some(app) = weak.upgrade() {
                    let left = until
                        .saturating_duration_since(Instant::now())
                        .as_secs_f64();
                    app.set_unlock_wait(left.ceil() as i32);
                }
            });
    }

    /// Vault `vault_id` opened: the failed tries before it are told once (how many, since
    /// when), and the count starts again.
    pub(super) fn tell_failed_unlocks(&self, vault_id: &str) {
        let before = unlock_attempts::succeeded(vault_id);
        self.show_unlock_wait(0);
        let app = self.app();
        app.set_unlock_failed(0);
        if before.is_clear() {
            return;
        }
        let since = view::date_time(
            before.first_at,
            vault_platform::locale::utc_offset_minutes(),
        );
        self.notify_long(notice::FAILED_UNLOCKS, &since);
        app.set_notice_count(i32::try_from(before.failed).unwrap_or(i32::MAX));
    }

    /// Tests: this window's clocks from now on, and the unlock screen's countdown again.
    #[cfg(test)]
    pub(crate) fn set_clock(&self, clock: fn() -> Clock) {
        self.state.borrow_mut().clock = clock;
        let id = self.app().get_vault_id().to_string();
        if !id.is_empty() && self.state.borrow().session.is_none() {
            self.unlock_wait(&id);
        }
    }
}
