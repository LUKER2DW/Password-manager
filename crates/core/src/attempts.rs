//! Unlock attempts on one device (THREAT_MODEL.md, "Unlock attempts"): the failed unlocks of a
//! vault, counted outside the vault on the device that saw them, holding no secret (a count
//! and two instants). After [`FREE_TRIES`] failures in a row the next try waits, longer after
//! each further failure ([`wait_after`]); the next right unlock tells how many there were and
//! since when, and starts the count again.
//!
//! The apps keep this in their device state, which a restart doesn't clear: a limit that a
//! restart resets is no limit. Time comes from two clocks. The wall clock (Unix seconds)
//! survives a restart but can be set: one set back never shortens a wait (the wait starts
//! again from the new time, [`UnlockAttempts::settle_clock`]), and one set forward is caught
//! while the device hasn't restarted by the second clock, the time since the device started
//! (`uptime`, which nobody sets): of the two, the one that says less time has passed counts.
//! Nothing here reads a clock; the callers pass both in.

use serde::{Deserialize, Serialize};

/// Failed unlocks allowed in a row before the next try waits.
pub const FREE_TRIES: u32 = 5;
/// The first wait, after the [`FREE_TRIES`]th failure; each further failure doubles it.
pub const FIRST_WAIT_SECONDS: i64 = 30;
/// The longest wait.
pub const LONGEST_WAIT_SECONDS: i64 = 15 * 60;

/// How long the next try waits after `failed` failures in a row: nothing before
/// [`FREE_TRIES`], then 30 s, 1 min, 2 min, 4 min, 8 min, and 15 min from then on.
pub fn wait_after(failed: u32) -> i64 {
    if failed < FREE_TRIES {
        return 0;
    }
    let doublings = (failed - FREE_TRIES).min(16);
    (FIRST_WAIT_SECONDS << doublings).min(LONGEST_WAIT_SECONDS)
}

/// The failed unlocks of one vault on this device since its last right one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnlockAttempts {
    /// How many, in a row.
    pub failed: u32,
    /// When the first of them was (Unix seconds).
    pub first_at: i64,
    /// When the last was (Unix seconds); the wait runs from it.
    pub last_at: i64,
    /// The device's time since it started at the last one (seconds; 0 = not known).
    pub last_uptime: i64,
}

impl UnlockAttempts {
    /// Nothing failed since the last right unlock.
    pub fn is_clear(&self) -> bool {
        self.failed == 0
    }

    /// One more failure, at `now` (Unix seconds) and `uptime` (the device's time since it
    /// started, when known).
    pub fn record_failure(&mut self, now: i64, uptime: Option<i64>) {
        if self.failed == 0 {
            self.first_at = now;
        }
        self.failed = self.failed.saturating_add(1);
        self.last_at = now;
        self.last_uptime = uptime.filter(|up| *up > 0).unwrap_or(0);
    }

    /// The wall clock reads earlier than the last failure (it was set back): the wait starts
    /// again from `now`, never shorter. Returns whether anything changed (to be saved).
    pub fn settle_clock(&mut self, now: i64) -> bool {
        if self.failed == 0 || now >= self.last_at {
            return false;
        }
        self.last_at = now;
        self.first_at = self.first_at.min(now);
        true
    }

    /// Seconds to wait before the next try may start (0: now). Of the two clocks, the one
    /// that says less time has passed since the last failure counts. A device restarted
    /// since (its time since it started is less than it was) has only the wall clock; one
    /// restarted that has been up longer than before counts too little time, which makes the
    /// wait longer, never shorter, and never more than [`LONGEST_WAIT_SECONDS`] from now.
    pub fn wait_left(&self, now: i64, uptime: Option<i64>) -> i64 {
        let wait = wait_after(self.failed);
        if wait == 0 {
            return 0;
        }
        let mut passed = now.saturating_sub(self.last_at).max(0);
        if let Some(up) = uptime
            && self.last_uptime > 0
            && up >= self.last_uptime
        {
            passed = passed.min(up - self.last_uptime);
        }
        (wait - passed).clamp(0, LONGEST_WAIT_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_grows_after_five_failures_up_to_fifteen_minutes() {
        let waits: Vec<i64> = (0..13).map(wait_after).collect();
        assert_eq!(waits, [0, 0, 0, 0, 0, 30, 60, 120, 240, 480, 900, 900, 900]);
        assert_eq!(wait_after(u32::MAX), LONGEST_WAIT_SECONDS);

        let mut attempts = UnlockAttempts::default();
        assert!(attempts.is_clear());
        for i in 0..4 {
            attempts.record_failure(1_000 + i, Some(50 + i));
            assert_eq!(attempts.wait_left(1_000 + i, Some(50 + i)), 0);
        }
        attempts.record_failure(1_010, Some(60));
        assert_eq!(attempts.failed, 5);
        assert_eq!((attempts.first_at, attempts.last_at), (1_000, 1_010));
        assert_eq!(attempts.wait_left(1_010, Some(60)), 30);
        assert_eq!(attempts.wait_left(1_030, Some(80)), 10);
        assert_eq!(attempts.wait_left(1_040, Some(90)), 0);
        attempts.record_failure(1_040, Some(90));
        assert_eq!(attempts.wait_left(1_040, Some(90)), 60);
    }

    #[test]
    fn a_clock_moved_either_way_never_shortens_the_wait() {
        let mut attempts = UnlockAttempts::default();
        for _ in 0..FREE_TRIES {
            attempts.record_failure(10_000, Some(500));
        }
        // Forward a day: the time since the device started still says 5 seconds.
        assert_eq!(attempts.wait_left(10_000 + 86_400, Some(505)), 25);
        // The device restarted: only the wall clock is left.
        assert_eq!(attempts.wait_left(10_005, Some(3)), 25);
        assert_eq!(attempts.wait_left(10_040, Some(3)), 0);
        // Restarted and up longer than before: too little time counts, at most the whole wait.
        assert_eq!(attempts.wait_left(10_040, Some(501)), 29);
        // No second clock at all (a browser).
        assert_eq!(attempts.wait_left(10_010, None), 20);

        // Back an hour: the wait starts again from the new time, whole.
        assert_eq!(attempts.wait_left(10_000 - 3_600, None), 30);
        assert!(attempts.settle_clock(10_000 - 3_600));
        assert_eq!(attempts.last_at, 10_000 - 3_600);
        assert!(!attempts.settle_clock(10_000 - 3_600));
        assert_eq!(attempts.wait_left(10_000 - 3_590, None), 20);
        assert!(!UnlockAttempts::default().settle_clock(0));
    }

    #[test]
    fn older_files_and_unknown_uptime_read() {
        let read: UnlockAttempts = serde_json::from_str(r#"{"failed": 6}"#).unwrap();
        assert_eq!(read.failed, 6);
        let mut attempts = UnlockAttempts::default();
        attempts.record_failure(5, None);
        assert_eq!(attempts.last_uptime, 0);
        attempts.record_failure(6, Some(0));
        assert_eq!((attempts.failed, attempts.first_at), (2, 5));
    }
}
