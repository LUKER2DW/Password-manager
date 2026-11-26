//! Updates (Settings → About): GitHub's newest release of the project, looked for by itself a
//! moment after the app starts and then every hour while it runs (unless the person turns that
//! off), and whenever the person presses Check for updates (`vault_platform::updates`: one
//! anonymous request, nothing about the vault in it). A newer version is told once, in a
//! notice, and its release page on github.com opens when asked. Nothing is downloaded or
//! installed here: the person replaces the program with the new one.

use std::time::Duration;

use slint::TimerMode;
use vault_platform::files;
use vault_sync_wire::releases::Release;

use super::{CURRENT, Controller, Runner, notice};

/// The first look on its own, once the app has started.
const FIRST_LOOK: Duration = Duration::from_secs(30);
/// Then one every hour, so a fix that was released reaches this computer soon.
const LOOK_EVERY: Duration = Duration::from_secs(60 * 60);

impl Controller {
    /// Starts the looks on their own (not in tests, which never reach the network).
    pub(super) fn start_update_checks(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let look = |controller: &Controller| {
            if controller.state.borrow().settings.update_checks {
                controller.ask_github(true);
            }
        };
        let weak = self.weak();
        self.timers
            .update_first
            .start(TimerMode::SingleShot, FIRST_LOOK, move || {
                if let Some(controller) = weak.upgrade() {
                    look(&controller);
                }
            });
        let weak = self.weak();
        self.timers
            .update_every
            .start(TimerMode::Repeated, LOOK_EVERY, move || {
                if let Some(controller) = weak.upgrade() {
                    look(&controller);
                }
            });
    }

    /// Check for updates (the button).
    pub(super) fn check_updates(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no network in tests: they call finish_update_check directly
        }
        self.ask_github(false);
    }

    /// Asks GitHub off the UI thread; `quietly` (on its own) only a newer version is told.
    fn ask_github(&self, quietly: bool) {
        let app = self.app();
        if app.get_update_state() == 1 {
            return; // asking already
        }
        if !quietly {
            app.set_update_state(1);
        }
        // Not a vault job: it holds nothing of the vault, so it stays good across a lock.
        std::thread::spawn(move || {
            let result = vault_platform::updates::latest();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.finish_update_check(result, quietly);
                }
            });
        });
    }

    pub(crate) fn finish_update_check(&self, result: Result<Release, String>, quietly: bool) {
        let app = self.app();
        match result {
            Ok(release) if release.is_newer_than(env!("CARGO_PKG_VERSION")) => {
                app.set_update_version(release.version.as_str().into());
                app.set_update_state(3);
                let told = self.state.borrow().update_told.as_deref() == Some(&release.version);
                if !told {
                    self.notify_long(notice::UPDATE_OUT, &release.version);
                }
                let mut state = self.state.borrow_mut();
                state.update_told = Some(release.version);
                state.release_page = Some(release.page);
            }
            Ok(_) => {
                self.state.borrow_mut().release_page = None;
                app.set_update_state(2);
            }
            // On its own, a failed look says nothing: the next one comes in an hour.
            Err(_) if quietly => {}
            Err(detail) => {
                app.set_update_detail(detail.as_str().into());
                app.set_update_state(4);
            }
        }
    }

    /// Settings → About → "Look for updates by itself" was turned on: a look now.
    pub(super) fn update_checks_turned_on(&self) {
        if self.state.borrow().runner != Runner::Inline {
            self.ask_github(true);
        }
    }

    /// Opens the newer release's page (on github.com, checked when it was read).
    pub(super) fn open_release(&self) {
        let Some(page) = self.state.borrow().release_page.clone() else {
            return;
        };
        if let Err(err) = files::open_web_link(&page) {
            self.notify_long(notice::LINK_FAILED, &format!("{page} ({err:#})"));
        }
    }
}
