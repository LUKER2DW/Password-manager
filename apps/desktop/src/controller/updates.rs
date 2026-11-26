//! Settings → About → Check for updates: asks GitHub for the project's newest release when the
//! person presses the button (never on its own; `vault_platform::updates`), says whether a newer
//! version is out and opens its release page on github.com when asked. Nothing is downloaded
//! or installed here: the person replaces the program with the new one.

use vault_platform::files;
use vault_sync_wire::releases::Release;

use super::{CURRENT, Controller, Runner, notice};

impl Controller {
    pub(super) fn check_updates(&self) {
        let app = self.app();
        if app.get_update_state() == 1 {
            return; // asking already
        }
        if self.state.borrow().runner == Runner::Inline {
            return; // no network in tests: they call finish_update_check directly
        }
        app.set_update_state(1);
        // Not a vault job: it holds nothing of the vault, so it stays good across a lock.
        std::thread::spawn(|| {
            let result = vault_platform::updates::latest();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.finish_update_check(result);
                }
            });
        });
    }

    pub(crate) fn finish_update_check(&self, result: Result<Release, String>) {
        let app = self.app();
        match result {
            Ok(release) if release.is_newer_than(env!("CARGO_PKG_VERSION")) => {
                app.set_update_version(release.version.as_str().into());
                self.state.borrow_mut().release_page = Some(release.page);
                app.set_update_state(3);
            }
            Ok(_) => {
                self.state.borrow_mut().release_page = None;
                app.set_update_state(2);
            }
            Err(detail) => {
                app.set_update_detail(detail.as_str().into());
                app.set_update_state(4);
            }
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
