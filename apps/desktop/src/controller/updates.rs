//! Updates (Settings → About, and the title bar): GitHub's newest release of the project,
//! looked for by itself a moment after the app starts and then every hour while it runs
//! (unless the person turns that off), and whenever the person presses Check for updates
//! (`vault_platform::updates`: one anonymous request, nothing about the vault in it). A release
//! counts only with its manifest signed by the project's release key
//! (`vault_platform::updates::latest`, CRYPTO.md §9). A newer version is told once, in a notice;
//! a version older than one already told isn't shown in its place.
//!
//! With "Install updates by itself" on (the default), a newer version then installs itself, off
//! the UI thread (`vault_platform::self_update`): the release read and its manifest checked
//! again, the program downloaded next to this one, its SHA-256 checked against the manifest,
//! and put in this program's place. The title bar's update button and Settings → About show
//! each step. Once it is in place, the app asks whether to restart now (the vault locks first,
//! as Lock now does) or later (the next start runs it). Off, the newer version is only told,
//! and Install now does the same on demand. A folder this app can't write in (Program Files)
//! is told, and the release page opens instead, as before.

use std::time::Duration;

use slint::{SharedString, TimerMode};
use vault_platform::{
    DeviceState, files,
    self_update::{self, Step, UpdateError},
};
use vault_sync_wire::releases::Verified;

use super::{CURRENT, Controller, Runner, error, notice};

/// The first look on its own, once the app has started.
const FIRST_LOOK: Duration = Duration::from_secs(30);
/// Then one every hour, so a fix that was released reaches this computer soon.
const LOOK_EVERY: Duration = Duration::from_secs(60 * 60);
/// How long a copy started after an update waits for this one to end.
pub const HANDOVER: Duration = Duration::from_secs(30);

/// The install's steps, as `install-step` shows them.
pub(crate) mod install {
    pub const NONE: i32 = 0;
    pub const MANIFEST: i32 = 1;
    pub const DOWNLOAD: i32 = 2;
    pub const CHECK: i32 = 3;
    pub const PUT: i32 = 4;
    pub const INSTALLED: i32 = 5;
    pub const FAILED: i32 = 6;

    /// Why it failed (`install-failure`).
    pub const NOT_WRITABLE: i32 = 1;
    pub const REFUSED: i32 = 2;
    pub const NETWORK: i32 = 3;
    pub const SWAP: i32 = 4;
}

impl Controller {
    /// Starts the looks on their own (not in tests, which never reach the network).
    pub(super) fn start_update_checks(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let look = |controller: &Controller| {
            // Alerts marked as read come back after a week: looked at with the hourly look.
            controller.refresh_alerts();
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
    pub(super) fn ask_github(&self, quietly: bool) {
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

    pub(crate) fn finish_update_check(&self, result: Result<Verified, String>, quietly: bool) {
        let app = self.app();
        // The browser extension of that release, when it is newer than what the app has.
        if let Ok(release) = &result {
            self.release_seen(release);
        }
        // Older than a version already told (an old release handed out again): the newer one
        // stays shown.
        let told = self.state.borrow().update_told.clone();
        if let (Ok(release), Some(told)) = (&result, &told)
            && vault_sync_wire::is_newer(told, release.version())
        {
            return;
        }
        match result {
            Ok(release) if release.is_newer_than(env!("CARGO_PKG_VERSION")) => {
                let version = release.version().to_owned();
                app.set_update_version(version.as_str().into());
                app.set_update_state(3);
                let first_time = told.as_deref() != Some(version.as_str());
                {
                    let mut state = self.state.borrow_mut();
                    state.update_told = Some(version.clone());
                    state.release_page = Some(release.page().to_owned());
                }
                // A folder it couldn't write in stays told: not tried again every hour.
                let cant_write = app.get_install_step() == install::FAILED
                    && app.get_install_failure() == install::NOT_WRITABLE;
                if self.installs_by_itself() && !cant_write {
                    self.install_update(false);
                } else if first_time {
                    self.notify_long(notice::UPDATE_OUT, &version);
                }
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

    /// Whether a newer version found installs itself now: the setting, and not a development
    /// build (whose program is cargo's, not a release's).
    fn installs_by_itself(&self) -> bool {
        let state = self.state.borrow();
        state.settings.update_install && (state.runner == Runner::Inline || !cfg!(debug_assertions))
    }

    /// Installs the newer version told (on its own, or `asked`: Install now / Try again): off
    /// the UI thread, each step shown. Nothing when one is under way, or that version is in
    /// already.
    pub(super) fn install_update(&self, asked: bool) {
        let app = self.app();
        let step = app.get_install_step();
        if (install::MANIFEST..=install::PUT).contains(&step) {
            return;
        }
        let Some(version) = self.state.borrow().update_told.clone() else {
            return;
        };
        if step == install::INSTALLED && app.get_install_version() == version.as_str() {
            return;
        }
        self.state.borrow_mut().install_asked = asked;
        app.set_install_failure(0);
        app.set_install_detail(SharedString::new());
        app.set_install_done_kb(0);
        app.set_install_total_kb(0);
        self.update_progress(Step::Manifest);
        if self.state.borrow().runner == Runner::Inline {
            return; // no network in tests: they call update_progress and finish_install
        }
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(err) => {
                self.finish_install(Err(UpdateError::Install(err.to_string())), true);
                return;
            }
        };
        std::thread::spawn(move || {
            let tell = |step: Step| {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                        controller.update_progress(step);
                    }
                });
            };
            // Read again and checked again: the release and its signed manifest as they are
            // now, never what an hour-old look saw.
            let result = vault_platform::updates::latest()
                .map_err(UpdateError::Network)
                .and_then(|release| {
                    // The program is told about at most once per percent.
                    let mut shown = (0u64, u64::MAX);
                    let mut progress = |step: Step| {
                        if let Step::Download { done, total } = step {
                            let percent = done.saturating_mul(100) / total.max(1);
                            if (percent, total) == shown && done != total {
                                return;
                            }
                            shown = (percent, total);
                        }
                        tell(step);
                    };
                    self_update::install(&release, &exe, env!("CARGO_PKG_VERSION"), &mut progress)
                        .map(|()| release.version().to_owned())
                });
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.finish_install(result, false);
                }
            });
        });
    }

    /// A step of the install under way (the tests call it in the install's place).
    pub(crate) fn update_progress(&self, step: Step) {
        let app = self.app();
        let kb = |bytes: u64| i32::try_from(bytes / 1024).unwrap_or(i32::MAX);
        match step {
            Step::Manifest => app.set_install_step(install::MANIFEST),
            Step::Download { done, total } => {
                app.set_install_step(install::DOWNLOAD);
                app.set_install_done_kb(kb(done));
                app.set_install_total_kb(kb(total));
            }
            Step::Check => app.set_install_step(install::CHECK),
            Step::Install => app.set_install_step(install::PUT),
        }
    }

    /// How the install ended: the version now in this program's place, or why not.
    /// `asked_now` is a failure before anything started (no program path).
    pub(crate) fn finish_install(&self, result: Result<String, UpdateError>, asked_now: bool) {
        let app = self.app();
        let reached = app.get_install_step();
        match result {
            Ok(version) => {
                app.set_install_version(version.as_str().into());
                app.set_install_step(install::INSTALLED);
                // Asked once; Later leaves it to the next start (or the panel's Restart now).
                app.set_update_panel(false);
                app.set_restart_asking(true);
            }
            Err(UpdateError::NotNewer) => {
                // Taken back, or this version is the newest after all: nothing to install.
                app.set_install_step(install::NONE);
            }
            Err(err) => {
                let (failure, detail) = match &err {
                    UpdateError::NotWritable(folder) => (install::NOT_WRITABLE, folder.clone()),
                    UpdateError::Refused(why) => (install::REFUSED, why.clone()),
                    UpdateError::Network(why) => (install::NETWORK, why.clone()),
                    UpdateError::Install(why) => (install::SWAP, why.clone()),
                    UpdateError::NotNewer => (install::SWAP, String::new()),
                };
                app.set_install_failed_at(if asked_now {
                    install::MANIFEST
                } else {
                    reached.clamp(install::MANIFEST, install::PUT)
                });
                app.set_install_failure(failure);
                app.set_install_detail(detail.as_str().into());
                app.set_install_step(install::FAILED);
                if failure == install::NOT_WRITABLE {
                    // As before the app installed itself: the release page, to take it by hand
                    // (opened at once when the person asked; on its own, it is told).
                    self.notify_long(notice::UPDATE_NOT_WRITABLE, &detail);
                    if self.state.borrow().install_asked {
                        self.open_release();
                    }
                }
            }
        }
    }

    /// Restart (the dialog, or the panel): the vault locks exactly as Lock now does, the new
    /// program starts (it waits for this one to end) and this one quits.
    pub(super) fn restart_now(&self) {
        let app = self.app();
        app.set_restart_asking(false);
        if app.get_install_step() != install::INSTALLED {
            return;
        }
        if self.state.borrow().vault_open || self.state.borrow().session.is_some() {
            self.lock();
        }
        if self.state.borrow().runner == Runner::Inline {
            self.state.borrow_mut().restarted = true;
            return;
        }
        let started = std::env::current_exe().and_then(|exe| {
            std::process::Command::new(exe)
                .arg(self_update::AFTER_UPDATE)
                .arg(std::process::id().to_string())
                .spawn()
        });
        match started {
            Ok(_) => {
                let _ = slint::quit_event_loop();
            }
            Err(err) => self.notify_long(notice::RESTART_FAILED, &err.to_string()),
        }
    }

    /// The first screen's switch (a new vault's): only this setting changes, saved at once;
    /// the others aren't on screen yet.
    pub(super) fn first_update_checks(&self, on: bool) {
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.settings.update_checks = on;
        if let Err(err) = device_state.save() {
            self.set_error(error::FILE, &err.to_string());
            return;
        }
        let was = std::mem::replace(&mut self.state.borrow_mut().settings.update_checks, on);
        if on && !was {
            self.update_checks_turned_on();
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
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        if let Err(err) = files::open_web_link(&page) {
            self.notify_long(notice::LINK_FAILED, &format!("{page} ({err:#})"));
        }
    }
}
