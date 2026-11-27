//! The browser extension itself: where its files come from (`vault_platform::extension_source`)
//! and the folder the browser loads them from (`vault_platform::extension_folder`).
//!
//! By default the files are the newest GitHub release's (`vault-extension-<version>.zip`,
//! downloaded when the app looks for its own updates and taken only with the SHA-256 the
//! release list gives), or the copy built into the app (`build.rs`) when that is newer, or
//! nothing was downloaded yet. The person may take them from a folder of theirs instead.
//!
//! Settings → Browser extension → Add to a browser writes the folder, copies its path, starts
//! the browser chosen on its extensions page and shows the steps there (no browser lets a
//! program add an extension from outside its store by itself: the person loads the folder).
//! While the browser link runs, the folder is kept as the app means it: when the link starts
//! (before it answers anything, so the extension of a new version of the app is in the folder
//! first), every few minutes, and when a newer release was taken. A file another program changed
//! is put back, and said.
//!
//! The extension updates itself from that folder: the app's answers to `status` and `logins`
//! name the version in use, and an older extension reloads (`apps/extension/update.js`).

use std::{path::Path, rc::Rc, time::Duration};

use slint::{ModelRc, TimerMode, VecModel};
use vault_browser::protocol::Response;
use vault_platform::{
    browsers::Browser,
    clipboard, extension_folder,
    extension_source::{self, Extension, Origin},
    files,
    updates::{self, PackageError},
};
use vault_sync_wire::releases::Release;
use zeroize::Zeroizing;

use super::{CURRENT, Controller, Runner, error, notice};
use crate::ui::ExtensionBrowser;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/extension_files.rs"));
}

/// The version of the extension built into the app (its `manifest.json`): the app's own
/// version, as the release requires.
pub(super) const VERSION: &str = embedded::VERSION;

/// How often the folder is looked at while the browser link runs.
const CHECK_EVERY: Duration = Duration::from_secs(5 * 60);

/// What the app writes into the folder now, for the card in Settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InUse {
    origin: Origin,
    version: String,
    /// The person's folder, when it comes from there.
    folder: String,
}

/// What one of the link's checks of the folder found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Checked {
    /// As the app means it (or put right without a word: a new version, another source, a
    /// missing file), or never written by the app.
    Fine,
    /// Another program had changed it: put back now.
    PutBack,
    /// It couldn't be looked at or put right (why): tried again at the next check.
    Failed(String),
}

fn built_in() -> Extension {
    Extension::built_in(VERSION, embedded::FILES)
}

/// The extension the app writes now, and what it is.
fn current() -> Result<(Extension, InUse), String> {
    let (extension, origin) =
        extension_source::current(&built_in()).map_err(|err| format!("{err:#}"))?;
    let folder = if origin == Origin::Folder {
        extension_source::choice()
            .folder
            .map(|folder| folder.display().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let in_use = InUse {
        origin,
        version: extension.version.clone(),
        folder,
    };
    Ok((extension, in_use))
}

/// The link's check: [`extension_folder::keep`] with what is in use. A folder the app never
/// wrote is left alone.
pub(super) fn keep_folder() -> (Checked, Option<InUse>) {
    match current() {
        Err(err) => (Checked::Failed(err), None),
        Ok((extension, in_use)) => {
            let checked = match extension_folder::keep(&extension) {
                Ok(Some(kept)) if kept.tampered => Checked::PutBack,
                Ok(_) => Checked::Fine,
                Err(err) => Checked::Failed(format!("{err:#}")),
            };
            (checked, Some(in_use))
        }
    }
}

impl Controller {
    /// The browsers Settings → Browser extension offers, the default one first. Headless tests
    /// get every browser the app knows, installed or not, and none is the default.
    pub(super) fn show_extension_browsers(&self) {
        let (browsers, default) = if self.state.borrow().runner == Runner::Inline {
            (Browser::ALL.to_vec(), None)
        } else {
            vault_platform::browsers::installed()
        };
        let rows: Vec<ExtensionBrowser> = browsers
            .iter()
            .map(|&browser| ExtensionBrowser {
                name: browser.name().into(),
                // Its brand's mark: SourceMark draws them in Browser::ALL's order.
                mark: Browser::ALL
                    .iter()
                    .position(|&known| known == browser)
                    .and_then(|index| i32::try_from(index).ok())
                    .unwrap_or(0),
                is_default: Some(browser) == default,
            })
            .collect();
        self.state.borrow_mut().extension_browsers = browsers;
        let app = self.app();
        app.set_extension_browsers(ModelRc::from(Rc::new(VecModel::from(rows))));
        app.set_extension_browser(0);
    }

    /// The card's line about what is in use, and the version the extension hears (left as it
    /// was while the person's folder can't be read).
    pub(super) fn show_extension_source(&self) {
        let in_use = current().ok().map(|(_, in_use)| in_use);
        self.extension_in_use(in_use.as_ref());
    }

    fn extension_in_use(&self, in_use: Option<&InUse>) {
        let Some(in_use) = in_use else {
            return;
        };
        self.state.borrow_mut().extension_version = in_use.version.clone();
        let app = self.app();
        app.set_extension_source(match in_use.origin {
            Origin::BuiltIn => 0,
            Origin::Release => 1,
            Origin::Folder => 2,
        });
        app.set_extension_version(in_use.version.as_str().into());
        app.set_extension_local(in_use.folder.as_str().into());
    }

    /// "Add to …": the folder written, its path copied, the browser started on its extensions
    /// page, and the steps shown. (Tests start no browser and leave the clipboard alone.)
    pub(super) fn add_extension(&self, index: i32) {
        let browser = usize::try_from(index)
            .ok()
            .and_then(|index| self.state.borrow().extension_browsers.get(index).copied());
        let Some(browser) = browser else {
            return;
        };
        let Some(folder) = self.install_extension() else {
            return;
        };
        let path = folder.display().to_string();
        let real = self.state.borrow().runner == Runner::Thread;
        // A folder's path, not a secret: an ordinary copy.
        let copied = real && clipboard::copy_plain(&path).is_ok();
        let started = real && browser.open_extensions_page().is_ok();
        let app = self.app();
        app.set_extension_steps_browser(browser.name().into());
        app.set_extension_steps_firefox(browser.is_firefox());
        app.set_extension_steps_page(browser.extensions_page().into());
        app.set_extension_steps_folder(path.into());
        app.set_extension_steps_started(started);
        app.set_extension_steps_copied(copied);
        app.set_extension_steps(true);
    }

    /// "Open the folder": written first, then shown in Explorer.
    pub(super) fn open_extension_folder(&self) {
        let Some(folder) = self.install_extension() else {
            return;
        };
        if self.state.borrow().runner == Runner::Inline {
            return; // headless tests open no window
        }
        if let Err(err) = files::open_with_default_app(&folder) {
            self.set_error(error::EXTENSION_FOLDER_OPEN, &format!("{err:#}"));
        }
    }

    /// Writes the folder with what is in use, or puts right what differs in it: its path, or
    /// `None` with the error shown on the card.
    fn install_extension(&self) -> Option<std::path::PathBuf> {
        self.set_error(error::NONE, "");
        let written = current().and_then(|(extension, in_use)| {
            extension_folder::install(&extension)
                .map(|kept| (kept, in_use))
                .map_err(|err| format!("{err:#}"))
        });
        match written {
            Ok((kept, in_use)) => {
                self.extension_in_use(Some(&in_use));
                if kept.tampered {
                    self.notify_long(notice::EXTENSION_PUT_BACK, "");
                }
                Some(kept.path)
            }
            Err(err) => {
                self.set_error(error::EXTENSION_FOLDER, &err);
                None
            }
        }
    }

    /// "Use a folder on this computer instead…": the person picks a folder holding a
    /// `manifest.json`.
    pub(super) fn choose_extension_folder(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // headless tests open no dialog: they call use_extension_folder
        }
        let picked = rfd::FileDialog::new().pick_folder();
        if let Some(folder) = picked {
            self.use_extension_folder(&folder);
        }
    }

    /// Takes the extension from the person's `folder` from now on (it must read as one: the
    /// same rules as a release's zip), and writes it into the app's folder when that is kept.
    pub fn use_extension_folder(&self, folder: &Path) {
        self.set_error(error::NONE, "");
        if let Err(err) = extension_source::set_folder(Some(folder)) {
            self.set_error(error::EXTENSION_LOCAL, &format!("{err:#}"));
            return;
        }
        self.check_extension_folder();
        self.show_extension_source();
    }

    /// "Use the extension from GitHub": back to the default, and a look at GitHub's releases
    /// for the newest one (the person asked; not in tests).
    pub(super) fn use_extension_release(&self) {
        self.set_error(error::NONE, "");
        if let Err(err) = extension_source::set_folder(None) {
            self.set_error(error::EXTENSION_FOLDER, &format!("{err:#}"));
            return;
        }
        self.check_extension_folder();
        self.show_extension_source();
        if self.state.borrow().runner == Runner::Thread {
            self.ask_github(true);
        }
    }

    /// The app looked at GitHub's newest release: its extension is downloaded when it is newer
    /// than what the app has and the person hasn't chosen a folder of theirs (off the UI
    /// thread; never in tests, which call `take_extension_release`).
    pub(super) fn release_seen(&self, release: &Release) {
        if self.state.borrow().runner == Runner::Inline || self.state.borrow().extension_fetching {
            return;
        }
        let choice = extension_source::choice();
        let have = choice
            .release
            .map(|kept| kept.version)
            .filter(|kept| extension_source::newer(kept, VERSION))
            .unwrap_or_else(|| VERSION.to_owned());
        if choice.folder.is_some()
            || release.extension_package().is_none()
            || !extension_source::newer(&release.version, &have)
        {
            return;
        }
        self.state.borrow_mut().extension_fetching = true;
        let release = release.clone();
        std::thread::spawn(move || {
            let taken = match updates::extension_package(&release) {
                Ok(zip) => {
                    let sha256 = release
                        .extension_package()
                        .and_then(|asset| asset.sha256.clone())
                        .unwrap_or_default();
                    Some(
                        extension_source::keep_release(&release.version, &sha256, &zip)
                            .map(drop)
                            .map_err(|err| format!("{err:#}")),
                    )
                }
                Err(PackageError::Refused(reason)) => Some(Err(reason)),
                // None listed, or the network failed: the next look tries again.
                Err(PackageError::None | PackageError::Network(_)) => None,
            };
            let version = release.version;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.state.borrow_mut().extension_fetching = false;
                    if let Some(taken) = taken {
                        controller.extension_release_taken(&version, taken);
                    }
                }
            });
        });
    }

    /// Takes a release's zip downloaded for `version` with the SHA-256 GitHub listed (`sha256`):
    /// what the app does once one is downloaded, which the headless tests do with zips of their
    /// own.
    pub fn take_extension_release(&self, version: &str, sha256: &str, zip: &[u8]) {
        let taken = extension_source::keep_release(version, sha256, zip)
            .map(drop)
            .map_err(|err| format!("{err:#}"));
        self.extension_release_taken(version, taken);
    }

    /// A release's extension was kept (the folder takes it now, without a word) or refused
    /// (said: the copy in use stays).
    fn extension_release_taken(&self, version: &str, taken: Result<(), String>) {
        match taken {
            Ok(()) => {
                self.check_extension_folder();
                self.show_extension_source();
            }
            Err(reason) => {
                self.notify_long(notice::EXTENSION_REFUSED, &format!("{version}: {reason}"));
            }
        }
    }

    /// The link's check of the folder: what differs from what is in use is put back, and a
    /// change another program made is told. Off the UI thread, except in tests.
    pub fn check_extension_folder(&self) {
        let runner = self.state.borrow().runner;
        match runner {
            Runner::Inline => {
                let (checked, in_use) = keep_folder();
                self.extension_checked(checked, in_use);
            }
            Runner::Thread => {
                std::thread::spawn(|| {
                    let (checked, in_use) = keep_folder();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.extension_checked(checked, in_use);
                        }
                    });
                });
            }
        }
    }

    /// Says what a check found. A folder that can't be put right is said from the second check
    /// in a row that fails (a file the browser was reading a moment is no news), and then at
    /// each one until it can: something may be keeping the app from putting the files back.
    pub(super) fn extension_checked(&self, checked: Checked, in_use: Option<InUse>) {
        self.extension_in_use(in_use.as_ref());
        let failed_before = std::mem::replace(
            &mut self.state.borrow_mut().extension_check_failed,
            matches!(checked, Checked::Failed(_)),
        );
        match checked {
            Checked::Fine => {}
            Checked::PutBack => self.notify_long(notice::EXTENSION_PUT_BACK, ""),
            Checked::Failed(detail) => {
                if failed_before {
                    self.notify_long(notice::EXTENSION_NOT_CHECKED, &detail);
                }
            }
        }
    }

    /// The checks every few minutes while the link runs (started and stopped with it).
    pub(super) fn start_extension_checks(&self) {
        let weak = self.weak();
        self.timers
            .extension_check
            .start(TimerMode::Repeated, CHECK_EVERY, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.check_extension_folder();
                }
            });
    }

    pub(super) fn stop_extension_checks(&self) {
        self.timers.extension_check.stop();
    }

    /// The answer to the connected extension's `status`: whether the vault is locked, its name
    /// while it is open, and the version of the extension in use, which an older extension
    /// reloads itself to take.
    pub(crate) fn browser_status(&self) -> Zeroizing<Vec<u8>> {
        let state = self.state.borrow();
        let response = Response::Status {
            locked: state.session.is_none(),
            name: state
                .session
                .as_ref()
                .map_or_else(String::new, |session| session.vault.settings().name.clone()),
            extension_version: Some(state.extension_version.clone()),
        };
        Zeroizing::new(
            serde_json::to_vec(&response)
                .unwrap_or_else(|_| br#"{"type":"error","code":"bad_request"}"#.to_vec()),
        )
    }

    /// The answer about a page's logins names the version in use too: the extension asks it
    /// at each sign-in field, so it notices a new version at its next request.
    pub(super) fn with_extension_version(
        &self,
        kind: &str,
        answer: Zeroizing<Vec<u8>>,
    ) -> Zeroizing<Vec<u8>> {
        if kind != "logins" {
            return answer;
        }
        // Names and usernames only (a list of logins, never a password).
        let Ok(serde_json::Value::Object(mut reply)) = serde_json::from_slice(&answer) else {
            return answer;
        };
        if reply.get("type").and_then(serde_json::Value::as_str) != Some("logins") {
            return answer;
        }
        let version = self.state.borrow().extension_version.clone();
        reply.insert("extension_version".into(), version.into());
        serde_json::to_vec(&reply).map_or(answer, Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_built_in_is_the_apps_version_and_what_the_release_ships() {
        assert_eq!(
            VERSION,
            env!("CARGO_PKG_VERSION"),
            "apps/extension/manifest.json and apps/desktop/Cargo.toml (release.yml refuses them unequal)"
        );
        let names: Vec<&str> = embedded::FILES.iter().map(|(name, _)| *name).collect();
        for name in [
            "manifest.json",
            "background.js",
            "update.js",
            "popup.html",
            "_locales/en/messages.json",
            "icons/icon128.png",
        ] {
            assert!(names.contains(&name), "{name} is built in");
        }
        for name in &names {
            assert!(
                !name.starts_with("test/") && *name != "package.json" && *name != "README.md",
                "{name} isn't shipped"
            );
        }
        let manifest = embedded::FILES
            .iter()
            .find(|(name, _)| *name == "manifest.json")
            .unwrap()
            .1;
        assert_eq!(
            extension_source::version_of(manifest).unwrap(),
            VERSION,
            "the version a browser reads"
        );
    }
}
