//! Sync through a folder (SYNC.md, M6.2): Settings → Sync, and the rounds that run at unlock,
//! a few seconds after each save, every few minutes and on demand.
//!
//! The folder is read and written on a worker thread (a cloud drive may fetch a file on
//! demand); the merge itself runs here, on the UI thread, where the vault is.

use std::{path::PathBuf, time::Duration};

use slint::{SharedString, TimerMode};
use vault_core::{storage, sync::DeviceId};
use vault_platform::{
    DeviceState, SyncPlace,
    sync::{self, FolderTarget, Target as _},
};

use super::{CURRENT, Controller, Runner, notice};

/// After a save, how long to wait for more saves before one round.
const AFTER_SAVE: Duration = Duration::from_secs(3);
/// While the vault is open, a round this often (copies from other devices arrive by
/// themselves through the folder's program).
const EVERY: Duration = Duration::from_secs(5 * 60);

/// What the Sync card shows (`sync-state` in the UI).
pub(super) mod state {
    pub const OFF: i32 = 0;
    pub const SYNCED: i32 = 1;
    pub const SYNCING: i32 = 2;
    /// The folder couldn't be read or written (`sync-detail` says why).
    pub const FAILED: i32 = 3;
    /// Edits made on two devices wait for the item lock (`sync-waiting` of them).
    pub const WAITING: i32 = 4;
}

/// Where this vault syncs, this device's id, and the vault's id.
struct Place {
    vault_id: String,
    device: DeviceId,
    place: SyncPlace,
}

/// The sync round in progress and its outcome so far, kept in the controller's state.
#[derive(Debug, Default)]
pub(super) struct SyncStatus {
    running: bool,
    /// Another round was asked for while one ran.
    again: bool,
    /// Items the last round left waiting for the item lock.
    waiting: usize,
}

impl Controller {
    /// The open vault's sync place on this device, if it syncs.
    fn sync_place(&self) -> Option<Place> {
        let vault_id = self.state.borrow().session.as_ref()?.vault.id_hex();
        let mut device_state = DeviceState::load().ok()?;
        let place = device_state.sync_place(&vault_id)?;
        let had_id = device_state.has_device_id();
        let device = device_state.device_id().ok()?;
        if !had_id {
            device_state.save().ok()?;
        }
        Some(Place {
            vault_id,
            device,
            place,
        })
    }

    /// Called once the vault is open: the vault writes as this device, and a first round
    /// runs; then one every few minutes.
    pub(super) fn start_sync(&self) {
        let Some(place) = self.sync_place() else {
            self.show_sync_settings();
            return;
        };
        if let Some(session) = self.state.borrow_mut().session.as_mut() {
            session.vault.set_device(place.device);
        }
        let weak = self.weak();
        self.timers
            .sync_every
            .start(TimerMode::Repeated, EVERY, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.sync_round();
                }
            });
        self.sync_round();
    }

    /// Stops the timers (the vault was locked).
    pub(super) fn stop_sync(&self) {
        self.timers.sync_every.stop();
        self.timers.sync_soon.stop();
    }

    /// A save happened: one round a moment later (several saves in a row make one round).
    pub(super) fn sync_after_save(&self) {
        if self.state.borrow().sync.running {
            self.state.borrow_mut().sync.again = true;
            return;
        }
        if self.state.borrow().runner == Runner::Inline || !self.timers.sync_every.running() {
            // Not syncing (the timer runs only while it is on), or a headless test.
            return;
        }
        let weak = self.weak();
        self.timers
            .sync_soon
            .start(TimerMode::SingleShot, AFTER_SAVE, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.sync_round();
                }
            });
    }

    /// The item lock was opened: edits that waited for it can be folded now.
    pub(super) fn sync_after_unlocking_items(&self) {
        if self.state.borrow().sync.waiting > 0 {
            self.sync_round();
        }
    }

    /// "Choose a folder…": the folder dialog, then syncing starts.
    pub(super) fn sync_choose(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
            self.sync_start(folder);
        }
    }

    /// Starts syncing the open vault through `folder`.
    pub(crate) fn sync_start(&self, folder: PathBuf) {
        let Some(vault_id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_sync_folder(&vault_id, Some(&folder));
        if let Err(err) = device_state.save() {
            self.notify_long(notice::DEVICE_STATE_NOT_SAVED, &err.to_string());
            return;
        }
        self.start_sync();
    }

    /// "Stop syncing": this computer stops; the copies in the folder are left.
    pub(super) fn sync_stop(&self) {
        self.stop_sync();
        let Some(vault_id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_sync_folder(&vault_id, None);
        let _ = device_state.save();
        self.state.borrow_mut().sync.waiting = 0;
        self.app().set_sync_state(state::OFF);
        self.show_sync_settings();
    }

    /// One round: read the other copies (worker thread), merge them here, save, publish.
    pub(crate) fn sync_round(&self) {
        if self.state.borrow().sync.running {
            self.state.borrow_mut().sync.again = true;
            return;
        }
        let Some(place) = self.sync_place() else {
            return;
        };
        let target = match FolderTarget::new(&place.place.folder, &place.vault_id) {
            Ok(target) => target,
            Err(err) => return self.sync_failed(&err.to_string()),
        };
        self.state.borrow_mut().sync.running = true;
        self.app().set_sync_state(state::SYNCING);
        let device = place.device;
        let fetch = move || sync::fetch(&target, device).map_err(|err| format!("{err:#}"));
        let runner = self.state.borrow().runner;
        if runner == Runner::Inline {
            let fetched = fetch();
            return self.sync_fetched(place, fetched);
        }
        std::thread::spawn(move || {
            let fetched = fetch();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.sync_fetched(place, fetched);
                }
            });
        });
    }

    fn sync_fetched(&self, mut place: Place, fetched: Result<sync::Fetched, String>) {
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(why) => return self.sync_failed(&why),
        };
        // Locked, or another vault opened, while the folder was read.
        let same_vault = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|s| s.vault.id_hex() == place.vault_id);
        if !same_vault {
            return self.sync_finished();
        }
        let (round, joined) = {
            let mut state = self.state.borrow_mut();
            let vault = &mut state.session.as_mut().expect("checked above").vault;
            let joined = sync::join(vault, place.device, &sync::device_name()).unwrap_or(false);
            (
                sync::merge_all(vault, &fetched, &mut place.place.seen),
                joined,
            )
        };
        if round.removed_here {
            let mut device_state = DeviceState::load().unwrap_or_default();
            device_state.set_sync_folder(&place.vault_id, None);
            let _ = device_state.save();
            self.stop_sync();
            self.notify_long(notice::SYNC_REMOVED, "");
            return self.sync_finished();
        }
        let changed = round.changed() || joined;
        if changed {
            self.state.borrow_mut().summaries_stale = true;
            if !self.save_vault() {
                return self.sync_failed("");
            }
            self.refresh_list();
            self.show_detail();
        }
        let revision = self
            .state
            .borrow()
            .session
            .as_ref()
            .map_or(0, |s| s.vault.revision());
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.record_sync(
            &place.vault_id,
            &place.place.seen,
            crate::view::now_unix(),
            0,
        );
        let _ = device_state.save();

        // What the person should know.
        let came: usize = round
            .reports
            .iter()
            .map(|r| r.added + r.updated + r.removed)
            .sum();
        self.state.borrow_mut().sync.waiting = round.waiting_for_lock();
        if round.unlock_changed() {
            self.notify_long(notice::SYNC_UNLOCK_CHANGED, "");
        } else if round.conflicts() > 0 {
            self.notify_long(notice::SYNC_CONFLICTS, &round.conflicts().to_string());
        } else if round.waiting_for_lock() > 0 {
            self.notify_long(notice::SYNC_WAITING, &round.waiting_for_lock().to_string());
        } else if let Some((_, err)) = round.refused.first() {
            self.notify_long(notice::SYNC_REFUSED, &err.to_string());
        } else if came > 0 {
            self.notify(notice::SYNC_CHANGED, &came.to_string());
        }

        if changed || revision > place.place.published {
            self.sync_publish(place, revision);
        } else {
            self.sync_finished();
        }
    }

    /// Puts this device's copy (the vault file as saved) in the folder.
    fn sync_publish(&self, place: Place, revision: u64) {
        let path = self.state.borrow().path.clone();
        let target = match FolderTarget::new(&place.place.folder, &place.vault_id) {
            Ok(target) => target,
            Err(err) => return self.sync_failed(&err.to_string()),
        };
        let device = place.device;
        let put = move || {
            let bytes = storage::read(&path).map_err(|err| err.to_string())?;
            target.put(device, &bytes).map_err(|err| format!("{err:#}"))
        };
        let vault_id = place.vault_id;
        let done = move |controller: &Controller, result: Result<(), String>| match result {
            Ok(()) => {
                let mut device_state = DeviceState::load().unwrap_or_default();
                if let Some(place) = device_state.sync_place(&vault_id) {
                    device_state.record_sync(&vault_id, &place.seen, place.at, revision);
                    let _ = device_state.save();
                }
                controller.sync_finished();
            }
            Err(why) => controller.sync_failed(&why),
        };
        if self.state.borrow().runner == Runner::Inline {
            let result = put();
            return done(self, result);
        }
        std::thread::spawn(move || {
            let result = put();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    done(&controller, result);
                }
            });
        });
    }

    fn sync_failed(&self, why: &str) {
        let app = self.app();
        app.set_sync_detail(SharedString::from(why));
        self.state.borrow_mut().sync.running = false;
        self.show_sync_settings();
        app.set_sync_state(state::FAILED);
    }

    fn sync_finished(&self) {
        self.state.borrow_mut().sync.running = false;
        self.app().set_sync_detail(SharedString::new());
        self.show_sync_settings();
        let again = std::mem::take(&mut self.state.borrow_mut().sync.again);
        if again {
            self.sync_round();
        }
    }

    /// The Sync card: the folder, when it last synced, the devices.
    pub(super) fn show_sync_settings(&self) {
        let app = self.app();
        let (vault_id, devices, own) = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            let own = session.vault.device();
            let devices: Vec<(DeviceId, String)> = session
                .vault
                .sync_devices()
                .iter()
                .map(|d| (d.id, d.name.clone()))
                .collect();
            (session.vault.id_hex(), devices, own)
        };
        let place = DeviceState::load()
            .ok()
            .and_then(|s| s.sync_place(&vault_id));
        let Some(place) = place else {
            app.set_sync_folder(SharedString::new());
            app.set_sync_state(state::OFF);
            app.set_sync_devices(SharedString::new());
            app.set_sync_this_device(SharedString::new());
            return;
        };
        app.set_sync_folder(SharedString::from(place.folder.display().to_string()));
        let minutes = if place.at > 0 {
            i32::try_from((crate::view::now_unix() - place.at).max(0) / 60).unwrap_or(i32::MAX)
        } else {
            -1
        };
        app.set_sync_minutes(minutes);
        let this = devices
            .iter()
            .find(|(id, _)| *id == own)
            .map_or_else(sync::device_name, |(_, name)| name.clone());
        let others: Vec<String> = devices
            .into_iter()
            .filter(|(id, _)| *id != own)
            .map(|(_, name)| name)
            .collect();
        app.set_sync_this_device(SharedString::from(this));
        app.set_sync_devices(SharedString::from(others.join(", ")));
        let running = self.state.borrow().sync.running;
        let waiting = self.state.borrow().sync.waiting;
        app.set_sync_waiting(i32::try_from(waiting).unwrap_or(i32::MAX));
        if !running && app.get_sync_state() != state::FAILED {
            app.set_sync_state(if waiting > 0 {
                state::WAITING
            } else {
                state::SYNCED
            });
        }
    }
}
