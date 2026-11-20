//! Sync (SYNC.md): Settings → Sync, and the rounds that run at unlock, a few seconds after each
//! save, every few minutes, when the server says another device published, and on demand.
//!
//! Targets: a folder (another program carries the files), our own server (signed requests,
//! long-poll) or WebDAV. Every read and write of the target runs on a worker thread; the
//! merge itself runs here, on the UI thread, where the vault is.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use slint::{ModelRc, SharedPixelBuffer, SharedString, TimerMode, VecModel};
use vault_core::{storage, sync::DeviceId};
use vault_platform::{
    DeviceState, SyncPlace, SyncTo, secret_store,
    sync::{self, ServerTarget, Tags, Target},
};
use vault_sync_wire::{DeviceKey, InviteLink};
use zeroize::Zeroizing;

use super::{CURRENT, Controller, Runner, field, notice};

/// After a save, how long to wait for more saves before one round.
const AFTER_SAVE: Duration = Duration::from_secs(3);
/// While the vault is open, a round this often, besides the ones a server's news or a change
/// in the folder start at once.
const EVERY: Duration = Duration::from_secs(5 * 60);
/// How long one long-poll waits on the server.
const WAIT_SECONDS: u64 = 50;

/// What the Sync card shows (`sync-state` in the UI).
pub(super) mod state {
    pub const OFF: i32 = 0;
    pub const SYNCED: i32 = 1;
    pub const SYNCING: i32 = 2;
    /// The target couldn't be read or written (`sync-detail` says why).
    pub const FAILED: i32 = 3;
    /// Edits made on two devices wait for the item lock (`sync-waiting` of them).
    pub const WAITING: i32 = 4;
}

/// Which kind of place (`sync-kind` in the UI).
mod kind {
    pub const OFF: i32 = 0;
    pub const FOLDER: i32 = 1;
    pub const SERVER: i32 = 2;
    pub const WEBDAV: i32 = 3;
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
    /// Tags of the copies already merged in this session: unchanged ones aren't read again.
    tags: Tags,
    /// Set to stop the thread that waits for the server's news.
    watch: Option<Arc<AtomicBool>>,
    /// The other devices, in the order the card lists them (for "Remove").
    others: Vec<(DeviceId, String)>,
    /// Joining a server or checking WebDAV is under way.
    busy: bool,
}

/// Runs `job` off the UI thread (inline in the headless tests) and hands its result back.
fn off_thread<T: Send + 'static>(
    runner: Runner,
    job: impl FnOnce() -> T + Send + 'static,
    done: impl FnOnce(&Controller, T) + Send + 'static,
) {
    if runner == Runner::Inline {
        let result = job();
        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
            done(&controller, result);
        }
        return;
    }
    std::thread::spawn(move || {
        let result = job();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                done(&controller, result);
            }
        });
    });
}

impl Controller {
    fn open_vault_id(&self) -> Option<String> {
        self.state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
    }

    /// This device's sync id, made the first time it is needed.
    fn sync_device_id(&self) -> Option<DeviceId> {
        let mut device_state = DeviceState::load().ok()?;
        let had_id = device_state.has_device_id();
        let device = device_state.device_id().ok()?;
        if !had_id {
            device_state.save().ok()?;
        }
        Some(device)
    }

    /// The open vault's sync place on this device, if it syncs.
    fn sync_place(&self) -> Option<Place> {
        let vault_id = self.open_vault_id()?;
        let place = DeviceState::load().ok()?.sync_place(&vault_id)?;
        let device = self.sync_device_id()?;
        Some(Place {
            vault_id,
            device,
            place,
        })
    }

    /// Called once the vault is open: the vault writes as this device, and a first round
    /// runs; then one every few minutes, and whenever the server has news.
    pub(super) fn start_sync(&self) {
        self.stop_watch();
        self.state.borrow_mut().sync.tags.clear();
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
        self.start_watch(&place);
        self.sync_round();
    }

    /// Stops the timers and the server watch (the vault was locked).
    pub(super) fn stop_sync(&self) {
        self.timers.sync_every.stop();
        self.timers.sync_soon.stop();
        self.stop_watch();
        let app = self.app();
        app.set_sync_invite(SharedString::new());
        app.set_sync_invite_qr(slint::Image::default());
        self.state.borrow_mut().sync.tags.clear();
    }

    fn stop_watch(&self) {
        if let Some(stop) = self.state.borrow_mut().sync.watch.take() {
            stop.store(true, Ordering::Relaxed);
        }
    }

    /// A thread that asks for a round as soon as another device published: with a server it
    /// waits for the server's news (a long-poll), with a folder it watches the folder. Not in
    /// the headless tests; WebDAV has only the regular rounds.
    fn start_watch(&self, place: &Place) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let ask_for_round = || {
            let _ = slint::invoke_from_event_loop(|| {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.sync_round();
                }
            });
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (vault_id, device, to) = (place.vault_id.clone(), place.device, place.place.to.clone());
        match &to {
            SyncTo::Server { .. } => {}
            SyncTo::Folder { path } => {
                self.state.borrow_mut().sync.watch = Some(stop.clone());
                let path = path.clone();
                std::thread::spawn(move || {
                    sync::watch_folder(&path, &vault_id, device, &stop, ask_for_round);
                });
                return;
            }
            SyncTo::Webdav { .. } => return,
        }
        self.state.borrow_mut().sync.watch = Some(stop.clone());
        std::thread::spawn(move || {
            let Ok(target) = sync::open_target(&vault_id, device, &to) else {
                return;
            };
            let mut after = 0;
            let mut pause = Duration::from_secs(5);
            while !stop.load(Ordering::Relaxed) {
                match target.wait(after, WAIT_SECONDS) {
                    Some(Ok(seq)) => {
                        pause = Duration::from_secs(5);
                        if after != 0 && seq != after && !stop.load(Ordering::Relaxed) {
                            ask_for_round();
                        }
                        after = seq;
                    }
                    Some(Err(_)) => {
                        // Offline or the server is down: look again later, a bit later each
                        // time (the 5-minute rounds still run).
                        let until = std::time::Instant::now() + pause;
                        while std::time::Instant::now() < until && !stop.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        pause = (pause * 2).min(Duration::from_secs(300));
                    }
                    None => return,
                }
            }
        });
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
            self.state.borrow_mut().sync.tags.clear();
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
    pub(crate) fn sync_start(&self, folder: std::path::PathBuf) {
        self.sync_use(SyncTo::Folder { path: folder });
    }

    /// Starts syncing the open vault through `to`.
    fn sync_use(&self, to: SyncTo) {
        let Some(vault_id) = self.open_vault_id() else {
            return;
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_sync_to(&vault_id, Some(to));
        if let Err(err) = device_state.save() {
            self.notify_long(notice::DEVICE_STATE_NOT_SAVED, &err.to_string());
            return;
        }
        let app = self.app();
        app.set_sync_form(0);
        app.set_sync_setup_error(SharedString::new());
        self.start_sync();
    }

    /// "Join": enrolls this computer on the server with the invite typed (or the whole
    /// `vaultsync:` line pasted), keeps its new key in the credential store, starts syncing.
    pub(super) fn sync_join_server(&self) {
        let app = self.app();
        let (Some(vault_id), Some(device)) = (self.open_vault_id(), self.sync_device_id()) else {
            return;
        };
        let typed = app.get_sync_invite_typed().trim().to_owned();
        let (address, invite) = match InviteLink::parse(&typed) {
            Some(link) if link.vault != vault_id => {
                return self.sync_setup_failed("that invite is for another vault");
            }
            Some(link) => (link.server, link.invite),
            None => (app.get_sync_address().trim().to_owned(), typed),
        };
        let address = match sync::check_address(&address) {
            Ok(address) => address,
            Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
        };
        app.set_sync_address(SharedString::from(address.as_str()));
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = {
            let (vault_id, address) = (vault_id.clone(), address.clone());
            move || -> Result<(), String> {
                let server =
                    ServerTarget::join(&address, &vault_id, device, &sync::device_name(), &invite)
                        .map_err(|err| format!("{err:#}"))?;
                secret_store::store_sync_key(&vault_id, &device.to_hex(), &server.key_seed())
                    .map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| {
            controller.sync_busy(false);
            match result {
                Ok(()) => {
                    let app = controller.app();
                    app.set_sync_invite_typed(SharedString::new());
                    controller.sync_use(SyncTo::Server { url: address });
                    controller.notify(notice::SYNC_JOINED, "");
                }
                Err(why) => controller.sync_setup_failed(&why),
            }
        });
    }

    /// "Connect": checks the WebDAV folder answers with these credentials, keeps the
    /// password in the credential store, starts syncing.
    pub(super) fn sync_use_webdav(&self) {
        let app = self.app();
        let Some(vault_id) = self.open_vault_id() else {
            return;
        };
        let address = match sync::check_address(&app.get_sync_address()) {
            Ok(address) => address,
            Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
        };
        let user = app.get_sync_user().trim().to_owned();
        if user.is_empty() {
            return self.sync_setup_failed("type the WebDAV user name");
        }
        let password = Zeroizing::new(
            self.state.borrow().secrets[field::SYNC_PASSWORD]
                .as_str()
                .to_owned(),
        );
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = {
            let (address, user) = (address.clone(), user.clone());
            move || -> Result<(), String> {
                let target = sync::WebDavTarget::new(&address, &vault_id, &user, &password)
                    .map_err(|err| format!("{err:#}"))?;
                target.list().map_err(|err| format!("{err:#}"))?;
                secret_store::store_webdav_password(&vault_id, &password)
                    .map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| {
            controller.sync_busy(false);
            match result {
                Ok(()) => {
                    controller.clear_secret(field::SYNC_PASSWORD);
                    controller.sync_use(SyncTo::Webdav { url: address, user });
                }
                Err(why) => controller.sync_setup_failed(&why),
            }
        });
    }

    fn sync_busy(&self, busy: bool) {
        self.state.borrow_mut().sync.busy = busy;
        let app = self.app();
        app.set_sync_busy(busy);
        if busy {
            app.set_sync_setup_error(SharedString::new());
        }
    }

    fn sync_setup_failed(&self, why: &str) {
        self.app().set_sync_setup_error(SharedString::from(why));
    }

    /// "Stop syncing": this computer stops; the copies there are left. The server key or the
    /// WebDAV password is forgotten here.
    pub(super) fn sync_stop(&self) {
        self.stop_sync();
        let Some(vault_id) = self.open_vault_id() else {
            return;
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_sync_to(&vault_id, None);
        let _ = device_state.save();
        if let Some(device) = self.sync_device_id() {
            let _ = secret_store::forget_sync_key(&vault_id, &device.to_hex());
        }
        let _ = secret_store::forget_webdav_password(&vault_id);
        self.state.borrow_mut().sync.waiting = 0;
        self.app().set_sync_state(state::OFF);
        self.show_sync_settings();
    }

    /// "Add a device": a one-time invite from the server, shown as a QR code and as text.
    pub(super) fn sync_add_device(&self) {
        let Some(place) = self.sync_place() else {
            return;
        };
        let SyncTo::Server { url } = place.place.to.clone() else {
            return;
        };
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = move || -> Result<(Zeroizing<String>, i64), String> {
            let seed = secret_store::load_sync_key(&place.vault_id, &place.device.to_hex())
                .map_err(|err| format!("{err:#}"))?
                .ok_or("this computer has no key for the server: stop syncing and join again")?;
            let server = ServerTarget::new(
                &url,
                &place.vault_id,
                place.device,
                DeviceKey::from_seed(&seed),
            )
            .map_err(|err| format!("{err:#}"))?;
            let invite = server.invite().map_err(|err| format!("{err:#}"))?;
            Ok((server.invite_link(&invite).to_text(), invite.expires_at))
        };
        off_thread(runner, job, |controller, result| {
            controller.sync_busy(false);
            match result {
                Ok((text, _expires_at)) => {
                    let app = controller.app();
                    app.set_sync_invite_qr(qr_image(&text));
                    app.set_sync_invite(SharedString::from(text.as_str()));
                }
                Err(why) => controller.sync_setup_failed(&why),
            }
        });
    }

    /// Hides the invite (it stays good until used or for an hour).
    pub(super) fn sync_hide_invite(&self) {
        let app = self.app();
        app.set_sync_invite(SharedString::new());
        app.set_sync_invite_qr(slint::Image::default());
    }

    /// "Remove" on another device: it leaves the vault's device list (so every device
    /// refuses its copies from then on) and its copy and key leave the target.
    pub(super) fn sync_remove_device(&self, index: i32) {
        let Some((id, name)) = usize::try_from(index)
            .ok()
            .and_then(|i| self.state.borrow().sync.others.get(i).cloned())
        else {
            return;
        };
        let removed = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.remove_sync_device(&id));
        if !matches!(removed, Some(Ok(()))) {
            return;
        }
        self.app().set_sync_removing(-1);
        if !self.save_vault() {
            return;
        }
        self.notify_long(notice::SYNC_DEVICE_REMOVED, &name);
        if let Some(place) = self.sync_place() {
            let runner = self.state.borrow().runner;
            let job = move || {
                sync::open_target(&place.vault_id, place.device, &place.place.to)
                    .and_then(|target| target.remove(id))
                    .map_err(|err| format!("{err:#}"))
            };
            // The copy left behind is refused anyway; nothing to tell if it couldn't go.
            off_thread(runner, job, |_, _| {});
        }
        self.show_sync_settings();
        self.sync_round();
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
        self.state.borrow_mut().sync.running = true;
        self.app().set_sync_state(state::SYNCING);
        let (vault_id, device, to) = (place.vault_id.clone(), place.device, place.place.to.clone());
        let known = self.state.borrow().sync.tags.clone();
        let runner = self.state.borrow().runner;
        let job = move || {
            sync::open_target(&vault_id, device, &to)
                .and_then(|target| sync::fetch(&*target, device, &known))
                .map_err(|err| format!("{err:#}"))
        };
        off_thread(runner, job, move |controller, fetched| {
            controller.sync_fetched(place, fetched);
        });
    }

    fn sync_fetched(&self, mut place: Place, fetched: Result<sync::Fetched, String>) {
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(why) => return self.sync_failed(&why),
        };
        // Locked, or another vault opened, while the copies were read.
        let same_vault = self.open_vault_id().as_deref() == Some(place.vault_id.as_str());
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
            device_state.set_sync_to(&place.vault_id, None);
            let _ = device_state.save();
            self.stop_sync();
            self.notify_long(notice::SYNC_REMOVED, "");
            return self.sync_finished();
        }
        // Copies whose edits wait for the item lock are read again once it opens.
        {
            let mut state = self.state.borrow_mut();
            if round.waiting_for_lock() == 0 {
                state.sync.tags = fetched.tags.clone();
            } else {
                state.sync.tags.clear();
            }
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

    /// Puts this device's copy (the vault file as saved) on the target.
    fn sync_publish(&self, place: Place, revision: u64) {
        let path = self.state.borrow().path.clone();
        let (vault_id, device, to) = (place.vault_id.clone(), place.device, place.place.to);
        let runner = self.state.borrow().runner;
        let job = {
            let vault_id = vault_id.clone();
            move || -> Result<(), String> {
                let bytes = storage::read(&path).map_err(|err| err.to_string())?;
                let target =
                    sync::open_target(&vault_id, device, &to).map_err(|err| format!("{err:#}"))?;
                target.put(device, &bytes).map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| match result {
            Ok(()) => {
                let mut device_state = DeviceState::load().unwrap_or_default();
                if let Some(place) = device_state.sync_place(&vault_id) {
                    device_state.record_sync(&vault_id, &place.seen, place.at, revision);
                    let _ = device_state.save();
                }
                controller.sync_finished();
            }
            Err(why) => controller.sync_failed(&why),
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

    /// The Sync card: the place, when it last synced, the devices.
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
            app.set_sync_kind(kind::OFF);
            app.set_sync_folder(SharedString::new());
            app.set_sync_state(state::OFF);
            app.set_sync_devices(SharedString::new());
            app.set_sync_others(ModelRc::default());
            app.set_sync_this_device(SharedString::new());
            self.state.borrow_mut().sync.others.clear();
            return;
        };
        app.set_sync_kind(match &place.to {
            SyncTo::Folder { .. } => kind::FOLDER,
            SyncTo::Server { .. } => kind::SERVER,
            SyncTo::Webdav { .. } => kind::WEBDAV,
        });
        app.set_sync_folder(SharedString::from(place.to.describe()));
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
        let others: Vec<(DeviceId, String)> =
            devices.into_iter().filter(|(id, _)| *id != own).collect();
        app.set_sync_this_device(SharedString::from(this));
        app.set_sync_devices(SharedString::from(
            others
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ));
        app.set_sync_others(ModelRc::new(VecModel::from(
            others
                .iter()
                .map(|(_, name)| SharedString::from(name.as_str()))
                .collect::<Vec<_>>(),
        )));
        let running = {
            let mut state = self.state.borrow_mut();
            state.sync.others = others;
            state.sync.running
        };
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

/// A QR code of `text`, black on white with a quiet zone, a few pixels per module.
fn qr_image(text: &str) -> slint::Image {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M) else {
        return slint::Image::default();
    };
    let modules = code.width();
    let colors = code.to_colors();
    let (quiet, scale) = (4, 6);
    let side = (modules + 2 * quiet) * scale;
    let mut buffer = SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    let pixels = buffer.make_mut_slice();
    for (i, pixel) in pixels.iter_mut().enumerate() {
        let (x, y) = (i % side / scale, i / side / scale);
        let dark = x >= quiet
            && y >= quiet
            && x - quiet < modules
            && y - quiet < modules
            && colors[(y - quiet) * modules + (x - quiet)] == qrcode::Color::Dark;
        let value = if dark { 0 } else { 255 };
        *pixel = slint::Rgb8Pixel {
            r: value,
            g: value,
            b: value,
        };
    }
    slint::Image::from_rgb8(buffer)
}
