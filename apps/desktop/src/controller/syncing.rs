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
    sync::{self, KnownTags, Role, ServerTarget, Target},
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
/// While one of the places doesn't answer, a round this often, so it catches up as soon as
/// it is back.
const RETRY: Duration = Duration::from_secs(60);

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
    /// The ids this computer synced the vault as before (out of its device list).
    retired: Vec<DeviceId>,
}

/// The sync round in progress and its outcome so far, kept in the controller's state.
#[derive(Debug, Default)]
pub(super) struct SyncStatus {
    running: bool,
    /// Another round was asked for while one ran.
    again: bool,
    /// Items the last round left waiting for the item lock.
    waiting: usize,
    /// Tags of the copies already merged in this session, per place: unchanged ones aren't
    /// read again.
    tags: KnownTags,
    /// Why the main place, or the backup place, didn't answer in the last round (`None`: it
    /// did), to say so once when it goes down and once when it is back.
    main_down: Option<String>,
    backup_down: Option<String>,
    /// Set to stop the thread that waits for the server's news.
    watch: Option<Arc<AtomicBool>>,
    /// The other devices, in the order the card lists them (for "Remove").
    others: Vec<(DeviceId, String)>,
    /// The devices with a copy where the vault syncs now (main or backup place), as the last
    /// round found them; `None` before the first round.
    here: Option<Vec<DeviceId>>,
    /// Joining a server or checking WebDAV is under way.
    busy: bool,
    /// The person was told that a newer item lock from another device waits here.
    lock_told: bool,
    /// Copies sealed under a vault key renewed on another device (SYNC.md §4.7), kept until
    /// this computer takes the new key (Settings → Sync asks for its Secret Key).
    renewed: Vec<(DeviceId, Vec<u8>)>,
    /// The person was told about them.
    renewed_told: bool,
    /// Devices whose copies are still sealed under a key this computer renewed or took.
    behind: Vec<DeviceId>,
}

impl SyncStatus {
    /// The copies sealed under a vault key renewed on another device.
    pub(super) fn renewed_copies(&self) -> &[(DeviceId, Vec<u8>)] {
        &self.renewed
    }

    /// The vault key changed here: what was refused for it is read again.
    pub(super) fn key_changed(&mut self) {
        self.renewed.clear();
        self.renewed_told = false;
        self.behind.clear();
        self.tags = KnownTags::default();
    }

    /// Folds in what a round found about other vault keys: a renewed copy replaces the one of
    /// the same device kept before, and a device whose copy merged is no longer behind.
    fn note_key_mismatch(&mut self, mismatch: sync::KeyMismatch, merged: &[DeviceId]) {
        self.behind.retain(|device| !merged.contains(device));
        for device in mismatch.behind {
            if !self.behind.contains(&device) {
                self.behind.push(device);
            }
        }
        self.renewed.retain(|(device, _)| !merged.contains(device));
        for (device, bytes) in mismatch.renewed {
            self.renewed.retain(|(kept, _)| *kept != device);
            self.renewed.push((device, bytes));
        }
    }
}

/// Items, or whole copies, that wait for the item lock: the items a merge left as they were
/// here, and each copy refused until this copy's own lock is open (it brings a newer item
/// lock). Either is read again once the lock opens.
fn waiting_for_lock(round: &sync::Round) -> usize {
    let refused = round
        .refused
        .iter()
        .filter(|(_, err)| matches!(err, vault_core::Error::SecretsLocked))
        .count();
    round.waiting_for_lock() + refused
}

/// Runs `job` off the UI thread (inline in the headless tests) and hands its result back.
pub(super) fn off_thread<T: Send + 'static>(
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

    /// This device's sync id for the open vault, made the first time it is needed.
    fn sync_device_id(&self) -> Option<DeviceId> {
        let vault_id = self.open_vault_id()?;
        let mut device_state = DeviceState::load().ok()?;
        let had_id = device_state.has_device_id();
        let device = device_state.device_id_for(&vault_id).ok()?;
        if !had_id {
            device_state.save().ok()?;
        }
        Some(device)
    }

    /// The open vault's sync place on this device, if it syncs.
    fn sync_place(&self) -> Option<Place> {
        let vault_id = self.open_vault_id()?;
        let device_state = DeviceState::load().ok()?;
        let place = device_state.sync_place(&vault_id)?;
        let retired = device_state.retired_ids(&vault_id);
        let device = self.sync_device_id()?;
        Some(Place {
            vault_id,
            device,
            place,
            retired,
        })
    }

    /// Called once the vault is open: the vault writes as this device, and a first round
    /// runs; then one every few minutes, and whenever the server has news.
    pub(super) fn start_sync(&self) {
        self.stop_watch();
        self.state.borrow_mut().sync.tags = KnownTags::default();
        self.state.borrow_mut().sync.here = None;
        self.state.borrow_mut().sync.lock_told = false;
        self.state.borrow_mut().sync.key_changed();
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
        self.timers.sync_retry.stop();
        self.timers.sync_soon.stop();
        self.stop_watch();
        let app = self.app();
        app.set_sync_invite(SharedString::new());
        app.set_sync_invite_qr(slint::Image::default());
        self.state.borrow_mut().sync.tags = KnownTags::default();
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

    /// The item lock was opened: edits that waited for it can be folded now, and a newer
    /// item lock from another device can take over once both locks are open.
    pub(super) fn sync_after_unlocking_items(&self) {
        let lock_waits = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|s| s.vault.guard_waiting());
        if self.state.borrow().sync.waiting > 0 || lock_waits {
            self.state.borrow_mut().sync.tags = KnownTags::default();
            self.sync_round();
        }
    }

    /// Both item locks are open (this copy's own and the newer one from another device): the
    /// copy that brought the newer one is read again, and the locked items move to it.
    pub(super) fn sync_for_the_newer_lock(&self) {
        self.state.borrow_mut().sync.tags = KnownTags::default();
        self.sync_round();
    }

    /// A merge took the item lock of another device. Whatever this copy's lock had opened
    /// belongs to the lock it replaced: the open period, the relock timer, a secret copied
    /// from a locked item, an item open in the editor (whose secrets were read under the old
    /// key, and must never be saved back over the new ones). All of it closes; the new lock
    /// is asked for next.
    fn after_guard_changed(&self) {
        let guarded_in_editor = {
            let state = self.state.borrow();
            match (state.editing, state.session.as_ref()) {
                (Some(Some(id)), Some(session)) => session
                    .vault
                    .get_item(&id)
                    .ok()
                    .is_none_or(|item| item.is_locked() || session.vault.guards(&item)),
                _ => false,
            }
        };
        if guarded_in_editor {
            self.close_editor();
        }
        self.timers.clipboard.stop();
        let copied = self.state.borrow_mut().copied.take();
        if let Some(value) = copied {
            vault_platform::clipboard::clear_if(&value);
        }
        self.lock_secrets();
        self.sync_guard_state();
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
        let Some(vault_id) = self.open_vault_id() else {
            return;
        };
        // The id it joins as: the one it has when it is enrolled there already, else a new
        // one, so that a computer removed from the vault (or coming from another place) joins
        // as a new device (`sync::join_server`).
        let ids = DeviceState::load().ok().and_then(|mut device_state| {
            let ids = (
                device_state.device_id_for(&vault_id).ok()?,
                device_state.joining_id_for(&vault_id).ok()?,
            );
            device_state.save().ok()?;
            Some(ids)
        });
        let Some((current, fresh)) = ids else {
            return self.sync_setup_failed("this computer's state can't be written");
        };
        // The whole vaultsync: line (pasted in either field), or the address, its pin and the
        // invite typed apart.
        let typed = app.get_sync_invite_typed().trim().to_owned();
        let in_address = app.get_sync_address().trim().to_owned();
        let link = InviteLink::parse(&typed).or_else(|| InviteLink::parse(&in_address));
        let (address, invite) = match link {
            Some(link) if !link.fits(&vault_id) => {
                return self.sync_setup_failed("that invite is for another vault");
            }
            Some(link) => (link.server, link.invite),
            None => match sync::with_pin(&in_address, &app.get_sync_pin()) {
                Ok(address) => (address, typed),
                Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
            },
        };
        let address = match sync::check_address(&address) {
            Ok(address) => address,
            Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
        };
        // Shown without its pin: that has a field of its own.
        let (shown, pin) = sync::split_pin(&address);
        app.set_sync_address(SharedString::from(shown));
        if let Some(pin) = pin {
            app.set_sync_pin(SharedString::from(sync::pin_text(&pin).as_str()));
        }
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = {
            let (vault_id, address) = (vault_id.clone(), address.clone());
            move || -> Result<DeviceId, String> {
                sync::join_server(
                    &address,
                    &vault_id,
                    &[current],
                    fresh,
                    &sync::device_name(),
                    &invite,
                    Role::Main,
                )
                .map(|(_, device)| device)
                .map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| {
            controller.sync_busy(false);
            match result {
                Ok(device) => {
                    let app = controller.app();
                    app.set_sync_invite_typed(SharedString::new());
                    let mut device_state = DeviceState::load().unwrap_or_default();
                    match device_state.adopt_device_id(&vault_id, device) {
                        Ok(Some(before)) => {
                            // Its old keys belong to the place it synced through before.
                            if device_state.save().is_ok() {
                                sync::forget_keys(&vault_id, before);
                            }
                        }
                        Ok(None) => {
                            let _ = device_state.save();
                        }
                        Err(err) => return controller.sync_setup_failed(&err.to_string()),
                    }
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
        let address = match sync::check_webdav_address(&app.get_sync_address()) {
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
            sync::forget_keys(&vault_id, device);
        }
        let _ = secret_store::forget_webdav_password(&vault_id);
        {
            let mut state = self.state.borrow_mut();
            state.sync.waiting = 0;
            state.sync.main_down = None;
            state.sync.backup_down = None;
        }
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
        let backup = match place.place.backup.clone() {
            Some(SyncTo::Server { url }) => Some(url),
            _ => None,
        };
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = move || -> Result<(Zeroizing<String>, i64), String> {
            let server_for = |url: &str, role: Role| -> Result<ServerTarget, String> {
                let seed = secret_store::load_sync_key(
                    &place.vault_id,
                    &sync::sync_key_name(place.device, role),
                )
                .map_err(|err| format!("{err:#}"))?
                .ok_or("this computer has no key for the server: stop syncing and join again")?;
                ServerTarget::new(
                    url,
                    &place.vault_id,
                    place.device,
                    DeviceKey::from_seed(&seed),
                )
                .map_err(|err| format!("{err:#}"))
            };
            let server = server_for(&url, Role::Main)?;
            let invite = server.invite().map_err(|err| format!("{err:#}"))?;
            let mut link = server.invite_link(&invite);
            // The backup server's invite rides along when it answers; without it the other
            // device joins the main server only, and can add the backup later.
            if let Some(backup) = &backup
                && let Ok(target) = server_for(backup, Role::Backup)
                && let Ok(backup_invite) = target.invite()
            {
                link.backup = Some((
                    target.invite_link(&backup_invite).server,
                    backup_invite.invite,
                ));
            }
            Ok((link.to_text(), invite.expires_at))
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
                let backup = place.place.backup.as_ref().map(|to| (to, Role::Backup));
                for (to, role) in std::iter::once((&place.place.to, Role::Main)).chain(backup) {
                    let _ = sync::open_target_as(&place.vault_id, place.device, to, role)
                        .and_then(|target| target.remove(id));
                }
            };
            // The copy left behind is refused anyway; nothing to tell if it couldn't go.
            off_thread(runner, job, |_, ()| {});
        }
        self.show_sync_settings();
        self.sync_round();
    }

    /// One round: read the other copies from every place (worker thread), merge them here,
    /// save, publish.
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
        let (vault_id, device, sync_place) =
            (place.vault_id.clone(), place.device, place.place.clone());
        let known = self.state.borrow().sync.tags.clone();
        let runner = self.state.borrow().runner;
        let job = move || sync::read_all(&vault_id, device, &sync_place, &known);
        off_thread(runner, job, move |controller, reading| {
            controller.sync_fetched(place, reading);
        });
    }

    fn sync_fetched(&self, mut place: Place, reading: sync::Reading) {
        self.sync_health(
            reading.main_down(),
            reading.backup_down(),
            place.place.backup.is_some(),
        );
        if !reading.reached() {
            return self.sync_failed(reading.main_down().unwrap_or_default());
        }
        // Locked, or another vault opened, while the copies were read.
        let same_vault = self.open_vault_id().as_deref() == Some(place.vault_id.as_str());
        if !same_vault {
            return self.sync_finished();
        }
        let (round, joined) = {
            let mut state = self.state.borrow_mut();
            let vault = &mut state.session.as_mut().expect("checked above").vault;
            let joined = sync::join(vault, place.device, &sync::device_name()).unwrap_or(false)
                | sync::retire(vault, &place.retired);
            (
                sync::merge_reading(vault, &reading, &mut place.place.seen),
                joined,
            )
        };
        if round.removed_here {
            // Removed, not barred: this computer takes a new id for the vault and can join
            // again (a new invite, or the folder chosen again) as a new device.
            let mut device_state = DeviceState::load().unwrap_or_default();
            if device_state.removed_from(&place.vault_id).is_err() {
                device_state.set_sync_to(&place.vault_id, None);
            }
            let _ = device_state.save();
            sync::forget_keys(&place.vault_id, place.device);
            let _ = secret_store::forget_webdav_password(&place.vault_id);
            self.stop_sync();
            self.notify_long(notice::SYNC_REMOVED, "");
            self.show_sync_settings();
            return self.sync_finished();
        }
        // Copies whose edits wait for the item lock are read again once it opens: those
        // merged in part, and those refused whole until it is open (a newer item lock that
        // takes this copy's own lock open first).
        let waiting = waiting_for_lock(&round);
        {
            let mut state = self.state.borrow_mut();
            let listed = reading.tags(&KnownTags::default());
            state.sync.here = Some(
                listed
                    .main
                    .keys()
                    .chain(listed.backup.keys())
                    .copied()
                    .collect(),
            );
            if waiting == 0 {
                state.sync.tags = reading.tags(&state.sync.tags);
            } else {
                state.sync.tags = KnownTags::default();
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
        let guard_changed = round.reports.iter().any(|report| report.guard_changed);
        if guard_changed {
            self.after_guard_changed();
        }
        let lock_waits = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|s| s.vault.guard_waiting());
        self.sync_guard_state();
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
        // Copies under another vault key: renewed on their device (its new Secret Key is
        // asked once), or still under a key this computer renewed or took.
        let mismatch = sync::key_mismatch(&place.vault_id, &reading, &round, &device_state);
        let merged: Vec<DeviceId> = round.reports.iter().map(|report| report.writer).collect();
        let tell_renewed = {
            let mut state = self.state.borrow_mut();
            state.sync.note_key_mismatch(mismatch, &merged);
            let renewed = !state.sync.renewed.is_empty();
            let told = std::mem::replace(&mut state.sync.renewed_told, renewed);
            renewed && !told
        };

        // What the person should know.
        let came: usize = round
            .reports
            .iter()
            .map(|r| r.added + r.updated + r.removed)
            .sum();
        // A newer item lock waiting is said once (the item lock's prompt and Settings show it
        // for as long as it waits), not at every round.
        let tell_lock = {
            let mut state = self.state.borrow_mut();
            state.sync.waiting = waiting;
            let told = std::mem::replace(&mut state.sync.lock_told, lock_waits);
            lock_waits && !told
        };
        // Copies that wait for the item lock, or that are under another vault key, are said
        // apart.
        let refused = round.refused.iter().find(|(_, err)| {
            !matches!(
                err,
                vault_core::Error::SecretsLocked | vault_core::Error::DecryptionFailed
            )
        });
        // A copy of another format version: said plainly, with what to update.
        let other_format = round.refused.iter().find_map(|(device, err)| match err {
            vault_core::Error::UnsupportedVersion(version) => Some((*device, *version)),
            _ => None,
        });
        if tell_renewed {
            self.notify_long(notice::SYNC_KEY_RENEWED, "");
            self.show_sync_settings();
        } else if let Some((device, version)) = other_format {
            let name = self
                .state
                .borrow()
                .session
                .as_ref()
                .and_then(|s| {
                    s.vault
                        .sync_devices()
                        .iter()
                        .find(|d| d.id == device)
                        .map(|d| d.name.clone())
                })
                .unwrap_or_default();
            self.notify_long(
                if version > vault_core::FORMAT_VERSION {
                    notice::SYNC_NEWER_FORMAT
                } else {
                    notice::SYNC_OLDER_FORMAT
                },
                &name,
            );
        } else if round.unlock_changed() {
            self.notify_long(notice::SYNC_UNLOCK_CHANGED, "");
        } else if guard_changed {
            self.notify_long(notice::GUARD_MOVED, "");
        } else if tell_lock {
            self.notify_long(notice::SYNC_LOCK_WAITING, "");
        } else if round.conflicts() > 0 {
            self.notify_long(notice::SYNC_CONFLICTS, &round.conflicts().to_string());
        } else if lock_waits {
            // Said already; what waits behind it is the same thing.
        } else if round.waiting_for_lock() > 0 {
            self.notify_long(notice::SYNC_WAITING, &round.waiting_for_lock().to_string());
        } else if let Some((_, err)) = refused {
            self.notify_long(notice::SYNC_REFUSED, &err.to_string());
        } else if came > 0 {
            self.notify(notice::SYNC_CHANGED, &came.to_string());
        }

        let roles = sync::to_publish(&place.place, &reading, revision, changed);
        if roles.is_empty() {
            self.sync_finished();
        } else {
            self.sync_publish(place, revision, roles);
        }
    }

    /// Puts this device's copy (the vault file as saved) on the places in `roles`.
    fn sync_publish(&self, place: Place, revision: u64, roles: Vec<Role>) {
        let path = self.state.borrow().path.clone();
        let (vault_id, device, sync_place) = (place.vault_id.clone(), place.device, place.place);
        let runner = self.state.borrow().runner;
        let job = {
            let vault_id = vault_id.clone();
            move || -> Result<sync::Published, String> {
                let bytes = storage::read(&path).map_err(|err| err.to_string())?;
                Ok(sync::publish_all(
                    &vault_id,
                    device,
                    &sync_place,
                    &bytes,
                    &roles,
                ))
            }
        };
        off_thread(runner, job, move |controller, result| {
            let results = match result {
                Ok(results) => results,
                Err(why) => return controller.sync_failed(&why),
            };
            let mut device_state = DeviceState::load().unwrap_or_default();
            let mut failed = None;
            for (role, put) in &results {
                match put {
                    Ok(()) => device_state.record_published(&vault_id, *role, revision),
                    Err(why) => failed = Some((*role, why.clone())),
                }
            }
            let _ = device_state.save();
            match failed {
                // Every place it went to refused it.
                Some((_, why)) if results.iter().all(|(_, put)| put.is_err()) => {
                    controller.sync_failed(&why);
                }
                Some((role, why)) => {
                    let has_backup = true;
                    match role {
                        Role::Main => controller.sync_health(Some(&why), None, has_backup),
                        Role::Backup => controller.sync_health(None, Some(&why), has_backup),
                    }
                    controller.sync_finished();
                }
                None => controller.sync_finished(),
            }
        });
    }

    /// Keeps track of which place answers. A place going down or coming back is said once;
    /// while one is down, a round runs every minute so it catches up as soon as it is back.
    fn sync_health(&self, main: Option<&str>, backup: Option<&str>, has_backup: bool) {
        let (was_main, was_backup) = {
            let state = self.state.borrow();
            (
                state.sync.main_down.is_some(),
                state.sync.backup_down.is_some(),
            )
        };
        {
            let mut state = self.state.borrow_mut();
            state.sync.main_down = main.map(str::to_owned);
            state.sync.backup_down = backup.map(str::to_owned);
        }
        let app = self.app();
        app.set_sync_main_down(SharedString::from(main.unwrap_or_default()));
        app.set_sync_backup_down(SharedString::from(backup.unwrap_or_default()));
        if has_backup {
            match (main.is_some(), was_main) {
                (true, false) => self.notify_long(notice::SYNC_MAIN_DOWN, main.unwrap_or_default()),
                (false, true) => self.notify(notice::SYNC_MAIN_BACK, ""),
                _ => {}
            }
            match (backup.is_some(), was_backup) {
                (true, false) if main.is_none() => {
                    self.notify_long(notice::SYNC_BACKUP_DOWN, backup.unwrap_or_default());
                }
                (false, true) => self.notify(notice::SYNC_BACKUP_BACK, ""),
                _ => {}
            }
        }
        if (main.is_some() || backup.is_some()) && self.state.borrow().runner != Runner::Inline {
            let weak = self.weak();
            self.timers
                .sync_retry
                .start(TimerMode::SingleShot, RETRY, move || {
                    if let Some(controller) = weak.upgrade() {
                        controller.sync_round();
                    }
                });
        } else {
            self.timers.sync_retry.stop();
        }
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

    /// "Add a backup server": joins a second server with an invite from it (made with
    /// `vault-server invite` there, or a `vaultsync:` line that names it), keeps this
    /// device's key for it, and syncs through both from now on.
    pub(super) fn sync_join_backup(&self) {
        let app = self.app();
        let (Some(vault_id), Some(device)) = (self.open_vault_id(), self.sync_device_id()) else {
            return;
        };
        let typed = app.get_sync_backup_invite().trim().to_owned();
        let (address, invite) = match InviteLink::parse(&typed) {
            Some(link) if !link.fits(&vault_id) => {
                return self.sync_setup_failed("that invite is for another vault");
            }
            Some(link) => (link.server, link.invite),
            None => (app.get_sync_backup_address().trim().to_owned(), typed),
        };
        let address = match sync::check_address(&address) {
            Ok(address) => address,
            Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
        };
        let main = DeviceState::load()
            .ok()
            .and_then(|state| state.sync_place(&vault_id))
            .map(|place| place.to);
        if let Some(SyncTo::Server { url }) = &main
            && sync::split_pin(url).0 == sync::split_pin(&address).0
        {
            return self.sync_setup_failed("that is the main server: a backup is another one");
        }
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = {
            let (vault_id, address) = (vault_id.clone(), address.clone());
            move || -> Result<(), String> {
                let server =
                    ServerTarget::join(&address, &vault_id, device, &sync::device_name(), &invite)
                        .map_err(|err| format!("{err:#}"))?;
                secret_store::store_sync_key(
                    &vault_id,
                    &sync::sync_key_name(device, Role::Backup),
                    &server.key_seed(),
                )
                .map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| {
            controller.sync_busy(false);
            match result {
                Ok(()) => {
                    let mut device_state = DeviceState::load().unwrap_or_default();
                    device_state.set_sync_backup(&vault_id, Some(SyncTo::Server { url: address }));
                    if let Err(err) = device_state.save() {
                        controller.notify_long(notice::DEVICE_STATE_NOT_SAVED, &err.to_string());
                        return;
                    }
                    let app = controller.app();
                    app.set_sync_backup_form(false);
                    app.set_sync_backup_invite(SharedString::new());
                    app.set_sync_backup_address(SharedString::new());
                    controller.state.borrow_mut().sync.tags = KnownTags::default();
                    controller.notify(notice::SYNC_BACKUP_JOINED, "");
                    controller.show_sync_settings();
                    controller.sync_round();
                }
                Err(why) => controller.sync_setup_failed(&why),
            }
        });
    }

    /// The address dialog (Settings → Sync → Change the address) opens with the address in use
    /// and its pin apart.
    pub(super) fn fill_server_address(&self, backup: bool) {
        let app = self.app();
        let url = self
            .open_vault_id()
            .and_then(|vault_id| DeviceState::load().ok()?.sync_place(&vault_id))
            .and_then(|place| if backup { place.backup } else { Some(place.to) })
            .and_then(|to| match to {
                SyncTo::Server { url } => Some(url),
                _ => None,
            })
            .unwrap_or_default();
        let (base, pin) = sync::split_pin(&url);
        app.set_sync_new_address(SharedString::from(base));
        app.set_sync_new_pin(SharedString::from(
            pin.map(|pin| sync::pin_text(&pin)).unwrap_or_default(),
        ));
    }

    /// "Change the address": the same server (or backup server), reached at another address.
    /// The new one is kept only once the server answers there with this vault and this
    /// device's key, so it can't send the sealed copies to some other server.
    pub(super) fn sync_change_address(&self, backup: bool) {
        let app = self.app();
        let (Some(vault_id), Some(device)) = (self.open_vault_id(), self.sync_device_id()) else {
            return;
        };
        let Some(place) = DeviceState::load()
            .ok()
            .and_then(|state| state.sync_place(&vault_id))
        else {
            return;
        };
        let current = if backup {
            place.backup.clone()
        } else {
            Some(place.to.clone())
        };
        if !matches!(current, Some(SyncTo::Server { .. })) {
            return;
        }
        let address = match sync::with_pin(&app.get_sync_new_address(), &app.get_sync_new_pin())
            .and_then(|address| sync::check_address(&address))
        {
            Ok(address) => address,
            Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
        };
        // A backup on the main server's address isn't a backup.
        let other = if backup {
            Some(place.to.clone())
        } else {
            place.backup.clone()
        };
        if let Some(SyncTo::Server { url }) = &other
            && sync::split_pin(url).0 == sync::split_pin(&address).0
        {
            return self.sync_setup_failed(if backup {
                "that is the main server: a backup is another one"
            } else {
                "that is the backup server's address"
            });
        }
        let role = if backup { Role::Backup } else { Role::Main };
        let to = SyncTo::Server {
            url: address.clone(),
        };
        self.sync_busy(true);
        let runner = self.state.borrow().runner;
        let job = {
            let (vault_id, to) = (vault_id.clone(), to.clone());
            move || -> Result<(), String> {
                sync::open_target_as(&vault_id, device, &to, role)
                    .and_then(|target| target.list())
                    .map(|_| ())
                    .map_err(|err| format!("{err:#}"))
            }
        };
        off_thread(runner, job, move |controller, result| {
            controller.sync_busy(false);
            if let Err(why) = result {
                return controller.sync_setup_failed(&why);
            }
            let mut device_state = DeviceState::load().unwrap_or_default();
            if backup {
                device_state.set_sync_backup(&vault_id, Some(to));
            } else {
                device_state.set_sync_to(&vault_id, Some(to));
            }
            if let Err(err) = device_state.save() {
                controller.notify_long(notice::DEVICE_STATE_NOT_SAVED, &err.to_string());
                return;
            }
            controller.app().set_settings_dialog(super::dialog::NONE);
            controller.state.borrow_mut().sync.tags = KnownTags::default();
            controller.notify(notice::SYNC_ADDRESS_CHANGED, "");
            controller.show_sync_settings();
            controller.sync_round();
        });
    }

    /// "Remove the backup": this device stops syncing through the second server (its copy
    /// there is left) and forgets its key for it.
    pub(super) fn sync_remove_backup(&self) {
        let Some(vault_id) = self.open_vault_id() else {
            return;
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_sync_backup(&vault_id, None);
        let _ = device_state.save();
        if let Some(device) = self.sync_device_id() {
            let _ = secret_store::forget_sync_key(
                &vault_id,
                &sync::sync_key_name(device, Role::Backup),
            );
        }
        self.state.borrow_mut().sync.backup_down = None;
        self.app().set_sync_backup_down(SharedString::new());
        self.show_sync_settings();
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
            app.set_sync_backup(SharedString::new());
            app.set_sync_main_down(SharedString::new());
            app.set_sync_backup_down(SharedString::new());
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
        app.set_sync_backup(SharedString::from(
            place
                .backup
                .as_ref()
                .map(SyncTo::describe)
                .unwrap_or_default(),
        ));
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
        let here = self.state.borrow().sync.here.clone();
        app.set_sync_others(ModelRc::new(VecModel::from(
            others
                .iter()
                .map(|(id, name)| crate::ui::DeviceLine {
                    name: SharedString::from(name.as_str()),
                    // Listed in the vault, but without a copy where it syncs now: it synced
                    // through another place, or hasn't joined this one yet.
                    away: here.as_ref().is_some_and(|here| !here.contains(id)),
                })
                .collect::<Vec<_>>(),
        )));
        let running = {
            let mut state = self.state.borrow_mut();
            state.sync.others = others;
            state.sync.running
        };
        let waiting = self.state.borrow().sync.waiting;
        app.set_sync_waiting(i32::try_from(waiting).unwrap_or(i32::MAX));
        {
            let state = self.state.borrow();
            app.set_sync_key_renewed(!state.sync.renewed.is_empty());
            app.set_sync_key_behind(i32::try_from(state.sync.behind.len()).unwrap_or(i32::MAX));
        }
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
