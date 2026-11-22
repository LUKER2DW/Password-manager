//! Sync on the phone (SYNC.md, M6.4): joins the vault's server with the invite a computer
//! shows (its `vaultsync:` line or QR code), then a round at unlock, a few seconds after each
//! save, every few minutes, as soon as the server says another device published, and on
//! demand. The server is read and written off the UI thread; the merge runs here, where the
//! vault is. Not in the browser preview, which has no network to sync over.

use super::Controller;

/// What Settings → Updates shows (`update-state`).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(super) mod update {
    pub const ASKING: i32 = 1;
    pub const NEWEST: i32 = 2;
    pub const WAITING: i32 = 3;
    pub const FETCHING: i32 = 4;
    pub const FAILED: i32 = 5;
    pub const HANDED: i32 = 6;
}

/// What the Sync part of Settings shows (`sync-state`).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(super) mod state {
    pub const OFF: i32 = 0;
    pub const SYNCED: i32 = 1;
    pub const SYNCING: i32 = 2;
    pub const FAILED: i32 = 3;
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Default)]
pub(super) struct SyncStatus {
    _nothing: (),
}

#[cfg(target_arch = "wasm32")]
impl Controller {
    pub(super) fn start_sync(&self) {}
    pub(super) fn stop_sync(&self) {}
    pub(super) fn sync_after_save(&self) {}
    pub(super) fn sync_join(&self) {}
    pub(super) fn sync_use_webdav(&self) {}
    pub(super) fn setup_from_server(&self) {
        self.set_error(
            super::error::SYNC_SETUP,
            "the browser preview has no server to sync with",
        );
    }
    pub(super) fn sync_stop(&self) {}
    pub(super) fn sync_remove_device(&self, _index: i32) {}
    pub(super) fn sync_add_device(&self) {}
    pub(super) fn sync_hide_invite(&self) {}
    pub(super) fn sync_change_address(&self) {}
    pub(super) fn sync_join_backup(&self) {}
    pub(super) fn sync_remove_backup(&self) {}
    pub(super) fn check_update(&self) {}
    pub(super) fn install_update(&self) {}
    pub fn update_installing(&self, _error: &str) {}
    pub fn sync_round(&self) {}
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) use native::SyncStatus;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use slint::{ModelRc, SharedPixelBuffer, SharedString, TimerMode, VecModel};
    use vault_core::sync::DeviceId;
    use vault_platform::{
        DeviceState, SyncPlace, SyncTo, secret_store,
        sync::{self, KnownTags, Role, ServerTarget, Tags},
    };
    use vault_sync_wire::{DeviceKey, InviteLink};

    use zeroize::Zeroizing;

    use super::{
        super::{CURRENT, error, field, size_text},
        Controller, state, update,
    };
    use crate::{ui::DeviceRow, view};

    /// Joins the server with the invite, or, when this phone already joined that vault there
    /// (a setup that failed after joining, tried again), goes on with the key it has: an
    /// invite works once, so trying again must not need a new one.
    fn join_or_resume(
        address: &str,
        vault_id: &str,
        device: DeviceId,
        invite: &str,
        role: Role,
    ) -> Result<ServerTarget, String> {
        let key_name = sync::sync_key_name(device, role);
        if let Ok(Some(seed)) = secret_store::load_sync_key(vault_id, &key_name)
            && let Ok(server) =
                ServerTarget::new(address, vault_id, device, DeviceKey::from_seed(&seed))
            && server.enrolled().is_ok()
        {
            return Ok(server);
        }
        let server = ServerTarget::join(address, vault_id, device, DEVICE_NAME, invite)
            .map_err(|err| format!("{err:#}"))?;
        secret_store::store_sync_key(vault_id, &key_name, &server.key_seed())
            .map_err(|err| format!("{err:#}"))?;
        Ok(server)
    }

    /// The backup server an invite line names, joined too when it answers (its address as
    /// checked). Without it the phone syncs through the main server only.
    fn join_backup(link: &InviteLink, vault_id: &str, device: DeviceId) -> Option<String> {
        let (address, invite) = link.backup.as_ref()?;
        let address = sync::check_address(address).ok()?;
        join_or_resume(&address, vault_id, device, invite, Role::Backup).ok()?;
        Some(address)
    }

    /// After a save, how long to wait for more saves before one round.
    const AFTER_SAVE: Duration = Duration::from_secs(3);
    /// While the vault is open, a round this often.
    const EVERY: Duration = Duration::from_secs(5 * 60);
    /// How long one long-poll waits on the server.
    const WAIT_SECONDS: u64 = 50;
    /// While one of the places doesn't answer, a round this often.
    const RETRY: Duration = Duration::from_secs(60);
    /// This device's name in the vault's device list.
    const DEVICE_NAME: &str = "Phone";

    #[derive(Debug, Default)]
    pub(in crate::controller) struct SyncStatus {
        running: bool,
        again: bool,
        /// Tags of the copies merged since unlock, per place: unchanged ones aren't read
        /// again.
        tags: KnownTags,
        watch: Option<Arc<AtomicBool>>,
        /// The size of each device's copy at the main place, as last read or written.
        sizes: HashMap<DeviceId, usize>,
        /// The devices behind Settings → Sync's rows, in order.
        devices: Vec<DeviceId>,
    }

    struct Place {
        vault_id: String,
        device: DeviceId,
        place: SyncPlace,
    }

    impl Controller {
        fn runs_inline(&self) -> bool {
            self.state.borrow().inline
        }

        /// Runs `job` off the UI thread (inline in tests) and hands its result back here.
        fn off_thread<T: Send + 'static>(
            &self,
            job: impl FnOnce() -> T + Send + 'static,
            done: impl FnOnce(&Controller, T) + Send + 'static,
        ) {
            if self.runs_inline() {
                let result = job();
                done(self, result);
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

        fn vault_id(&self) -> Option<String> {
            self.state.borrow().vault.as_ref().map(|v| v.id_hex())
        }

        fn device_id(&self) -> Option<DeviceId> {
            let mut device_state = DeviceState::load().ok()?;
            let had = device_state.has_device_id();
            let id = device_state.device_id().ok()?;
            if !had {
                device_state.save().ok()?;
            }
            Some(id)
        }

        fn sync_place(&self) -> Option<Place> {
            let vault_id = self.vault_id()?;
            let place = DeviceState::load().ok()?.sync_place(&vault_id)?;
            Some(Place {
                vault_id,
                device: self.device_id()?,
                place,
            })
        }

        /// The vault is open: write as this device and run a first round.
        pub(in crate::controller) fn start_sync(&self) {
            self.stop_watch();
            self.state.borrow_mut().sync.tags = KnownTags::default();
            self.state.borrow_mut().sync.sizes.clear();
            let Some(place) = self.sync_place() else {
                self.show_sync();
                return;
            };
            if let Some(vault) = self.state.borrow_mut().vault.as_mut() {
                vault.set_device(place.device);
            }
            self.sync_every.start(TimerMode::Repeated, EVERY, || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.sync_round();
                }
            });
            self.start_watch(&place);
            self.sync_round();
        }

        pub(in crate::controller) fn stop_sync(&self) {
            self.sync_every.stop();
            self.sync_soon.stop();
            self.stop_watch();
            self.state.borrow_mut().sync.tags = KnownTags::default();
        }

        fn stop_watch(&self) {
            if let Some(stop) = self.state.borrow_mut().sync.watch.take() {
                stop.store(true, Ordering::Relaxed);
            }
        }

        /// Waits on the server's news on a thread and asks for a round when another device
        /// published. Not in tests.
        fn start_watch(&self, place: &Place) {
            if self.runs_inline() || !matches!(place.place.to, SyncTo::Server { .. }) {
                return;
            }
            let stop = Arc::new(AtomicBool::new(false));
            self.state.borrow_mut().sync.watch = Some(stop.clone());
            let (vault_id, device, to) =
                (place.vault_id.clone(), place.device, place.place.to.clone());
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
                                let _ = slint::invoke_from_event_loop(|| {
                                    if let Some(c) = CURRENT.with(|c| c.borrow().upgrade()) {
                                        c.sync_round();
                                    }
                                });
                            }
                            after = seq;
                        }
                        Some(Err(_)) => {
                            let until = std::time::Instant::now() + pause;
                            while std::time::Instant::now() < until && !stop.load(Ordering::Relaxed)
                            {
                                std::thread::sleep(Duration::from_millis(500));
                            }
                            pause = (pause * 2).min(Duration::from_secs(300));
                        }
                        None => return,
                    }
                }
            });
        }

        /// A save happened: one round a moment later.
        pub(in crate::controller) fn sync_after_save(&self) {
            if self.state.borrow().sync.running {
                self.state.borrow_mut().sync.again = true;
                return;
            }
            if self.runs_inline() || !self.sync_every.running() {
                return;
            }
            self.sync_soon.start(TimerMode::SingleShot, AFTER_SAVE, || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.sync_round();
                }
            });
        }

        /// "Join": enrolls this phone with the invite line from the computer and keeps its
        /// new key in the credential store.
        pub(in crate::controller) fn sync_join(&self) {
            let app = self.app();
            let (Some(vault_id), Some(device)) = (self.vault_id(), self.device_id()) else {
                return;
            };
            let typed = app.get_sync_invite_typed().trim().to_owned();
            let link = match InviteLink::parse(&typed) {
                Some(link) if link.vault == vault_id => link,
                Some(_) => return self.sync_setup_failed("that invite is for another vault"),
                None => {
                    return self.sync_setup_failed(
                        "paste the whole line that starts with vaultsync:1? from Add a device on your computer",
                    );
                }
            };
            let address = match sync::check_address(&link.server) {
                Ok(address) => address,
                Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
            };
            app.set_sync_busy(true);
            app.set_sync_detail(SharedString::new());
            let job = {
                let (vault_id, address) = (vault_id.clone(), address.clone());
                move || -> Result<Option<String>, String> {
                    join_or_resume(&address, &vault_id, device, &link.invite, Role::Main)?;
                    Ok(join_backup(&link, &vault_id, device))
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok(backup) => {
                        app.set_sync_invite_typed(SharedString::new());
                        let mut device_state = DeviceState::load().unwrap_or_default();
                        device_state.set_sync_to(&vault_id, Some(SyncTo::Server { url: address }));
                        device_state
                            .set_sync_backup(&vault_id, backup.map(|url| SyncTo::Server { url }));
                        if let Err(err) = device_state.save() {
                            return controller.sync_setup_failed(&format!("{err:#}"));
                        }
                        controller.start_sync();
                    }
                    Err(why) => controller.sync_setup_failed(&why),
                }
            });
        }

        /// "Connect": checks the WebDAV folder answers with these credentials, keeps the
        /// password in the credential store, starts syncing.
        pub(in crate::controller) fn sync_use_webdav(&self) {
            let app = self.app();
            let Some(vault_id) = self.vault_id() else {
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
            app.set_sync_busy(true);
            app.set_sync_detail(SharedString::new());
            let job = {
                let (vault_id, address, user) = (vault_id.clone(), address.clone(), user.clone());
                move || -> Result<(), String> {
                    let target = sync::WebDavTarget::new(&address, &vault_id, &user, &password)
                        .map_err(|err| format!("{err:#}"))?;
                    sync::Target::list(&target).map_err(|err| format!("{err:#}"))?;
                    secret_store::store_webdav_password(&vault_id, &password)
                        .map_err(|err| format!("{err:#}"))
                }
            };
            self.off_thread(job, move |controller, result| {
                controller.app().set_sync_busy(false);
                match result {
                    Ok(()) => {
                        controller.state.borrow_mut().secrets[field::SYNC_PASSWORD].clear();
                        controller.publish_lengths();
                        let mut device_state = DeviceState::load().unwrap_or_default();
                        device_state
                            .set_sync_to(&vault_id, Some(SyncTo::Webdav { url: address, user }));
                        if let Err(err) = device_state.save() {
                            return controller.sync_setup_failed(&format!("{err:#}"));
                        }
                        controller.app().set_sync_form(0);
                        controller.start_sync();
                    }
                    Err(why) => controller.sync_setup_failed(&why),
                }
            });
        }

        /// "Set up from the server", on the start screen: joins the server with the invite
        /// line, fetches a copy another device put there and brings it in like a chosen file
        /// (it replaces nothing until it opens with the person's master password and Secret
        /// Key). Sync stays on for that vault; the first round after unlock merges the rest.
        pub(in crate::controller) fn setup_from_server(&self) {
            let app = self.app();
            let typed = app.get_setup_invite().trim().to_owned();
            let Some(link) = InviteLink::parse(&typed) else {
                return self.set_error(
                    super::super::error::SYNC_SETUP,
                    "paste the whole line that starts with vaultsync:1? from Add a device on your computer",
                );
            };
            let address = match sync::check_address(&link.server) {
                Ok(address) => address,
                Err(err) => {
                    return self.set_error(super::super::error::SYNC_SETUP, &format!("{err:#}"));
                }
            };
            let Some(device) = self.device_id() else {
                return self.set_error(
                    super::super::error::SYNC_SETUP,
                    "this phone's state can't be written",
                );
            };
            self.set_error(super::super::error::NONE, "");
            app.set_sync_busy(true);
            let vault_id = link.vault.clone();
            let job = {
                let (vault_id, address) = (vault_id.clone(), address.clone());
                move || -> Result<(Vec<u8>, Option<String>), String> {
                    let server =
                        join_or_resume(&address, &vault_id, device, &link.invite, Role::Main)?;
                    let backup = join_backup(&link, &vault_id, device);
                    let fetched = sync::fetch(&server, device, &Tags::new())
                        .map_err(|err| format!("{err:#}"))?;
                    // The biggest copy is the most likely to be the fullest; the first sync
                    // round after unlock merges every other one anyway.
                    fetched
                        .copies
                        .into_iter()
                        .max_by_key(|(_, bytes)| bytes.len())
                        .map(|(_, bytes)| (bytes, backup))
                        .ok_or_else(|| {
                            "no device has put the vault on the server yet: press Sync now on the computer first".to_owned()
                        })
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok((bytes, backup)) => {
                        let mut device_state = DeviceState::load().unwrap_or_default();
                        device_state.set_sync_to(&vault_id, Some(SyncTo::Server { url: address }));
                        device_state
                            .set_sync_backup(&vault_id, backup.map(|url| SyncTo::Server { url }));
                        if let Err(err) = device_state.save() {
                            return controller
                                .set_error(super::super::error::SYNC_SETUP, &format!("{err:#}"));
                        }
                        app.set_setup_invite(SharedString::new());
                        controller.bring_vault(bytes);
                    }
                    Err(why) => controller.set_error(super::super::error::SYNC_SETUP, &why),
                }
            });
        }

        fn sync_setup_failed(&self, why: &str) {
            let app = self.app();
            app.set_sync_detail(SharedString::from(why));
            app.set_sync_state(state::FAILED);
        }

        /// "Stop syncing": this phone stops, and forgets its server key.
        pub(in crate::controller) fn sync_stop(&self) {
            self.stop_sync();
            let Some(vault_id) = self.vault_id() else {
                return;
            };
            let mut device_state = DeviceState::load().unwrap_or_default();
            device_state.set_sync_to(&vault_id, None);
            let _ = device_state.save();
            if let Some(device) = self.device_id() {
                let _ = secret_store::forget_sync_key(&vault_id, &device.to_hex());
                let _ = secret_store::forget_sync_key(
                    &vault_id,
                    &sync::sync_key_name(device, Role::Backup),
                );
            }
            let _ = secret_store::forget_webdav_password(&vault_id);
            self.app().set_sync_detail(SharedString::new());
            self.show_sync();
        }

        /// One round: read the other copies from every place (off the UI thread), merge them
        /// here, save, publish this phone's copy.
        pub fn sync_round(&self) {
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
            let job = move || sync::read_all(&vault_id, device, &sync_place, &known);
            self.off_thread(job, move |controller, reading| {
                controller.sync_fetched(place, reading);
            });
        }

        fn sync_fetched(&self, mut place: Place, reading: sync::Reading) {
            self.sync_health(reading.main_down(), reading.backup_down());
            if !reading.reached() {
                return self.sync_failed(reading.main_down().unwrap_or_default());
            }
            if self.vault_id().as_deref() != Some(place.vault_id.as_str()) {
                return self.sync_finished();
            }
            if let Ok(fetched) = &reading.main {
                let mut state = self.state.borrow_mut();
                for (device, bytes) in &fetched.copies {
                    state.sync.sizes.insert(*device, bytes.len());
                }
            }
            let (round, joined) = {
                let mut state = self.state.borrow_mut();
                let vault = state.vault.as_mut().expect("checked above");
                let joined = sync::join(vault, place.device, DEVICE_NAME).unwrap_or(false);
                (
                    sync::merge_reading(vault, &reading, &mut place.place.seen),
                    joined,
                )
            };
            if round.removed_here {
                let mut device_state = DeviceState::load().unwrap_or_default();
                device_state.set_sync_to(&place.vault_id, None);
                let _ = device_state.save();
                self.stop_sync();
                self.sync_setup_failed("this phone was removed from the vault on another device");
                self.state.borrow_mut().sync.running = false;
                return;
            }
            {
                let mut state = self.state.borrow_mut();
                state.sync.tags = if round.waiting_for_lock() == 0 {
                    reading.tags(&state.sync.tags)
                } else {
                    KnownTags::default()
                };
            }
            let changed = round.changed() || joined;
            if changed {
                if !self.save_quietly() {
                    return self.sync_failed("the phone's copy couldn't be saved");
                }
                self.after_sync_changes();
            }
            let revision = self
                .state
                .borrow()
                .vault
                .as_ref()
                .map_or(0, |v| v.revision());
            let mut device_state = DeviceState::load().unwrap_or_default();
            device_state.record_sync(&place.vault_id, &place.place.seen, unix_now(), 0);
            let _ = device_state.save();
            let came: usize = round
                .reports
                .iter()
                .map(|r| r.added + r.updated + r.removed)
                .sum();
            if came > 0 {
                self.notify(super::super::notice::SYNCED, &came.to_string());
            }
            let roles = sync::to_publish(&place.place, &reading, revision, changed);
            if roles.is_empty() {
                self.sync_finished();
            } else {
                self.sync_publish(place, revision, roles);
            }
        }

        fn sync_publish(&self, place: Place, revision: u64, roles: Vec<Role>) {
            let path = self.state.borrow().path.clone();
            let (vault_id, device, sync_place) =
                (place.vault_id.clone(), place.device, place.place);
            let job = {
                let vault_id = vault_id.clone();
                move || -> Result<(usize, sync::Published), String> {
                    let bytes =
                        crate::platform::files::read(&path).map_err(|err| err.to_string())?;
                    Ok((
                        bytes.len(),
                        sync::publish_all(&vault_id, device, &sync_place, &bytes, &roles),
                    ))
                }
            };
            self.off_thread(job, move |controller, result| {
                let (len, results) = match result {
                    Ok(results) => results,
                    Err(why) => return controller.sync_failed(&why),
                };
                if results
                    .iter()
                    .any(|(role, put)| *role == Role::Main && put.is_ok())
                {
                    controller.state.borrow_mut().sync.sizes.insert(device, len);
                }
                let mut device_state = DeviceState::load().unwrap_or_default();
                for (role, put) in &results {
                    if put.is_ok() {
                        device_state.record_published(&vault_id, *role, revision);
                    }
                }
                let _ = device_state.save();
                let refused = |role| {
                    results
                        .iter()
                        .find(|(r, put)| *r == role && put.is_err())
                        .and_then(|(_, put)| put.as_ref().err().cloned())
                };
                if results.iter().all(|(_, put)| put.is_err()) {
                    let why = refused(Role::Main).or_else(|| refused(Role::Backup));
                    return controller.sync_failed(&why.unwrap_or_default());
                }
                let (main, backup) = (refused(Role::Main), refused(Role::Backup));
                if main.is_some() || backup.is_some() {
                    controller.sync_health(main.as_deref(), backup.as_deref());
                }
                controller.sync_finished();
            });
        }

        /// Which place answers: what Settings warns about. While one doesn't, a round runs
        /// every minute, so it catches up as soon as it is back.
        fn sync_health(&self, main: Option<&str>, backup: Option<&str>) {
            let app = self.app();
            app.set_sync_main_down(SharedString::from(main.unwrap_or_default()));
            app.set_sync_backup_down(SharedString::from(backup.unwrap_or_default()));
            if (main.is_some() || backup.is_some()) && !self.runs_inline() {
                let weak = CURRENT.with(|c| c.borrow().clone());
                self.sync_soon.start(TimerMode::SingleShot, RETRY, move || {
                    if let Some(controller) = weak.upgrade() {
                        controller.sync_round();
                    }
                });
            }
        }

        fn sync_failed(&self, why: &str) {
            self.state.borrow_mut().sync.running = false;
            self.show_sync();
            let app = self.app();
            app.set_sync_detail(SharedString::from(why));
            app.set_sync_state(state::FAILED);
        }

        fn sync_finished(&self) {
            self.state.borrow_mut().sync.running = false;
            self.app().set_sync_detail(SharedString::new());
            self.show_sync();
            let again = std::mem::take(&mut self.state.borrow_mut().sync.again);
            if again {
                self.sync_round();
            }
        }

        /// This phone's key for the server in `role`, as a client of it at `url`.
        fn server_for(place: &Place, url: &str, role: Role) -> Result<ServerTarget, String> {
            let seed = secret_store::load_sync_key(
                &place.vault_id,
                &sync::sync_key_name(place.device, role),
            )
            .map_err(|err| format!("{err:#}"))?
            .ok_or("this phone has no key for that server: stop syncing and join again")?;
            ServerTarget::new(
                url,
                &place.vault_id,
                place.device,
                DeviceKey::from_seed(&seed),
            )
            .map_err(|err| format!("{err:#}"))
        }

        /// "Add a device": a one-time invite from the server (and the backup's, when it
        /// answers), shown as a QR code and as its `vaultsync:` line.
        pub(in crate::controller) fn sync_add_device(&self) {
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
            self.app().set_sync_busy(true);
            let job = move || -> Result<Zeroizing<String>, String> {
                let server = Self::server_for(&place, &url, Role::Main)?;
                let invite = server.invite().map_err(|err| format!("{err:#}"))?;
                let mut link = server.invite_link(&invite);
                if let Some(backup) = &backup
                    && let Ok(target) = Self::server_for(&place, backup, Role::Backup)
                    && let Ok(backup_invite) = target.invite()
                {
                    link.backup = Some((
                        target.invite_link(&backup_invite).server,
                        backup_invite.invite,
                    ));
                }
                Ok(link.to_text())
            };
            self.off_thread(job, |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok(text) => {
                        app.set_sync_invite_qr(qr_image(&text));
                        app.set_sync_invite(SharedString::from(text.as_str()));
                    }
                    Err(why) => controller.sync_setup_failed(&why),
                }
            });
        }

        /// Settings → Updates: asks the vault server for the phone app's update (what its
        /// owner put there with `vault-server publish-app`).
        pub(in crate::controller) fn check_update(&self) {
            let Some(place) = self.sync_place() else {
                return;
            };
            let SyncTo::Server { url } = place.place.to.clone() else {
                return;
            };
            let installed = self.app().get_app_version().to_string();
            self.app().set_update_state(update::ASKING);
            let job = move || -> Result<Option<String>, String> {
                let release = Self::server_for(&place, &url, Role::Main)?
                    .app_release()
                    .map_err(|err| format!("{err:#}"))?;
                Ok(release
                    .filter(|r| vault_sync_wire::is_newer(&r.version, &installed))
                    .map(|r| r.version))
            };
            self.off_thread(job, |controller, result| {
                let app = controller.app();
                match result {
                    Ok(Some(version)) => {
                        app.set_update_version(version.into());
                        app.set_update_state(update::WAITING);
                    }
                    Ok(None) => app.set_update_state(update::NEWEST),
                    Err(why) => {
                        controller.set_error(error::UPDATE, &why);
                        app.set_update_state(update::FAILED);
                    }
                }
            });
        }

        /// "Install version …": the package is fetched, checked against its release (size and
        /// SHA-256) and handed to Android's installer, which asks the person and installs it
        /// only if it is signed like the app already here.
        pub(in crate::controller) fn install_update(&self) {
            let Some(place) = self.sync_place() else {
                return;
            };
            let SyncTo::Server { url } = place.place.to.clone() else {
                return;
            };
            let installed = self.app().get_app_version().to_string();
            self.app().set_update_state(update::FETCHING);
            let job = move || -> Result<Vec<u8>, String> {
                let server = Self::server_for(&place, &url, Role::Main)?;
                let release = server
                    .app_release()
                    .map_err(|err| format!("{err:#}"))?
                    .filter(|r| vault_sync_wire::is_newer(&r.version, &installed))
                    .ok_or("the server has no newer version any more")?;
                server
                    .app_package(&release)
                    .map_err(|err| format!("{err:#}"))
            };
            self.off_thread(job, |controller, result| {
                let handed =
                    result.and_then(|package| controller.system().install_update(&package));
                if let Err(why) = handed {
                    controller.set_error(error::UPDATE, &why);
                    controller.app().set_update_state(update::FAILED);
                }
            });
        }

        /// The installer's answer: it asks the person now (""), or the update can't go in.
        pub fn update_installing(&self, error: &str) {
            let app = self.app();
            if error.is_empty() {
                app.set_update_state(update::HANDED);
            } else {
                self.set_error(error::UPDATE, error);
                app.set_update_state(update::FAILED);
            }
        }

        /// Hides the invite (it stays good until used, or for an hour).
        pub(in crate::controller) fn sync_hide_invite(&self) {
            let app = self.app();
            app.set_sync_invite(SharedString::new());
            app.set_sync_invite_qr(slint::Image::default());
        }

        /// "Change the server's address": the same server somewhere else. It is used only once
        /// it answers this phone's key there (so it is the server that knows this phone).
        pub(in crate::controller) fn sync_change_address(&self) {
            let app = self.app();
            let Some(place) = self.sync_place() else {
                return;
            };
            if !matches!(place.place.to, SyncTo::Server { .. }) {
                return;
            }
            let address = match sync::check_address(app.get_sync_new_address().trim()) {
                Ok(address) => address,
                Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
            };
            app.set_sync_busy(true);
            let vault_id = place.vault_id.clone();
            let job = {
                let address = address.clone();
                move || -> Result<(), String> {
                    Self::server_for(&place, &address, Role::Main)?
                        .enrolled()
                        .map(|_| ())
                        .map_err(|err| format!("{err:#}"))
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                if let Err(why) = result {
                    return controller.sync_setup_failed(&why);
                }
                let mut device_state = DeviceState::load().unwrap_or_default();
                device_state.set_sync_to(&vault_id, Some(SyncTo::Server { url: address }));
                if let Err(err) = device_state.save() {
                    return controller.sync_setup_failed(&format!("{err:#}"));
                }
                app.set_sync_editing(false);
                controller.notify(super::super::notice::ADDRESS_CHANGED, "");
                controller.start_sync();
            });
        }

        /// "Add a backup server": joins a second server with an invite for it (a
        /// `vaultsync:` line that names it, or one from `vault-server invite` with its
        /// address), keeps this phone's key for it, and syncs through both from now on.
        pub(in crate::controller) fn sync_join_backup(&self) {
            let app = self.app();
            let (Some(vault_id), Some(device)) = (self.vault_id(), self.device_id()) else {
                return;
            };
            let typed = app.get_sync_backup_invite().trim().to_owned();
            let (address, invite) = match InviteLink::parse(&typed) {
                Some(link) if link.vault != vault_id => {
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
            app.set_sync_busy(true);
            let job = {
                let (vault_id, address) = (vault_id.clone(), address.clone());
                move || -> Result<(), String> {
                    join_or_resume(&address, &vault_id, device, &invite, Role::Backup).map(|_| ())
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                if let Err(why) = result {
                    return controller.sync_setup_failed(&why);
                }
                let mut device_state = DeviceState::load().unwrap_or_default();
                device_state.set_sync_backup(&vault_id, Some(SyncTo::Server { url: address }));
                if let Err(err) = device_state.save() {
                    return controller.sync_setup_failed(&format!("{err:#}"));
                }
                app.set_sync_backup_form(false);
                app.set_sync_backup_invite(SharedString::new());
                app.set_sync_backup_address(SharedString::new());
                controller.state.borrow_mut().sync.tags = KnownTags::default();
                controller.notify(super::super::notice::BACKUP_JOINED, "");
                controller.show_sync();
                controller.sync_round();
            });
        }

        /// "Remove the backup server": this phone stops syncing through it (its copy there is
        /// left) and forgets its key for it.
        pub(in crate::controller) fn sync_remove_backup(&self) {
            let (Some(vault_id), Some(device)) = (self.vault_id(), self.device_id()) else {
                return;
            };
            let mut device_state = DeviceState::load().unwrap_or_default();
            device_state.set_sync_backup(&vault_id, None);
            let _ = device_state.save();
            let _ = secret_store::forget_sync_key(
                &vault_id,
                &sync::sync_key_name(device, Role::Backup),
            );
            self.app().set_sync_backup_down(SharedString::new());
            self.show_sync();
        }

        /// "Remove" on another device's row: it leaves the vault's device list (so every
        /// device refuses its copies from then on), and its copy and key leave the place.
        pub(in crate::controller) fn sync_remove_device(&self, index: i32) {
            let Some(id) = usize::try_from(index)
                .ok()
                .and_then(|i| self.state.borrow().sync.devices.get(i).copied())
            else {
                return;
            };
            let removed = {
                let mut state = self.state.borrow_mut();
                let Some(vault) = state.vault.as_mut() else {
                    return;
                };
                let name = vault
                    .sync_devices()
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| d.name.clone())
                    .unwrap_or_default();
                vault.remove_sync_device(&id).map(|()| name)
            };
            let Ok(name) = removed else {
                return;
            };
            self.app().set_sync_removing(-1);
            if !self.save() {
                return;
            }
            self.state.borrow_mut().sync.sizes.remove(&id);
            self.notify(super::super::notice::DEVICE_REMOVED, &name);
            if let Some(place) = self.sync_place() {
                let job = move || {
                    sync::open_target(&place.vault_id, place.device, &place.place.to)
                        .and_then(|target| target.remove(id))
                        .map_err(|err| format!("{err:#}"))
                };
                // A copy left behind is refused anyway: nothing to say if it couldn't go.
                self.off_thread(job, |_, _| {});
            }
            self.show_sync();
        }

        /// The devices that sync this vault, and the copies the place keeps.
        fn show_devices(&self) {
            let app = self.app();
            let (rows, ids, own) = {
                let state = self.state.borrow();
                let Some(vault) = state.vault.as_ref() else {
                    return;
                };
                let own = vault.device();
                let mut devices: Vec<_> = vault.sync_devices().to_vec();
                // This phone first, then the others as they joined.
                devices.sort_by_key(|d| (d.id != own, d.added_at));
                let rows: Vec<DeviceRow> = devices
                    .iter()
                    .map(|d| DeviceRow {
                        name: d.name.as_str().into(),
                        added: view::date(d.added_at).into(),
                        own: d.id == own,
                    })
                    .collect();
                (rows, devices.iter().map(|d| d.id).collect(), own)
            };
            let (copies, total, own_size) = {
                let mut state = self.state.borrow_mut();
                state.sync.devices = ids;
                let sizes = &state.sync.sizes;
                (
                    sizes.len(),
                    sizes.values().sum::<usize>(),
                    sizes.get(&own).copied(),
                )
            };
            app.set_sync_devices(ModelRc::new(VecModel::from(rows)));
            app.set_sync_copies(i32::try_from(copies).unwrap_or(i32::MAX));
            app.set_sync_total(size_text(total).into());
            app.set_sync_own(own_size.map(size_text).unwrap_or_default().into());
        }

        /// The Sync part of Settings.
        pub(in crate::controller) fn show_sync(&self) {
            let app = self.app();
            app.set_sync_available(true);
            self.show_devices();
            let through_server = self
                .vault_id()
                .and_then(|id| DeviceState::load().ok()?.sync_place(&id))
                .is_some_and(|place| matches!(place.to, SyncTo::Server { .. }));
            app.set_updates_available(through_server && self.system().installs_updates());
            let place = self
                .vault_id()
                .and_then(|id| DeviceState::load().ok()?.sync_place(&id));
            let Some(place) = place else {
                app.set_sync_place(SharedString::new());
                app.set_sync_copies(0);
                app.set_sync_backup(SharedString::new());
                app.set_sync_main_down(SharedString::new());
                app.set_sync_backup_down(SharedString::new());
                if app.get_sync_state() != state::FAILED {
                    app.set_sync_state(state::OFF);
                }
                return;
            };
            app.set_sync_place(SharedString::from(place.to.describe()));
            app.set_sync_backup(SharedString::from(
                place
                    .backup
                    .as_ref()
                    .map(SyncTo::describe)
                    .unwrap_or_default(),
            ));
            app.set_sync_webdav(matches!(place.to, SyncTo::Webdav { .. }));
            app.set_sync_minutes(if place.at > 0 {
                i32::try_from((unix_now() - place.at).max(0) / 60).unwrap_or(i32::MAX)
            } else {
                -1
            });
            if !self.state.borrow().sync.running && app.get_sync_state() != state::FAILED {
                app.set_sync_state(state::SYNCED);
            }
        }
    }

    /// A QR code of `text`, black on white with a quiet zone, a few pixels per module (the
    /// desktop's).
    fn qr_image(text: &str) -> slint::Image {
        let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M) else {
            return slint::Image::default();
        };
        let modules = code.width();
        let colors = code.to_colors();
        let (quiet, scale) = (4, 6);
        let side = (modules + 2 * quiet) * scale;
        let Ok(side_px) = u32::try_from(side) else {
            return slint::Image::default();
        };
        let mut buffer = SharedPixelBuffer::<slint::Rgb8Pixel>::new(side_px, side_px);
        for (i, pixel) in buffer.make_mut_slice().iter_mut().enumerate() {
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

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}
