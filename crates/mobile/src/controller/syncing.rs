//! Sync on the phone (SYNC.md, M6.4): joins the vault's server with the invite a computer
//! shows (its `vaultsync:` line or QR code), then a round at unlock, a few seconds after each
//! save, every few minutes, as soon as the server says another device published, and on
//! demand. The server is read and written off the UI thread; the merge runs here, where the
//! vault is. Not in the browser preview, which has no network to sync over.

use super::Controller;

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
    pub fn sync_round(&self) {}
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) use native::SyncStatus;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use slint::{SharedString, TimerMode};
    use vault_core::sync::DeviceId;
    use vault_platform::{
        DeviceState, SyncPlace, SyncTo, secret_store,
        sync::{self, ServerTarget, Tags},
    };
    use vault_sync_wire::InviteLink;

    use zeroize::Zeroizing;

    use super::{
        super::{CURRENT, field},
        Controller, state,
    };

    /// After a save, how long to wait for more saves before one round.
    const AFTER_SAVE: Duration = Duration::from_secs(3);
    /// While the vault is open, a round this often.
    const EVERY: Duration = Duration::from_secs(5 * 60);
    /// How long one long-poll waits on the server.
    const WAIT_SECONDS: u64 = 50;
    /// This device's name in the vault's device list.
    const DEVICE_NAME: &str = "Phone";

    #[derive(Debug, Default)]
    pub(in crate::controller) struct SyncStatus {
        running: bool,
        again: bool,
        /// Tags of the copies merged since unlock: unchanged ones aren't read again.
        tags: Tags,
        watch: Option<Arc<AtomicBool>>,
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
            self.state.borrow_mut().sync.tags.clear();
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
            self.state.borrow_mut().sync.tags.clear();
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
                move || -> Result<(), String> {
                    let server =
                        ServerTarget::join(&address, &vault_id, device, DEVICE_NAME, &link.invite)
                            .map_err(|err| format!("{err:#}"))?;
                    secret_store::store_sync_key(&vault_id, &device.to_hex(), &server.key_seed())
                        .map_err(|err| format!("{err:#}"))
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok(()) => {
                        app.set_sync_invite_typed(SharedString::new());
                        let mut device_state = DeviceState::load().unwrap_or_default();
                        device_state.set_sync_to(&vault_id, Some(SyncTo::Server { url: address }));
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
                move || -> Result<Vec<u8>, String> {
                    let server =
                        ServerTarget::join(&address, &vault_id, device, DEVICE_NAME, &link.invite)
                            .map_err(|err| format!("{err:#}"))?;
                    secret_store::store_sync_key(&vault_id, &device.to_hex(), &server.key_seed())
                        .map_err(|err| format!("{err:#}"))?;
                    let fetched = sync::fetch(&server, device, &Tags::new())
                        .map_err(|err| format!("{err:#}"))?;
                    // The biggest copy is the most likely to be the fullest; the first sync
                    // round after unlock merges every other one anyway.
                    fetched
                        .copies
                        .into_iter()
                        .max_by_key(|(_, bytes)| bytes.len())
                        .map(|(_, bytes)| bytes)
                        .ok_or_else(|| {
                            "no device has put the vault on the server yet: press Sync now on the computer first".to_owned()
                        })
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok(bytes) => {
                        let mut device_state = DeviceState::load().unwrap_or_default();
                        device_state.set_sync_to(&vault_id, Some(SyncTo::Server { url: address }));
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
            }
            let _ = secret_store::forget_webdav_password(&vault_id);
            self.app().set_sync_detail(SharedString::new());
            self.show_sync();
        }

        /// One round: read the other copies (off the UI thread), merge them here, save,
        /// publish this phone's copy.
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
            let (vault_id, device, to) =
                (place.vault_id.clone(), place.device, place.place.to.clone());
            let known = self.state.borrow().sync.tags.clone();
            let job = move || {
                sync::open_target(&vault_id, device, &to)
                    .and_then(|target| sync::fetch(&*target, device, &known))
                    .map_err(|err| format!("{err:#}"))
            };
            self.off_thread(job, move |controller, fetched| {
                controller.sync_fetched(place, fetched);
            });
        }

        fn sync_fetched(&self, mut place: Place, fetched: Result<sync::Fetched, String>) {
            let fetched = match fetched {
                Ok(fetched) => fetched,
                Err(why) => return self.sync_failed(&why),
            };
            if self.vault_id().as_deref() != Some(place.vault_id.as_str()) {
                return self.sync_finished();
            }
            let (round, joined) = {
                let mut state = self.state.borrow_mut();
                let vault = state.vault.as_mut().expect("checked above");
                let joined = sync::join(vault, place.device, DEVICE_NAME).unwrap_or(false);
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
                self.sync_setup_failed("this phone was removed from the vault on another device");
                self.state.borrow_mut().sync.running = false;
                return;
            }
            {
                let mut state = self.state.borrow_mut();
                state.sync.tags = if round.waiting_for_lock() == 0 {
                    fetched.tags.clone()
                } else {
                    Tags::new()
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
            if changed || revision > place.place.published {
                self.sync_publish(place, revision);
            } else {
                self.sync_finished();
            }
        }

        fn sync_publish(&self, place: Place, revision: u64) {
            let path = self.state.borrow().path.clone();
            let (vault_id, device, to) = (place.vault_id.clone(), place.device, place.place.to);
            let job = {
                let vault_id = vault_id.clone();
                move || -> Result<(), String> {
                    let bytes =
                        crate::platform::files::read(&path).map_err(|err| err.to_string())?;
                    sync::open_target(&vault_id, device, &to)
                        .and_then(|target| target.put(device, &bytes))
                        .map_err(|err| format!("{err:#}"))
                }
            };
            self.off_thread(job, move |controller, result| match result {
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

        /// The Sync part of Settings.
        pub(in crate::controller) fn show_sync(&self) {
            let app = self.app();
            app.set_sync_available(true);
            let place = self
                .vault_id()
                .and_then(|id| DeviceState::load().ok()?.sync_place(&id));
            let Some(place) = place else {
                app.set_sync_place(SharedString::new());
                if app.get_sync_state() != state::FAILED {
                    app.set_sync_state(state::OFF);
                }
                return;
            };
            app.set_sync_place(SharedString::from(place.to.describe()));
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

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}
