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
    /// The server's newest is the one installed (`update-version`), or an older one.
    pub const NEWEST: i32 = 2;
    pub const WAITING: i32 = 3;
    pub const FETCHING: i32 = 4;
    pub const FAILED: i32 = 5;
    pub const HANDED: i32 = 6;
    /// No server the vault syncs through has an update published.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const NONE_PUBLISHED: i32 = 7;
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
    pub(super) fn syncs(_vault_id: &str) -> bool {
        false
    }
    pub(super) fn forget_sync_here(&self, _vault_id: &str) {}
    pub(super) fn sync_remove_device(&self, _index: i32) {}
    pub(super) fn sync_add_device(&self) {}
    pub(super) fn sync_hide_invite(&self) {}
    pub(super) fn sync_change_address(&self) {}
    pub(super) fn sync_join_backup(&self) {}
    pub(super) fn sync_remove_backup(&self) {}
    pub(super) fn check_update(&self) {}
    pub(super) fn sync_take_key(&self) {}
    pub(super) fn install_update(&self) {}
    pub(super) fn sync_now(&self) {}
    pub(super) fn update_put_off(&self) {}
    pub(super) fn ask_for_update_soon(&self) {}
    pub(super) fn update_source_changed(&self, _index: i32) {}
    pub(super) fn update_checks_changed(&self, _on: bool) {}
    pub fn update_installing(&self, _error: &str) {}
    pub fn sync_round(&self) {}
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use native::Github;
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
    use vault_core::{
        Error as CoreError, FormerKey, SecretKey, Vault, VaultSnapshot, sync::DeviceId,
    };
    use vault_platform::{
        DeviceState, SyncPlace, SyncTo, secret_store,
        sync::{self, KnownTags, Role, ServerTarget, Tags},
    };
    use vault_sync_wire::{
        DeviceKey, InviteLink,
        releases::{self, Verified as GithubRelease},
    };

    use zeroize::Zeroizing;

    use super::{
        super::{CURRENT, error, field, fingerprint, notice, sheet, size_text},
        Controller, state, update,
    };
    use crate::{platform::files, prefs, ui::DeviceRow, view};

    /// The ids a join of the vault may use: the one this phone syncs it as, and the new one
    /// it enrolls as when it isn't enrolled there already (see `sync::join_server`).
    #[derive(Clone, Copy)]
    struct JoinIds {
        current: DeviceId,
        fresh: DeviceId,
    }

    impl JoinIds {
        fn for_vault(vault_id: &str) -> Option<Self> {
            let mut device_state = DeviceState::load().ok()?;
            let ids = Self {
                current: device_state.device_id_for(vault_id).ok()?,
                fresh: device_state.joining_id_for(vault_id).ok()?,
            };
            device_state.save().ok()?;
            Some(ids)
        }

        /// Joins the main server; the id it is enrolled as.
        fn join(
            self,
            address: &str,
            vault_id: &str,
            invite: &str,
        ) -> Result<(ServerTarget, DeviceId), String> {
            sync::join_server(
                address,
                vault_id,
                &[self.current],
                self.fresh,
                DEVICE_NAME,
                invite,
                Role::Main,
            )
            .map_err(|err| format!("{err:#}"))
        }
    }

    /// The backup server an invite line names, joined too (as `device`, the id the main
    /// server was joined as) when it answers; its address as checked. Without it the phone
    /// syncs through the main server only.
    fn join_backup(link: &InviteLink, vault_id: &str, device: DeviceId) -> Option<String> {
        let (address, invite) = link.backup.as_ref()?;
        let address = sync::check_address(address).ok()?;
        sync::join_server(
            &address,
            vault_id,
            &[],
            device,
            DEVICE_NAME,
            invite,
            Role::Backup,
        )
        .ok()?;
        Some(address)
    }

    /// A join succeeded as `device`: the vault syncs through `main` (and `backup`) as that id
    /// from now on, and the keys of the id it synced as before are forgotten.
    fn joined(
        vault_id: &str,
        device: DeviceId,
        main: SyncTo,
        backup: Option<SyncTo>,
    ) -> Result<(), String> {
        let mut device_state = DeviceState::load().unwrap_or_default();
        let before = device_state
            .adopt_device_id(vault_id, device)
            .map_err(|err| err.to_string())?;
        device_state.set_sync_to(vault_id, Some(main));
        device_state.set_sync_backup(vault_id, backup);
        device_state.save().map_err(|err| format!("{err:#}"))?;
        if let Some(before) = before {
            sync::forget_keys(vault_id, before);
        }
        Ok(())
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
        /// The devices with a copy where the vault syncs now (main or backup place), as the
        /// last round found them; `None` before the first round.
        here: Option<Vec<DeviceId>>,
        /// When the servers were last asked for an update (Unix seconds): `None` until the
        /// first round since unlock, and again after Sync now.
        update_asked_at: Option<i64>,
        /// The version put off with Later since unlock: not offered again until the next one.
        update_put_off: Option<String>,
        /// What stands in for GitHub in tests (`None`: GitHub itself).
        github: Option<Github>,
        /// The keys a release manifest is checked with: tests' own (`None`: the project's,
        /// `releases::RELEASE_KEYS`).
        release_keys: Option<Vec<String>>,
        /// Copies sealed under a vault key renewed on another device (SYNC.md §4.7), kept
        /// until this phone takes the new key (Settings, Sync asks for its Secret Key).
        renewed: Vec<(DeviceId, Vec<u8>)>,
        /// The person was told about them.
        renewed_told: bool,
        /// Devices whose copies are still sealed under a key this phone took.
        behind: Vec<DeviceId>,
        /// Copies the rounds couldn't use (refused or unreadable), named in Settings, Sync.
        problems: sync::CopyProblems,
    }

    impl SyncStatus {
        /// The vault key changed here: what was refused for it is read again.
        fn key_changed(&mut self) {
            self.renewed.clear();
            self.renewed_told = false;
            self.behind.clear();
            self.tags = KnownTags::default();
        }

        /// Folds in what a round found about other vault keys: a renewed copy replaces the
        /// one of the same device kept before, and a device whose copy merged is no longer
        /// behind.
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

    /// What [`Controller::write_taken_key`] couldn't do.
    enum NotKept {
        /// The file wasn't written: nothing changed.
        NotWritten(String),
        /// The new Secret Key couldn't be kept; the file was put back as it was.
        PutBack(String),
        /// Neither: the phone's copy opens with the new kit only, and the phone doesn't hold it.
        OnlyNew(String),
    }

    /// What the job that takes a renewed key hands back.
    struct Taken {
        vault: Vault,
        secret_key: SecretKey,
        new_key: SecretKey,
        snapshot: VaultSnapshot,
        state: Option<DeviceState>,
        outcome: Result<FormerKey, (i32, String)>,
    }

    /// What the place updates come from has of the phone app.
    enum Release {
        /// A newer version than the one installed: on GitHub (`None`), or on the server in
        /// this role.
        Newer(String, Option<Role>),
        /// The newest version there, which is this one or older.
        Newest(String),
        /// None of the servers has an update published.
        Nothing,
    }

    /// Where the phone app's updates are looked for (Settings → About and updates).
    enum Source {
        /// The project's releases on GitHub (the default).
        Github(Github),
        /// The servers the open vault syncs through, and the keys their updates' manifests
        /// must be signed with (the servers are trusted with nothing there).
        Servers(Box<Place>, Vec<String>),
    }

    /// How GitHub is asked: `vault_platform::updates`, or a stand-in in tests (which never
    /// reach the network). Either hands back a release only with its manifest checked.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Github {
        pub latest: fn() -> Result<GithubRelease, String>,
        pub package: fn(&GithubRelease) -> Result<Vec<u8>, String>,
    }

    impl Github {
        const REAL: Self = Self {
            latest: vault_platform::updates::latest,
            package: vault_platform::updates::phone_package,
        };
    }

    struct Place {
        vault_id: String,
        device: DeviceId,
        place: SyncPlace,
        /// The ids this phone synced the vault as before (out of its device list).
        retired: Vec<DeviceId>,
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

        /// This phone's sync id for the open vault.
        fn device_id(&self) -> Option<DeviceId> {
            let vault_id = self.vault_id()?;
            let mut device_state = DeviceState::load().ok()?;
            let had = device_state.has_device_id();
            let id = device_state.device_id_for(&vault_id).ok()?;
            if !had {
                device_state.save().ok()?;
            }
            Some(id)
        }

        fn sync_place(&self) -> Option<Place> {
            let vault_id = self.vault_id()?;
            let device_state = DeviceState::load().ok()?;
            let place = device_state.sync_place(&vault_id)?;
            let retired = device_state.retired_ids(&vault_id);
            Some(Place {
                vault_id,
                device: self.device_id()?,
                place,
                retired,
            })
        }

        /// The vault is open: write as this device and run a first round.
        pub(in crate::controller) fn start_sync(&self) {
            self.stop_watch();
            self.state.borrow_mut().sync.tags = KnownTags::default();
            self.state.borrow_mut().sync.sizes.clear();
            self.state.borrow_mut().sync.here = None;
            self.state.borrow_mut().sync.update_asked_at = None;
            self.state.borrow_mut().sync.update_put_off = None;
            self.state.borrow_mut().sync.key_changed();
            // GitHub is asked at unlock (when its time has come), with or without sync; the
            // servers after the first round.
            if self.updates_from_github() {
                self.ask_for_update_soon();
            }
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
            let mut state = self.state.borrow_mut();
            state.sync.tags = KnownTags::default();
            state.sync.problems.clear();
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
            let Some(vault_id) = self.vault_id() else {
                return;
            };
            let Some(ids) = JoinIds::for_vault(&vault_id) else {
                return self.sync_setup_failed("this phone's state can't be written");
            };
            // The whole vaultsync: line (scanned or pasted), or the server's address, its pin
            // and the invite typed apart.
            let typed = app.get_sync_invite_typed().trim().to_owned();
            let link = match InviteLink::parse(&typed) {
                Some(link) if link.fits(&vault_id) => link,
                Some(_) => return self.sync_setup_failed("that invite is for another vault"),
                // Typed apart, only while those fields are open: the WebDAV form shares the
                // address field.
                None if app.get_sync_by_hand() && !app.get_sync_address().trim().is_empty() => {
                    let server = match sync::with_pin(&app.get_sync_address(), &app.get_sync_pin())
                    {
                        Ok(server) => server,
                        Err(err) => return self.sync_setup_failed(&format!("{err:#}")),
                    };
                    InviteLink {
                        server,
                        vault: vault_id.clone(),
                        invite: typed.to_ascii_lowercase(),
                        backup: None,
                    }
                }
                None => {
                    return self.sync_setup_failed(
                        "paste the whole line that starts with vaultsync:1? (from Add a device on your computer, or from vault-server invite), or type the server's address and the invite",
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
                move || -> Result<(DeviceId, Option<String>), String> {
                    let (_, device) = ids.join(&address, &vault_id, &link.invite)?;
                    Ok((device, join_backup(&link, &vault_id, device)))
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok((device, backup)) => {
                        app.set_sync_invite_typed(SharedString::new());
                        let main = SyncTo::Server { url: address };
                        let backup = backup.map(|url| SyncTo::Server { url });
                        if let Err(why) = joined(&vault_id, device, main, backup) {
                            return controller.sync_setup_failed(&why);
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
            let Some(link) = InviteLink::parse(&typed).filter(|link| !link.vault.is_empty()) else {
                // A line good for any vault can't say which one to fetch: the one from Add a
                // device on the computer (or `vault-server invite --vault`) does.
                return self.set_error(super::super::error::NOT_INVITE, "");
            };
            let address = match sync::check_address(&link.server) {
                Ok(address) => address,
                Err(err) => {
                    return self.set_error(super::super::error::SYNC_SETUP, &format!("{err:#}"));
                }
            };
            let vault_id = link.vault.clone();
            let Some(ids) = JoinIds::for_vault(&vault_id) else {
                return self.set_error(
                    super::super::error::SYNC_SETUP,
                    "this phone's state can't be written",
                );
            };
            self.set_error(super::super::error::NONE, "");
            app.set_sync_busy(true);
            let job = {
                let (vault_id, address) = (vault_id.clone(), address.clone());
                move || -> Result<(Vec<u8>, DeviceId, Option<String>), String> {
                    let (server, device) = ids.join(&address, &vault_id, &link.invite)?;
                    let backup = join_backup(&link, &vault_id, device);
                    let fetched = sync::fetch(&server, device, &Tags::new())
                        .map_err(|err| format!("{err:#}"))?;
                    // The biggest copy is the most likely to be the fullest; the first sync
                    // round after unlock merges every other one anyway.
                    fetched
                        .copies
                        .into_iter()
                        .max_by_key(|(_, bytes)| bytes.len())
                        .map(|(_, bytes)| (bytes, device, backup))
                        .ok_or_else(|| {
                            "no device has put the vault on the server yet: press Sync now on the computer first".to_owned()
                        })
                }
            };
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                app.set_sync_busy(false);
                match result {
                    Ok((bytes, device, backup)) => {
                        let main = SyncTo::Server { url: address };
                        let backup = backup.map(|url| SyncTo::Server { url });
                        if let Err(why) = joined(&vault_id, device, main, backup) {
                            return controller.set_error(super::super::error::SYNC_SETUP, &why);
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
        /// Whether vault `vault_id` syncs on this phone (a place is set up for it), open or not.
        pub(in crate::controller) fn syncs(vault_id: &str) -> bool {
            DeviceState::load()
                .ok()
                .and_then(|state| state.sync_place(vault_id))
                .is_some()
        }

        /// This phone stops syncing vault `vault_id` and forgets its keys there, without a word
        /// to the server (whose copies stay): its copy is being removed while it is locked.
        pub(in crate::controller) fn forget_sync_here(&self, vault_id: &str) {
            self.stop_sync();
            let Ok(mut device_state) = DeviceState::load() else {
                return;
            };
            if let Ok(device) = device_state.device_id_for(vault_id) {
                sync::forget_keys(vault_id, device);
            }
            device_state.set_sync_to(vault_id, None);
            let _ = device_state.save();
            let _ = secret_store::forget_webdav_password(vault_id);
        }

        pub(in crate::controller) fn sync_stop(&self) {
            self.stop_sync();
            let Some(vault_id) = self.vault_id() else {
                return;
            };
            let mut device_state = DeviceState::load().unwrap_or_default();
            device_state.set_sync_to(&vault_id, None);
            let _ = device_state.save();
            if let Some(device) = self.device_id() {
                sync::forget_keys(&vault_id, device);
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
            let (round, joined, before) = {
                let mut state = self.state.borrow_mut();
                let vault = state.vault.as_mut().expect("checked above");
                let before = vault.sync_devices().to_vec();
                let joined = sync::join(vault, place.device, DEVICE_NAME).unwrap_or(false)
                    | sync::retire(vault, &place.retired);
                (
                    sync::merge_reading(vault, &reading, &mut place.place.seen),
                    joined,
                    before,
                )
            };
            self.log_device_changes(&before);
            if round.removed_here {
                // Removed, not barred: the phone takes a new id for this vault and can join
                // again with a new invite, as a new device.
                let mut device_state = DeviceState::load().unwrap_or_default();
                if device_state.removed_from(&place.vault_id).is_err() {
                    device_state.set_sync_to(&place.vault_id, None);
                }
                let _ = device_state.save();
                sync::forget_keys(&place.vault_id, place.device);
                let _ = secret_store::forget_webdav_password(&place.vault_id);
                self.stop_sync();
                self.sync_setup_failed(
                    "this phone was removed from the vault on another device: to sync it again, join with a new invite",
                );
                self.state.borrow_mut().sync.running = false;
                return;
            }
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
                state.sync.tags = if waits_for_the_item_lock(&round) {
                    KnownTags::default()
                } else {
                    reading.tags(&state.sync.tags)
                };
            }
            let changed = round.changed() || joined;
            if changed {
                if !self.save_quietly() {
                    return self.sync_failed("the phone's copy couldn't be saved");
                }
                // Another device's item lock was taken: what the old one opened closes first.
                if round.reports.iter().any(|report| report.guard_changed) {
                    self.after_guard_changed();
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
            // Copies under another vault key: renewed on their device (its new Secret Key is
            // asked once), or still under a key this phone took.
            let mismatch = sync::key_mismatch(&place.vault_id, &reading, &round, &device_state);
            let merged: Vec<DeviceId> = round.reports.iter().map(|report| report.writer).collect();
            let tell_renewed = {
                let mut state = self.state.borrow_mut();
                state.sync.note_key_mismatch(mismatch, &merged);
                let renewed = !state.sync.renewed.is_empty();
                let told = std::mem::replace(&mut state.sync.renewed_told, renewed);
                renewed && !told
            };
            let came: usize = round
                .reports
                .iter()
                .map(|r| r.added + r.updated + r.removed)
                .sum();
            // Copies that couldn't be used, each said once (SYNC.md §8; those under another
            // vault key or waiting for the item lock are said apart), named in Settings, Sync.
            let problem = {
                let mut state = self.state.borrow_mut();
                let new = state.sync.problems.note(&reading, &round, unix_now());
                new.into_iter().next().map(|p| {
                    let name = state
                        .vault
                        .as_ref()
                        .and_then(|v| {
                            v.sync_devices()
                                .iter()
                                .find(|d| d.id == p.device)
                                .map(|d| d.name.clone())
                        })
                        .unwrap_or_default();
                    (p.refused, name)
                })
            };
            if tell_renewed {
                self.notify(notice::SYNC_KEY_RENEWED, "");
                self.show_sync();
            } else if let Some((refused, name)) = problem {
                let code = if refused {
                    notice::SYNC_REFUSED
                } else {
                    notice::SYNC_UNREADABLE
                };
                self.notify(code, &name);
                self.show_sync();
            } else if came > 0 {
                self.notify(notice::SYNCED, &came.to_string());
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

        /// Is there an update? Asked by itself (unless the person turned that off) while a
        /// vault is open: from GitHub at unlock and then every [`GITHUB_EVERY`], kept across
        /// restarts, so a new release reaches the phone within the hour; from the servers
        /// after the first round of an unlock, after Sync now, and otherwise at most every
        /// [`UPDATE_EVERY`] (rounds run every few minutes and after each save).
        pub(in crate::controller) fn ask_for_update_soon(&self) {
            if self.runs_inline()
                || !self.system().installs_updates()
                || !self.state.borrow().prefs.update_checks
                || self.state.borrow().vault.is_none()
            {
                return;
            }
            let now = unix_now();
            let github = self.updates_from_github();
            let (asked_at, every) = if github {
                let at = self.state.borrow().prefs.github_asked_at;
                ((at != 0).then_some(at), GITHUB_EVERY)
            } else {
                (self.state.borrow().sync.update_asked_at, UPDATE_EVERY)
            };
            if asked_at.is_some_and(|at| now >= at && now - at < every) {
                return;
            }
            if github {
                self.change_prefs(|prefs| prefs.github_asked_at = now);
            } else {
                self.state.borrow_mut().sync.update_asked_at = Some(now);
            }
            self.ask_for_update(true);
        }

        fn updates_from_github(&self) -> bool {
            self.state.borrow().prefs.update_source != prefs::UPDATES_FROM_SERVER
        }

        /// Where updates are looked for now; `None` when they come from the servers and the
        /// open vault syncs through none.
        fn update_source(&self) -> Option<Source> {
            if self.updates_from_github() {
                let github = self.state.borrow().sync.github.unwrap_or(Github::REAL);
                return Some(Source::Github(github));
            }
            let place = self.sync_place()?;
            let keys = self.release_keys();
            (!Self::update_servers(&place).is_empty())
                .then_some(Source::Servers(Box::new(place), keys))
        }

        /// The keys a release manifest must be signed with.
        fn release_keys(&self) -> Vec<String> {
            self.state
                .borrow()
                .sync
                .release_keys
                .clone()
                .unwrap_or_else(|| releases::RELEASE_KEYS.map(str::to_owned).to_vec())
        }

        /// Settings → About and updates → "Get updates from": GitHub (0) or the vault's
        /// servers (1). What was found at the other place is forgotten.
        pub(in crate::controller) fn update_source_changed(&self, index: i32) {
            let source = if index == 1 {
                prefs::UPDATES_FROM_SERVER
            } else {
                prefs::UPDATES_FROM_GITHUB
            };
            self.change_prefs(|prefs| prefs.update_source = source);
            self.state.borrow_mut().sync.update_asked_at = None;
            let app = self.app();
            app.set_update_source(i32::from(source));
            app.set_update_state(0);
            app.set_update_version(SharedString::new());
        }

        /// Settings → About and updates → "Look for updates by itself".
        pub(in crate::controller) fn update_checks_changed(&self, on: bool) {
            self.change_prefs(|prefs| prefs.update_checks = on);
            if on {
                self.ask_for_update_soon();
            }
        }

        /// Tests: GitHub answers through `github` instead of the network.
        #[cfg(test)]
        pub(crate) fn use_github(&self, github: Github) {
            self.state.borrow_mut().sync.github = Some(github);
        }

        /// Tests: a server's update is checked with `keys` (test keys) instead of the
        /// project's.
        #[cfg(test)]
        pub(crate) fn use_release_keys(&self, keys: Vec<String>) {
            self.state.borrow_mut().sync.release_keys = Some(keys);
        }

        /// Settings → Sync now: a round, and the servers asked for an update after it.
        pub(in crate::controller) fn sync_now(&self) {
            self.state.borrow_mut().sync.update_asked_at = None;
            self.sync_round();
        }

        /// The update sheet closed with Later: that version isn't offered again until the
        /// next unlock (Settings → Updates still has it).
        pub(in crate::controller) fn update_put_off(&self) {
            let version = self.app().get_update_version().to_string();
            if !version.is_empty() {
                self.state.borrow_mut().sync.update_put_off = Some(version);
            }
        }

        fn sync_finished(&self) {
            self.state.borrow_mut().sync.running = false;
            self.app().set_sync_detail(SharedString::new());
            self.show_sync();
            self.ask_for_update_soon();
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

        /// The servers the vault syncs through (main, then backup), by role.
        fn update_servers(place: &Place) -> Vec<(String, Role)> {
            let mut servers = Vec::new();
            if let SyncTo::Server { url } = &place.place.to {
                servers.push((url.clone(), Role::Main));
            }
            if let Some(SyncTo::Server { url }) = &place.place.backup {
                servers.push((url.clone(), Role::Backup));
            }
            servers
        }

        /// Asks `source` for the phone app's newest version (off the UI thread) and compares it
        /// with `installed`.
        fn newest_release(source: &Source, installed: &str) -> Result<Release, String> {
            match source {
                Source::Github(github) => {
                    let release = (github.latest)()?;
                    if !release.is_newer_than(installed) {
                        return Ok(Release::Newest(release.version().to_owned()));
                    }
                    release
                        .phone_package()
                        .map_err(|err| format!("release {}: {err}", release.version()))?;
                    Ok(Release::Newer(release.version().to_owned(), None))
                }
                Source::Servers(place, keys) => Self::newest_on_servers(place, keys, installed),
            }
        }

        /// Asks every server the vault syncs through for the phone app's update and compares
        /// the newest one with `installed`. An update is offered only when its release's
        /// manifest, which the server hands on, is signed by one of `keys` and lists the
        /// package the server has (`releases::verify_app_release`): a server can withhold an
        /// update, never make one. A server that doesn't answer is an error only when none
        /// answered; an update refused is one only when no other server has one.
        fn newest_on_servers(
            place: &Place,
            keys: &[String],
            installed: &str,
        ) -> Result<Release, String> {
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            let mut newest: Option<(vault_sync_wire::AppRelease, Role)> = None;
            let mut there: Option<String> = None;
            let (mut failed, mut refused) = (None, None);
            let mut answered = false;
            for (url, role) in Self::update_servers(place) {
                let asked = Self::server_for(place, &url, role)
                    .and_then(|server| server.app_release().map_err(|err| format!("{err:#}")));
                let release = match asked {
                    Ok(release) => {
                        answered = true;
                        release
                    }
                    Err(why) => {
                        failed = failed.or(Some(why));
                        continue;
                    }
                };
                let Some(release) = release else {
                    continue;
                };
                if !vault_sync_wire::is_newer(&release.version, installed) {
                    // Not an update: only said as the newest there is.
                    if there
                        .as_deref()
                        .is_none_or(|known| vault_sync_wire::is_newer(&release.version, known))
                    {
                        there = Some(release.version);
                    }
                    continue;
                }
                if let Err(err) = releases::verify_app_release(&release, &keys) {
                    refused = refused.or(Some(format!("version {}: {err}", release.version)));
                    continue;
                }
                if newest.as_ref().is_none_or(|(known, _)| {
                    vault_sync_wire::is_newer(&release.version, &known.version)
                }) {
                    newest = Some((release, role));
                }
            }
            if !answered {
                return Err(
                    failed.unwrap_or_else(|| "this vault doesn't sync through a server".into())
                );
            }
            if let Some((release, role)) = newest {
                return Ok(Release::Newer(release.version, Some(role)));
            }
            if let Some(why) = refused {
                return Err(format!("the server's update isn't taken: {why}"));
            }
            Ok(there.map_or(Release::Nothing, Release::Newest))
        }

        /// Settings → Updates: asks GitHub, or the vault servers (what their owner put there,
        /// or the server itself, following the releases), for the phone app's update.
        pub(in crate::controller) fn check_update(&self) {
            self.ask_for_update(false);
        }

        /// Asks for an update; `quietly` (on its own) only a newer version is told, and
        /// nothing that went wrong.
        fn ask_for_update(&self, quietly: bool) {
            let Some(source) = self.update_source() else {
                return;
            };
            let installed = self.app().get_app_version().to_string();
            if !quietly {
                self.app().set_update_state(update::ASKING);
            }
            let from_github = matches!(source, Source::Github(_));
            let job = move || Self::newest_release(&source, &installed);
            self.off_thread(job, move |controller, result| {
                let app = controller.app();
                match result {
                    Ok(Release::Newer(version, _)) => {
                        app.set_update_version(version.as_str().into());
                        app.set_update_state(update::WAITING);
                        let put_off = controller.state.borrow().sync.update_put_off.as_deref()
                            == Some(version.as_str());
                        if quietly && !put_off {
                            // Asked in a sheet over the open vault; while another sheet is
                            // up (a password being typed), a notice says it instead.
                            if app.get_screen() == crate::ui::Screen::Vault
                                && app.get_confirming() == 0
                            {
                                app.invoke_ask(super::super::sheet::UPDATE);
                            } else {
                                controller.notify(super::super::notice::UPDATE_READY, &version);
                            }
                        }
                    }
                    // GitHub not reached on its own (the network is often not back yet
                    // right after the phone wakes): asked again in a few minutes, not an hour.
                    Err(_) if quietly && from_github => {
                        let again = unix_now() - GITHUB_EVERY + GITHUB_RETRY;
                        controller.change_prefs(|prefs| prefs.github_asked_at = again);
                    }
                    _ if quietly => {}
                    Ok(Release::Newest(version)) => {
                        app.set_update_version(version.into());
                        app.set_update_state(update::NEWEST);
                    }
                    Ok(Release::Nothing) => app.set_update_state(update::NONE_PUBLISHED),
                    Err(why) => {
                        controller.set_error(error::UPDATE, &why);
                        app.set_update_state(update::FAILED);
                    }
                }
            });
        }

        /// "Install version …": the package is fetched from GitHub or the server that has it,
        /// checked against its release's signed manifest (size and SHA-256) and handed to
        /// Android's installer, once this app has checked it is this app, newer and signed with
        /// the same certificate (`Updates.java`); Android asks the person and checks the
        /// signature again.
        pub(in crate::controller) fn install_update(&self) {
            let Some(source) = self.update_source() else {
                return;
            };
            let installed = self.app().get_app_version().to_string();
            self.app().set_update_state(update::FETCHING);
            let job = move || -> Result<Vec<u8>, String> {
                match source {
                    Source::Github(github) => {
                        let release = (github.latest)()?;
                        if !release.is_newer_than(&installed) {
                            return Err("GitHub has no newer version any more".into());
                        }
                        (github.package)(&release)
                    }
                    Source::Servers(place, keys) => {
                        Self::package_from_servers(&place, &keys, &installed)
                    }
                }
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

        /// The newer package from the server that has it, checked against its release and that
        /// release's signed manifest (again: the server may have changed it since).
        fn package_from_servers(
            place: &Place,
            keys: &[String],
            installed: &str,
        ) -> Result<Vec<u8>, String> {
            let Release::Newer(_, Some(role)) = Self::newest_on_servers(place, keys, installed)?
            else {
                return Err("the server has no newer version any more".into());
            };
            let (url, _) = Self::update_servers(place)
                .into_iter()
                .find(|(_, r)| *r == role)
                .ok_or("the server has no newer version any more")?;
            let server = Self::server_for(place, &url, role)?;
            let release = server
                .app_release()
                .map_err(|err| format!("{err:#}"))?
                .filter(|r| vault_sync_wire::is_newer(&r.version, installed))
                .ok_or("the server has no newer version any more")?;
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            releases::verify_app_release(&release, &keys)
                .map_err(|err| format!("the server's update isn't taken: {err}"))?;
            server
                .app_package(&release)
                .map_err(|err| format!("{err:#}"))
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
            // A new address without a pin keeps the certificate this phone knows: the server's
            // own certificate authority stays when it moves (docs/SERVER.md).
            let typed = app.get_sync_new_address().trim().to_owned();
            let typed = match &place.place.to {
                SyncTo::Server { url } if !typed.contains("#pin=") => match sync::split_pin(url) {
                    (_, Some(pin)) => {
                        let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
                        format!("{typed}#pin={hex}")
                    }
                    _ => typed,
                },
                _ => typed,
            };
            let address = match sync::check_address(&typed) {
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
            app.set_sync_busy(true);
            let job = {
                let (vault_id, address) = (vault_id.clone(), address.clone());
                move || -> Result<(), String> {
                    sync::join_server(
                        &address,
                        &vault_id,
                        &[],
                        device,
                        DEVICE_NAME,
                        &invite,
                        Role::Backup,
                    )
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
            self.log_event(super::super::security::kind::DEVICE_REMOVED, "", "", &name);
            self.notify(super::super::notice::DEVICE_REMOVED, &name);
            if let Some(place) = self.sync_place() {
                let job = move || {
                    let backup = place.place.backup.as_ref().map(|to| (to, Role::Backup));
                    for (to, role) in std::iter::once((&place.place.to, Role::Main)).chain(backup) {
                        let _ = sync::open_target_as(&place.vault_id, place.device, to, role)
                            .and_then(|target| target.remove(id));
                    }
                };
                // A copy left behind is refused anyway: nothing to say if it couldn't go.
                self.off_thread(job, |_, ()| {});
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
                let here = state.sync.here.as_ref();
                let offset = self.system().utc_offset_minutes();
                let problems = &state.sync.problems;
                let rows: Vec<DeviceRow> = devices
                    .iter()
                    .map(|d| DeviceRow {
                        problem: problems
                            .of(d.id)
                            .map(|p| p.why.as_str().into())
                            .unwrap_or_default(),
                        problem_at: problems
                            .of(d.id)
                            .map(|p| view::date_time(p.at, offset).into())
                            .unwrap_or_default(),
                        refused: problems.of(d.id).is_some_and(|p| p.refused),
                        name: d.name.as_str().into(),
                        added: view::date(d.added_at).into(),
                        own: d.id == own,
                        // Listed in the vault, but without a copy where it syncs now: it
                        // synced through another place, or hasn't joined this one yet.
                        away: d.id != own && here.is_some_and(|here| !here.contains(&d.id)),
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
            app.set_updates_available(self.system().installs_updates());
            app.set_update_servers(through_server);
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
            // The address as typed, without the certificate's pin (a long hex string kept for
            // the connection only); that it is pinned shows apart.
            let (address, pinned) = match &place.to {
                SyncTo::Server { url } | SyncTo::Webdav { url, .. } => {
                    let (address, pin) = sync::split_pin(url);
                    (address.to_owned(), pin.is_some())
                }
                other => (other.describe(), false),
            };
            app.set_sync_place(SharedString::from(address.as_str()));
            app.set_sync_pinned(pinned);
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
            let state = self.state.borrow();
            app.set_sync_key_renewed(!state.sync.renewed.is_empty());
            app.set_sync_key_behind(i32::try_from(state.sync.behind.len()).unwrap_or(i32::MAX));
        }

        /// Settings, Sync, "Type the new Secret Key" (sheet `TAKE_KEY`): the Secret Key of the
        /// kit made where the vault key was renewed, and the master password, open one of the
        /// copies sealed under the new key; this phone takes it (`sync::take_renewed_key`).
        /// The file is written only over what was read, and kept only together with the new
        /// Secret Key, as after a recovery with two parts.
        pub(in crate::controller) fn sync_take_key(&self) {
            if self.app().get_busy() {
                return;
            }
            let Ok(new_key) = SecretKey::parse(&self.secret(field::SECRET_KEY)) else {
                return self.set_error(error::SECRET_KEY, "");
            };
            let master = self.secret(field::EXPORT_MASTER);
            if master.is_empty() {
                return self.set_error(error::WRONG_CURRENT, "");
            }
            let copies = self.state.borrow().sync.renewed.clone();
            if copies.is_empty() {
                return self.close_sheet(sheet::TAKE_KEY);
            }
            self.set_error(error::NONE, "");
            let Some((vault, secret_key, session)) = self.lend_vault() else {
                return;
            };
            self.run(
                move || {
                    let mut vault = vault;
                    let snapshot = vault.snapshot();
                    let mut state = DeviceState::load();
                    let outcome = match state.as_mut() {
                        Err(err) => Err((error::UNREADABLE, format!("{err:#}"))),
                        Ok(state) => match sync::take_renewed_key(
                            &mut vault, &copies, &master, &new_key, None, state,
                        ) {
                            Ok(Some(former)) => Ok(former),
                            Ok(None) | Err(CoreError::DecryptionFailed) => {
                                Err((error::KEY_NOT_TAKEN, String::new()))
                            }
                            Err(err) => Err((error::UNREADABLE, err.to_string())),
                        },
                    };
                    Taken {
                        vault,
                        secret_key,
                        new_key,
                        snapshot,
                        state: state.ok(),
                        outcome,
                    }
                },
                move |c, taken| c.key_taken(taken, session),
            );
        }

        fn key_taken(&self, taken: Taken, session: u64) {
            let Taken {
                vault,
                secret_key,
                new_key,
                snapshot,
                state,
                outcome,
            } = taken;
            // Locked meanwhile: nothing was written, and the copy that took the key goes.
            if !self.take_back(vault, secret_key, session) {
                return;
            }
            let former = match outcome {
                Ok(former) => former,
                Err((code, detail)) => {
                    self.clear_fields(&[field::EXPORT_MASTER]);
                    return self.set_error(code, &detail);
                }
            };
            let put_back = |c: &Controller, snapshot, former| {
                if let Some(vault) = c.state.borrow_mut().vault.as_mut() {
                    let _ = vault.put_back_key(snapshot, former);
                }
            };
            let not_kept = match self.write_taken_key(&new_key) {
                Ok(()) => None,
                Err(NotKept::OnlyNew(why)) => Some(why),
                Err(NotKept::NotWritten(why)) => {
                    put_back(self, snapshot, former);
                    return self.set_error(error::NOT_SAVED, &why);
                }
                Err(NotKept::PutBack(why)) => {
                    put_back(self, snapshot, former);
                    return self.set_error(error::TAKE_NOT_KEPT, &why);
                }
            };
            let (id, revision) = {
                let mut state = self.state.borrow_mut();
                state.secret_key = Some(new_key);
                let vault = state.vault.as_ref().expect("taken back above");
                (vault.id_hex(), vault.revision())
            };
            if let Some(mut state) = state {
                state.record_revision(&id, revision);
                let _ = state.save();
            }
            let bio = self.reseal_after_new_key(&former);
            self.reseal_security_log(&former);
            drop(former);
            self.log_event(super::super::security::kind::KEY_RENEWED, "", "", "taken");
            self.clear_fields(&[field::SECRET_KEY, field::EXPORT_MASTER]);
            self.close_sheet(sheet::TAKE_KEY);
            // The copies refused until now are read again, under the new key; what that
            // round brings is said first, so the word about the key stays on screen.
            self.state.borrow_mut().sync.key_changed();
            self.show_sync();
            self.refresh_security();
            self.sync_round();
            match not_kept {
                Some(why) => self.set_error(error::TAKE_ONLY_NEW, &why),
                None => self.notify(notice::KEY_TAKEN, if bio { "1" } else { "" }),
            }
        }

        /// Writes the vault (a renewed key just taken) over the phone's copy while it still
        /// holds what this app read or wrote, then keeps `new_key` for it; when that fails,
        /// the copy is put back as it was.
        fn write_taken_key(&self, new_key: &SecretKey) -> Result<(), NotKept> {
            let (path, expected, bytes, id) = {
                let mut state = self.state.borrow_mut();
                let state = &mut *state;
                let vault = state
                    .vault
                    .as_mut()
                    .ok_or_else(|| NotKept::NotWritten("the vault is locked".to_owned()))?;
                let bytes = vault
                    .to_bytes()
                    .map_err(|err| NotKept::NotWritten(err.to_string()))?;
                (state.path.clone(), state.file_hash, bytes, vault.id_hex())
            };
            let before = files::read(&path).map_err(|err| NotKept::NotWritten(err.to_string()))?;
            if expected.is_some_and(|hash| fingerprint(&before) != hash) {
                return Err(NotKept::NotWritten(
                    "the file was changed by something else".to_owned(),
                ));
            }
            files::write_atomic(&path, &bytes)
                .map_err(|err| NotKept::NotWritten(err.to_string()))?;
            let written = fingerprint(&bytes);
            if let Err(detail) = self.keep_secret_key(&id, new_key) {
                // Back as it was, unless something else wrote it in this moment.
                let back = match files::read(&path) {
                    Ok(now) if fingerprint(&now) == written => {
                        files::write_atomic(&path, &before).map_err(|err| err.to_string())
                    }
                    Ok(_) => Err("the vault file was changed by something else".to_owned()),
                    Err(err) => Err(err.to_string()),
                };
                return Err(match back {
                    Ok(()) => NotKept::PutBack(detail),
                    Err(back) => {
                        self.state.borrow_mut().file_hash = Some(written);
                        NotKept::OnlyNew(format!("{detail}; {back}"))
                    }
                });
            }
            self.state.borrow_mut().file_hash = Some(written);
            Ok(())
        }

        /// What this phone sealed with the former vault key (the generator's history, website
        /// icons, the leak watch, the drop box for autofill) sealed again under the new one.
        /// Fingerprint unlock, whose copy of the key opens nothing any more, is turned off:
        /// `true` when it was on.
        fn reseal_after_new_key(&self, former: &FormerKey) -> bool {
            let folder = self.folder();
            let id = {
                let state = self.state.borrow();
                let Some(vault) = state.vault.as_ref() else {
                    return false;
                };
                let id = vault.id_hex();
                let beside = |name: String| state.path.with_file_name(name);
                let reseal = vault_platform::files::reseal;
                reseal(
                    &beside(format!("generated-{id}.history")),
                    vault,
                    former,
                    super::super::generated::PURPOSE,
                );
                reseal(&beside(format!("icons-{id}.cache")), vault, former, "icons");
                reseal(
                    &folder.join(format!("leak-watch-{id}.bin")),
                    vault,
                    former,
                    vault_platform::leak_check::WATCH_PURPOSE,
                );
                crate::autofill::reseal_drop_box(&folder, vault, former);
                id
            };
            let bio = crate::bio::read(&folder, &id).is_some();
            if bio {
                self.forget_biometrics(&id);
            }
            bio
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

    /// Whether something of this round waits for the item lock: items a merge left as they
    /// were here, or a whole copy refused until this phone's own lock is open (it brings a
    /// newer item lock). Then no copy's tag is kept, so the next round reads them again
    /// instead of skipping them as already merged.
    fn waits_for_the_item_lock(round: &sync::Round) -> bool {
        round.waiting_for_lock() > 0
            || round
                .refused
                .iter()
                .any(|(_, err)| matches!(err, vault_core::Error::SecretsLocked))
    }

    /// How often the servers are asked for an update between rounds (seconds).
    const UPDATE_EVERY: i64 = 10 * 60;
    /// How often GitHub is asked while a vault is open, and at most at unlock (seconds): one
    /// small anonymous request an hour, so a fix reaches the phone soon after its release.
    const GITHUB_EVERY: i64 = 60 * 60;
    /// After GitHub couldn't be reached on its own, it is asked again this soon (seconds).
    const GITHUB_RETRY: i64 = 5 * 60;

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    #[cfg(test)]
    mod tests {
        use vault_core::sync::{DeviceId, MergeReport};
        use vault_platform::sync::Round;

        use super::waits_for_the_item_lock;

        #[test]
        fn a_copy_refused_until_the_item_lock_opens_is_read_again() {
            let other = DeviceId::from_bytes([7; 16]);
            assert!(!waits_for_the_item_lock(&Round::default()));
            // Refused for another reason (an older copy put back): not read again for nothing.
            let rollback = Round {
                refused: vec![(other, vault_core::Error::SyncRollback)],
                ..Round::default()
            };
            assert!(!waits_for_the_item_lock(&rollback));
            // Refused whole until this phone's lock is open: waits like a merged copy's items.
            let locked = Round {
                refused: vec![(other, vault_core::Error::SecretsLocked)],
                ..Round::default()
            };
            assert!(waits_for_the_item_lock(&locked));
            let merged = Round {
                reports: vec![MergeReport {
                    waiting_for_lock: 1,
                    ..MergeReport::default()
                }],
                ..Round::default()
            };
            assert!(waits_for_the_item_lock(&merged));
        }
    }
}
