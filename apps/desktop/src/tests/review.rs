//! Headless tests for what the review of the 2026-11-25 audit fixes found: results of
//! background jobs bound to the vault and session they were started for, the tray's lock, an
//! item lock changed on another device, what the browser is told about writes, and filling
//! while locked after the upgrade.

use std::{
    cell::Cell,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, ItemData, KdfParams, SecretKey, Unlock, Vault, sync::DeviceId};
use vault_platform::{
    paths,
    quick_unlock::{self, DeviceVerifier},
    secret_store,
};

use super::{FakeHello, ForgetOnDrop, PASSWORD, app_home, type_into};
use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, ItemLock, Panel, Screen},
};

/// Field numbers (controller.rs `field`).
const MASTER: i32 = 0;
const ITEM_PASSWORD: i32 = 4;
const REPROMPT: i32 = 11;
const GUARD_NEW: i32 = 12;
const GUARD_CURRENT: i32 = 13;
const PAIRING: i32 = 14;

/// A vault file at `dir/name` with one login per `(title, password)`, its Secret Key in the
/// credential store (forgotten when the returned guard drops).
pub(super) fn vault_file(
    dir: &Path,
    name: &str,
    logins: &[(&str, &str)],
    lock: impl FnOnce(&mut Vault),
) -> (PathBuf, SecretKey, ForgetOnDrop) {
    let path = dir.join(name);
    let key = SecretKey::generate().unwrap();
    let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    for (title, password) in logins {
        let site = format!("https://{}.example", title.to_lowercase());
        vault
            .add_item(&ItemData::login(title, "me", password, &site))
            .unwrap();
    }
    lock(&mut vault);
    vault.lock_secrets();
    std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    secret_store::store(&vault.id_hex(), &key).unwrap();
    (path, key, ForgetOnDrop(vault.id_hex()))
}

pub(super) fn open_file(path: &Path, key: &SecretKey) -> Vault {
    Vault::open(
        &std::fs::read(path).unwrap(),
        Unlock::Password {
            password: PASSWORD,
            secret_key: key,
        },
    )
    .unwrap()
}

/// The app on `path`, unlocked.
pub(super) fn open_app(path: &Path, hello: Option<Arc<FakeHello>>) -> (AppWindow, Rc<Controller>) {
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let verifier = hello.map(|hello| hello as Arc<dyn DeviceVerifier>);
    let controller =
        Controller::install(&app, path.to_path_buf(), Runner::Inline, verifier).unwrap();
    crate::i18n::apply("en");
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    (app, controller)
}

fn select(app: &AppWindow, title: &str) {
    app.invoke_select_category(0);
    let index = app
        .get_items()
        .iter()
        .position(|row| row.title == title)
        .unwrap_or_else(|| panic!("{title} is listed"));
    app.invoke_select(i32::try_from(index).unwrap());
}

fn waiting(app: &AppWindow) -> i32 {
    app.global::<ItemLock>().get_waiting()
}

/// Puts `vault`'s copy as another device's in the sync folder `dir`, as that device's sync
/// would.
pub(super) fn publish(dir: &Path, vault: &mut Vault, device: DeviceId) {
    let devices = dir.join(vault.id_hex()).join("devices");
    std::fs::create_dir_all(&devices).unwrap();
    std::fs::write(
        devices.join(format!("{}.vault", device.to_hex())),
        vault.to_bytes().unwrap(),
    )
    .unwrap();
}

// ---- PM-19: a result counts only for the vault and session it was started for ----

#[test]
fn an_unlock_that_finishes_after_another_vault_was_chosen_opens_nothing() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (first, _, _forget_first) = vault_file(dir.path(), "a.vault", &[("Alpha", "a-pw")], |_| {});
    let (second, second_key, _forget_second) =
        vault_file(dir.path(), "b.vault", &[("Bravo", "b-pw")], |_| {});
    let second_bytes = std::fs::read(&second).unwrap();
    let (app, controller) = open_app(&first, None);

    // The unlock of the first vault comes back once the second one is on screen.
    controller.unlock_finishes_after_switching_to(second.clone());
    assert_eq!(
        app.get_screen(),
        Screen::Unlock,
        "the second one's lock screen"
    );
    assert_eq!(std::fs::read(&second).unwrap(), second_bytes, "untouched");

    // Opened, it is the second vault, and what it saves is its own.
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    select(&app, "Bravo");
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let saved = open_file(&second, &second_key);
    let titles: Vec<String> = saved
        .item_ids()
        .map(|id| saved.get_item(&id).unwrap().title.clone())
        .collect();
    assert_eq!(titles, ["Bravo"]);
}

#[test]
fn the_tray_locks_a_vault_a_job_holds() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, _, _forget) = vault_file(dir.path(), "t.vault", &[("Alpha", "a-pw")], |_| {});
    let (app, controller) = open_app(&path, None);
    controller.tray_lock_while_a_job_holds_the_vault(|locked| {
        assert!(!locked, "open while the job holds it: Lock now is offered");
    });
    assert_eq!(
        app.get_screen(),
        Screen::Unlock,
        "the job's result was dropped"
    );
    assert!(!app.get_secrets_open());
    assert!(Controller::tray_status().unwrap().0, "locked");
}

#[test]
fn a_backup_is_checked_before_the_target_is_touched() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, _, _forget) = vault_file(dir.path(), "k.vault", &[("Alpha", "a-pw")], |_| {});
    let (app, controller) = open_app(&path, None);
    let vault_bytes = std::fs::read(&path).unwrap();
    // The vault file itself is never a backup's target.
    controller.save_confirmed_backup(&path);
    assert_ne!(app.get_error_code(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), vault_bytes);
    // A good backup, then a save that fails: the copy in memory is a revision ahead of the
    // file. A backup made now is refused before the good one is replaced.
    let backup = dir.path().join("backup.vault");
    controller.save_confirmed_backup(&backup);
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let good = std::fs::read(&backup).unwrap();
    #[cfg(windows)]
    {
        let writable = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = writable.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        select(&app, "Alpha");
        app.invoke_toggle_favorite();
        std::fs::set_permissions(&path, writable).unwrap();
        assert_eq!(app.get_notice_code(), 23, "not saved");
        controller.save_confirmed_backup(&backup);
        assert_ne!(app.get_error_code(), 0, "not the revision open here");
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            good,
            "the good backup stays"
        );
    }
}

/// Settings → Item lock: every item behind PIN `pin`, with Windows Hello. Saved with the
/// master password.
fn set_lock(app: &AppWindow, pin: &str) {
    app.invoke_open_settings();
    app.set_guard_check(1);
    app.set_guard_all(true);
    app.set_guard_hello(true);
    type_into(app, GUARD_NEW, pin);
    type_into(app, GUARD_CURRENT, PASSWORD);
}

#[test]
fn an_item_lock_change_that_comes_back_after_the_vault_locked_changes_nothing() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, _, _forget) = vault_file(dir.path(), "g.vault", &[("Bank", "bank-secret")], |_| {});
    let hello = Arc::new(FakeHello::default());
    let (app, controller) = open_app(&path, Some(hello));
    // The generator's result on screen when the lock is saved goes with what was open (it
    // may be a locked login's password now).
    app.invoke_open_generator();
    set_lock(&app, "4821");
    assert!(controller.generated_result().is_some());
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_gen_result(), "");
    assert_eq!(controller.generated_result(), None);
    let id = app.get_vault_id().to_string();
    assert!(quick_unlock::item_lock_enrolled(&id));
    let saved = std::fs::read(&path).unwrap();

    // Another PIN, whose Windows Hello prompt is answered after the vault locked.
    controller.guard_change_finishes_after_lock("9137", PASSWORD);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(
        app.get_notice_code(),
        82,
        "the person is told it was not changed"
    );
    assert_eq!(std::fs::read(&path).unwrap(), saved, "nothing written");
    assert!(
        !quick_unlock::item_lock_enrolled(&id),
        "Windows Hello's key was made again: its copy for the earlier lock opens no more"
    );

    // The earlier PIN is still the lock.
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    select(&app, "Bank");
    type_into(&app, REPROMPT, "9137");
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 35, "never set");
    type_into(&app, REPROMPT, "4821");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
}

#[cfg(windows)]
#[test]
fn an_item_lock_change_that_cant_be_written_is_undone() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, key, _forget) =
        vault_file(dir.path(), "r.vault", &[("Bank", "bank-secret")], |_| {});
    let hello = Arc::new(FakeHello::default());
    let (app, _controller) = open_app(&path, Some(hello));
    set_lock(&app, "4821");
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let id = app.get_vault_id().to_string();
    assert!(quick_unlock::item_lock_enrolled(&id));

    // Another PIN, which the disk refuses.
    let writable = std::fs::metadata(&path).unwrap().permissions();
    let mut readonly = writable.clone();
    readonly.set_readonly(true);
    std::fs::set_permissions(&path, readonly).unwrap();
    set_lock(&app, "9137");
    app.invoke_save_guard();
    std::fs::set_permissions(&path, writable).unwrap();
    assert_eq!(app.get_notice_code(), 23, "not saved");
    assert!(
        !quick_unlock::item_lock_enrolled(&id),
        "Windows Hello was set up for a lock never written: forgotten"
    );

    // Memory holds the lock the file holds: the earlier PIN.
    select(&app, "Bank");
    assert!(app.get_detail_locked());
    type_into(&app, REPROMPT, "9137");
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 35, "rolled back");
    type_into(&app, REPROMPT, "4821");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    let mut on_disk = open_file(&path, &key);
    assert!(on_disk.unlock_secrets("4821").unwrap());
}

// ---- PM-13: an item lock changed on another device ----

/// A vault whose PIN lock (4821, every item) seals the login "Bank" here, and another
/// device's copy where the lock was set again with PIN 9137: another key.
fn lock_changed_elsewhere(dir: &Path) -> (PathBuf, SecretKey, ForgetOnDrop, PathBuf) {
    let (path, key, forget) = vault_file(dir, "v.vault", &[("Bank", "bank-secret")], |vault| {
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("4821"), Some(PASSWORD))
            .unwrap();
    });
    let sync_dir = dir.join("sync folder");
    let mut phone = open_file(&path, &key);
    let device = DeviceId::from_bytes([0x42; 16]);
    phone.set_device(device);
    assert!(phone.unlock_secrets("4821").unwrap());
    phone
        .set_item_guard(true, GuardCheck::Master, None, None)
        .unwrap();
    phone
        .set_item_guard(true, GuardCheck::Pin, Some("9137"), Some(PASSWORD))
        .unwrap();
    phone.lock_secrets();
    publish(&sync_dir, &mut phone, device);
    (path, key, forget, sync_dir)
}

#[test]
fn a_newer_item_lock_waits_and_moves_once_both_pins_are_typed() {
    i_slint_backend_testing::init_no_event_loop();
    // The new PIN first (on a locked item), or this computer's own first (then Settings asks
    // for the new one): either way the locked items move to the new lock.
    for newer_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let _turn = app_home(&dir.path().join("home"));
        let (path, key, _forget, sync_dir) = lock_changed_elsewhere(dir.path());
        let (app, controller) = open_app(&path, None);

        // The first round runs with the item lock closed: the other copy is refused whole,
        // and that counts as waiting (it is read again once the lock opens).
        controller.sync_start(sync_dir.clone());
        assert_eq!(waiting(&app), 1, "a newer lock that opens with a PIN");
        assert_eq!(app.get_notice_code(), 80, "told once");
        assert!(app.get_sync_waiting() > 0);
        app.set_notice_code(0);
        controller.sync_round();
        assert_ne!(app.get_notice_code(), 80, "not at every round");
        assert_eq!(waiting(&app), 1);

        select(&app, "Bank");
        assert!(app.get_detail_locked());
        if newer_first {
            type_into(&app, REPROMPT, "9137");
            app.invoke_unlock_item();
            assert_eq!(
                app.get_error_code(),
                60,
                "not a wrong try: the earlier PIN next"
            );
            assert!(app.get_detail_locked() && !app.get_secrets_open());
            type_into(&app, REPROMPT, "4821");
            app.invoke_unlock_item();
        } else {
            type_into(&app, REPROMPT, "4821");
            app.invoke_unlock_item();
            assert!(app.get_secrets_open(), "this computer's own lock is open");
            assert_eq!(waiting(&app), 1, "the new lock still waits for its PIN");
            app.invoke_open_settings();
            type_into(&app, REPROMPT, "9137");
            app.invoke_unlock_item();
        }
        assert_eq!(
            app.get_notice_code(),
            81,
            "moved: {}",
            app.get_error_detail()
        );
        assert_eq!(waiting(&app), 0);
        assert!(
            !app.get_secrets_open(),
            "what the earlier lock opened is closed"
        );

        // From now on the new PIN opens it, here and in the file.
        select(&app, "Bank");
        assert!(app.get_detail_locked());
        type_into(&app, REPROMPT, "4821");
        app.invoke_unlock_item();
        assert_eq!(app.get_error_code(), 35, "the earlier PIN is wrong now");
        type_into(&app, REPROMPT, "9137");
        app.invoke_unlock_item();
        assert!(!app.get_detail_locked());
        app.invoke_reveal();
        assert_eq!(app.get_revealed_password(), "bank-secret");
        let mut saved = open_file(&path, &key);
        assert!(!saved.unlock_secrets("4821").unwrap());
        assert!(saved.unlock_secrets("9137").unwrap());
        let bank = saved.item_ids().next().unwrap();
        assert_eq!(saved.get_item(&bank).unwrap().password, "bank-secret");
        drop(controller);
    }
}

#[test]
fn taking_another_devices_lock_closes_what_the_replaced_one_opened() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    // The master password as the item lock here (nothing encrypted)...
    let (path, key, _forget) =
        vault_file(dir.path(), "m.vault", &[("Mail", "mail-secret")], |vault| {
            vault
                .set_item_guard(true, GuardCheck::Master, None, None)
                .unwrap();
        });
    // ...and a PIN lock set on the phone, which holds a login sealed under it.
    let sync_dir = dir.path().join("sync folder");
    let mut phone = open_file(&path, &key);
    let device = DeviceId::from_bytes([0x43; 16]);
    phone.set_device(device);
    phone
        .set_item_guard(true, GuardCheck::Pin, Some("9137"), Some(PASSWORD))
        .unwrap();
    phone
        .add_item(&ItemData::login(
            "Bank",
            "me",
            "bank-secret",
            "https://bank.example",
        ))
        .unwrap();
    phone.lock_secrets();
    publish(&sync_dir, &mut phone, device);

    let (app, controller) = open_app(&path, None);
    select(&app, "Mail");
    type_into(&app, REPROMPT, PASSWORD);
    app.invoke_unlock_item();
    assert!(app.get_secrets_open());
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Editor);

    controller.sync_start(sync_dir);
    assert_eq!(app.get_notice_code(), 81, "{}", app.get_error_detail());
    assert!(
        !app.get_secrets_open(),
        "the master password's opening was for the old lock"
    );
    assert_eq!(app.get_panel(), Panel::Detail, "the editor closed with it");
    // The phone's login is sealed under a key not open here: never shown or edited blank.
    select(&app, "Bank");
    assert!(app.get_detail_locked());
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_detail_check(), 1, "its PIN is asked for");
    type_into(&app, REPROMPT, "9137");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "bank-secret");
}

// ---- N-03 / PM-18: what the browser is told about writes ----

/// The connected extension: requests sealed with the connection key, as the extension seals
/// them.
struct Extension<'a> {
    controller: &'a Controller,
    key: vault_browser::pairing::PairingKey,
    counter: Cell<u64>,
}

fn raw(controller: &Controller, message: &str) -> String {
    String::from_utf8(controller.browser_request(message.as_bytes()).to_vec()).unwrap()
}

fn json_field(json: &str, name: &str) -> String {
    json.split(&format!(r#""{name}":""#))
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("{name} in {json}"))
        .to_owned()
}

impl<'a> Extension<'a> {
    /// Connects as the extension does: the key agreement, then the code it shows typed into
    /// the app with the master password.
    fn pair(controller: &'a Controller, app: &AppWindow) -> Self {
        let joiner = vault_browser::pairing::Joiner::new().unwrap();
        let offer = raw(
            controller,
            &format!(r#"{{"type":"pair","commit":"{}"}}"#, joiner.commit_hex()),
        );
        let agreed = joiner.finish(&json_field(&offer, "key")).unwrap();
        raw(
            controller,
            &format!(r#"{{"type":"pair_key","key":"{}"}}"#, joiner.public_hex()),
        );
        assert_eq!(app.get_pairing_code(), agreed.code.as_str());
        type_into(app, PAIRING, PASSWORD);
        app.invoke_pairing_decided(true);
        assert!(app.get_browser_paired(), "{}", app.get_error_detail());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Extension {
            controller,
            key: agreed.key,
            counter: Cell::new(u64::try_from(now).unwrap() * vault_browser::pairing::COUNTER_SCALE),
        }
    }

    fn ask(&self, message: &str) -> String {
        self.counter.set(self.counter.get() + 1);
        let (request, nonce) = self
            .key
            .seal_request(self.counter.get(), message.as_bytes())
            .unwrap();
        let answer = raw(self.controller, &request);
        // Sealed to this request, as the extension opens it (pairing.rs).
        self.key
            .open_answer(self.counter.get(), &nonce, answer.as_bytes())
            .map_or(answer, |text| text.to_string())
    }
}

#[cfg(windows)]
#[test]
fn the_browser_hears_updated_only_once_it_is_on_disk() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, key, _forget) = vault_file(dir.path(), "u.vault", &[("Shop", "old-pw")], |_| {});
    let (app, controller) = open_app(&path, None);
    let extension = Extension::pair(&controller, &app);
    let logins = extension.ask(r#"{"type":"logins","url":"https://shop.example/login"}"#);
    let id = json_field(&logins, "id");
    let update = |password: &str| {
        extension.ask(&format!(
            r#"{{"type":"update","url":"https://shop.example/login","id":"{id}","password":"{password}"}}"#
        ))
    };
    let on_disk = || {
        let vault = open_file(&path, &key);
        let id = vault.item_ids().next().unwrap();
        vault.get_item(&id).unwrap().password.clone()
    };
    let writable = std::fs::metadata(&path).unwrap().permissions();
    let mut readonly = writable.clone();
    readonly.set_readonly(true);

    // A new password the disk refuses: the browser is told, and memory goes back.
    std::fs::set_permissions(&path, readonly.clone()).unwrap();
    let refused = update("browser-pw");
    assert!(refused.contains(r#""code":"not_saved""#), "{refused}");
    select(&app, "Shop");
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "old-pw", "rolled back");
    app.invoke_conceal();

    // A change made in the app that couldn't be written stays only in memory: the browser
    // asking for that same password is not told it is there.
    app.invoke_edit_item();
    type_into(&app, ITEM_PASSWORD, "app-pw");
    app.invoke_save_item();
    assert_eq!(app.get_notice_code(), 23, "not saved");
    let refused = update("app-pw");
    assert!(refused.contains(r#""code":"not_saved""#), "{refused}");
    std::fs::set_permissions(&path, writable).unwrap();
    assert_eq!(on_disk(), "old-pw");

    // Writable again: written first, then answered.
    let updated = update("app-pw");
    assert!(updated.contains(r#""type":"updated""#), "{updated}");
    assert_eq!(on_disk(), "app-pw");

    // The generator's result saved by the browser as a login's password is not left on the
    // generator page.
    app.invoke_open_generator();
    let generated = app.get_gen_result().to_string();
    assert!(!generated.is_empty());
    let saved = extension.ask(
        &serde_json::json!({
            "type": "save",
            "url": "https://new.example/signup",
            "username": "me",
            "password": generated,
        })
        .to_string(),
    );
    assert!(saved.contains(r#""type":"saved""#), "{saved}");
    assert_eq!(app.get_gen_result(), "");
    assert_eq!(controller.generated_result(), None);
}

#[test]
fn a_browser_change_that_also_seals_a_login_is_written_once() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, key, _forget) = vault_file(dir.path(), "w.vault", &[("Shop", "old-pw")], |vault| {
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("4821"), Some(PASSWORD))
            .unwrap();
    });
    let (app, controller) = open_app(&path, None);
    let extension = Extension::pair(&controller, &app);
    // A login the browser saves while the item lock is closed waits for its seal.
    let saved = extension.ask(
        r#"{"type":"save","url":"https://new.example/signup","username":"me","password":"new-pw"}"#,
    );
    assert!(saved.contains(r#""type":"saved""#), "{saved}");
    assert_eq!(controller.pending_seal(), Some(1));
    let logins = extension.ask(r#"{"type":"logins","url":"https://shop.example/login"}"#);
    let id = json_field(&logins, "id");
    let before = std::fs::read(&path).unwrap();

    // A new password with the PIN: the lock opens (the waiting login is sealed then) and the
    // password changes, in one write. Two would leave the first one as the backup, and a
    // second that failed would roll memory back behind the file.
    let updated = extension.ask(&format!(
        r#"{{"type":"update","url":"https://shop.example/login","id":"{id}","password":"new-shop-pw","check":"4821"}}"#
    ));
    assert!(updated.contains(r#""type":"updated""#), "{updated}");
    assert_eq!(controller.pending_seal(), Some(0));
    assert_eq!(
        std::fs::read(vault_core::storage::backup_path(&path)).unwrap(),
        before,
        "written once: the backup is the file as it was before"
    );
    let mut on_disk = open_file(&path, &key);
    assert!(on_disk.unlock_secrets("4821").unwrap());
    let shop = on_disk
        .item_ids()
        .map(|id| on_disk.get_item(&id).unwrap())
        .find(|item| item.title == "Shop")
        .unwrap();
    assert_eq!(shop.password, "new-shop-pw");
}

// ---- PM-03: filling while locked after the upgrade ----

#[test]
fn filling_while_locked_is_made_again_after_the_upgrade() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let _turn = app_home(&home);
    let (path, _, _forget) = vault_file(dir.path(), "f.vault", &[("Shop", "shop-pw")], |_| {});
    let hello = Arc::new(FakeHello::default());
    let (app, _controller) = open_app(&path, Some(hello));
    app.set_browser_extension(true);
    app.invoke_settings_changed();
    // The item lock with Windows Hello: filling while locked is made with it.
    app.invoke_open_settings();
    app.set_guard_check(1);
    app.set_guard_all(true);
    app.set_guard_hello(true);
    type_into(&app, GUARD_NEW, "4821");
    type_into(&app, GUARD_CURRENT, PASSWORD);
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let id = app.get_vault_id().to_string();
    let app_dir = paths::app_dir().unwrap();
    let index = app_dir.join(format!("browser-locked-v2-{id}.bin"));
    assert!(index.exists());

    // What the upgrade finds: only the file of the earlier version.
    std::fs::remove_file(&index).unwrap();
    let _ = std::fs::remove_file(index.with_extension("bin.bak"));
    let legacy = app_dir.join(format!("browser-locked-{id}.bin"));
    std::fs::write(&legacy, b"earlier version").unwrap();
    app.invoke_lock();
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert!(!legacy.exists(), "removed");
    assert_eq!(
        app.get_notice_code(),
        83,
        "the person is told it needs Windows Hello once"
    );
    assert!(!index.exists());
    // The next Windows Hello answer for the item lock makes it again.
    select(&app, "Shop");
    app.invoke_unlock_item_hello();
    assert!(!app.get_detail_locked());
    assert!(index.exists(), "made again");
}
