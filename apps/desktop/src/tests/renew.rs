//! Headless tests of renewing the vault key (CRYPTO.md §3.8) on the Kit page, and of taking a
//! key renewed on another device (SYNC.md §4.7) in Settings → Sync.

use vault_core::{ItemData, SecretKey, Unlock, Vault, sync::DeviceId};
use vault_platform::{paths, secret_store};

use super::{
    PASSWORD,
    review::{open_app, open_file, publish, vault_file},
    type_into,
};
use crate::ui::Panel;

/// Field numbers (controller.rs `field`).
const SECRET_KEY: i32 = 2;
const CURRENT: i32 = 5;
const CONFIRM_MASTER: i32 = 20;

fn opens(path: &std::path::Path, key: &SecretKey) -> bool {
    Vault::open(
        &std::fs::read(path).unwrap(),
        Unlock::Password {
            password: PASSWORD,
            secret_key: key,
        },
    )
    .is_ok()
}

#[test]
fn a_renewed_key_shows_the_new_kit_and_other_devices_catch_up() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let _turn = super::app_home(&home);
    let (path, old_key, _forget) =
        vault_file(dir.path(), "a.vault", &[("Alpha", "alpha-pw")], |_| {});
    let sync_dir = dir.path().join("sync");
    std::fs::create_dir_all(&sync_dir).unwrap();
    // Another device on the same vault, in sync before the renewal.
    let laptop_id = DeviceId::from_bytes([0x51; 16]);
    let mut laptop = open_file(&path, &old_key);
    laptop.set_device(laptop_id);
    publish(&sync_dir, &mut laptop, laptop_id);

    let (app, controller) = open_app(&path, None);
    let id = app.get_vault_id().to_string();
    controller.sync_start(sync_dir.clone());
    assert_eq!(app.get_sync_state(), 1, "{}", app.get_sync_detail());
    // Something this computer sealed with the vault key, outside the file.
    let icons = home.join(format!("icons-{id}.cache"));
    {
        let vault = open_file(&path, &old_key);
        std::fs::write(&icons, vault.seal_local("icons", b"test icons").unwrap()).unwrap();
    }

    app.invoke_open_kit();
    assert_eq!(app.get_panel(), Panel::Kit);
    // A wrong master password renews nothing.
    let before = std::fs::read(&path).unwrap();
    type_into(&app, CURRENT, "not the master password");
    app.invoke_renew_key();
    assert_eq!(app.get_error_code(), 11);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(app.get_kit_part_a(), "");

    type_into(&app, CURRENT, PASSWORD);
    app.invoke_renew_key();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), 85);
    // The new kit shows: a new Secret Key, and its parts.
    let new_key = SecretKey::parse(&app.get_kit_secret_key()).unwrap();
    assert_ne!(new_key, old_key);
    assert!(app.get_kit_part_a().starts_with("A0-"));
    assert!(
        secret_store::load(&id)
            .unwrap()
            .is_some_and(|kept| kept == new_key)
    );
    assert!(opens(&path, &new_key));
    assert!(!opens(&path, &old_key), "the old Secret Key opens nothing");
    // What was sealed here opens with the new key.
    let renewed = open_file(&path, &new_key);
    assert_eq!(
        renewed
            .open_local("icons", &std::fs::read(&icons).unwrap())
            .unwrap()
            .as_slice(),
        b"test icons"
    );
    assert!(!vault_core::storage::backup_path(&icons).exists());

    // The laptop, still on the former key, is said to be behind; its copy waits.
    laptop
        .add_item(&ItemData::login(
            "From the laptop",
            "l",
            "laptop-pw",
            "https://laptop.example",
        ))
        .unwrap();
    publish(&sync_dir, &mut laptop, laptop_id);
    app.invoke_open_settings();
    controller.sync_round();
    assert_eq!(app.get_sync_key_behind(), 1);
    assert!(!app.get_sync_key_renewed());
    assert_eq!(app.get_total_items(), 1);
    // It takes the new key (its new Secret Key and the master password)...
    let ours = std::fs::read_dir(sync_dir.join(&id).join("devices"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| !p.ends_with(format!("{}.vault", laptop_id.to_hex())))
        .unwrap();
    let opened = Vault::open(
        &std::fs::read(ours).unwrap(),
        Unlock::Password {
            password: PASSWORD,
            secret_key: &new_key,
        },
    )
    .unwrap();
    assert!(laptop.adopt_key(&opened).unwrap().is_some());
    publish(&sync_dir, &mut laptop, laptop_id);
    // ...and what it changed meanwhile comes in.
    controller.sync_round();
    assert_eq!(app.get_sync_key_behind(), 0);
    assert_eq!(app.get_total_items(), 2);
    assert!(opens(&path, &new_key));
}

#[test]
fn a_key_renewed_on_another_device_is_taken_with_its_new_secret_key() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let _turn = super::app_home(&home);
    let (path, old_key, _forget) =
        vault_file(dir.path(), "a.vault", &[("Alpha", "alpha-pw")], |_| {});
    let sync_dir = dir.path().join("sync");
    std::fs::create_dir_all(&sync_dir).unwrap();
    let (app, controller) = open_app(&path, None);
    let id = app.get_vault_id().to_string();
    controller.sync_start(sync_dir.clone());

    // The laptop renews the key, after one change of its own.
    let laptop_id = DeviceId::from_bytes([0x52; 16]);
    let mut laptop = open_file(&path, &old_key);
    laptop.set_device(laptop_id);
    laptop
        .add_item(&ItemData::login(
            "From the laptop",
            "l",
            "laptop-pw",
            "https://laptop.example",
        ))
        .unwrap();
    let renewed = laptop.renew_key(PASSWORD, &old_key, None).unwrap();
    publish(&sync_dir, &mut laptop, laptop_id);

    // This computer can't read it, and says where to type the new key.
    app.invoke_open_settings();
    controller.sync_round();
    assert_eq!(app.get_notice_code(), 87);
    assert!(app.get_sync_key_renewed());
    assert_eq!(app.get_total_items(), 1);

    app.invoke_open_settings_dialog(14);
    // The old Secret Key isn't the new one.
    type_into(&app, SECRET_KEY, &old_key.to_display_string());
    type_into(&app, CONFIRM_MASTER, PASSWORD);
    app.invoke_sync_take_key();
    assert_eq!(app.get_error_code(), 61);
    assert!(opens(&path, &old_key), "nothing changed");
    // A typo in it is said as one.
    type_into(&app, SECRET_KEY, "S0-1234567-1234567-1234567-1234567");
    app.invoke_sync_take_key();
    assert!(matches!(app.get_error_code(), 2 | 3));

    type_into(&app, SECRET_KEY, &renewed.secret_key.to_display_string());
    type_into(&app, CONFIRM_MASTER, PASSWORD);
    app.invoke_sync_take_key();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), 86);
    assert_eq!(app.get_settings_dialog(), 0);
    assert!(!app.get_sync_key_renewed());
    assert!(
        secret_store::load(&id)
            .unwrap()
            .is_some_and(|kept| kept == renewed.secret_key)
    );
    // The laptop's copy merged; this file and the copy it published open with the new key.
    assert_eq!(app.get_total_items(), 2);
    assert!(opens(&path, &renewed.secret_key));
    assert!(!opens(&path, &old_key));
    let ours = std::fs::read_dir(sync_dir.join(&id).join("devices"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| !p.ends_with(format!("{}.vault", laptop_id.to_hex())))
        .unwrap();
    assert!(
        Vault::open(
            &std::fs::read(ours).unwrap(),
            Unlock::Password {
                password: PASSWORD,
                secret_key: &renewed.secret_key,
            },
        )
        .is_ok()
    );
    assert!(paths::app_dir().unwrap().starts_with(&home));
}
