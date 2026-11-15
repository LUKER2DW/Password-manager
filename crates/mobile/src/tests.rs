//! The phone app end to end, headless: a vault made on the computer is brought in, then
//! items, the item page, codes, generator, lock, unlock and a newer copy. Slow work runs
//! inline; test values only.

use std::path::Path;

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Unlock, Vault};

use crate::{
    Controller,
    ui::{Page, PhoneWindow, Place, Screen, Secrets},
};

const PASSWORD: &str = "phone test master passphrase";

fn type_secret(app: &PhoneWindow, field: i32, text: &str) {
    app.global::<Secrets>().invoke_clear(field);
    app.global::<Secrets>().invoke_insert(field, text.into());
}

fn length(app: &PhoneWindow, field: usize) -> i32 {
    app.global::<Secrets>()
        .get_lengths()
        .row_data(field)
        .unwrap()
}

fn open_file(path: &Path, secret_key: &str) -> Vault {
    let key = SecretKey::parse(secret_key).unwrap();
    Vault::open(
        &std::fs::read(path).unwrap(),
        Unlock::Password {
            password: PASSWORD,
            secret_key: &key,
        },
    )
    .unwrap()
}

#[test]
fn the_phone_app_from_a_computer_vault_to_a_locked_one() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: the only test of this crate; nothing else reads the environment meanwhile.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", dir.path().join("home"));
    }

    // ---- the vault, as the desktop app made it ----
    let key = SecretKey::generate().unwrap();
    let secret_key = key.to_display_string().to_string();
    let mut made = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    let mut settings = made.settings().clone();
    settings.name = "Test vault".into();
    made.set_settings(settings).unwrap();
    let from_computer = dir.path().join("from-the-computer.vault");
    std::fs::write(&from_computer, made.to_bytes().unwrap()).unwrap();
    let vault_id = made.id_hex();
    drop(made);

    i_slint_backend_testing::init_no_event_loop();
    let app = PhoneWindow::new().unwrap();
    let path = dir.path().join("phone").join("vault.vault");
    let controller = Controller::start(&app, path.clone(), true);

    // ---- no vault on the phone: one is brought in, never made ----
    assert_eq!(app.get_screen(), Screen::Start);
    controller.bring_vault(b"not a vault at all".to_vec());
    assert_eq!((app.get_error_code(), app.get_screen()), (2, Screen::Start));
    controller.bring_vault_file(&from_computer);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_incoming() && !app.get_has_copy());
    assert!(app.get_needs_secret_key(), "a new phone asks for the key");
    app.invoke_cancel_incoming();
    assert_eq!(app.get_screen(), Screen::Start, "back to choosing a file");
    controller.bring_vault_file(&from_computer);
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, "S0-not-a-key");
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 3);
    type_secret(&app, 0, "not the master password");
    type_secret(&app, 1, &secret_key);
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (1, Screen::Unlock)
    );
    assert!(
        !path.exists(),
        "a file that didn't open is not kept on the phone"
    );
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(&from_computer).unwrap(),
        "the phone keeps its own copy"
    );
    assert_eq!(app.get_vault_name(), "Test vault");
    assert_eq!(
        (length(&app, 0), length(&app, 1)),
        (0, 0),
        "typed keys wiped"
    );
    assert_eq!((app.get_total(), app.get_items().row_count()), (0, 0));

    // ---- a login ----
    app.invoke_new_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 5, "a name is needed");
    app.set_ed_title("GitHub".into());
    app.set_ed_username("octocat".into());
    app.set_ed_website("github.com".into());
    app.set_ed_totp("not a key!".into());
    type_secret(&app, 3, "gh-test-password-1");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 10);
    app.set_ed_totp("JBSWY3DPEHPK3PXP".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), 3);
    assert_eq!(app.get_page(), Page::Item, "the saved login is shown");
    assert_eq!(app.get_d_title(), "GitHub");
    assert_eq!(app.get_d_username(), "octocat");
    assert!(app.get_d_has_password());
    assert_eq!(app.get_d_password(), "", "hidden until asked for");
    assert!(app.get_d_has_code());
    assert_eq!(app.get_d_code().replace(' ', "").len(), 6);
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "gh-test-password-1");
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "");
    app.invoke_toggle_favorite();
    assert!(app.get_d_favorite());
    app.invoke_close_item();
    assert_eq!(app.get_page(), Page::None);
    assert_eq!(app.get_d_title(), "", "nothing of the item stays behind");

    // ---- a note, then the list ----
    app.invoke_new_item();
    app.set_ed_kind(1);
    app.set_ed_title("Wi-Fi".into());
    app.set_ed_notes("network: test-net".into());
    app.invoke_save_item();
    app.invoke_close_item();
    assert_eq!(app.get_total(), 2);
    let titles = |app: &PhoneWindow| -> Vec<String> {
        app.get_items()
            .iter()
            .map(|row| row.title.to_string())
            .collect()
    };
    assert_eq!(titles(&app), ["GitHub", "Wi-Fi"]);
    assert!(app.get_items().row_data(0).unwrap().favorite);
    app.set_search("wi".into());
    app.invoke_search_changed("wi".into());
    assert_eq!(titles(&app), ["Wi-Fi"]);
    app.set_search("".into());
    app.invoke_search_changed("".into());
    for (filter, expected) in [
        (1, vec!["GitHub"]),
        (2, vec!["GitHub"]),
        (4, vec!["Wi-Fi"]),
        (3, vec![]),
    ] {
        app.set_filter(filter);
        app.invoke_filter_changed(filter);
        assert_eq!(titles(&app), expected, "filter {filter}");
    }
    app.set_filter(0);
    app.invoke_filter_changed(0);

    // ---- edit: the password changes, the rest stays ----
    app.invoke_open_item(0);
    app.invoke_edit_item();
    assert_eq!(app.get_ed_title(), "GitHub");
    assert_eq!(
        length(&app, 3),
        18,
        "the editor holds the password, not the screen"
    );
    assert_eq!(app.get_ed_password(), "");
    app.invoke_ed_generate();
    let generated = app.get_ed_password().to_string();
    assert_eq!(generated.chars().count(), 20, "a made password is shown");
    app.invoke_save_item();
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), generated.as_str());
    app.invoke_close_item();

    // ---- codes and the generator ----
    app.set_place(Place::Codes);
    let codes = app.get_codes();
    assert_eq!(codes.row_count(), 1);
    let row = codes.row_data(0).unwrap();
    assert_eq!(
        (row.title.as_str(), row.account.as_str()),
        ("GitHub", "octocat")
    );
    assert!(row.left >= 1 && row.left <= 30 && row.period == 30);
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    assert_eq!(app.get_gen_password().chars().count(), 20);
    assert!(app.get_gen_bits() > 100);
    for off in [
        PhoneWindow::set_gen_upper,
        PhoneWindow::set_gen_lower,
        PhoneWindow::set_gen_digits,
        PhoneWindow::set_gen_symbols,
    ] {
        off(&app, false);
    }
    app.invoke_gen_changed();
    assert_eq!(
        (app.get_gen_password().as_str(), app.get_error_code()),
        ("", 11)
    );
    app.set_gen_mode(1);
    app.invoke_gen_changed();
    assert_eq!(app.get_gen_password().split('-').count(), 6);
    assert_eq!(app.get_error_code(), 0);

    // ---- the item lock: a PIN before the secrets ----
    {
        let mut vault = open_file(&path, &secret_key);
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("4821"), None)
            .unwrap();
        // As another device would have written it: the phone must not overwrite it.
        std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    }
    app.set_place(Place::Items);
    app.invoke_open_item(0);
    app.invoke_toggle_favorite();
    assert_eq!(
        app.get_error_code(),
        6,
        "a file changed elsewhere is not overwritten"
    );
    app.invoke_lock_now();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!controller.is_unlocked());
    assert_eq!(app.get_items().row_count(), 0);
    assert!(!app.get_needs_secret_key(), "this phone has the Secret Key");
    assert!(!app.get_incoming());

    // ---- unlock ----
    type_secret(&app, 0, "not the master password");
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (1, Screen::Unlock)
    );
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert!(app.get_items().row_data(0).unwrap().locked);
    app.set_place(Place::Codes);
    assert_eq!(
        app.get_codes().row_data(0).unwrap().code,
        "",
        "no digits behind the lock"
    );
    app.set_place(Place::Items);
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "the PIN is asked for");
    assert!(!app.get_d_has_password() && !app.get_d_has_code());
    assert_eq!(
        app.get_d_username(),
        "octocat",
        "who the account is stays visible"
    );
    app.invoke_toggle_password();
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(
        (app.get_d_password().as_str(), app.get_notice_code()),
        ("", 0),
        "nothing shown, nothing copied"
    );
    type_secret(&app, 2, "0000");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (7, 2));
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (0, 0));
    assert!(app.get_d_has_password() && app.get_d_has_code());
    app.invoke_close_item();
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "closed again when the item is left");
    app.invoke_close_item();

    // ---- delete, asked twice ----
    app.invoke_open_item(1);
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_delete_item();
    assert!(app.get_ed_confirm_delete());
    assert_eq!(app.get_total(), 2);
    app.invoke_delete_item();
    assert_eq!((app.get_total(), app.get_page()), (1, Page::None));
    assert_eq!(app.get_notice_code(), 4);

    // ---- a copy older than the phone's: refused, the phone's copy stays ----
    let phone_copy = std::fs::read(&path).unwrap();
    controller.bring_vault_file(&from_computer);
    assert!(
        !controller.is_unlocked(),
        "the open vault left memory first"
    );
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_incoming() && app.get_has_copy());
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (8, Screen::Unlock)
    );
    assert_eq!(std::fs::read(&path).unwrap(), phone_copy);
    app.invoke_cancel_incoming();
    assert!(!app.get_incoming(), "back to the phone's own copy");

    // ---- a newer copy from the computer: it replaces the phone's ----
    {
        let mut vault = open_file(&path, &secret_key);
        vault
            .add_item(&ItemData::new(
                ItemKind::SecureNote,
                "Added on the computer",
            ))
            .unwrap();
        std::fs::write(&from_computer, vault.to_bytes().unwrap()).unwrap();
    }
    controller.bring_vault_file(&from_computer);
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total(), 2);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(&from_computer).unwrap()
    );
    app.invoke_open_item(0);
    app.invoke_toggle_favorite();
    assert_eq!(
        app.get_error_code(),
        0,
        "the new copy is the one this phone saves to"
    );
    app.invoke_close_item();

    // ---- another phone: the Secret Key is typed once ----
    app.invoke_lock_now();
    vault_platform::secret_store::forget(&vault_id).unwrap();
    app.invoke_lock_now();
    assert!(app.get_needs_secret_key());
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, &secret_key);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    app.invoke_lock_now();
    assert!(!app.get_needs_secret_key(), "kept on the phone from now on");
    vault_platform::secret_store::forget(&vault_id).unwrap();
}
