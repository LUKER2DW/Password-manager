//! The phone app end to end, headless: new vault, items, the item page, codes, generator,
//! lock and unlock. Slow work runs inline; test values only.

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, SecretKey, Unlock, Vault};

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

#[test]
fn the_phone_app_from_a_new_vault_to_a_locked_one() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: the only test of this crate; nothing else reads the environment meanwhile.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", dir.path().join("home"));
    }
    i_slint_backend_testing::init_no_event_loop();
    let app = PhoneWindow::new().unwrap();
    let path = dir.path().join("phone.vault");
    let controller = Controller::start(&app, path.clone(), true);

    // ---- no vault yet: make one ----
    assert_eq!(app.get_screen(), Screen::Welcome);
    app.invoke_create_start();
    assert_eq!(app.get_screen(), Screen::Create);
    type_secret(&app, 0, "too short");
    type_secret(&app, 1, "too short");
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 3);
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, "another passphrase entirely");
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 2);
    assert!(
        !path.exists(),
        "nothing is written before the form is right"
    );
    type_secret(&app, 1, PASSWORD);
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_screen(), Screen::Keys);
    let secret_key = app.get_kit_secret_key().to_string();
    assert!(secret_key.starts_with("S0-") && app.get_kit_recovery_key().starts_with("R0-"));
    assert_eq!(length(&app, 0), 0, "typed passwords are wiped");
    app.invoke_keys_noted();
    assert_eq!(app.get_kit_secret_key(), "", "the keys leave the screen");
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!((app.get_total(), app.get_items().row_count()), (0, 0));
    let vault_id = Vault::inspect(&std::fs::read(&path).unwrap())
        .unwrap()
        .id_hex;

    // ---- a login ----
    app.invoke_new_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 6, "a name is needed");
    app.set_ed_title("GitHub".into());
    app.set_ed_username("octocat".into());
    app.set_ed_website("github.com".into());
    app.set_ed_totp("not a key!".into());
    type_secret(&app, 4, "gh-test-password-1");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 11);
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
        length(&app, 4),
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
        ("", 12)
    );
    app.set_gen_mode(1);
    app.invoke_gen_changed();
    assert_eq!(app.get_gen_password().split('-').count(), 6);
    assert_eq!(app.get_error_code(), 0);

    // ---- the item lock: a PIN before the secrets ----
    {
        let bytes = std::fs::read(&path).unwrap();
        let key = SecretKey::parse(&secret_key).unwrap();
        let mut vault = Vault::open(
            &bytes,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &key,
            },
        )
        .unwrap();
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
        7,
        "a file changed elsewhere is not overwritten"
    );
    app.invoke_lock_now();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!controller.is_unlocked());
    assert_eq!(app.get_items().row_count(), 0);
    assert!(!app.get_needs_secret_key(), "this phone has the Secret Key");

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
    type_secret(&app, 3, "0000");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (8, 2));
    type_secret(&app, 3, "4821");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (0, 0));
    assert!(app.get_d_has_password() && app.get_d_has_code());
    app.invoke_close_item();
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "closed again when the item is left");
    app.invoke_close_item();

    // ---- delete, asked twice ----
    app.invoke_open_item(1);
    type_secret(&app, 3, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_delete_item();
    assert!(app.get_ed_confirm_delete());
    assert_eq!(app.get_total(), 2);
    app.invoke_delete_item();
    assert_eq!((app.get_total(), app.get_page()), (1, Page::None));
    assert_eq!(app.get_notice_code(), 4);

    // ---- another phone: the Secret Key is typed once ----
    app.invoke_lock_now();
    vault_platform::secret_store::forget(&vault_id).unwrap();
    app.invoke_lock_now();
    assert!(app.get_needs_secret_key());
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 2, "S0-not-a-key");
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 4);
    type_secret(&app, 2, &secret_key);
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
