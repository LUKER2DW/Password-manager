//! Headless end-to-end test: the real Slint window and controller, driven through the same
//! callbacks the UI uses, with Slint's testing backend (nothing is drawn on screen).
//! Argon2id runs at the format's minimum cost here to keep the test fast.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use slint::{ComponentHandle, Model};
use vault_platform::{
    quick_unlock::{DeviceVerifier, QuickUnlockError},
    secret_store,
};
use zeroize::Zeroizing;

use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Panel, Screen, Secrets},
};

const PASSWORD: &str = "desktop test passphrase one";
const NEW_PASSWORD: &str = "desktop test passphrase two";

fn type_into(app: &AppWindow, field: i32, text: &str) {
    let secrets = app.global::<Secrets>();
    secrets.invoke_clear(field);
    for c in text.chars() {
        secrets.invoke_insert(field, c.to_string().into());
    }
}

fn length(app: &AppWindow, field: usize) -> i32 {
    app.global::<Secrets>()
        .get_lengths()
        .row_data(field)
        .unwrap()
}

/// Stands in for Windows Hello: "verifies" instantly and returns a fixed secret.
#[derive(Debug, Default)]
struct FakeHello {
    cancel: AtomicBool,
    other_device: AtomicBool,
}

impl DeviceVerifier for FakeHello {
    fn name(&self) -> &'static str {
        "Fake Hello"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn enroll(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        self.secret(vault_id)
    }
    fn secret(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(QuickUnlockError::Cancelled);
        }
        let byte = if self.other_device.load(Ordering::SeqCst) {
            2
        } else {
            1
        };
        let mut secret = vec![byte; 256];
        secret[..vault_id.len()].copy_from_slice(vault_id.as_bytes());
        Ok(Zeroizing::new(secret))
    }
    fn remove(&self, _vault_id: &str) {}
}

/// Removes the test vault's Secret Key from the OS credential store, even if the test fails.
struct ForgetOnDrop(String);

impl Drop for ForgetOnDrop {
    fn drop(&mut self) {
        let _ = secret_store::forget(&self.0);
    }
}

#[test]
fn whole_app_flow_headless() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: set before any thread of this test reads the environment; other tests in this
    // binary never read VAULT_HOME.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", dir.path().join("home"));
    }
    let path = dir.path().join("test.vault");

    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let hello = Arc::new(FakeHello::default());
    let controller = Controller::install(
        &app,
        path.clone(),
        Runner::Inline,
        Some(hello.clone() as Arc<dyn DeviceVerifier>),
    )
    .unwrap();
    assert!(app.get_quick_unlock_available());

    // ---- onboarding ----
    assert_eq!(app.get_screen(), Screen::Onboarding);
    type_into(&app, 0, "short");
    type_into(&app, 1, "short");
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 5, "too short");

    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, &format!("{PASSWORD}x"));
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 4, "mismatch");
    app.global::<Secrets>().invoke_backspace(1);
    assert_eq!(length(&app, 1), PASSWORD.chars().count() as i32);

    app.invoke_suggest_passphrase();
    assert!(app.get_suggestion().split('-').count() >= 6);

    app.invoke_create_vault();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_onboarding_step(), 2);
    let secret_key = app.get_kit_secret_key().to_string();
    let recovery_key = app.get_kit_recovery_key().to_string();
    let _cleanup = ForgetOnDrop(app.get_vault_id().to_string());
    assert!(secret_key.starts_with("S0-") && recovery_key.starts_with("R0-"));
    assert_eq!(length(&app, 0), 0, "typed password wiped after use");
    assert!(path.exists());

    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(
        app.get_kit_secret_key(),
        "",
        "kit hidden once the vault opens"
    );
    assert_eq!(app.get_total_items(), 0);

    // ---- add a login ----
    app.invoke_new_item();
    assert_eq!(app.get_panel(), Panel::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 9, "title required");
    app.set_ed_title("GitHub".into());
    app.set_ed_username("octocat".into());
    app.set_ed_url("https://github.com".into());
    app.set_ed_totp("not a secret!".into());
    type_into(&app, 4, "gh-item-pass");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 10, "bad TOTP rejected");
    app.set_ed_totp("JBSWY3DPEHPK3PXP".into());
    app.invoke_save_item();
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_total_items(), 1);
    assert_eq!(app.get_detail_title(), "GitHub");
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_code().len(), 7, "grouped 6-digit code");
    assert_eq!(app.get_notice_code(), 5);

    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "gh-item-pass");
    app.invoke_conceal();
    assert_eq!(app.get_revealed_password(), "");

    // ---- a note, search, categories, favorites ----
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Alarm code".into());
    app.set_ed_notes("1234 then #".into());
    app.invoke_save_item();
    assert_eq!(app.get_total_items(), 2);
    let counts: Vec<i32> = app.get_counts().iter().collect();
    assert_eq!(counts, [2, 0, 1, 0, 1]);

    app.set_search_text("git".into());
    app.invoke_search("git".into());
    assert_eq!(app.get_items().row_count(), 1);
    app.set_search_text("".into());
    app.invoke_search("".into());
    app.invoke_select_category(4);
    assert_eq!(app.get_items().row_count(), 1);
    app.invoke_select(0);
    assert_eq!(app.get_detail_title(), "Alarm code");
    app.invoke_toggle_favorite();
    assert!(app.get_detail_favorite());
    assert_eq!(app.get_counts().row_data(1), Some(1));

    // ---- edit keeps the password; delete ----
    app.invoke_select_category(0);
    let github = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "GitHub")
        .unwrap();
    app.invoke_select(github as i32);
    app.invoke_edit_item();
    assert_eq!(
        length(&app, 4),
        "gh-item-pass".len() as i32,
        "existing password preloaded"
    );
    app.set_ed_username("hubot".into());
    app.invoke_save_item();
    assert_eq!(app.get_detail_username(), "hubot");
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "gh-item-pass");

    app.invoke_select_category(4);
    app.invoke_select(0);
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), 1);
    assert_eq!(app.get_notice_code(), 6);

    // ---- folders and recovery codes ----
    // The folder dialog: a name is required, a picture link must look like one.
    app.invoke_new_folder();
    assert_eq!(app.get_folder_dialog(), 0);
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 30, "a folder needs a name");
    assert_eq!(app.get_folder_dialog(), 0, "the dialog stays open");
    app.set_fd_name("Google".into());
    app.set_fd_link("not a link".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 28);
    app.set_fd_link("".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_folder_dialog(), -1, "closed once saved");
    assert_eq!(app.get_folders().row_count(), 1);
    assert_eq!(app.get_category(), 100, "the new folder opens");
    assert_eq!(app.get_folder_name(), "Google");
    assert_eq!(app.get_items().row_count(), 0);
    // A new item made while browsing a folder starts in it.
    app.invoke_new_item();
    assert_eq!(app.get_ed_folder(), 1);
    app.set_ed_title("Gmail".into());
    app.set_ed_recovery_codes("1. aaaa-1111\n2. bbbb-2222\n3. cccc-3333".into());
    app.invoke_save_item();
    assert_eq!(app.get_items().row_count(), 1);
    assert_eq!(app.get_folders().row_data(0).unwrap().count, 1);
    assert_eq!(app.get_detail_folder(), "Google");
    assert_eq!(app.get_detail_codes_total(), 3);
    assert_eq!(
        app.get_detail_codes().row_count(),
        0,
        "codes hidden until asked"
    );
    app.invoke_show_codes();
    assert_eq!(
        app.get_detail_codes().row_data(0).unwrap().code,
        "aaaa-1111"
    );
    app.invoke_copy_code(0);
    assert_eq!(app.get_notice_code(), 18);
    app.invoke_toggle_code_used(0);
    assert_eq!(app.get_detail_codes_left(), 2);
    assert!(
        app.get_detail_codes().row_data(0).unwrap().used,
        "still shown, marked"
    );
    // Editing keeps the used mark for codes that stay.
    app.invoke_edit_item();
    assert!(app.get_ed_recovery_codes().contains("aaaa-1111"));
    app.set_ed_recovery_codes("aaaa-1111\nbbbb-2222\ndddd-4444".into());
    app.invoke_save_item();
    assert_eq!(
        (app.get_detail_codes_total(), app.get_detail_codes_left()),
        (3, 2)
    );
    // Folder settings: name, icon, colour and a picture link in one go (the picture itself is
    // only downloaded by the app, not in this test).
    app.invoke_edit_folder(0);
    assert_eq!(app.get_folder_dialog(), 1);
    assert_eq!(app.get_fd_name(), "Google");
    app.set_fd_name("Google accounts".into());
    app.set_fd_icon("globe".into());
    app.set_fd_color(3);
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_folder_name(), "Google accounts");
    assert_eq!(app.get_folder_icon(), "globe");
    assert_eq!(app.get_folder_color(), 3);
    let row = app.get_folders().row_data(0).unwrap();
    assert_eq!((row.icon.as_str(), row.color), ("globe", 3));
    assert!(!row.has_image);
    app.invoke_edit_folder(0);
    app.set_fd_name("".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 30, "a folder needs a name");
    app.invoke_folder_dialog_cancel();
    assert_eq!(
        app.get_folder_name(),
        "Google accounts",
        "cancel keeps the folder"
    );

    // Reordering keeps the browsed folder selected.
    app.invoke_new_folder();
    app.set_fd_name("Work".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_category(), 101, "the new folder opens");
    app.invoke_move_folder(1, 0);
    assert_eq!(app.get_folders().row_data(0).unwrap().name, "Work");
    assert_eq!(app.get_category(), 100, "still browsing Work");
    assert_eq!(app.get_folder_name(), "Work");
    app.invoke_ask_delete_folder(0);
    assert_eq!(app.get_folder_dialog(), 2);
    app.invoke_folder_dialog_delete();
    assert_eq!(app.get_folders().row_count(), 1);
    assert_eq!(app.get_notice_code(), 32);

    // Back and forward through the places visited.
    app.invoke_select_category(0);
    app.invoke_open_generator();
    assert!(app.get_can_go_back());
    app.invoke_go_back();
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_category(), 0);
    assert!(app.get_can_go_forward());
    app.invoke_go_forward();
    assert_eq!(app.get_panel(), Panel::Generator);
    assert!(!app.get_can_go_forward());
    app.invoke_select_category(100);

    app.invoke_ask_delete_folder(0);
    app.invoke_folder_dialog_delete();
    assert_eq!(app.get_folders().row_count(), 0);
    assert_eq!(app.get_category(), 0);
    assert_eq!(app.get_total_items(), 2, "the folder's item stays");
    let gmail = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "Gmail")
        .unwrap();
    app.invoke_select(gmail as i32);
    assert_eq!(app.get_detail_folder(), "");
    app.invoke_delete_item();

    // ---- cards: checked fields, no generated PIN ----
    app.invoke_new_item();
    app.set_ed_kind(1);
    app.set_ed_title("Visa".into());
    app.set_ed_username("A. Person".into());
    app.set_ed_card_number("4111 1111 1111 1112".into());
    app.invoke_card_number_edited("4111 1111 1111 1112".into());
    assert_eq!(app.get_ed_card_brand(), "Visa");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 20, "typo caught by the checksum");
    app.set_ed_card_number("4111 1111 1111 1111".into());
    app.set_ed_card_expiry("13/29".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 21);
    app.set_ed_card_expiry("8/2029".into());
    app.set_ed_card_code("12".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 22);
    app.set_ed_card_code("123".into());
    type_into(&app, 4, "12ab");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 23, "a PIN is digits");
    type_into(&app, 4, "1234");
    app.invoke_save_item();
    assert_eq!(
        app.get_panel(),
        Panel::Detail,
        "detail: {}",
        app.get_error_code()
    );
    let fields = app.get_detail_fields();
    assert_eq!(fields.row_data(0).unwrap().value, "Visa •••• 1111");
    assert_eq!(fields.row_data(1).unwrap().value, "08/29");
    assert!(fields.row_data(2).unwrap().sensitive);
    assert_eq!(fields.row_count(), 3, "the brand is not repeated");
    // The masked number and the hidden security code can be shown, one at a time.
    assert!(fields.row_data(0).unwrap().hideable);
    assert!(!fields.row_data(1).unwrap().hideable);
    let number = fields.row_data(0).unwrap().index;
    app.invoke_reveal_field(number);
    assert_eq!(app.get_revealed_field_value(), "4111 1111 1111 1111");
    assert!(app.get_reveal_left() > 0);
    let code = fields.row_data(2).unwrap().index;
    app.invoke_reveal_field(code);
    assert_eq!(app.get_revealed_field(), code);
    assert_eq!(app.get_revealed_field_value(), "123");
    app.invoke_reveal_field(code);
    assert_eq!(app.get_revealed_field(), -1, "a second click hides it");
    assert_eq!(app.get_revealed_field_value(), "");
    let visa = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "Visa")
        .unwrap();
    assert_eq!(
        app.get_items().row_data(visa).unwrap().subtitle,
        "Visa •••• 1111"
    );
    app.invoke_delete_item();

    // ---- authenticator page ----
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_open_authenticator();
    assert_eq!(app.get_panel(), Panel::Authenticator);
    assert_eq!(app.get_auth_rows().row_count(), 1);
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert_eq!(row.title, "GitHub");
    assert_eq!(row.code.len(), 7);
    assert!(row.left >= 1 && row.left <= 30 && row.period == 30);
    app.invoke_auth_copy(0);
    assert_eq!(app.get_notice_code(), 3);
    app.set_auth_search("zzz".into());
    app.invoke_auth_search_changed("zzz".into());
    assert_eq!(app.get_auth_rows().row_count(), 0);
    app.set_auth_search("".into());
    app.invoke_auth_search_changed("".into());
    app.invoke_auth_open(0);
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_detail_title(), "GitHub");

    // ---- browser extension: logins for the exact site, a password only when picked ----
    let raw = |message: &str| {
        String::from_utf8(controller.browser_request(message.as_bytes()).to_vec()).unwrap()
    };
    assert!(raw(r#"{"type":"status"}"#).contains(r#""locked":false"#));
    // Unconnected, nothing is answered: not plain requests, not ones signed with any key.
    let counter = std::cell::Cell::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    );
    let signed = |key: &[u8], message: &str| {
        use hmac::{Hmac, KeyInit, Mac};
        counter.set(counter.get() + 1);
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&counter.get().to_le_bytes());
        mac.update(message.as_bytes());
        let mac: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let body = message.replace('\\', "\\\\").replace('"', "\\\"");
        raw(&format!(
            r#"{{"type":"signed","counter":{},"body":"{body}","mac":"{mac}"}}"#,
            counter.get()
        ))
    };
    let logins_request = r#"{"type":"logins","url":"https://github.com/login"}"#;
    assert!(raw(logins_request).contains("bad_request"));
    assert!(signed(&[9u8; 32], logins_request).contains("not_paired"));
    // The extension asks to connect: the app shows a code and waits for the person.
    let pairing = raw(r#"{"type":"pair"}"#);
    let field = |json: &str, name: &str| {
        json.split(&format!(r#""{name}":""#))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap()
            .to_owned()
    };
    let key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&field(&pairing, "key")[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    assert_eq!(app.get_pairing_code(), field(&pairing, "code").as_str());
    assert!(
        signed(&key, logins_request).contains("not_paired"),
        "the key opens nothing until it is allowed in the app"
    );
    app.invoke_pairing_decided(false);
    assert_eq!(app.get_pairing_code(), "");
    assert!(
        signed(&key, logins_request).contains("not_paired"),
        "refused"
    );
    let pairing = raw(r#"{"type":"pair"}"#);
    let key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&field(&pairing, "key")[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_notice_code(), 41);
    assert!(app.get_browser_paired());
    let ask = |message: &str| signed(&key, message);
    let logins = ask(logins_request);
    assert!(
        logins.contains(r#""origin":"https://github.com""#),
        "{logins}"
    );
    assert!(logins.contains(r#""title":"GitHub""#) && !logins.contains("password"));
    let id = logins
        .split(r#""id":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_owned();
    app.set_notice_code(0);
    let phishing = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com.evil.example/login","id":"{id}"}}"#
    ));
    assert!(phishing.contains("no_match"), "{phishing}");
    assert_eq!(app.get_notice_code(), 0);
    let filled = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/session","id":"{id}"}}"#
    ));
    assert!(filled.contains(r#""username":""#) && filled.contains(r#""password":""#));
    assert_eq!(app.get_notice_code(), 40, "a fill is announced in the app");
    assert_eq!(app.get_notice_arg(), "GitHub");
    // The same request sent again is refused, and so is one from another time.
    let replayed = format!(
        r#"{{"type":"signed","counter":{},"body":"{{}}","mac":"{}"}}"#,
        counter.get(),
        "00".repeat(32)
    );
    assert!(raw(&replayed).contains("not_paired"));

    // ---- extra fields ----
    app.invoke_edit_item();
    app.invoke_field_add();
    app.invoke_field_edited(0, true, "Customer no.".into());
    app.invoke_field_edited(0, false, "C-42".into());
    app.invoke_field_hidden(0, true);
    assert!(app.get_ed_fields().row_data(0).unwrap().hidden);
    app.invoke_field_add(); // left empty: dropped on save
    app.invoke_save_item();
    let fields = app.get_detail_fields();
    assert_eq!(fields.row_count(), 1);
    assert_eq!(fields.row_data(0).unwrap().label, "Customer no.");
    assert!(fields.row_data(0).unwrap().sensitive);
    assert_eq!(
        fields.row_data(0).unwrap().value,
        "",
        "hidden values stay in Rust"
    );
    app.invoke_reveal_field(0);
    assert_eq!(app.get_revealed_field_value(), "C-42");
    app.invoke_reveal();
    assert_eq!(
        app.get_revealed_field(),
        -1,
        "one secret on screen at a time"
    );
    app.invoke_edit_item();
    assert_eq!(app.get_ed_fields().row_data(0).unwrap().value, "C-42");
    app.invoke_field_remove(0);
    app.invoke_save_item();
    assert_eq!(app.get_detail_fields().row_count(), 0);

    // ---- a change made outside this window is never overwritten ----
    let good = std::fs::read(&path).unwrap();
    let mut other = good.clone();
    other.push(0);
    std::fs::write(&path, &other).unwrap();
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 24);
    assert_eq!(app.get_notice_code(), 23);
    assert_eq!(std::fs::read(&path).unwrap(), other, "left untouched");
    std::fs::write(&path, &good).unwrap();
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 0, "saves again once the file matches");
    app.invoke_toggle_favorite();

    // ---- an icon taken from another website ----
    app.invoke_edit_item();
    app.set_ed_icon_url("  github.example ".into());
    app.invoke_save_item();
    app.invoke_edit_item();
    assert_eq!(app.get_ed_icon_url(), "https://github.example");
    app.set_ed_icon_url("".into());
    app.invoke_save_item();

    // ---- password history: the old password is kept when it changes ----
    assert_eq!(app.get_detail_title(), "GitHub");
    assert_eq!(app.get_detail_history_count(), 0);
    assert!(app.get_detail_strength_score() >= 1);
    app.invoke_edit_item();
    type_into(&app, 4, "password123");
    assert!(
        app.get_ed_strength_bits() > 0,
        "strength shown while typing"
    );
    assert_eq!(app.get_ed_weakness(), 3, "a very common password");
    app.invoke_save_item();
    assert_eq!(app.get_detail_history_count(), 1);
    assert_eq!(app.get_detail_strength_score(), 0);
    assert_eq!(app.get_detail_age_unit(), 0, "changed today");
    app.invoke_show_history();
    assert!(app.get_detail_history_shown());
    assert_eq!(app.get_detail_history().row_data(0).unwrap().password, "");
    app.invoke_reveal_history(0);
    assert_eq!(
        app.get_detail_history().row_data(0).unwrap().password,
        "gh-item-pass"
    );
    app.invoke_reveal_history(0);
    assert_eq!(app.get_detail_history().row_data(0).unwrap().password, "");

    // ---- password health ----
    app.invoke_open_health();
    assert_eq!(app.get_panel(), Panel::Health);
    assert!(app.get_health_logins() >= 1);
    assert!(
        app.get_health_counts().row_data(1).unwrap() >= 1,
        "a weak one"
    );
    assert!(app.get_health_score() < 100);
    app.set_health_filter(1);
    app.invoke_health_filter_changed(1);
    let weak = app.get_health_rows();
    let github_row = (0..weak.row_count())
        .find(|&i| weak.row_data(i).unwrap().title == "GitHub")
        .expect("GitHub listed as weak");
    assert_eq!(weak.row_data(github_row).unwrap().problem, 2);
    app.invoke_health_open(i32::try_from(github_row).unwrap());
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_detail_title(), "GitHub");
    app.set_health_filter(-1);
    app.invoke_clear_history();
    assert_eq!(app.get_detail_history_count(), 0);
    assert_eq!(app.get_notice_code(), 24);

    // ---- vault settings ----
    app.invoke_open_settings();
    assert_eq!(app.get_history_limit(), 10);
    app.set_vault_name_edit("x".repeat(61).into());
    app.invoke_vault_settings_changed();
    assert_eq!(app.get_error_code(), 27);
    app.set_vault_name_edit("Home".into());
    app.set_history_limit(3);
    app.invoke_vault_settings_changed();
    assert_eq!(app.get_vault_name(), "Home");
    assert_eq!(app.get_notice_code(), 26);
    assert_eq!((app.get_kdf_memory(), app.get_kdf_passes()), (64, 2));

    // ---- generator ----
    app.invoke_open_generator();
    assert_eq!(app.get_panel(), Panel::Generator);
    assert_eq!(app.get_gen_result().chars().count(), 24);
    app.set_gen_mode(1);
    app.invoke_regenerate();
    assert!(app.get_gen_result().split('-').count() >= 6);
    assert!(app.get_gen_bits() >= 77);
    // Word case and separator.
    app.set_gen_word_case(1);
    app.set_gen_separator(".".into());
    app.invoke_regenerate();
    let phrase = app.get_gen_result().to_string();
    assert!(phrase.split('.').count() >= 6, "{phrase}");
    assert_eq!(phrase, phrase.to_uppercase());
    // A word list of one's own.
    let list = dir.path().join("palavras.txt");
    std::fs::write(
        &list,
        (0..600)
            .map(|i| format!("palavra{i}\n"))
            .collect::<String>(),
    )
    .unwrap();
    controller.add_wordlist_file(&list);
    assert_eq!(app.get_gen_wordlist(), 1);
    assert!(app.get_gen_wordlist_removable());
    assert!(
        app.get_gen_result()
            .to_lowercase()
            .split('.')
            .all(|w| w.starts_with("palavra"))
    );
    let short = dir.path().join("short.txt");
    std::fs::write(&short, "um\ndois\n").unwrap();
    controller.add_wordlist_file(&short);
    assert_eq!(app.get_error_code(), 25);
    app.invoke_remove_wordlist();
    assert_eq!(app.get_gen_wordlist(), 0);
    app.set_gen_word_case(0);
    app.set_gen_separator("-".into());
    // Random characters: extended ASCII plus extra characters, minus excluded ones.
    app.set_gen_mode(0);
    app.set_gen_lowercase(false);
    app.set_gen_uppercase(false);
    app.set_gen_digits(false);
    app.set_gen_symbols(false);
    app.set_gen_extended(true);
    app.set_gen_also_use("xyz".into());
    app.set_gen_never_use("é".into());
    app.invoke_regenerate();
    assert_eq!(app.get_gen_alphabet(), 96);
    assert!(
        app.get_gen_result()
            .chars()
            .all(|c| "xyz".contains(c) || ('\u{a1}'..='\u{ff}').contains(&c))
    );
    app.set_gen_lowercase(true);
    app.set_gen_uppercase(true);
    app.set_gen_digits(true);
    app.set_gen_symbols(true);
    app.set_gen_extended(false);
    app.set_gen_also_use("".into());
    app.set_gen_never_use("".into());

    // ---- settings: master password and kit ----
    app.invoke_open_settings();
    type_into(&app, 5, "not the current one");
    type_into(&app, 6, NEW_PASSWORD);
    type_into(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_error_code(), 11, "wrong current password");
    type_into(&app, 5, PASSWORD);
    app.invoke_change_password();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 7);

    // ---- unlock protection: Argon2id level, checked with the current password ----
    app.invoke_open_settings();
    assert_eq!(
        app.get_kdf_current(),
        -1,
        "the test vault uses the minimum cost"
    );
    app.set_kdf_level(0);
    type_into(&app, 9, "not the current one");
    app.invoke_change_kdf();
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_kdf_failed(), "the error shows on that card");
    type_into(&app, 9, NEW_PASSWORD);
    app.invoke_change_kdf();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 30);
    assert_eq!(app.get_kdf_current(), 0);
    assert_eq!(length(&app, 9), 0, "the password field is cleared");
    assert_ne!(app.get_unlock_time(), "");
    // Other hash methods (scrypt, PBKDF2-SHA-256) and back to Argon2id.
    assert_eq!(app.get_kdf_current_method(), 0);
    for method in [1, 2, 0] {
        app.invoke_open_settings();
        app.set_kdf_method(method);
        type_into(&app, 9, NEW_PASSWORD);
        app.invoke_change_kdf();
        assert_eq!(
            app.get_error_code(),
            0,
            "detail: {}",
            app.get_error_detail()
        );
        assert_eq!(
            (app.get_kdf_current_method(), app.get_kdf_current()),
            (method, 0)
        );
        app.invoke_lock();
        type_into(&app, 0, NEW_PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault, "method {method} unlocks");
    }

    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();

    // ---- emergency kit page: printable PDF, wiped on lock ----
    app.invoke_open_kit();
    assert_eq!(app.get_panel(), Panel::Kit);
    assert_eq!(
        app.get_kit_secret_key(),
        "",
        "hidden until the password is typed"
    );
    app.invoke_print_kit();
    let print_dir = dir.path().join("home").join("print");
    assert!(
        !print_dir.exists(),
        "nothing to print before the kit is shown"
    );
    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_print_kit();
    let printed: Vec<_> = std::fs::read_dir(&print_dir).unwrap().flatten().collect();
    assert_eq!(printed.len(), 1);
    let pdf = std::fs::read(printed[0].path()).unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(
        pdf.windows(secret_key.len())
            .any(|w| w == secret_key.as_bytes())
    );
    assert_eq!(app.get_notice_code(), 16);

    // ---- lock and unlock ----
    app.invoke_lock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_items().row_count(), 0);
    assert_eq!(
        std::fs::read_dir(&print_dir).unwrap().count(),
        0,
        "printed kit wiped on lock"
    );
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 1, "old password no longer works");
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- item lock: secrets wait for a second check, the rest stays visible ----
    let relock = |app: &AppWindow| {
        app.invoke_lock();
        type_into(app, 0, NEW_PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault);
    };
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_edit_item();
    app.set_ed_reprompt(true);
    app.invoke_save_item();
    assert!(app.get_detail_locked(), "marked: locked from now on");
    assert!(
        ask(r#"{"type":"logins","url":"https://github.com/"}"#).contains(r#""locked":true"#),
        "the extension sees the item lock too"
    );
    assert_eq!(app.get_detail_check(), 0, "the master password by default");
    assert_eq!(app.get_detail_title(), "GitHub");
    assert_ne!(
        app.get_detail_username(),
        "",
        "who the account is stays visible"
    );
    assert!(app.get_detail_urls().row_count() > 0);
    assert!(!app.get_detail_has_password());
    assert_eq!(app.get_totp_code(), "");
    assert_eq!(app.get_detail_codes_total(), 0);
    app.invoke_copy_username();
    assert_eq!(app.get_notice_code(), 2, "what is visible can be copied");
    // No route reaches the secrets: reveal, copy, edit and delete do nothing.
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "");
    app.invoke_copy_password();
    assert_ne!(app.get_notice_code(), 1);
    app.invoke_copy_totp();
    assert_ne!(app.get_notice_code(), 3);
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Detail);
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), 1);
    // The Authenticator still lists its code, masked and not copyable.
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_open_authenticator();
    assert!(app.get_auth_locked() && !app.get_auth_guarded_open());
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert_eq!(row.title, "GitHub");
    assert!(row.locked && row.code.is_empty());
    app.invoke_auth_copy(0);
    assert_ne!(app.get_notice_code(), 3);
    // The check, typed there, opens every locked item at once.
    type_into(&app, 11, "not the master password");
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 35);
    assert_eq!(app.get_error_detail(), "4", "tries left");
    assert!(app.get_auth_locked());
    type_into(&app, 11, NEW_PASSWORD);
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(length(&app, 11), 0, "what was typed is cleared");
    assert!(!app.get_auth_locked() && app.get_auth_guarded_open());
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert!(!row.locked);
    assert_eq!(row.code.len(), 7);
    app.invoke_auth_copy(0);
    assert_eq!(app.get_notice_code(), 3);
    app.invoke_auth_open(0);
    assert_eq!(app.get_panel(), Panel::Detail);
    assert!(!app.get_detail_locked() && app.get_detail_guarded_open());
    assert!(app.get_detail_has_password());
    // Locked again by hand; opened from the item page this time.
    app.invoke_lock_secrets();
    assert_eq!(app.get_notice_code(), 39);
    assert!(app.get_detail_locked() && !app.get_detail_has_password());
    type_into(&app, 11, NEW_PASSWORD);
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Editor);
    app.set_ed_reprompt(false);
    app.invoke_save_item();
    assert!(!app.get_detail_guarded_open());
    app.invoke_lock_secrets();
    assert!(!app.get_detail_locked(), "no longer marked");

    // A PIN for every item, set after a master password check. From here the locked
    // secrets are encrypted under a key only the PIN opens.
    app.invoke_open_settings();
    assert_eq!(
        (app.get_guard_all(), app.get_guard_current_check()),
        (false, 0)
    );
    assert!(!app.get_guard_encrypts());
    app.set_guard_check(1);
    app.set_guard_all(true);
    type_into(&app, 12, "12");
    type_into(&app, 13, "not the current one");
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_guard_failed(), "the error shows on that card");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 36, "two digits are not a PIN");
    type_into(&app, 12, "4821");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    assert_eq!(app.get_guard_current_check(), 1);
    assert!(app.get_guard_encrypts() && !app.get_secrets_open());
    assert_eq!((length(&app, 12), length(&app, 13)), (0, 0));
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "every item is locked now");
    assert_eq!(app.get_detail_check(), 1);
    // The extension: the PIN typed in its window opens the one login asked for, on the same
    // count of wrong tries, and leaves the app's lock closed.
    let listed = ask(r#"{"type":"logins","url":"https://github.com/"}"#);
    assert!(listed.contains(r#""check":"pin""#) && listed.contains(r#""locked":true"#));
    let fill = |pin: &str| {
        ask(&format!(
            r#"{{"type":"fill","url":"https://github.com/","id":"{id}","check":"{pin}"}}"#
        ))
    };
    assert!(
        ask(&format!(
            r#"{{"type":"fill","url":"https://github.com/","id":"{id}"}}"#
        ))
        .contains(r#""code":"item_locked","check":"pin""#)
    );
    let wrong = fill("0000");
    assert!(
        wrong.contains(r#""code":"wrong_check""#) && wrong.contains(r#""left":4"#),
        "{wrong}"
    );
    app.set_notice_code(0);
    let right = fill("4821");
    assert!(right.contains(r#""password":""#), "{right}");
    assert_eq!(app.get_notice_code(), 40);
    assert!(!app.get_secrets_open());
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "still locked in the app");
    assert!(!app.get_detail_has_password());
    // Windows Hello as the easy way in: turned on with the item lock, it opens locked items
    // in the app and for the extension, with nothing typed.
    assert!(!app.get_guard_hello_on());
    app.invoke_open_settings();
    assert!(!app.get_guard_hello());
    app.set_guard_hello(true);
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked() && app.get_guard_hello_on());
    app.invoke_unlock_item_hello();
    assert!(!app.get_detail_locked() && app.get_detail_has_password());
    app.invoke_lock_secrets();
    let listed = ask(r#"{"type":"logins","url":"https://github.com/"}"#);
    assert!(listed.contains(r#""hello":true"#), "{listed}");
    let by_hello = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/","id":"{id}","hello":true}}"#
    ));
    assert!(by_hello.contains(r#""password":""#), "{by_hello}");
    assert!(!app.get_secrets_open(), "closed again after the one fill");
    // Cancelled at the prompt: the extension is told to ask for the PIN instead.
    hello.cancel.store(true, Ordering::SeqCst);
    let cancelled = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/","id":"{id}","hello":true}}"#
    ));
    assert!(
        cancelled.contains(r#""code":"item_locked","check":"pin""#),
        "{cancelled}"
    );
    app.invoke_unlock_item_hello();
    assert!(app.get_detail_locked() || !app.get_secrets_open());
    hello.cancel.store(false, Ordering::SeqCst);
    assert_eq!(app.get_detail_title(), "GitHub");
    assert!(!app.get_detail_has_password());
    assert_eq!(app.get_totp_count(), 1);
    // A new item would be sealed too: saving it asks for the PIN in the editor.
    let before = app.get_total_items();
    app.invoke_new_item();
    app.set_ed_title("Sealed at birth".into());
    type_into(&app, 4, "born-locked");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 37);
    assert_eq!(app.get_panel(), Panel::Editor);
    type_into(&app, 11, "0000");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 35);
    assert_eq!(app.get_panel(), Panel::Editor);
    type_into(&app, 11, "4821");
    app.invoke_save_item();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_total_items(), before + 1);
    assert!(app.get_secrets_open() && !app.get_detail_locked());
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "born-locked");
    app.invoke_conceal();
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), before);
    app.invoke_lock_secrets();
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked());
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_code().len(), 7);
    // A forgotten PIN is replaced with the master password alone.
    relock(&app);
    app.invoke_open_settings();
    type_into(&app, 12, "777777");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    // The PIN survives a save and a reopen; five wrong tries lock the whole vault.
    relock(&app);
    app.invoke_select(0);
    assert!(app.get_detail_locked());
    for left in ["4", "3", "2", "1"] {
        type_into(&app, 11, "4821");
        app.invoke_unlock_item();
        assert_eq!(app.get_error_code(), 35);
        assert_eq!(app.get_error_detail(), left);
        assert_eq!(app.get_screen(), Screen::Vault);
    }
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert_eq!(app.get_screen(), Screen::Unlock, "locked out");
    assert_eq!(app.get_notice_code(), 38);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    app.invoke_select(0);
    type_into(&app, 11, "777777");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    app.invoke_lock_secrets();
    // Back to no lock: the master password opens the sealed secrets for good.
    app.invoke_open_settings();
    app.set_guard_check(0);
    app.set_guard_all(false);
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    assert!(!app.get_guard_encrypts());
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(!app.get_detail_locked(), "back to no lock");
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_count(), 1);

    // ---- keyfile: a file needed together with the master password ----
    app.invoke_open_settings();
    assert!(!app.get_keyfile_on());
    let keyfile = dir.path().join("test.keyfile");
    app.set_keyfile_target(keyfile.to_str().unwrap().into());
    type_into(&app, 10, "not the current one");
    app.invoke_keyfile_action(0);
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_keyfile_failed(), "the error shows on that card");
    assert!(!keyfile.exists(), "nothing written before the check");
    type_into(&app, 10, NEW_PASSWORD);
    app.invoke_keyfile_action(0);
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 35);
    assert!(app.get_keyfile_on());
    assert!(keyfile.is_file());
    assert_eq!(length(&app, 10), 0);
    // The master password still checks out (it now needs the keyfile behind the scenes).
    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();

    app.invoke_lock();
    assert!(app.get_needs_keyfile());
    assert_eq!(
        app.get_keyfile_path().as_str(),
        keyfile.to_str().unwrap(),
        "this computer remembers where the file is"
    );
    app.set_keyfile_path("".into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 32, "no keyfile, no vault");
    let other = dir.path().join("other.keyfile");
    std::fs::write(&other, "vault-keyfile-v1 not the right one\n").unwrap();
    app.set_keyfile_path(other.to_str().unwrap().into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_error_code(),
        34,
        "the right password with the wrong file"
    );
    assert_eq!(app.get_screen(), Screen::Unlock);
    app.set_keyfile_path(keyfile.to_str().unwrap().into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    app.invoke_open_settings();
    assert!(app.get_keyfile_on());
    type_into(&app, 10, NEW_PASSWORD);
    app.invoke_keyfile_action(2);
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 36);
    assert!(!app.get_keyfile_on());
    app.invoke_lock();
    assert!(!app.get_needs_keyfile());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- quick unlock (fake Windows Hello) ----
    let id = app.get_vault_id().to_string();
    let home = dir.path().join("home");
    let enable = |app: &AppWindow| {
        app.set_quick_unlock_on(true);
        app.invoke_quick_unlock_toggled(true);
    };
    assert!(!app.get_quick_unlock_on());
    hello.cancel.store(true, Ordering::SeqCst);
    enable(&app);
    assert!(!app.get_quick_unlock_on(), "cancelled prompt leaves it off");
    hello.cancel.store(false, Ordering::SeqCst);
    enable(&app);
    assert!(app.get_quick_unlock_on());
    assert_eq!(app.get_notice_code(), 12);
    assert!(home.join(format!("quick-unlock-{id}.bin")).exists());

    app.invoke_lock();
    assert!(app.get_quick_unlock_on(), "offered on the lock screen");
    app.invoke_quick_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total_items(), 1);

    // Cancelling at unlock is silent.
    app.invoke_lock();
    hello.cancel.store(true, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_error_code(), 0);
    hello.cancel.store(false, Ordering::SeqCst);

    // The master password is required again after the interval (here: no record at all).
    std::fs::remove_file(home.join(format!("last-password-{id}.bin"))).unwrap();
    app.invoke_quick_unlock();
    assert_eq!(app.get_error_code(), 16, "password due");
    assert_eq!(app.get_screen(), Screen::Unlock);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    app.invoke_lock();
    app.invoke_quick_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "works again after the password"
    );

    // A different device secret (another PC, a reset TPM) cannot open it, and it is dropped.
    app.invoke_lock();
    hello.other_device.store(true, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_error_code(), 15);
    assert!(!app.get_quick_unlock_on());
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());
    hello.other_device.store(false, Ordering::SeqCst);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    // Turned on again, then off from Settings.
    app.invoke_open_settings();
    enable(&app);
    assert!(app.get_quick_unlock_on());
    app.set_quick_unlock_on(false);
    app.invoke_quick_unlock_toggled(false);
    assert_eq!(app.get_notice_code(), 13);
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());

    // Changing the master password turns it off.
    enable(&app);
    type_into(&app, 5, NEW_PASSWORD);
    type_into(&app, 6, PASSWORD);
    type_into(&app, 7, PASSWORD);
    app.invoke_change_password();
    assert_eq!(
        app.get_notice_code(),
        15,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(!app.get_quick_unlock_on());
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, NEW_PASSWORD);
    type_into(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 7);
    enable(&app);
    assert!(app.get_quick_unlock_on());

    // ---- a new device: the Secret Key must be typed once ----
    app.invoke_lock();
    secret_store::forget(&app.get_vault_id()).unwrap();
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 3, "Secret Key required");
    assert!(app.get_needs_secret_key());
    type_into(&app, 2, &secret_key.to_lowercase());
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(!app.get_needs_secret_key());

    // ---- recovery with the emergency kit ----
    app.invoke_lock();
    app.invoke_show_recovery();
    assert_eq!(app.get_screen(), Screen::Recover);
    type_into(&app, 3, "R0-not-a-key");
    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, PASSWORD);
    app.invoke_recover();
    assert_eq!(app.get_error_code(), 8);
    type_into(&app, 3, &recovery_key);
    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, PASSWORD);
    app.invoke_recover();
    assert_eq!(
        app.get_screen(),
        Screen::Onboarding,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(app.get_recovered());
    assert!(!app.get_quick_unlock_on(), "recovery sets a new password");
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());
    let new_secret_key = app.get_kit_secret_key().to_string();
    assert!(new_secret_key.starts_with("S0-") && new_secret_key != secret_key);
    assert_eq!(
        app.get_kit_recovery_key(),
        "",
        "the Recovery Key itself did not change"
    );
    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- import & export ----
    app.invoke_open_transfer();
    assert_eq!(app.get_panel(), Panel::Transfer);
    let export_file = dir.path().join("export.json");
    std::fs::write(
        &export_file,
        r#"{"encrypted": false,
            "folders": [{"id": "f1", "name": "Shopping"}],
            "items": [
              {"type": 1, "name": "Shop", "folderId": "f1",
               "login": {"username": "buyer", "password": "shop-pass", "uris": [{"uri": "https://shop.example"}]}},
              {"type": 1, "name": "GitHub",
               "login": {"username": "hubot", "password": "password123", "uris": [{"uri": "https://github.com"}]}}
            ]}"#,
    )
    .unwrap();
    controller.start_import(export_file.clone());
    assert_eq!(
        app.get_import_stage(),
        2,
        "detail: {}",
        app.get_error_detail()
    );
    // Review: every entry listed, passwords never shown, duplicates unticked.
    let rows = app.get_import_rows();
    assert_eq!(rows.row_count(), 2);
    let shop = rows.row_data(0).unwrap();
    assert_eq!(
        (shop.title.as_str(), shop.folder.as_str()),
        ("Shop", "Shopping")
    );
    assert!(shop.include && shop.has_password && !shop.duplicate);
    assert!(rows.row_data(1).unwrap().duplicate);
    assert_eq!(
        app.get_import_selected(),
        1,
        "GitHub is already in the vault"
    );
    assert_eq!(app.get_import_duplicates(), 1);
    app.invoke_import_select_all(false);
    assert_eq!(app.get_import_selected(), 0);
    app.invoke_import_toggle(0, true);
    assert_eq!(app.get_import_selected(), 1);
    app.invoke_import_confirm();
    assert_eq!(app.get_import_stage(), 3);
    assert_eq!(app.get_import_added(), 1);
    assert_eq!(app.get_notice_code(), 19);
    assert!(app.get_import_plaintext());
    assert_eq!(app.get_folders().row_count(), 1);
    app.invoke_import_wipe();
    assert!(!export_file.exists(), "plain-text export wiped");
    assert_eq!(app.get_import_stage(), 0);

    // A file that isn't an export is refused with a message.
    let junk = dir.path().join("junk.csv");
    std::fs::write(&junk, "a,b\n1,2\n").unwrap();
    controller.start_import(junk);
    assert_eq!(app.get_error_code(), 19);
    app.invoke_import_cancel();

    // Unencrypted export needs the master password.
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 11);
    type_into(&app, 5, PASSWORD);
    app.invoke_export_plain();
    let exported = path.with_extension("export.json");
    let text = std::fs::read_to_string(&exported).unwrap();
    assert!(text.contains("\"Shop\"") && text.contains("Shopping"));
    assert_eq!(app.get_notice_code(), 21);
    std::fs::remove_file(exported).unwrap();

    // ---- a second vault, and back to the first ----
    let second = dir.path().join("second.vault");
    controller.switch_vault(second.clone());
    assert_eq!(app.get_screen(), Screen::Onboarding, "no vault there yet");
    assert_eq!(app.get_items().row_count(), 0, "the first vault was locked");
    assert!(app.get_recent_vaults().row_count() >= 2);
    type_into(&app, 0, NEW_PASSWORD);
    type_into(&app, 1, NEW_PASSWORD);
    app.invoke_create_vault();
    let _cleanup_second = ForgetOnDrop(app.get_vault_id().to_string());
    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 0);
    assert!(second.exists());
    app.invoke_switch_vault();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_choosing_vault());
    let recent = app.get_recent_vaults();
    assert!(recent.row_data(0).unwrap().current, "most recent first");
    let first = (0..recent.row_count())
        .find(|&i| recent.row_data(i).unwrap().name == "test")
        .unwrap();
    app.invoke_pick_vault(first as i32);
    assert!(!app.get_choosing_vault());
    assert_eq!(app.get_vault_path(), path.display().to_string().as_str());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 1, "each vault has its own password");
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert!(app.get_total_items() >= 1);

    // ---- nothing readable on disk ----
    let bytes = std::fs::read(&path).unwrap();
    for needle in [
        "GitHub",
        "hubot",
        "gh-item-pass",
        "password123",
        "github.com",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} leaked"
        );
    }
}
