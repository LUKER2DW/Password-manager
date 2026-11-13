//! Headless end-to-end test: the real Slint window and controller, driven through the same
//! callbacks the UI uses, with Slint's testing backend (nothing is drawn on screen).
//! Argon2id runs at the format's minimum cost here to keep the test fast.

use slint::{ComponentHandle, Model};
use vault_platform::secret_store;

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
    let _controller = Controller::install(&app, path.clone(), Runner::Inline).unwrap();

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

    // ---- generator ----
    app.invoke_open_generator();
    assert_eq!(app.get_panel(), Panel::Generator);
    assert_eq!(app.get_gen_result().chars().count(), 24);
    app.set_gen_mode(1);
    app.invoke_regenerate();
    assert!(app.get_gen_result().split('-').count() >= 6);
    assert!(app.get_gen_bits() >= 77);

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

    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();

    // ---- lock and unlock ----
    app.invoke_lock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_items().row_count(), 0);
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 1, "old password no longer works");
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

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

    // ---- nothing readable on disk ----
    let bytes = std::fs::read(&path).unwrap();
    for needle in ["GitHub", "hubot", "gh-item-pass", "github.com"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} leaked"
        );
    }
}
