//! A new password's review (controller/passwords.rs): an easy master password or item lock
//! password is warned about at onboarding and in Settings, and kept only when the person says
//! so; six random words can take its place; the breach check runs only when ticked, and its
//! answers (found, or no answer) are warned about the same way; a protected export's password
//! below the one-factor floor is refused, with the generated passphrase as the way out.

use slint::{ComponentHandle, Model};

use super::{ForgetOnDrop, app_home, length, type_into};
use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, NewPassword, Screen, Secrets},
};

/// Field numbers (controller.rs `field`).
const MASTER: i32 = 0;
const CONFIRM: i32 = 1;
const CURRENT: i32 = 5;
const NEW: i32 = 6;
const NEW_AGAIN: i32 = 7;
const GUARD_NEW: i32 = 12;
const GUARD_CURRENT: i32 = 13;
/// What the review says (passwords.rs `warning`) and where (`place`).
const WEAK_MASTER: i32 = 1;
const LEAKED: i32 = 2;
const LEAK_CHECK_FAILED: i32 = 3;
const WEAK_LOCK: i32 = 4;
/// Error and notice codes (controller.rs).
const WEAK_EXPORT: i32 = 73;
const PASSWORD_CHANGED: i32 = 7;
const GUARD_SAVED: i32 = 37;

/// Twelve characters, and the first guess of many.
const EASY: &str = "password1234";

fn never_asked(_: &str) -> Result<u64, String> {
    panic!("the breach check runs only when it is ticked")
}

fn found_three_times(_: &str) -> Result<u64, String> {
    Ok(3)
}

fn no_answer(_: &str) -> Result<u64, String> {
    Err("no network".into())
}

fn review(app: &AppWindow) -> (i32, i32, String) {
    let review = app.global::<NewPassword>();
    (
        review.get_place(),
        review.get_warning(),
        review.get_arg().to_string(),
    )
}

fn shown(app: &AppWindow, field: usize) -> String {
    app.global::<Secrets>()
        .get_shown()
        .row_data(field)
        .unwrap()
        .to_string()
}

#[test]
fn easy_passwords_are_warned_about_and_a_weak_export_refused() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let path = dir.path().join("new.vault");
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let controller = Controller::install(&app, path.clone(), Runner::Inline, None).unwrap();
    crate::i18n::apply("en");
    controller.set_leak_count(never_asked);
    assert_eq!(app.get_screen(), Screen::Onboarding);

    // ---- onboarding: an easy master password is warned about, and nothing goes on ----
    type_into(&app, MASTER, EASY);
    type_into(&app, CONFIRM, EASY);
    app.invoke_create_vault();
    assert_eq!(review(&app), (1, WEAK_MASTER, String::new()));
    assert_eq!(app.get_onboarding_step(), 1);
    // Typing in it takes the warning away; the same password brings it back.
    app.global::<Secrets>().invoke_backspace(MASTER);
    assert_eq!(review(&app).0, 0);
    type_into(&app, MASTER, EASY);
    app.invoke_create_vault();
    assert_eq!(review(&app).1, WEAK_MASTER);
    // Six random words instead: in both fields, and shown so they can be learnt.
    app.global::<NewPassword>().invoke_use_passphrase(MASTER);
    assert_eq!(review(&app).0, 0);
    let phrase = shown(&app, 0);
    assert_eq!(phrase.split('-').count(), 6, "{phrase}");
    assert_eq!(length(&app, 0), length(&app, 1));
    // Ticked, the breach check is asked first (a stand-in here): found, it is warned about.
    controller.set_leak_count(found_three_times);
    app.global::<NewPassword>().set_check_leaks(true);
    app.invoke_create_vault();
    assert_eq!(review(&app), (1, LEAKED, "3".into()));
    assert_eq!(app.get_onboarding_step(), 1);
    // The person may keep it all the same.
    app.global::<NewPassword>().invoke_keep();
    assert_eq!(app.get_onboarding_step(), 2, "{}", app.get_error_detail());
    assert_eq!(review(&app).0, 0);

    // ---- the item lock: an easy item password is warned about too (a PIN never) ----
    app.set_onboarding_guard(1);
    type_into(&app, GUARD_NEW, "longer one");
    app.invoke_create_vault();
    assert_eq!(review(&app), (4, WEAK_LOCK, String::new()));
    assert!(!path.exists(), "nothing written before the answer");
    app.global::<NewPassword>().invoke_keep();
    assert_eq!(app.get_onboarding_step(), 3, "{}", app.get_error_detail());
    let _forget = ForgetOnDrop(app.get_vault_id().to_string());
    assert!(path.exists());
    assert!(
        !app.global::<NewPassword>().get_check_leaks(),
        "unticked again for the next new password"
    );
    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);

    // ---- Settings → Change master password: easy, then no answer from the breach check ----
    controller.set_leak_count(no_answer);
    app.invoke_open_settings();
    app.global::<NewPassword>().set_check_leaks(true);
    type_into(&app, CURRENT, &phrase);
    type_into(&app, NEW, EASY);
    type_into(&app, NEW_AGAIN, EASY);
    app.invoke_change_password();
    assert_eq!(review(&app), (3, WEAK_MASTER, String::new()));
    app.global::<NewPassword>().invoke_keep();
    assert_eq!(review(&app), (3, LEAK_CHECK_FAILED, "no network".into()));
    app.global::<NewPassword>().invoke_keep();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), PASSWORD_CHANGED);
    assert_eq!(review(&app).0, 0);

    // ---- Settings → Item lock: an easy item password, kept ----
    controller.set_leak_count(never_asked);
    app.invoke_open_settings();
    app.set_guard_check(2);
    type_into(&app, GUARD_NEW, "another one");
    type_into(&app, GUARD_CURRENT, EASY);
    app.invoke_save_guard();
    assert_eq!(review(&app), (5, WEAK_LOCK, String::new()));
    app.global::<NewPassword>().invoke_keep();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), GUARD_SAVED);

    // ---- a protected export: a password below the floor is refused before any work ----
    app.invoke_lock_secrets();
    app.invoke_open_transfer();
    app.set_export_format(3);
    app.invoke_export_ask();
    type_into(&app, CURRENT, EASY);
    type_into(&app, NEW, "a file password");
    type_into(&app, NEW_AGAIN, "a file password");
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), WEAK_EXPORT);
    let exported = path.with_extension("export.vaultx");
    assert!(!exported.exists());
    // Six random words take its place, shown, and the export is made with them.
    app.global::<NewPassword>().invoke_use_passphrase(NEW);
    let file_phrase = shown(&app, 6);
    assert_eq!(file_phrase.split('-').count(), 6);
    assert_eq!(app.get_error_code(), 0);
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let sealed = std::fs::read(&exported).unwrap();
    assert!(vault_core::sealed_export::open(&file_phrase, &sealed).is_ok());
    drop(controller);
}
