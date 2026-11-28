//! Unlock attempts on this computer (controller/attempts.rs): each failed try counted in the
//! device state; from the fifth a wait that the controller enforces (the right password too
//! is refused before then), that a new window on the same `VAULT_HOME` still keeps, and that a
//! clock set back doesn't shorten; Windows Hello failing counted the same; and the count told
//! once at the next unlock, then started again.

use std::{
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use vault_platform::{device::Clock, quick_unlock::DeviceVerifier};

use super::{FakeHello, PASSWORD, app_home, review::vault_file, type_into};
use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Screen},
};

/// Field numbers (controller.rs `field`).
const MASTER: i32 = 0;
/// Error codes (controller.rs `error`) and the notice (`notice`).
const WRONG_PASSWORD: i32 = 1;
const HELLO_FAILED: i32 = 14;
const UNLOCK_WAIT: i32 = 74;
const FAILED_UNLOCKS: i32 = 124;

/// The wall clock these windows read, moved by the test (no time since start: the wall clock
/// alone counts). In the past: a window reads the real clock until the test's is set, and a
/// real clock behind the failures would count as one set back.
static NOW: AtomicI64 = AtomicI64::new(1_000_000_000);

fn test_clock() -> Clock {
    Clock {
        now: NOW.load(Ordering::SeqCst),
        uptime: None,
    }
}

/// The app on `path`, locked, reading the test's clock.
fn window(path: &std::path::Path, hello: &Arc<FakeHello>) -> (AppWindow, Rc<Controller>) {
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let verifier = Some(hello.clone() as Arc<dyn DeviceVerifier>);
    let controller =
        Controller::install(&app, path.to_path_buf(), Runner::Inline, verifier).unwrap();
    crate::i18n::apply("en");
    controller.set_clock(test_clock);
    (app, controller)
}

fn try_password(app: &AppWindow, password: &str) {
    type_into(app, MASTER, password);
    app.invoke_unlock();
}

#[test]
fn failed_unlocks_wait_survive_a_restart_and_are_told_once() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, _key, _forget) = vault_file(dir.path(), "a.vault", &[("Mail", "mail-pw")], |_| {});
    let hello = Arc::new(FakeHello::default());
    let (app, controller) = window(&path, &hello);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_unlock_wait(), 0);

    // Four wrong tries cost nothing but the hashing; the fifth starts a wait of 30 s.
    for attempt in 1..=4 {
        try_password(&app, "not the password");
        assert_eq!(app.get_error_code(), WRONG_PASSWORD);
        assert_eq!(app.get_unlock_wait(), 0, "try {attempt} waits for nothing");
        NOW.fetch_add(1, Ordering::SeqCst);
    }
    try_password(&app, "not the password");
    assert_eq!(app.get_error_code(), WRONG_PASSWORD);
    assert_eq!((app.get_unlock_wait(), app.get_unlock_failed()), (30, 5));

    // The controller refuses the next try before then, the right password too, and Windows
    // Hello as well.
    NOW.fetch_add(10, Ordering::SeqCst);
    try_password(&app, PASSWORD);
    assert_eq!(app.get_error_code(), UNLOCK_WAIT);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_unlock_wait(), 20);
    app.invoke_quick_unlock();
    assert_eq!(app.get_screen(), Screen::Unlock);

    // The app started again (a new window, the same VAULT_HOME): still waiting.
    drop(controller);
    drop(app);
    let (app, controller) = window(&path, &hello);
    assert_eq!(app.get_unlock_wait(), 20, "the wait is shown at once");
    try_password(&app, PASSWORD);
    assert_eq!(app.get_error_code(), UNLOCK_WAIT);

    // A clock set back an hour doesn't shorten it: the wait starts again, whole, from there.
    NOW.fetch_sub(3_600, Ordering::SeqCst);
    try_password(&app, PASSWORD);
    assert_eq!(app.get_error_code(), UNLOCK_WAIT);
    assert_eq!(app.get_unlock_wait(), 30);

    // Once it has passed, the right password opens the vault and says, once, how many tries
    // failed and since when.
    NOW.fetch_add(31, Ordering::SeqCst);
    try_password(&app, PASSWORD);
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), FAILED_UNLOCKS);
    assert_eq!(app.get_notice_count(), 5);
    assert!(
        app.get_notice_arg().starts_with("20"),
        "a date: {}",
        app.get_notice_arg()
    );
    assert_eq!((app.get_unlock_wait(), app.get_unlock_failed()), (0, 0));

    // The count started again: the next unlock tells nothing, and a wrong try waits for
    // nothing.
    app.invoke_lock();
    app.set_notice_code(0);
    try_password(&app, "not the password");
    assert_eq!(app.get_unlock_wait(), 0);
    try_password(&app, PASSWORD);
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_notice_code(), FAILED_UNLOCKS, "the one wrong try");
    assert_eq!(app.get_notice_count(), 1);

    // Windows Hello failing (as when its chip is locked after wrong PINs) counts the same.
    app.invoke_quick_unlock_toggled(true);
    assert!(app.get_quick_unlock_on());
    app.invoke_lock();
    hello.fail.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        app.invoke_quick_unlock();
        assert_eq!(app.get_error_code(), HELLO_FAILED);
    }
    assert_eq!((app.get_unlock_wait(), app.get_unlock_failed()), (30, 5));
    hello.fail.store(false, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_error_code(), UNLOCK_WAIT);
    assert_eq!(app.get_screen(), Screen::Unlock);
    NOW.fetch_add(30, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_notice_count(), 5);
    drop(controller);
}
