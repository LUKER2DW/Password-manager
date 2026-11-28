//! Auto-type (controller/autotype.rs) into a desktop in memory: the window's title shown with
//! the countdown, username, Tab, password and Enter typed into it, nothing when it changed
//! meanwhile or the login waits for the item lock, and the lock cancelling a countdown.

use std::{cell::RefCell, rc::Rc};

use vault_core::{GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Vault};
use vault_platform::{
    autotype::{Desktop, KeyEvent, Target, VK_RETURN, VK_TAB},
    secret_store,
};

use super::{ForgetOnDrop, PASSWORD, app_home, type_into};
use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Screen},
};

const MASTER: i32 = 0;
const REPROMPT: i32 = 11;
const AUTOTYPE_DONE: i32 = 152;
const AUTOTYPE_CHANGED: i32 = 153;
const SECRETS_LOCKED: i32 = 37;

/// A window called "Remote Desktop" behind the app; what reached it.
struct FakeDesktop {
    title: RefCell<String>,
    front: RefCell<isize>,
    typed: RefCell<Vec<KeyEvent>>,
}

impl Desktop for FakeDesktop {
    fn window_behind(&self, _own: isize) -> Option<Target> {
        Some(Target {
            window: 42,
            process: 7,
            title: self.title.borrow().clone(),
        })
    }
    fn still_there(&self, target: &Target) -> bool {
        *self.title.borrow() == target.title
    }
    fn activate(&self, target: &Target) -> bool {
        *self.front.borrow_mut() = target.window;
        true
    }
    fn foreground(&self) -> Option<isize> {
        Some(*self.front.borrow())
    }
    fn modifiers_held(&self) -> bool {
        false
    }
    fn send(&self, events: &[KeyEvent]) -> bool {
        self.typed.borrow_mut().extend_from_slice(events);
        true
    }
}

/// What the window received: the characters, with Tab and Enter as `\t` and `\n`.
fn received(desktop: &FakeDesktop) -> String {
    let mut units = Vec::new();
    for event in desktop.typed.borrow().iter() {
        match *event {
            KeyEvent::Unicode { unit, up: false } => units.push(unit),
            KeyEvent::Virtual { key, up: false } if key == VK_TAB => units.push(u16::from(b'\t')),
            KeyEvent::Virtual { key, up: false } if key == VK_RETURN => {
                units.push(u16::from(b'\n'));
            }
            _ => {}
        }
    }
    String::from_utf16(&units).unwrap()
}

#[test]
fn auto_type_types_a_login_into_the_window_shown() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let key = SecretKey::generate().unwrap();
    let path = dir.path().join("autotype.vault");
    let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    for (title, guarded) in [("A Plain", false), ("B Guarded", true)] {
        let mut login = ItemData::new(ItemKind::Login, title);
        login.username = "test.user".into();
        login.password = format!("test pässword {title}");
        login.reprompt = guarded;
        vault.add_item(&login).unwrap();
    }
    vault
        .set_item_guard(false, GuardCheck::Pin, Some("2468"), None)
        .unwrap();
    std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    let _cleanup = ForgetOnDrop(vault.id_hex());
    secret_store::store(&vault.id_hex(), &key).unwrap();
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let controller = Controller::install(&app, path.clone(), Runner::Inline, None).unwrap();
    crate::i18n::apply("en");
    let desktop = Rc::new(FakeDesktop {
        title: RefCell::new("Remote Desktop".into()),
        front: RefCell::new(1),
        typed: RefCell::new(Vec::new()),
    });
    controller.use_desktop(desktop.clone());
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    let select = |title: &str| {
        let items = app.get_items();
        let index = (0..slint::Model::row_count(&items))
            .find(|&i| slint::Model::row_data(&items, i).is_some_and(|row| row.title == title))
            .unwrap();
        app.invoke_select(i32::try_from(index).unwrap());
    };
    app.invoke_select_category(0);

    // The window's title and the countdown first; nothing typed until it ends.
    select("A Plain");
    app.invoke_auto_type();
    assert_eq!(app.get_autotype_title(), "Remote Desktop");
    assert_eq!(app.get_autotype_left(), 3);
    assert!(desktop.typed.borrow().is_empty());
    controller.autotype_now();
    assert_eq!(received(&desktop), "test.user\ttest pässword A Plain\n");
    assert_eq!(app.get_notice_code(), AUTOTYPE_DONE);
    assert_eq!(app.get_autotype_title(), "");

    // In the security log: the login and the window, never what was typed.
    app.invoke_open_settings();
    let typed: Vec<_> = slint::Model::iter(&app.get_security_log())
        .filter(|line| line.kind == 19)
        .collect();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].title, "A Plain");
    assert_eq!(typed[0].detail, "Remote Desktop");
    app.invoke_select_category(0);
    select("A Plain");

    // Cancelled: nothing.
    desktop.typed.borrow_mut().clear();
    app.invoke_auto_type();
    app.invoke_autotype_cancel();
    controller.autotype_now();
    assert!(desktop.typed.borrow().is_empty());

    // The window changed during the countdown (another tab, another page): nothing.
    app.invoke_auto_type();
    *desktop.title.borrow_mut() = "Something else".into();
    controller.autotype_now();
    assert!(desktop.typed.borrow().is_empty());
    assert_eq!(app.get_notice_code(), AUTOTYPE_CHANGED);
    *desktop.title.borrow_mut() = "Remote Desktop".into();

    // Behind the item lock: refused until the lock is open.
    select("B Guarded");
    app.invoke_auto_type();
    assert_eq!(app.get_error_code(), SECRETS_LOCKED);
    assert_eq!(app.get_autotype_title(), "");
    type_into(&app, REPROMPT, "2468");
    app.invoke_unlock_item();
    app.invoke_auto_type();
    assert_eq!(app.get_autotype_title(), "Remote Desktop");
    controller.autotype_now();
    assert_eq!(received(&desktop), "test.user\ttest pässword B Guarded\n");

    // Locking cancels a countdown.
    desktop.typed.borrow_mut().clear();
    select("A Plain");
    app.invoke_auto_type();
    app.invoke_lock();
    assert_eq!(app.get_autotype_title(), "");
    controller.autotype_now();
    assert!(desktop.typed.borrow().is_empty());
}
