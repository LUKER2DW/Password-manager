//! Headless tests of how the app keeps the Secret Key on this computer (CRYPTO.md §2.2.1),
//! with the stand-in chip every test of this binary uses: kept under the chip and said in
//! Settings, a cleared chip asking once for the kit's Secret Key, and a chip that doesn't
//! answer changing nothing (and leaving a new key with Windows until it does).

use vault_core::Vault;
use vault_platform::secret_store::{self, Kept};

use super::{PASSWORD, app_home, memory_chip, review::open_app, review::vault_file, type_into};
use crate::ui::Screen;

/// Field numbers (controller.rs `field`).
const MASTER: i32 = 0;
const SECRET_KEY: i32 = 2;
/// Error codes (controller.rs `error`).
const SECRET_KEY_CHIP_LOST: i32 = 90;
const SECRET_KEY_UNREADABLE: i32 = 92;

/// Makes the stand-in chip fail until dropped, so the next test finds it answering.
struct Failing;

impl Failing {
    fn start() -> Self {
        memory_chip().set_failing(true);
        Self
    }
}

impl Drop for Failing {
    fn drop(&mut self) {
        memory_chip().set_failing(false);
    }
}

fn vault_id(path: &std::path::Path) -> String {
    Vault::inspect(&std::fs::read(path).unwrap())
        .unwrap()
        .id_hex
}

#[test]
fn a_cleared_chip_asks_for_the_kits_secret_key_and_keeps_it_again() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, key, _forget) = vault_file(dir.path(), "k.vault", &[("Mail", "mail-pw")], |_| {});
    let id = vault_id(&path);
    assert_eq!(secret_store::kept(&id).unwrap(), Some(Kept::Chip));

    // Opened with the key kept under the chip, which Settings says.
    let (app, _controller) = open_app(&path, None);
    assert_eq!(app.get_secret_key_kept(), 1);
    app.invoke_lock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!app.get_needs_secret_key(), "a kept key isn't asked for");

    // The chip was cleared: the unlock says so, asks for the kit's Secret Key and deletes
    // nothing.
    memory_chip().lose(&id);
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_error_code(), SECRET_KEY_CHIP_LOST);
    assert!(app.get_needs_secret_key());
    assert_eq!(secret_store::kept(&id).unwrap(), Some(Kept::Chip));

    // Typed from the kit, it opens the vault and is kept again, under a new chip key.
    type_into(&app, SECRET_KEY, &key.to_display_string());
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_secret_key_kept(), 1);
    assert_eq!(secret_store::load(&id).unwrap(), Some(key));
}

#[test]
fn a_chip_that_doesnt_answer_changes_nothing_and_windows_keeps_a_new_key_until_it_does() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let (path, key, _forget) = vault_file(dir.path(), "f.vault", &[("Shop", "shop-pw")], |_| {});
    let id = vault_id(&path);
    let (app, _controller) = open_app(&path, None);
    app.invoke_lock();

    {
        let _failing = Failing::start();
        // The kept key can't be read now: said, the kit's asked for, nothing deleted.
        type_into(&app, MASTER, PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Unlock);
        assert_eq!(app.get_error_code(), SECRET_KEY_UNREADABLE);
        assert!(app.get_needs_secret_key());

        // Typed, it opens the vault; what is kept under the chip stays as it was.
        type_into(&app, SECRET_KEY, &key.to_display_string());
        type_into(&app, MASTER, PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault);
        assert_eq!(
            app.get_secret_key_kept(),
            0,
            "not said while the chip doesn't answer"
        );
        assert_eq!(secret_store::kept(&id).unwrap(), Some(Kept::Chip));
        app.invoke_lock();

        // A computer that doesn't have the key yet, its chip not answering: Windows keeps it,
        // and Settings says that is weaker.
        secret_store::forget(&id).unwrap();
        type_into(&app, SECRET_KEY, &key.to_display_string());
        type_into(&app, MASTER, PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault);
        assert_eq!(app.get_secret_key_kept(), 2);
        assert_eq!(secret_store::kept(&id).unwrap(), Some(Kept::System));
        app.invoke_lock();
    }

    // The chip answers again: the next unlock moves the key under it.
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_secret_key_kept(), 1);
    assert_eq!(secret_store::kept(&id).unwrap(), Some(Kept::Chip));
    assert_eq!(secret_store::load(&id).unwrap(), Some(key));
}
