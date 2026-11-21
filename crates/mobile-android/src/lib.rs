//! The phone app on Android: the activity's native entry point. It points the app's folder
//! at the app's private storage, starts Slint's Android backend and opens the same screens
//! and controller as everywhere else (`vault-mobile`).
//!
//! Build: `crates/mobile-android/build.ps1` (cargo-apk, Android NDK). See docs/MOBILE.md §7.2.

#![cfg(target_os = "android")]

use std::rc::Rc;

use slint::ComponentHandle;
use vault_mobile::{Controller, ui::PhoneWindow};

mod shell;

/// Called by the activity on its own thread once the app starts.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    // The app's private folder (other apps can't read it; Android encrypts it at rest). The
    // vault copy, device state and sync state live here.
    let Some(home) = app.internal_data_path() else {
        return;
    };
    // SAFETY: set before this library starts any thread of its own; the activity's Java
    // threads don't read the process environment.
    unsafe {
        std::env::set_var("VAULT_HOME", &home);
    }
    if slint::android::init(app).is_err() {
        return;
    }
    let Ok(window) = PhoneWindow::new() else {
        return;
    };
    // Secret fields take the system keyboard asked for a password: keyboards learn nothing
    // from it and suggest nothing, and the field itself only ever holds placeholders.
    window
        .global::<vault_mobile::ui::Secrets>()
        .set_system_keyboard(true);
    let controller = Controller::start(&window, home.join("vault.vault"), false);
    shell::CONTROLLER.with(|current| *current.borrow_mut() = Rc::downgrade(&controller));
    // The system's file picker (the activity, VaultActivity.java): a vault file to open, and
    // where to save a copy.
    let weak = Rc::downgrade(&controller);
    window.on_pick_vault(move || {
        if let (Err(detail), Some(controller)) = (shell::open_document(), weak.upgrade()) {
            controller.file_failed(&detail);
        }
    });
    let weak = Rc::downgrade(&controller);
    window.on_save_copy(move || {
        let Some(controller) = weak.upgrade() else {
            return;
        };
        if let Some((name, bytes)) = controller.copy_to_save()
            && let Err(detail) = shell::create_document(&name, &bytes)
        {
            controller.file_failed(&detail);
        }
    });
    let _ = window.run();
}
