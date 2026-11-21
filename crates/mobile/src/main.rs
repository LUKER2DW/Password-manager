//! The phone app in a phone-sized window, for work on a computer. On Android the same
//! controller is started by the app's activity, and the system's file picker hands it the
//! vault file (docs/MOBILE.md, M7.1 and M7.2).
//!
//! The phone's copy lives in `<app dir>/phone/vault.vault` (or `VAULT_FILE`), never on the
//! desktop app's own vault file, and its device state in `<app dir>/phone` (unless
//! `VAULT_HOME` is set), so it syncs as a device of its own.

use std::rc::Rc;

use slint::ComponentHandle;
use vault_mobile::{Controller, ui::PhoneWindow};

fn main() -> Result<(), slint::PlatformError> {
    // The "phone" keeps its own app folder (device state, sync id) inside the computer's, so
    // it syncs as a device of its own and never as the desktop app on the same computer.
    let phone_home = vault_platform::paths::app_dir()
        .ok()
        .map(|dir| dir.join("phone"));
    if std::env::var_os("VAULT_HOME").is_none()
        && let Some(home) = &phone_home
    {
        // SAFETY: set at the very start of `main`, before any other thread exists.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("VAULT_HOME", home);
        }
    }
    let app = PhoneWindow::new()?;
    let path = std::env::var_os("VAULT_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| phone_home.map(|dir| dir.join("vault.vault")))
        .unwrap_or_else(|| std::path::PathBuf::from("phone.vault"));
    let controller = Controller::start(&app, path, false);
    let weak = Rc::downgrade(&controller);
    app.on_pick_vault(move || {
        let Some(controller) = weak.upgrade() else {
            return;
        };
        if let Some(file) = rfd::FileDialog::new()
            .add_filter("Vault", &["vault"])
            .pick_file()
        {
            controller.bring_vault_file(&file);
        }
    });
    // Save a copy: written, read back, checked; a copy that fails is deleted.
    let weak = Rc::downgrade(&controller);
    app.on_save_copy(move || {
        let Some(controller) = weak.upgrade() else {
            return;
        };
        let Some((name, bytes)) = controller.copy_to_save() else {
            return;
        };
        let Some(target) = rfd::FileDialog::new()
            .set_file_name(&name)
            .add_filter("Vault", &["vault"])
            .save_file()
        else {
            return;
        };
        let read_back = vault_core::storage::write_atomic(&target, &bytes)
            .and_then(|()| vault_core::storage::read(&target))
            .map_err(|e| e.to_string());
        if !controller.copy_written(&target.display().to_string(), read_back) {
            let _ = std::fs::remove_file(&target);
        }
    });
    app.run()
}
