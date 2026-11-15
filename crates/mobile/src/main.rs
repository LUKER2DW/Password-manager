//! The phone app in a phone-sized window, for work on a computer. On Android the same
//! controller is started by the app's activity, and the system's file picker hands it the
//! vault file (docs/MOBILE.md, M7.1 and M7.2).
//!
//! The phone's copy lives in `<app dir>/phone/vault.vault` (or `VAULT_FILE`), never on the
//! desktop app's own vault file.

use std::rc::Rc;

use slint::ComponentHandle;
use vault_mobile::{Controller, ui::PhoneWindow};

fn main() -> Result<(), slint::PlatformError> {
    let app = PhoneWindow::new()?;
    let path = std::env::var_os("VAULT_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            vault_platform::paths::app_dir()
                .ok()
                .map(|dir| dir.join("phone").join("vault.vault"))
        })
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
    app.run()
}
