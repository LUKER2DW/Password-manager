//! The phone app in a phone-sized window, for work on a computer. On Android the same
//! controller is started by the app's activity (docs/MOBILE.md, M7.1).

use slint::ComponentHandle;
use vault_mobile::{Controller, ui::PhoneWindow};

fn main() -> Result<(), slint::PlatformError> {
    let app = PhoneWindow::new()?;
    let path = vault_platform::paths::default_vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from("default.vault"));
    let _controller = Controller::start(&app, path, false);
    app.run()
}
