//! Desktop app entry point.
//!
//! Set `VAULT_ALLOW_CAPTURE=1` to allow screenshots of the window (design reviews only).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use slint::ComponentHandle;
use vault_desktop::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::AppWindow,
};

fn main() -> anyhow::Result<()> {
    let app = AppWindow::new()?;
    apply_sketches(&app);
    // VAULT_FILE wins; otherwise the vault used last on this computer, if it is still there.
    let path = if std::env::var_os("VAULT_FILE").is_some() {
        vault_platform::paths::default_vault_path()?
    } else {
        match vault_platform::DeviceState::load()
            .ok()
            .and_then(|state| state.recent_vaults().into_iter().find(|p| p.exists()))
        {
            Some(path) => path,
            None => vault_platform::paths::default_vault_path()?,
        }
    };
    let _controller = Controller::install(
        &app,
        path,
        Runner::Thread,
        vault_platform::quick_unlock::system_verifier(),
    )?;

    // The native window exists once the event loop runs.
    let weak = app.as_weak();
    slint::Timer::single_shot(Duration::from_millis(120), move || {
        if std::env::var_os("VAULT_ALLOW_CAPTURE").is_some() {
            return;
        }
        if let Some(app) = weak.upgrade() {
            use raw_window_handle::HasWindowHandle;
            if let Ok(handle) = app.window().window_handle().window_handle() {
                vault_platform::screen::exclude_from_capture(handle.as_raw());
            }
        }
    });

    app.run()?;
    Ok(())
}
