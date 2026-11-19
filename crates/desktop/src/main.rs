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
    let controller = Controller::install(
        &app,
        path,
        Runner::Thread,
        vault_platform::quick_unlock::system_verifier(),
    )?;

    // The native window exists once the event loop runs.
    let weak = app.as_weak();
    slint::Timer::single_shot(Duration::from_millis(120), move || {
        // Exactly "1": an empty or stray value left in the environment keeps the protection.
        if std::env::var_os("VAULT_ALLOW_CAPTURE").is_some_and(|value| value == "1") {
            return;
        }
        if let Some(app) = weak.upgrade() {
            use raw_window_handle::HasWindowHandle;
            if let Ok(handle) = app.window().window_handle().window_handle() {
                vault_platform::screen::exclude_from_capture(handle.as_raw());
            }
        }
    });

    // The icon next to the clock. Closing the window then hides it (when the setting is on)
    // and the app keeps answering the browser extension; Quit in the icon's menu ends it.
    let tray = vault_desktop::tray::install(&app);
    let in_tray = tray.is_some();
    let weak_controller = std::rc::Rc::downgrade(&controller);
    app.window().on_close_requested(move || {
        let keep = weak_controller
            .upgrade()
            .is_some_and(|controller| controller.close_to_tray(in_tray));
        if !keep {
            let _ = slint::quit_event_loop();
        }
        slint::CloseRequestResponse::HideWindow
    });

    app.show()?;
    slint::run_event_loop_until_quit()?;
    drop(tray);
    Ok(())
}
