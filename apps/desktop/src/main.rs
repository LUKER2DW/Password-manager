//! Desktop app entry point.
//!
//! A `.vault` file given as the first argument (a double-click in Explorer, "Open with") is
//! the vault the app opens. Set `VAULT_ALLOW_CAPTURE=1` to allow screenshots of the window
//! (design reviews only).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{path::PathBuf, time::Duration};

use slint::ComponentHandle;
use vault_desktop::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Messages},
};
use vault_platform::file_types;

fn main() -> anyhow::Result<()> {
    // Started by Chrome or Edge as the browser extension's native host (the extension's origin
    // is the first argument): relay its messages to the app that holds the pipe, show nothing.
    if vault_browser::host::is_our_extension(std::env::args().nth(1).as_deref()) {
        let me = std::env::current_exe()?;
        return if vault_browser::host::run(&me) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("the browser link ended with an error"))
        };
    }
    let app = AppWindow::new()?;
    apply_sketches(&app);
    let opened = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .filter(|path| file_types::is_vault_file(path) && path.is_file())
        .and_then(|path| std::path::absolute(path).ok());
    // A file opened from Explorer wins, then VAULT_FILE, then the vault used last on this
    // computer, if it is still there.
    let path = if let Some(path) = opened {
        path
    } else if std::env::var_os("VAULT_FILE").is_some() {
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

    // .vault files show this app's icon and open in it (for this user, pointing at this
    // program). A development build leaves the registration to the installed app.
    if !cfg!(debug_assertions)
        && let Ok(exe) = std::env::current_exe()
    {
        let type_name = app.global::<Messages>().get_vault_file_type();
        std::thread::spawn(move || {
            let _ = file_types::register_vault_files(&exe, &type_name);
        });
    }

    // The native window exists once the event loop runs.
    let weak = app.as_weak();
    slint::Timer::single_shot(Duration::from_millis(120), move || {
        // The window draws its own title bar (no frame of the system's): it keeps the
        // system's shadow all the same.
        #[cfg(windows)]
        if let Some(app) = weak.upgrade() {
            use slint::winit_030::{
                WinitWindowAccessor, winit::platform::windows::WindowExtWindows,
            };
            app.window()
                .with_winit_window(|window| window.set_undecorated_shadow(true));
        }
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
