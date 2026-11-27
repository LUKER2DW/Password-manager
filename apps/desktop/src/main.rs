//! Desktop app entry point.
//!
//! A `.vault` file given as the first argument (a double-click in Explorer, "Open with") is
//! the vault the app opens. `--at-sign-in` is Windows starting it at sign-in (Settings →
//! Appearance): it then waits in the notification area when the person chose so. Started
//! again without a file while it runs, it brings the running copy's window to the front.
//! Set `VAULT_ALLOW_CAPTURE=1` to allow screenshots of the window (design reviews only).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{path::PathBuf, time::Duration};

use slint::ComponentHandle;
use vault_desktop::{
    apply_sketches,
    controller::{Controller, Runner, TrayAction},
    ui::{AppWindow, Messages},
};
use vault_platform::{
    autostart, file_types,
    single_instance::{self, Claim},
};

fn main() -> anyhow::Result<()> {
    // Before anything loads a DLL by name: System32 only, never next to the exe.
    vault_platform::process::restrict_dll_search();
    // Other programs of this user can't read, write or steer the process (release builds: a
    // debugger can't attach afterwards), and the mitigation policies that keep it working.
    if !cfg!(debug_assertions) {
        vault_platform::process::protect_memory();
    }
    vault_platform::process::apply_mitigations();
    // The vault key and the item guard key stay encrypted between uses (CryptProtectMemory).
    vault_platform::secure_memory::install_key_shield();
    // Started by a browser as the browser extension's native host (Chrome and Edge give the
    // extension's origin, Firefox the host's manifest and the extension's id): relay its
    // messages to the app that holds the pipe, show nothing.
    let first: Vec<String> = std::env::args_os()
        .skip(1)
        .take(2)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if vault_browser::host::is_our_extension(&first) {
        let me = std::env::current_exe()?;
        return if vault_browser::host::run(&me) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("the browser link ended with an error"))
        };
    }
    let opened = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .filter(|path| file_types::is_vault_file(path) && path.is_file())
        .and_then(|path| std::path::absolute(path).ok());
    let at_sign_in = autostart::is_sign_in_start(std::env::args_os().skip(1));
    // One copy of the app: started again, it shows the running copy's window and ends. A file
    // to open, or a test vault in VAULT_FILE, still gets a window of its own.
    let alone = opened.is_none() && std::env::var_os("VAULT_FILE").is_none();
    let instance = match alone.then(vault_platform::paths::app_dir) {
        Some(Ok(app_dir)) => match single_instance::claim(&app_dir) {
            Claim::Running => return Ok(()),
            Claim::First(instance) => Some(instance),
        },
        _ => None,
    };
    let app = AppWindow::new()?;
    apply_sketches(&app);
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

    if let Some(instance) = instance {
        instance.when_called(|| {
            let _ = slint::invoke_from_event_loop(|| Controller::tray_action(TrayAction::Open));
        });
    }

    // Windows locking the session, switching user, signing out or going to sleep locks the
    // vault (Settings → Security). The watching thread waits for the lock, up to a second and
    // a half, before Windows hears back: a suspend is given about two seconds.
    vault_platform::session_watch::watch(|_| {
        let (done, locked) = std::sync::mpsc::channel();
        let asked = slint::invoke_from_event_loop(move || {
            Controller::windows_session_ended();
            let _ = done.send(());
        });
        if asked.is_ok() {
            let _ = locked.recv_timeout(Duration::from_millis(1500));
        }
    });

    // .vault files show this app's icon and open in it (for this user, pointing at this
    // program), and a start at sign-in starts this copy (a moved app, a newer one downloaded).
    // A development build leaves both to the installed app, and so does a run on a test vault
    // or app folder (VAULT_FILE, VAULT_HOME) for the start at sign-in.
    if !cfg!(debug_assertions)
        && let Ok(exe) = std::env::current_exe()
    {
        let type_name = app.global::<Messages>().get_vault_file_type();
        let follow =
            std::env::var_os("VAULT_FILE").is_none() && std::env::var_os("VAULT_HOME").is_none();
        std::thread::spawn(move || {
            let _ = file_types::register_vault_files(&exe, &type_name);
            if follow && let Ok(Some(before)) = autostart::follow(&exe) {
                let _ = slint::invoke_from_event_loop(move || {
                    Controller::sign_in_start_moved(&before);
                });
            }
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

    if at_sign_in && in_tray && controller.starts_in_tray() {
        // Started by Windows at sign-in: only the icon next to the clock. The window is made
        // all the same, hidden, so it is kept out of screen captures (above) before it is
        // ever shown.
        app.show()?;
        app.hide()?;
    } else {
        app.show()?;
    }
    slint::run_event_loop_until_quit()?;
    drop(tray);
    Ok(())
}
