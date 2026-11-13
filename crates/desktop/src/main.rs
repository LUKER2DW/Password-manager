//! Desktop app for the password manager (Windows first).
//!
//! Set `VAULT_ALLOW_CAPTURE=1` to allow screenshots of the window (design reviews only).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod controller;
mod sketch;
#[cfg(test)]
mod tests;
mod view;

pub(crate) mod ui {
    #![allow(missing_debug_implementations, clippy::all)]
    slint::include_modules!();
}

use std::time::Duration;

use slint::ComponentHandle;

fn main() -> anyhow::Result<()> {
    let app = ui::AppWindow::new()?;
    apply_sketches(&app);
    let path = vault_platform::paths::default_vault_path()?;
    let _controller = controller::Controller::install(&app, path, controller::Runner::Thread)?;

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

pub(crate) fn apply_sketches(app: &ui::AppWindow) {
    let sketches = sketch::Sketches::generate();
    let global = app.global::<ui::Sketch>();
    global.set_box_a(sketches.boxes[0].as_str().into());
    global.set_box_b(sketches.boxes[1].as_str().into());
    global.set_box_c(sketches.boxes[2].as_str().into());
    global.set_marker_a(sketches.markers[0].as_str().into());
    global.set_marker_b(sketches.markers[1].as_str().into());
    global.set_marker_c(sketches.markers[2].as_str().into());
    global.set_underline_a(sketches.underlines[0].as_str().into());
    global.set_underline_b(sketches.underlines[1].as_str().into());
    global.set_padlock(sketches.padlock.as_str().into());
    global.set_check(sketches.check.as_str().into());
    global.set_star(sketches.star.as_str().into());
    global.set_plus(sketches.plus.as_str().into());
}
