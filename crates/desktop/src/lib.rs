//! Desktop app for the password manager (Windows first), built with Slint.
//!
//! The binary (`src/main.rs`) only opens the window; everything else lives here so that tests
//! and the off-screen screenshot tool (`examples/screenshots.rs`) can drive the real UI.

pub mod controller;
mod favicon;
mod sketch;
#[cfg(test)]
mod tests;
pub mod tray;
mod view;

/// The Slint screens (generated code, in a crate of its own to keep rebuilds short).
pub use vault_desktop_ui as ui;

use slint::ComponentHandle;

/// Generates the hand-drawn details and hands them to the UI.
pub fn apply_sketches(app: &ui::AppWindow) {
    let sketches = sketch::Sketches::generate();
    let global = app.global::<ui::Sketch>();
    global.set_marker_a(sketches.markers[0].as_str().into());
    global.set_marker_b(sketches.markers[1].as_str().into());
    global.set_marker_c(sketches.markers[2].as_str().into());
    global.set_padlock(sketches.padlock.as_str().into());
    global.set_check(sketches.check.as_str().into());
    global.set_star(sketches.star.as_str().into());
}
