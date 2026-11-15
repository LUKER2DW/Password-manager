//! The phone app: Slint screens (`ui/app.slint`) driven by one controller.
//!
//! It shares the core, the platform crate and the desktop's design (tokens, widgets, icons)
//! and has its own window logic: a phone shows one thing at a time. See docs/MOBILE.md.

#[allow(
    missing_debug_implementations,
    clippy::all,
    unsafe_code,
    unused_qualifications
)]
pub mod ui {
    slint::include_modules!();
}

mod controller;
// The hand-drawn strokes are the desktop's: one file, used by both apps.
#[path = "../../desktop/src/sketch.rs"]
#[allow(dead_code)]
mod sketch;
#[cfg(test)]
mod tests;

pub use controller::Controller;
