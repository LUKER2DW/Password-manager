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

pub mod autofill;
mod bio;
mod controller;
pub mod i18n;
pub mod platform;
mod prefs;
pub mod system;
// The hand-drawn strokes are the desktop's: one file, used by both apps.
#[path = "../../desktop/src/sketch.rs"]
#[allow(dead_code)]
mod sketch;
#[cfg(test)]
mod tests;
// The crack-time estimate is the desktop's, so both apps say the same.
#[path = "../../desktop/src/view.rs"]
#[allow(dead_code)]
mod view;

pub use controller::Controller;
pub use system::{NoSystem, PromptWords, System};
