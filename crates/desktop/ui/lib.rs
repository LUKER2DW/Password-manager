//! The desktop app's screens: the Rust code Slint generates from the `.slint` files next to
//! this file (`app.slint` and what it imports).
//!
//! It is a crate of its own for build time only. The generated code is large and slow to
//! compile; kept apart from `vault-desktop`, it is rebuilt when a `.slint` file changes and
//! not every time the controller does.

#![allow(missing_debug_implementations, clippy::all)]

slint::include_modules!();
