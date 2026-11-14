//! The native messaging host: started by the browser when the extension needs the desktop
//! app. It relays messages and exits when the browser closes its end.
//!
//! It refuses to run for any caller other than our extension, and sends only to the desktop
//! app installed next to it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;

use vault_browser::host;
use vault_platform::browser_link;

fn main() -> ExitCode {
    // Browsers pass the calling extension's origin as the first argument.
    if !host::is_our_extension(std::env::args().nth(1).as_deref()) {
        return ExitCode::FAILURE;
    }
    let Some(app) = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(browser_link::APP_EXE)))
    else {
        return ExitCode::FAILURE;
    };
    let Ok(pipe) = browser_link::pipe_name() else {
        return ExitCode::FAILURE;
    };
    let relayed = host::relay(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        |message| browser_link::request(&pipe, &app, message).ok(),
    );
    if relayed.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
