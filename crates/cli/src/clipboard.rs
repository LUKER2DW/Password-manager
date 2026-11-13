//! Terminal flavor of the secure clipboard: copy, count down, clear.

use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

use anyhow::Result;
use vault_platform::clipboard;

pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

/// Copies `secret` (kept out of clipboard history), waits `CLEAR_AFTER` with a countdown, then
/// clears the clipboard if it still holds the secret.
pub fn copy_and_clear(secret: &str, what: &str) -> Result<()> {
    clipboard::copy_secret(secret)?;
    for left in (1..=CLEAR_AFTER.as_secs()).rev() {
        eprint!("\r{what} copied. Clipboard clears in {left:>2} s (keep this running) ");
        io::stderr().flush().ok();
        thread::sleep(Duration::from_secs(1));
    }
    if clipboard::clear_if(secret) {
        eprintln!("\r{what} cleared from the clipboard.{:30}", "");
    } else {
        eprintln!("\rClipboard changed meanwhile; left untouched.{:20}", "");
    }
    Ok(())
}
