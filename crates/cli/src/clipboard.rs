//! Clipboard copy that stays out of history and is cleared automatically.

use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

/// Copies `secret`, waits `CLEAR_AFTER` (showing a countdown), then clears the clipboard if it
/// still holds the secret. On Windows the value is excluded from clipboard history, cloud
/// clipboard and clipboard monitors.
pub fn copy_and_clear(secret: &str, what: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context("opening the clipboard")?;
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        clipboard
            .set()
            .exclude_from_history()
            .exclude_from_cloud()
            .exclude_from_monitoring()
            .text(secret)
            .context("copying to the clipboard")?;
    }
    #[cfg(not(windows))]
    clipboard
        .set_text(secret)
        .context("copying to the clipboard")?;

    let total = CLEAR_AFTER.as_secs();
    for left in (1..=total).rev() {
        eprint!("\r{what} copied. Clipboard clears in {left:>2} s (keep this running) ");
        io::stderr().flush().ok();
        thread::sleep(Duration::from_secs(1));
    }
    let still_ours = clipboard
        .get_text()
        .map(Zeroizing::new)
        .is_ok_and(|current| current.as_str() == secret);
    if still_ours {
        clipboard.clear().context("clearing the clipboard")?;
        eprintln!("\r{what} cleared from the clipboard.{:30}", "");
    } else {
        eprintln!("\rClipboard changed meanwhile; left untouched.{:20}", "");
    }
    Ok(())
}
