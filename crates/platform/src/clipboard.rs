//! Clipboard access that keeps secrets out of history and lets callers clear them later.

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Copies a secret. On Windows it is excluded from clipboard history, cloud clipboard and
/// clipboard monitors. The caller is responsible for calling [`clear_if`] later.
pub fn copy_secret(text: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context("opening the clipboard")?;
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        clipboard
            .set()
            .exclude_from_history()
            .exclude_from_cloud()
            .exclude_from_monitoring()
            .text(text)
            .context("copying to the clipboard")
    }
    #[cfg(not(windows))]
    {
        clipboard.set_text(text).context("copying to the clipboard")
    }
}

/// Copies non-secret text (e.g. a username) normally.
pub fn copy_plain(text: &str) -> Result<()> {
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set_text(text))
        .context("copying to the clipboard")
}

/// Clears the clipboard only if it still holds `expected` (the user may have copied something
/// else since). Returns whether it was cleared.
pub fn clear_if(expected: &str) -> bool {
    let Ok(mut clipboard) = arboard::Clipboard::new() else {
        return false;
    };
    let still_ours = clipboard
        .get_text()
        .map(Zeroizing::new)
        .is_ok_and(|current| current.as_str() == expected);
    still_ours && clipboard.clear().is_ok()
}
