//! The relay the native host runs: messages from the browser on standard input go to the
//! desktop app, and its answers come back on standard output. The host understands none of
//! them and keeps nothing.
//!
//! The host is the desktop app's own executable: a browser starts `vault-desktop.exe` with the
//! extension's origin as its first argument, and the app then runs [`run`] instead of opening
//! a window.

use std::{
    io::{Read, Write},
    path::Path,
};

use vault_platform::browser_link::{self, read_frame, write_frame};

/// Sent in place of the app's answer when the app can't be reached.
pub const NOT_RUNNING: &[u8] = br#"{"type":"error","code":"not_running"}"#;

/// Whether `caller` (the first argument a browser gives the host) is our extension.
pub fn is_our_extension(caller: Option<&str>) -> bool {
    caller == Some(vault_platform::browser_link::extension_origin().as_str())
}

/// The native host's whole run, for the browser that started `app` (this executable) as the
/// host: relays to the copy of `app` that holds the pipe until the browser closes its end.
/// Whether it ended cleanly.
pub fn run(app: &Path) -> bool {
    let Ok(pipe) = browser_link::pipe_name() else {
        return false;
    };
    relay(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        |message| browser_link::request(&pipe, app, message).ok(),
    )
    .is_ok()
}

/// Relays messages until the browser closes the input. `send` delivers one message to the
/// app; when it fails, the browser gets [`NOT_RUNNING`].
pub fn relay(
    mut input: impl Read,
    mut output: impl Write,
    mut send: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> std::io::Result<()> {
    while let Some(message) = read_frame(&mut input)? {
        let mut reply = send(&message).unwrap_or_else(|| NOT_RUNNING.to_vec());
        let written = write_frame(&mut output, &reply);
        // The reply may hold a password.
        zeroize::Zeroize::zeroize(&mut reply);
        written?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_extension_may_start_the_host() {
        let ours = vault_platform::browser_link::extension_origin();
        assert!(is_our_extension(Some(&ours)));
        assert!(!is_our_extension(None));
        assert!(!is_our_extension(Some(
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        )));
        assert!(!is_our_extension(Some(ours.trim_end_matches('/'))));
        assert!(!is_our_extension(Some("--parent-window=0")));
    }

    #[test]
    fn messages_are_relayed_in_order_and_failures_are_reported() {
        let mut input = Vec::new();
        for message in [&b"one"[..], b"two", b"three"] {
            write_frame(&mut input, message).unwrap();
        }
        let mut output = Vec::new();
        relay(input.as_slice(), &mut output, |message| {
            (message != b"two").then(|| [b"re:".as_slice(), message].concat())
        })
        .unwrap();
        let mut replies = output.as_slice();
        assert_eq!(read_frame(&mut replies).unwrap().unwrap(), b"re:one");
        assert_eq!(read_frame(&mut replies).unwrap().unwrap(), NOT_RUNNING);
        assert_eq!(read_frame(&mut replies).unwrap().unwrap(), b"re:three");
        assert!(read_frame(&mut replies).unwrap().is_none());
        // Garbage on the input stops the relay with an error instead of guessing.
        let huge = u32::MAX.to_le_bytes();
        assert!(relay(huge.as_slice(), Vec::new(), |_| None).is_err());
    }
}
