//! The relay the native host runs: messages from the browser on standard input go to the
//! desktop app, and its answers come back on standard output. The host understands none of
//! them and keeps nothing.
//!
//! The host is the desktop app's own executable: a browser starts `vault-desktop.exe` with
//! arguments that name the extension ([`is_our_extension`]), and the app then runs [`run`]
//! instead of opening a window.

use std::{
    io::{Read, Write},
    path::Path,
};

use vault_platform::browser_link::{self, read_frame, write_frame};

/// Sent in place of the app's answer when the app can't be reached.
pub const NOT_RUNNING: &[u8] = br#"{"type":"error","code":"not_running"}"#;

/// Whether the arguments a browser started the host with (`args`, after the program's own
/// path) name our extension. Chrome and Edge give its origin first (then a window handle);
/// Firefox gives the path of the host's manifest, then the extension's add-on id.
///
/// This only tells a browser's start from a person's (a vault file to open): anyone may start
/// the program with these arguments, and the app answers only the extension paired with it.
pub fn is_our_extension<S: AsRef<str>>(args: &[S]) -> bool {
    match args {
        [first, ..] if first.as_ref() == browser_link::extension_origin() => true,
        [manifest, id, ..] => {
            id.as_ref() == browser_link::GECKO_ID
                && manifest.as_ref().to_ascii_lowercase().ends_with(".json")
        }
        _ => false,
    }
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
        assert!(is_our_extension(&[ours.as_str()]));
        assert!(is_our_extension(&[ours.as_str(), "--parent-window=0"]));
        assert!(!is_our_extension::<&str>(&[]));
        assert!(!is_our_extension(&[
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        ]));
        assert!(!is_our_extension(&[ours.trim_end_matches('/')]));
        assert!(!is_our_extension(&["--parent-window=0"]));
        // A vault file opened from Explorer is no browser.
        assert!(!is_our_extension(&[r"C:\Vaults\test.vault"]));
    }

    #[test]
    fn firefox_starts_the_host_with_its_manifest_and_our_add_on_id() {
        let manifest = r"C:\Users\Test User\AppData\Roaming\vault\browser\vault.desktop.browser_host.firefox.json";
        let id = vault_platform::browser_link::GECKO_ID;
        assert!(is_our_extension(&[manifest, id]));
        assert!(!is_our_extension(&[manifest]));
        assert!(!is_our_extension(&[
            manifest,
            "{00000000-0000-0000-0000-000000000000}"
        ]));
        assert!(!is_our_extension(&[manifest, id.to_uppercase().as_str()]));
        assert!(!is_our_extension(&[r"C:\Vaults\test.vault", id]));
        assert!(!is_our_extension(&[id, manifest]));
    }

    #[test]
    fn the_ids_the_host_accepts_are_the_extensions_own() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../apps/extension/manifest.json")).unwrap();
        assert_eq!(
            manifest["browser_specific_settings"]["gecko"]["id"],
            vault_platform::browser_link::GECKO_ID
        );
        // Chrome's id: the first 16 bytes of the SHA-256 of the manifest's public key, one
        // letter a-p per half-byte.
        use base64::Engine;
        use sha2::Digest;
        let key = base64::engine::general_purpose::STANDARD
            .decode(manifest["key"].as_str().unwrap())
            .unwrap();
        let id: String = sha2::Sha256::digest(&key)[..16]
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 15])
            .map(|half| char::from(b'a' + half))
            .collect();
        assert_eq!(id, vault_platform::browser_link::EXTENSION_ID);
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
