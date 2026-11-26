//! "Check for updates" (the desktop app's Settings → About): asks GitHub for the project's
//! newest release. It runs only when the person presses the button (AGENTS.md §4.1, rule 5):
//! one anonymous HTTPS request to GitHub's API, nothing about the vault or this device in it.
//! The answer is read and checked by `vault_sync_wire::releases`; the app only says what it
//! found and opens the release page (on github.com) when asked.

use std::time::Duration;

use vault_sync_wire::releases::{self, Release};

/// The newest release of the project. Blocks: call it off the UI thread.
pub fn latest() -> Result<Release, String> {
    // GitHub's API answers directly: no redirect is followed.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(20)))
        .user_agent("vault-password-manager")
        .build()
        .into();
    let mut response = agent
        .get(releases::latest_url(releases::REPOSITORY))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    Release::parse(&body).ok_or_else(|| "GitHub's answer isn't a release".to_owned())
}
