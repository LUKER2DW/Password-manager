//! The leak check: whether passwords appear in known breaches, asked of the "Have I Been Pwned"
//! range API without telling it the passwords (k-anonymity, `vault_core::health::BreachQuery`).
//!
//! Only the first 5 hex characters of each password's SHA-1 leave the device, once per
//! distinct prefix; the service answers with every suffix it knows in that range, padded so
//! that the answer's size doesn't tell which prefix was asked. It runs only when the person
//! asks for it (AGENTS.md §4.1, rule 5), and only over HTTPS: on a tap, or every day with the
//! leak watch turned on ([`Watch`]).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use vault_core::{Vault, health::BreachQuery};
use zeroize::Zeroizing;

const BREACH_API: &str = "https://api.pwnedpasswords.com/range/";

/// How many times each password appears in the breaches, in the order of `queries`. Blocks:
/// call it off the UI thread. One request per distinct prefix.
pub fn lookup<K: Copy>(queries: &[(K, BreachQuery)]) -> Result<Vec<(K, u64)>, String> {
    // No redirects: the prefixes go to the breach service and nowhere it might point at.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .user_agent("vault-password-manager")
        .build()
        .into();
    let mut answers: HashMap<String, String> = HashMap::new();
    let mut out = Vec::with_capacity(queries.len());
    for (key, query) in queries {
        let prefix = query.prefix().to_owned();
        if !answers.contains_key(&prefix) {
            let mut response = agent
                .get(format!("{BREACH_API}{prefix}"))
                // Padding makes every answer about the same size, so the traffic doesn't
                // reveal which prefix was asked for.
                .header("Add-Padding", "true")
                .call()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("the breach service answered {}", response.status()));
            }
            let body = response
                .body_mut()
                .with_config()
                .limit(4 * 1024 * 1024)
                .read_to_string()
                .map_err(|e| e.to_string())?;
            answers.insert(prefix.clone(), body);
        }
        out.push((*key, query.count_in(&answers[&prefix])));
    }
    Ok(out)
}

/// [`lookup`] for one password.
pub fn count(password: &str) -> Result<u64, String> {
    lookup(&[((), BreachQuery::new(password))]).map(|found| found[0].1)
}

/// How often the leak watch asks again: the breach service adds new leaks all the time.
pub const WATCH_EVERY: i64 = 24 * 60 * 60;

const WATCH_PURPOSE: &str = "leak-watch";

/// The leak watch's memory for one vault on this device: when it last asked, and how often each
/// login's password was found then. Keys are `<item id>:<prefix>` (the 5 hex characters the
/// check sends), so a password changed since starts afresh. Kept sealed with a vault subkey
/// (`Vault::seal_local`): without the vault key it says nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watch {
    pub checked_at: i64,
    pub counts: BTreeMap<String, u64>,
}

impl Watch {
    /// The key a login's count is kept under.
    pub fn key(item_id: &str, query: &BreachQuery) -> String {
        format!("{item_id}:{}", query.prefix())
    }

    /// What [`Watch::seal`] kept, or a fresh watch when it doesn't open (another vault's, or
    /// damaged).
    pub fn open(vault: &Vault, sealed: &[u8]) -> Self {
        vault
            .open_local(WATCH_PURPOSE, sealed)
            .ok()
            .and_then(|plain| serde_json::from_slice(&plain).ok())
            .unwrap_or_default()
    }

    pub fn seal(&self, vault: &Vault) -> Option<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(self).ok()?);
        vault.seal_local(WATCH_PURPOSE, &plain).ok()
    }

    /// Never checked yet, or a day has passed since the last check (a clock set back counts
    /// as due too, so a wrong date never stops the watch).
    pub fn due(&self, now: i64) -> bool {
        self.checked_at == 0
            || now < self.checked_at
            || now.saturating_sub(self.checked_at) >= WATCH_EVERY
    }

    /// Folds in a fresh check of every login (`key`, times found): returns the keys found in
    /// more breaches than last time (every one found, the first time). Logins gone since are
    /// forgotten.
    pub fn record(&mut self, found: &[(String, u64)], now: i64) -> Vec<String> {
        let mut newly = Vec::new();
        let mut counts = BTreeMap::new();
        for (key, count) in found {
            if *count > self.counts.get(key).copied().unwrap_or(0) {
                newly.push(key.clone());
            }
            counts.insert(key.clone(), *count);
        }
        self.counts = counts;
        self.checked_at = now;
        newly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, SecretKey};

    #[test]
    fn the_watch_tells_a_new_leak_once() {
        let mut watch = Watch::default();
        assert!(watch.due(1_000));
        let first = [("a:11111".to_owned(), 0), ("b:22222".to_owned(), 3)];
        assert_eq!(
            watch.record(&first, 1_000),
            ["b:22222"],
            "the first time: every one found"
        );
        assert!(!watch.due(1_000 + 3_600));
        assert!(watch.due(1_000 + WATCH_EVERY));
        assert!(watch.due(500), "a clock set back");
        let same = [("a:11111".to_owned(), 0), ("b:22222".to_owned(), 3)];
        assert!(watch.record(&same, 2_000).is_empty(), "nothing new");
        let more = [
            ("a:11111".to_owned(), 1),
            ("b:22222".to_owned(), 5),
            ("c:33333".to_owned(), 0),
        ];
        assert_eq!(watch.record(&more, 3_000), ["a:11111", "b:22222"]);
        // A changed password has another key: its count starts afresh.
        let changed = [("a:44444".to_owned(), 0), ("b:22222".to_owned(), 5)];
        assert!(watch.record(&changed, 4_000).is_empty());
        assert_eq!(watch.counts.len(), 2, "the old key is forgotten");

        let vault = Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let sealed = watch.seal(&vault).unwrap();
        assert_eq!(Watch::open(&vault, &sealed), watch);
        let other = Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        assert_eq!(
            Watch::open(&other, &sealed),
            Watch::default(),
            "another vault's opens nothing"
        );
    }
}
