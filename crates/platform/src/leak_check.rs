//! The leak check: whether passwords appear in known breaches, asked of the "Have I Been Pwned"
//! range API without telling it the passwords (k-anonymity, `vault_core::health::BreachQuery`).
//!
//! Only the first 5 hex characters of each password's SHA-1 leave the device, once per
//! distinct prefix; the service answers with every suffix it knows in that range, padded so
//! that the answer's size doesn't tell which prefix was asked. It runs only when the person
//! asks for it (AGENTS.md §4.1, rule 5), and only over HTTPS.

use std::collections::HashMap;

use vault_core::health::BreachQuery;

const BREACH_API: &str = "https://api.pwnedpasswords.com/range/";

/// How many times each password appears in the breaches, in the order of `queries`. Blocks:
/// call it off the UI thread. One request per distinct prefix.
pub fn lookup<K: Copy>(queries: &[(K, BreachQuery)]) -> Result<Vec<(K, u64)>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .user_agent("vault-password-manager")
        .build()
        .into();
    let mut answers: HashMap<String, String> = HashMap::new();
    let mut out = Vec::with_capacity(queries.len());
    for (key, query) in queries {
        let prefix = query.prefix().to_owned();
        if !answers.contains_key(&prefix) {
            let body = agent
                .get(format!("{BREACH_API}{prefix}"))
                // Padding makes every answer about the same size, so the traffic doesn't
                // reveal which prefix was asked for.
                .header("Add-Padding", "true")
                .call()
                .map_err(|e| e.to_string())?
                .body_mut()
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
