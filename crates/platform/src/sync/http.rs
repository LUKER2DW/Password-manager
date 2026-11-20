//! What the HTTP targets share: which addresses are allowed, one client, bounded reads.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use anyhow::{Context, Result, bail};

/// The longest a request may take; a long-poll waits up to a minute of it.
const TIMEOUT: Duration = Duration::from_secs(90);

/// Checks a server or WebDAV address and returns it without a trailing `/`.
///
/// `https://` always. Plain `http://` only to this computer or to a Tailscale address
/// (100.64.0.0/10, fd7a:115c:a1e0::/48), where the network itself is encrypted. No user name
/// or password in the address, no query or fragment.
pub fn check_address(address: &str) -> Result<String> {
    let address = address.trim().trim_end_matches('/');
    let (secure, rest) = if let Some(rest) = address.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = address.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("the address must start with https://");
    };
    if address.contains(['?', '#', ' ', '\\']) || address.chars().any(char::is_control) {
        bail!("not a valid address");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        bail!("the address has no host");
    }
    if authority.contains('@') {
        bail!("put the user name in its own field, not in the address");
    }
    if !secure && !private_network(authority) {
        bail!(
            "use https:// (plain http:// is accepted only for this computer or a Tailscale address)"
        );
    }
    Ok(address.to_owned())
}

/// Whether `authority` (host[:port]) is this computer or a Tailscale address.
fn private_network(authority: &str) -> bool {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || tailscale_v4(ip),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || tailscale_v6(ip),
        Err(_) => false,
    }
}

fn tailscale_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

fn tailscale_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

/// One HTTP client: no redirects (a target that sends us elsewhere is refused), statuses
/// handled by the caller, the system's certificate roots.
pub fn agent(non_standard_methods: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .http_status_as_error(false)
        .allow_non_standard_methods(non_standard_methods)
        .user_agent("vault-sync/1")
        .build()
        .into()
}

/// Reads a response body, refusing more than `limit` bytes.
pub fn read_body(response: &mut ureq::http::Response<ureq::Body>, limit: usize) -> Result<Vec<u8>> {
    response
        .body_mut()
        .with_config()
        .limit(limit as u64 + 1)
        .read_to_vec()
        .context("reading the answer")
        .and_then(|bytes| {
            if bytes.len() > limit {
                bail!("the answer is too big");
            }
            Ok(bytes)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_safe_addresses_are_taken() {
        for good in [
            "https://vault.example.ts.net",
            "https://vault.example.ts.net:8443/",
            "https://cloud.example.com/remote.php/dav/files/me",
            "http://127.0.0.1:8750",
            "http://localhost:8750",
            "http://[::1]:8750",
            "http://100.101.102.103:8750",
            "http://[fd7a:115c:a1e0::1]:8750",
        ] {
            assert!(check_address(good).is_ok(), "{good}");
        }
        assert_eq!(
            check_address(" https://host/dav/ ").unwrap(),
            "https://host/dav"
        );
        for bad in [
            "http://example.com",
            "http://192.168.1.10:8750",
            "http://100.200.1.1",
            "ftp://host",
            "host:8750",
            "https://",
            "https://user:pass@host",
            "https://host/?x=1",
            "https://host/#x",
            "https://ho st",
        ] {
            assert!(check_address(bad).is_err(), "{bad}");
        }
    }
}
