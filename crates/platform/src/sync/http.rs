//! What the HTTP targets share: which addresses are allowed, one client, bounded reads.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

/// The longest a request may take; a long-poll waits up to a minute of it.
const TIMEOUT: Duration = Duration::from_secs(90);

/// The most a server's certificate authority may weigh.
const MAX_AUTHORITY_BYTES: usize = 16 * 1024;

/// Checks a server or WebDAV address and returns it without a trailing `/`.
///
/// `https://` always. Plain `http://` only to this computer or to a Tailscale address
/// (100.64.0.0/10, fd7a:115c:a1e0::/48), where the network itself is encrypted. No user name
/// or password in the address, no query. The one fragment taken is `#pin=<64 hex>`: the
/// SHA-256 of the certificate authority of a server with HTTPS of its own (`vault-server
/// serve --tls`), which is then the only one trusted for that address.
pub fn check_address(address: &str) -> Result<String> {
    let address = address.trim();
    let (address, pin) = match address.split_once('#') {
        Some((address, fragment)) => {
            let Some(pin) = fragment.strip_prefix("pin=").and_then(parse_pin) else {
                bail!("the part after # must be pin= and the 64 characters the server printed");
            };
            if !address.starts_with("https://") {
                bail!("a pinned certificate needs an https:// address");
            }
            (address, Some(pin))
        }
        None => (address, None),
    };
    let address = address.trim_end_matches('/');
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
    Ok(match pin {
        Some(pin) => format!("{address}#pin={}", hex(&pin)),
        None => address.to_owned(),
    })
}

/// The address with the pin typed in a field of its own, as `check_address` takes it. The pin
/// may be written with spaces or colons between its pairs; an empty one adds nothing, and an
/// address that already has one keeps it.
pub fn with_pin(address: &str, pin: &str) -> Result<String> {
    let address = address.trim().trim_end_matches('/');
    let pin: String = pin
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    if pin.is_empty() || address.contains("#pin=") {
        return Ok(address.to_owned());
    }
    if parse_pin(&pin).is_none() {
        bail!("the pin is the 64 letters and digits the server printed (pin=…)");
    }
    Ok(format!("{address}#pin={pin}"))
}

/// A pin as the pin field shows it (hex).
pub fn pin_text(pin: &[u8; 32]) -> String {
    hex(pin)
}

/// Splits a checked address into where requests go and the pinned authority's hash.
pub fn split_pin(address: &str) -> (&str, Option<[u8; 32]>) {
    match address.split_once("#pin=") {
        Some((base, pin)) => (base, parse_pin(pin)),
        None => (address, None),
    }
}

fn parse_pin(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut pin = [0; 32];
    for (i, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(pin)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
/// handled by the caller, the usual certificate roots.
pub fn agent(non_standard_methods: bool) -> ureq::Agent {
    config(non_standard_methods, TlsConfig::default())
}

fn config(non_standard_methods: bool, tls: TlsConfig) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .http_status_as_error(false)
        .allow_non_standard_methods(non_standard_methods)
        .user_agent("vault-sync/1")
        .tls_config(tls)
        .build()
        .into()
}

/// The client for a checked address: with a pin, one that trusts only the server's own
/// certificate authority, fetched from `/v1/certificate` and checked against the pin (once
/// per run of the app). That first request carries nothing but its path, and what comes
/// back is used only if its hash is the pin.
pub fn agent_for(address: &str, non_standard_methods: bool) -> Result<ureq::Agent> {
    let (base, Some(pin)) = split_pin(address) else {
        return Ok(agent(non_standard_methods));
    };
    let authority = authority(base, &pin)?;
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(vec![
            Certificate::from_der(&authority).to_owned(),
        ])))
        .build();
    Ok(config(non_standard_methods, tls))
}

fn authority(base: &str, pin: &[u8; 32]) -> Result<Vec<u8>> {
    static KNOWN: Mutex<Option<HashMap<[u8; 32], Vec<u8>>>> = Mutex::new(None);
    if let Some(der) = KNOWN.lock().unwrap().as_ref().and_then(|k| k.get(pin)) {
        return Ok(der.clone());
    }
    let unchecked = config(
        false,
        TlsConfig::builder().disable_verification(true).build(),
    );
    let mut response = unchecked
        .get(format!("{base}/v1/certificate"))
        .call()
        .context("can't reach the server")?;
    if !response.status().is_success() {
        bail!(
            "the server didn't give its certificate ({}): is it running with --tls?",
            response.status()
        );
    }
    let der = read_body(&mut response, MAX_AUTHORITY_BYTES)?;
    if !bool::from(Sha256::digest(&der).as_slice().ct_eq(pin)) {
        bail!(
            "the server's certificate isn't the one pinned in the address: \
             someone may be in between, or the server's tls folder was replaced"
        );
    }
    KNOWN
        .lock()
        .unwrap()
        .get_or_insert_default()
        .insert(*pin, der.clone());
    Ok(der)
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
            "https://192.168.1.10:8750#pin=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
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
            "http://192.168.1.10:8750#pin=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "https://192.168.1.10:8750#pin=0011",
            "https://192.168.1.10:8750#key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "https://host/?x=1#pin=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ] {
            assert!(check_address(bad).is_err(), "{bad}");
        }
        let pinned = check_address(
            "https://192.168.1.10:8750/#pin=00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff",
        )
        .unwrap();
        assert_eq!(
            pinned,
            "https://192.168.1.10:8750#pin=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        let (base, pin) = split_pin(&pinned);
        assert_eq!(base, "https://192.168.1.10:8750");
        assert_eq!(pin.unwrap()[..2], [0x00, 0x11]);
    }
}
