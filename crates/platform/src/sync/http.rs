//! What the HTTP targets share: which addresses are allowed, one client, bounded reads.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ureq::{
    http::Uri,
    tls::{Certificate, RootCerts, TlsConfig},
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
};

/// The longest a request may take; a long-poll waits up to a minute of it.
const TIMEOUT: Duration = Duration::from_secs(90);

/// The most a server's certificate authority may weigh.
const MAX_AUTHORITY_BYTES: usize = 16 * 1024;

/// Where a plain `http://` address may lead. The two kinds of target send different things,
/// so they are held to different rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainHttp {
    /// The vault server: every request is signed with the device's own key, carries a time
    /// and a nonce the server checks, and holds sealed copies only, never a password. Seen on
    /// the way it gives nothing that opens the vault or lets anyone in, so this computer or a
    /// Tailscale address (whose network encrypts) is accepted.
    LoopbackOrTailscale,
    /// WebDAV: every request carries the account's user name and password (Basic). That
    /// address range is also used by carriers and other networks, and nothing in an address
    /// proves the connection goes through a tunnel, so only this computer.
    Loopback,
}

/// Checks a vault server address and returns it without a trailing `/`.
///
/// `https://` always. Plain `http://` only to this computer or to a Tailscale address
/// (100.64.0.0/10, fd7a:115c:a1e0::/48), where the network itself is encrypted: the server's
/// requests are signed and carry no password (`PlainHttp::LoopbackOrTailscale`). No user name
/// or password in the address, no query. The one fragment taken is `#pin=<64 hex>`: the
/// SHA-256 of the certificate authority of a server with HTTPS of its own (`vault-server
/// serve --tls`), which is then the only one trusted for that address.
///
/// A WebDAV address goes through [`check_webdav_address`] instead.
pub fn check_address(address: &str) -> Result<String> {
    check(address, PlainHttp::LoopbackOrTailscale)
}

/// Checks a WebDAV address and returns it without a trailing `/`: as [`check_address`], but
/// plain `http://` only to this computer (its requests carry the password, see
/// `PlainHttp::Loopback`), and no `#pin=` (that is for the vault server).
pub fn check_webdav_address(address: &str) -> Result<String> {
    let checked = check(address, PlainHttp::Loopback)?;
    if split_pin(&checked).1.is_some() {
        bail!(
            "a pinned certificate is for the vault server; use the WebDAV server's https:// address"
        );
    }
    Ok(checked)
}

fn check(address: &str, plain: PlainHttp) -> Result<String> {
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
    if !secure {
        match plain {
            PlainHttp::LoopbackOrTailscale if !loopback(authority) && !tailscale(authority) => {
                bail!(
                    "use https:// (plain http:// is accepted only for this computer or a Tailscale address)"
                )
            }
            PlainHttp::Loopback if !loopback(authority) => bail!(
                "use the WebDAV server's https:// address: plain http:// would send the password \
                 readable, so it is accepted only for this computer"
            ),
            _ => {}
        }
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

/// The host of `authority` (`host`, `host:port`, `[v6]` or `[v6]:port`), or `None` when the
/// rest isn't a plain port: a host read one way here and another way by the HTTP client
/// must not pass for this computer.
fn host(authority: &str) -> Option<&str> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after {
            "" => (host, None),
            after => (host, Some(after.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(host)
}

/// Whether `authority` (host[:port]) is this computer.
fn loopback(authority: &str) -> bool {
    let Some(host) = host(authority) else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether `authority` (host[:port]) is a Tailscale address.
fn tailscale(authority: &str) -> bool {
    match host(authority).map(str::parse::<IpAddr>) {
        Some(Ok(IpAddr::V4(ip))) => tailscale_v4(ip),
        Some(Ok(IpAddr::V6(ip))) => tailscale_v6(ip),
        _ => false,
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

/// What a client sends, which decides whether a proxy may stand between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sends {
    /// A vault server's requests: signed, sealed copies only.
    Signed,
    /// WebDAV's: the account's password in every one (and WebDAV's own methods).
    Password,
}

/// The client for a checked WebDAV address. Never through a proxy: the password goes to the
/// server the person set up and nowhere else.
pub fn webdav_agent(address: &str) -> ureq::Agent {
    client(address, Sends::Password, TlsConfig::default())
}

/// One HTTP client for `base` (a checked address without its pin): no redirects (a target that
/// sends us elsewhere is refused), statuses handled by the caller.
///
/// The HTTP library reads a proxy from the environment (`ALL_PROXY`, `HTTPS_PROXY`,
/// `HTTP_PROXY`) and would send any address through it, also one that was let in only because
/// it is this computer. So a plain `http://` address, this computer's and a WebDAV server's are
/// always connected to directly; a vault server's `https://` may go through one, which sees the
/// server's name and bytes it can't read. A plain `http://` address is also connected to as
/// checked, without asking anyone where its name leads ([`Literal`]).
fn client(base: &str, sends: Sends, tls: TlsConfig) -> ureq::Agent {
    let secure = base.strip_prefix("https://");
    let here = secure.is_some_and(|rest| loopback(rest.split('/').next().unwrap_or_default()));
    let mut config = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .http_status_as_error(false)
        .allow_non_standard_methods(sends == Sends::Password)
        .user_agent("vault-sync/1")
        .tls_config(tls);
    if secure.is_none() || here || sends == Sends::Password {
        config = config.proxy(None);
    }
    let config = config.build();
    if secure.is_some() {
        config.into()
    } else {
        ureq::Agent::with_parts(config, DefaultConnector::default(), Literal)
    }
}

/// Where a plain `http://` address leads: to the address it spells out, and for `localhost` to
/// this computer, whatever a hosts file or a name server says of that name. Nothing else passes
/// the check, so nothing else is found.
#[derive(Debug)]
struct Literal;

impl Literal {
    fn addresses(uri: &Uri) -> Vec<SocketAddr> {
        let port = uri.port_u16().unwrap_or(80);
        let host = uri.host().unwrap_or_default();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let ips: Vec<IpAddr> = if host.eq_ignore_ascii_case("localhost") {
            vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]
        } else {
            host.parse().into_iter().collect()
        };
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }
}

impl Resolver for Literal {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut found = self.empty();
        for address in Self::addresses(uri) {
            found.push(address);
        }
        if found.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(found)
    }
}

/// The client for a checked vault server address: with a pin, one that trusts only the
/// server's own certificate authority, fetched from `/v1/certificate` and checked against the
/// pin (once per run of the app). That first request carries nothing but its path, and what
/// comes back is used only if its hash is the pin.
pub fn agent_for(address: &str) -> Result<ureq::Agent> {
    let (base, Some(pin)) = split_pin(address) else {
        return Ok(client(address, Sends::Signed, TlsConfig::default()));
    };
    let authority = authority(base, &pin)?;
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(vec![
            Certificate::from_der(&authority).to_owned(),
        ])))
        .build();
    Ok(client(base, Sends::Signed, tls))
}

fn authority(base: &str, pin: &[u8; 32]) -> Result<Vec<u8>> {
    static KNOWN: Mutex<Option<HashMap<[u8; 32], Vec<u8>>>> = Mutex::new(None);
    if let Some(der) = KNOWN.lock().unwrap().as_ref().and_then(|k| k.get(pin)) {
        return Ok(der.clone());
    }
    let unchecked = client(
        base,
        Sends::Signed,
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
    use std::{
        io::{Read, Write},
        sync::atomic::{AtomicBool, Ordering},
    };

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

    /// A host the HTTP client could read differently is not taken for this computer.
    #[test]
    fn plain_http_needs_a_host_read_one_way() {
        for bad in [
            "http://[::1]evil.example",
            "http://[::1]:80:80",
            "http://127.0.0.1:8750:80",
            "http://127.0.0.1:",
            "http://127.0.0.1:port",
            "http://127.0.0.1:123456",
            "http://[::ffff:127.0.0.1]:8750",
            "http://localhost.evil.example",
        ] {
            assert!(check_address(bad).is_err(), "{bad}");
            assert!(check_webdav_address(bad).is_err(), "{bad}");
        }
    }

    /// WebDAV sends its password (Basic) with every request: plain http:// only to this
    /// computer. An address in Tailscale's range proves nothing about the path taken.
    #[test]
    fn webdav_takes_plain_http_only_to_this_computer() {
        for good in [
            "https://cloud.example.com/remote.php/dav/files/me",
            "https://100.101.102.103/dav",
            "https://[fd7a:115c:a1e0::1]:8443/dav",
            "http://127.0.0.1:8080/dav",
            "http://127.1.2.3/dav",
            "http://localhost:8080/dav",
            "http://LOCALHOST/dav",
            "http://[::1]:8080/dav",
            "http://[::1]/dav",
        ] {
            assert!(check_webdav_address(good).is_ok(), "{good}");
        }
        for bad in [
            "http://100.64.0.1/dav",
            "http://100.101.102.103:8080/dav",
            "http://100.127.255.254/dav",
            "http://[fd7a:115c:a1e0::1]:8080/dav",
            "http://192.168.1.10/dav",
            "http://example.com/dav",
            "https://192.168.1.10:8750#pin=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ] {
            let err = check_webdav_address(bad).unwrap_err().to_string();
            assert!(err.contains("https://"), "{bad}: {err}");
        }
        // The vault server keeps its own rule: signed requests, no password.
        assert!(check_address("http://100.101.102.103:8750").is_ok());
        assert!(check_address("http://[fd7a:115c:a1e0::1]:8750").is_ok());
    }

    /// Where a plain http:// request goes is what the check read, not what a resolver says.
    #[test]
    fn plain_http_leads_where_the_address_says() {
        let at = |url: &str| -> Vec<String> {
            Literal::addresses(&url.parse().unwrap())
                .iter()
                .map(SocketAddr::to_string)
                .collect()
        };
        for localhost in ["http://localhost:8080/dav", "http://LOCALHOST:8080/dav"] {
            assert_eq!(
                at(localhost),
                ["127.0.0.1:8080", "[::1]:8080"],
                "{localhost}"
            );
        }
        assert_eq!(at("http://127.0.0.1/dav"), ["127.0.0.1:80"]);
        assert_eq!(at("http://[::1]:8080/dav"), ["[::1]:8080"]);
        assert_eq!(
            at("http://100.101.102.103:8750"),
            ["100.101.102.103:8750"],
            "a Tailscale address"
        );
        for elsewhere in ["http://example.com/dav", "http://localhost.evil.example/"] {
            assert!(at(elsewhere).is_empty(), "{elsewhere}");
        }
    }

    /// Answers every request that comes to a free port of this computer with `answer`, and
    /// keeps what each one's head said.
    struct Listening {
        address: SocketAddr,
        heads: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Listening {
        fn start(answer: &'static str) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            // Nothing here waits for long: not for a connection, nor for what it sends.
            listener.set_nonblocking(true).unwrap();
            let heads = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (heads, stop) = (heads.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((mut stream, _)) = listener.accept() else {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        };
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut head = Vec::new();
                        let mut piece = [0; 1024];
                        // To the end of the head; a TLS greeting (no letter first) has none.
                        while !head.windows(4).any(|w| w == b"\r\n\r\n")
                            && head.first().is_none_or(u8::is_ascii_alphabetic)
                        {
                            match stream.read(&mut piece) {
                                Ok(read) if read > 0 => head.extend_from_slice(&piece[..read]),
                                _ => break,
                            }
                        }
                        heads
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&head).into_owned());
                        let _ = stream.write_all(answer.as_bytes());
                    }
                })
            };
            Self {
                address,
                heads,
                stop,
                thread: Some(thread),
            }
        }

        fn heads(&self) -> Vec<String> {
            self.heads.lock().unwrap().clone()
        }
    }

    impl Drop for Listening {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// PM-10: the HTTP library reads a proxy from the environment on its own. Nothing plain,
    /// and no WebDAV password, goes to it. The variables are set for a process of its own (this
    /// test, run again), never for the tests running beside it.
    #[test]
    fn a_proxy_in_the_environment_gets_nothing_plain_and_no_password() {
        const SERVER: &str = "VAULT_TEST_SERVER_BEHIND_A_PROXY";
        if let Ok(server) = std::env::var(SERVER) {
            return with_a_proxy_in_the_environment(server.parse().unwrap());
        }
        let proxy = Listening::start(
            "HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        );
        let server = Listening::start(
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        );
        let (_, tests) = module_path!().split_once("::").unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(format!(
                "{tests}::a_proxy_in_the_environment_gets_nothing_plain_and_no_password"
            ))
            .arg("--nocapture")
            .env(SERVER, server.address.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for name in ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"] {
            for name in [name.to_owned(), name.to_lowercase()] {
                command.env(name, format!("http://{}", proxy.address));
            }
        }
        for name in ["NO_PROXY", "no_proxy"] {
            command.env_remove(name);
        }
        let mut child = command.spawn().unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the test's own process didn't end");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(proxy.heads(), Vec::<String>::new());
        // It ran, and its requests came here, the password in WebDAV's.
        let heads = server.heads();
        let with_password = heads
            .iter()
            .filter(|head| {
                head.starts_with("PROPFIND /dav/")
                    && head.to_lowercase().contains("authorization: basic ")
            })
            .count();
        assert_eq!(with_password, 2, "{heads:?}");
        assert!(
            heads.iter().any(|head| head.starts_with("GET /v1/vaults/")),
            "{heads:?}"
        );
    }

    /// What the test above runs with the proxy variables set; `server` answers 404 to all.
    fn with_a_proxy_in_the_environment(server: SocketAddr) {
        use crate::sync::{ServerTarget, Target, WebDavTarget};
        assert!(ureq::Proxy::try_from_env().is_some(), "a proxy is set");
        let id = "a".repeat(32);
        let webdav = |address: &str| {
            WebDavTarget::new(address, &id, "dav-tester", "dav test password").unwrap()
        };
        for address in [
            format!("http://{server}/dav"),
            format!("http://localhost:{}/dav", server.port()),
        ] {
            let listed = webdav(&address).list().unwrap();
            assert!(listed.is_empty(), "{address}: nothing there yet (404)");
        }
        // No certificate there, so this fails, but not by way of the proxy.
        assert!(webdav(&format!("https://{server}/dav")).list().is_err());
        let vault_server = ServerTarget::new(
            &format!("http://{server}"),
            &id,
            vault_core::sync::DeviceId::from_bytes([1; 16]),
            vault_sync_wire::DeviceKey::generate(),
        )
        .unwrap();
        let answer = format!("{:#}", vault_server.list().unwrap_err());
        assert!(answer.contains("not on the server"), "{answer}");

        let proxied = |base: &str, sends: Sends| {
            client(base, sends, TlsConfig::default())
                .config()
                .proxy()
                .is_some()
        };
        for base in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://[::1]:8080",
            "http://100.101.102.103:8750",
            "https://127.0.0.1:8443",
            "https://localhost",
        ] {
            assert!(!proxied(base, Sends::Signed), "{base}");
            assert!(!proxied(base, Sends::Password), "{base}");
        }
        assert!(!proxied("https://dav.example.com/dav", Sends::Password));
        // Signed requests and sealed copies inside TLS: a proxy the network needs is used.
        assert!(proxied("https://vault.example.com", Sends::Signed));
    }
}
