//! Website icons — opt-in (Settings → Website icons).
//!
//! Privacy model:
//! - Icons are requested **directly from each site** (no third-party icon service), HTTPS only,
//!   without cookies, one request chain per site, and only for sites saved in the vault. A site
//!   on its own port (`https://192.168.1.10:8443`) is asked on that port.
//! - A site whose certificate isn't trusted (its own, self-signed one, as routers and NAS boxes
//!   have, or an expired or wrong one) gets no picture from it: nothing it sends is used. The
//!   item shows a globe with a warning mark instead ([`Fetched::Untrusted`]), so it reads as
//!   "a web address whose identity couldn't be checked".
//! - Results (and "this site has no icon") are cached in a file encrypted with the vault key
//!   (`Vault::seal_local`), so each site is contacted once, and the cache reveals nothing.
//! - Even so, someone watching the network can see which sites were contacted. That is why the
//!   feature is off until the user turns it on.
//! - A site on the internet can't send the fetcher into this computer or the local network:
//!   the links in its page and its redirects reach public addresses only, checked as each
//!   name is looked up ([`Reach`]). A site saved with a local address (a router, a NAS) is
//!   asked at the addresses its name had when the fetch began.
//!
//! Every downloaded image is untrusted input: size-limited, decoded by pure-Rust decoders with
//! allocation limits (SVG drawn without fetching anything it links to), and reduced to a
//! 64 × 64 RGBA bitmap.

use std::{
    collections::BTreeMap,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};

pub const ICON_SIZE: u32 = 64;
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;
/// Icon links tried from the page itself; the usual places (`/favicon.ico`…) are tried after
/// them in any case.
const MAX_PAGE_CANDIDATES: usize = 7;
const RETRY_MISSING_AFTER_SECS: u64 = 7 * 24 * 3600;
const USER_AGENT: &str = "Mozilla/5.0 (compatible; vault icon fetcher)";

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Entry {
    /// 64 × 64 RGBA pixels.
    Rgba(Vec<u8>),
    /// Looked for and not found (retried after a week).
    Missing { checked_at: u64 },
    /// The site answers, but its certificate isn't trusted: shown as a globe (retried after a
    /// week, in case it gets a proper certificate).
    Untrusted { checked_at: u64 },
}

/// What looking for an icon found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// 64 × 64 RGBA pixels.
    Icon(Vec<u8>),
    /// The site answered only without the certificate check: no picture is taken from it.
    Untrusted,
    /// Nothing usable.
    Missing,
}

impl Fetched {
    /// Something is drawn for it (its icon or the globe).
    pub fn shows(&self) -> bool {
        !matches!(self, Self::Missing)
    }
}

/// The picture for a site whose certificate isn't trusted (self-signed, expired, for another
/// name): an amber shield with a warning mark on a slate tile (Lucide's "shield-alert"), so it
/// reads as "this site's certificate isn't one the system trusts", not as a missing icon.
fn untrusted_icon() -> &'static [u8] {
    static ICON: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    ICON.get_or_init(|| {
        const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <rect width="24" height="24" rx="5.5" fill="#3E4A5A"/>
            <g transform="translate(3.6 3.6) scale(0.7)" fill="none" stroke="#E7A33E"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
                <path d="M12 8v4 M12 16h.01"/>
            </g>
        </svg>"##;
        decode_svg(SVG.as_bytes()).unwrap_or_else(|| vec![0; (ICON_SIZE * ICON_SIZE * 4) as usize])
    })
}

/// Icons by host (lowercase, without `www.`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IconCache {
    entries: BTreeMap<String, Entry>,
}

impl IconCache {
    pub fn get(&self, host: &str) -> Option<&[u8]> {
        match self.entries.get(host) {
            Some(Entry::Rgba(pixels)) if !is_banner(pixels) => Some(pixels),
            Some(Entry::Untrusted { .. }) => Some(untrusted_icon()),
            _ => None,
        }
    }

    pub fn needs_fetch(&self, host: &str) -> bool {
        match self.entries.get(host) {
            None => true,
            Some(Entry::Missing { checked_at } | Entry::Untrusted { checked_at }) => {
                now().saturating_sub(*checked_at) > RETRY_MISSING_AFTER_SECS
            }
            // Kept by an older version, which took a site's wide logo (its name written out)
            // for its icon: looked for again.
            Some(Entry::Rgba(pixels)) => is_banner(pixels),
        }
    }

    pub fn insert(&mut self, host: String, icon: Fetched) {
        let entry = match icon {
            Fetched::Icon(pixels) if pixels.len() == (ICON_SIZE * ICON_SIZE * 4) as usize => {
                Entry::Rgba(pixels)
            }
            Fetched::Untrusted => Entry::Untrusted { checked_at: now() },
            _ => Entry::Missing { checked_at: now() },
        };
        self.entries.insert(host, entry);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The site part of a URL: its host, lowercase, with the port when it isn't the usual one
/// (`192.168.1.10:8443`). `None` for anything that isn't a plain web address.
pub fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = match url.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http") =>
        {
            rest
        }
        Some(_) => return None,
        None => url,
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .to_lowercase();
    let (host, port) = split_port(&authority)?;
    let valid = if let Some(inner) = host.strip_prefix('[') {
        // An IPv6 address in brackets.
        inner.strip_suffix(']').is_some_and(|address| {
            address.contains(':')
                && address
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        })
    } else {
        !host.is_empty()
            && host.contains('.')
            && !host.starts_with('.')
            && !host.ends_with('.')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    };
    if !valid {
        return None;
    }
    Some(match port {
        Some(port) if port != 443 && port != 80 => format!("{host}:{port}"),
        _ => host.to_owned(),
    })
}

/// `host:port` → host and port (`[::1]:8443` too). `None` for a port that isn't a number.
fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, rest) = authority.split_at(end + 1);
        (host, rest.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port.filter(|port| !port.is_empty()) {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => None,
    };
    Some((host, port))
}

/// Cache key for a site: `www.github.com` and `github.com` share one icon.
pub fn cache_key(host: &str) -> String {
    host.strip_prefix("www.").unwrap_or(host).to_owned()
}

/// Where a chosen icon comes from: a website (its own icon) or a direct link to a picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconSource {
    /// A site (host and port) whose icon is looked up like any saved site.
    Site(String),
    /// An `https://` link to a PNG, JPEG, GIF, WebP, BMP, ICO or SVG file.
    Image(String),
}

const IMAGE_EXTENSIONS: [&str; 8] = [
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
];

impl IconSource {
    /// Reads what the user typed: a link whose path ends in a picture extension is a picture,
    /// anything else with a usable host is a website. HTTP links are upgraded to HTTPS.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        let path = lower.split(['?', '#']).next().unwrap_or_default();
        let after_host = path.split_once("://").map_or(path, |(_, rest)| rest);
        let has_path = after_host.contains('/');
        if has_path && IMAGE_EXTENSIONS.iter().any(|ext| path.ends_with(ext)) {
            host_of(text)?;
            let rest = match text.split_once("://") {
                Some((_, rest)) => rest,
                None => text,
            };
            return Some(Self::Image(format!("https://{rest}")));
        }
        host_of(text).map(Self::Site)
    }

    /// Key in the icon cache.
    pub fn key(&self) -> String {
        match self {
            Self::Site(host) => cache_key(host),
            Self::Image(url) => format!("img:{url}"),
        }
    }

    /// Downloads and decodes the picture. Blocking; call from a worker thread.
    pub fn fetch(&self) -> Fetched {
        match self {
            Self::Site(host) => fetch(host),
            Self::Image(url) => {
                let reach = Reach::of(&host_of(url).unwrap_or_default());
                match get(&agent(false, &reach), url, false) {
                    Ok(Some((_, bytes))) => decode(&bytes).map_or(Fetched::Missing, Fetched::Icon),
                    Ok(None) => Fetched::Missing,
                    Err(why) => untrusted_or_missing(url, why, &reach),
                }
            }
        }
    }
}

/// Why a request got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoAnswer {
    /// The site's certificate was refused (self-signed, expired, for another name…).
    Certificate,
    /// Anything else: no connection, a timeout, a refused or cut connection.
    Other,
}

/// Whether a failed request failed on the site's certificate, as rustls words it.
fn no_answer(err: &ureq::Error) -> NoAnswer {
    let text = format!("{err} {err:?}").to_ascii_lowercase();
    if text.contains("certificate")
        || text.contains("unknownissuer")
        || text.contains("badsignature")
    {
        NoAnswer::Certificate
    } else {
        NoAnswer::Other
    }
}

/// After a request refused on its certificate: [`Fetched::Untrusted`] when the address
/// answers once its certificate goes unchecked (nothing of that answer is used), else
/// [`Fetched::Missing`]. Other failures (a timeout, a cut connection) are only missing: a
/// site that was slow once isn't marked as untrusted.
fn untrusted_or_missing(url: &str, why: NoAnswer, reach: &Reach) -> Fetched {
    if why == NoAnswer::Certificate && agent(true, reach).get(url).call().is_ok() {
        Fetched::Untrusted
    } else {
        Fetched::Missing
    }
}

/// Which addresses one fetch may reach. A site on the internet can't send the fetcher into
/// this computer or the local network: the links in its page and its redirects reach public
/// addresses only, checked as each name is looked up (so a name that is made to point home
/// halfway is caught too). A site saved with a local address (a router, a NAS) is asked at the
/// addresses its name had when the fetch began, and what its page links to may be local too.
#[derive(Debug, Clone)]
struct Reach {
    /// The saved site's host, lowercase, without brackets.
    host: String,
    /// Where a local site is; `None` for a site on the internet.
    local: Option<Vec<IpAddr>>,
}

impl Reach {
    /// For a site given as `host[:port]`.
    fn of(site: &str) -> Self {
        let host = bare_host(split_port(site).map_or(site, |(host, _)| host));
        let local = if let Ok(ip) = host.parse::<IpAddr>() {
            (!is_public(ip)).then(|| vec![ip])
        } else {
            let found: Vec<IpAddr> = (host.as_str(), 443)
                .to_socket_addrs()
                .map(|all| all.map(|address| address.ip()).collect())
                .unwrap_or_default();
            (!found.is_empty() && !found.iter().copied().any(is_public)).then_some(found)
        };
        Self { host, local }
    }

    fn is_local(&self) -> bool {
        self.local.is_some()
    }
}

fn bare_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

impl Resolver for Reach {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().map(bare_host).unwrap_or_default();
        if let Some(local) = &self.local
            && host == self.host
        {
            let port = uri.port_u16().unwrap_or(443);
            let mut pinned = self.empty();
            for ip in local.iter().take(16) {
                pinned.push(SocketAddr::new(*ip, port));
            }
            return Ok(pinned);
        }
        let found = DefaultResolver::default().resolve(uri, config, timeout)?;
        if self.is_local() {
            return Ok(found);
        }
        let mut public = self.empty();
        for address in found.iter().filter(|address| is_public(address.ip())) {
            public.push(*address);
        }
        if public.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(public)
        }
    }
}

/// Whether an address is out on the internet: not this computer, not a private, local or
/// shared network (Tailscale's and carriers' 100.64.0.0/10 included), and not one set aside
/// (documentation, benchmarks, multicast, IPv6 forms that carry an IPv4 address).
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (18..20).contains(&b)))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // NAT64 (an IPv6-only network reaching IPv4 sites): the IPv4 address inside counts.
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                let inside = (u32::from(s[6]) << 16) | u32::from(s[7]);
                return is_public(IpAddr::V4(Ipv4Addr::from(inside)));
            }
            // Global unicast, but not 6to4 or Teredo (an IPv4 address of any kind inside) or
            // documentation.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8))
        }
    }
}

/// `unchecked` skips the certificate check: only to tell an untrusted site from one that is
/// down (see [`untrusted_or_missing`]), never to take a picture. `reach` says which addresses
/// it may connect to.
fn agent(unchecked: bool, reach: &Reach) -> ureq::Agent {
    let mut config = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(10)))
        // Statuses are judged here: a sign-in page often answers 401 or 403 with a page that
        // still names its icon.
        .http_status_as_error(false)
        .user_agent(USER_AGENT);
    if unchecked {
        config = config.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        );
    }
    ureq::Agent::with_parts(
        config.build(),
        ureq::unversioned::transport::DefaultConnector::default(),
        reach.clone(),
    )
}

/// Fetches and decodes the best icon for `site` (a host, maybe with a port). Blocking; call
/// from a worker thread.
pub fn fetch(site: &str) -> Fetched {
    let reach = Reach::of(site);
    let agent = agent(false, &reach);
    let mut origin = format!("https://{site}");
    let home = format!("{origin}/");
    let mut candidates: Vec<String> = Vec::new();
    let page = match get(&agent, &home, true) {
        Ok(page) => page,
        // No answer: the same site under `www.` (or without it) may answer where this didn't;
        // else maybe only the certificate is refused. A local site has no `www.` twin (and a
        // name looked up anew might point anywhere).
        Err(why) => {
            let other = match site.strip_prefix("www.") {
                _ if reach.is_local() => return untrusted_or_missing(&home, why, &reach),
                Some(bare) => bare.to_owned(),
                None if site.matches('.').count() == 1 => format!("www.{site}"),
                None => return untrusted_or_missing(&home, why, &reach),
            };
            match get(&agent, &format!("https://{other}/"), true) {
                Ok(page) => {
                    origin = format!("https://{other}");
                    page
                }
                Err(_) => return untrusted_or_missing(&home, why, &reach),
            }
        }
    };
    if let Some((page, html)) = page {
        let html = String::from_utf8_lossy(&html);
        let base = base_href(&html)
            .and_then(|href| resolve(&page, &href))
            .unwrap_or(page);
        candidates.extend(
            icon_links(&html)
                .iter()
                .filter_map(|href| resolve(&base, href))
                .take(MAX_PAGE_CANDIDATES),
        );
        // A web app manifest lists icons too (self-hosted apps often have only those).
        if let Some(manifest) = manifest_link(&html).and_then(|href| resolve(&base, &href))
            && let Ok(Some((manifest_url, json))) = get(&agent, &manifest, false)
        {
            candidates.extend(
                manifest_icons(&json)
                    .iter()
                    .filter_map(|src| resolve(&manifest_url, src))
                    .take(3),
            );
        }
    }
    for path in ["/favicon.ico", "/apple-touch-icon.png", "/favicon.svg"] {
        candidates.push(format!("{origin}{path}"));
    }
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|url| seen.insert(url.clone()));

    candidates
        .iter()
        .find_map(|url| match get(&agent, url, false) {
            Ok(Some((_, bytes))) => decode(&bytes),
            _ => None,
        })
        .map_or(Fetched::Missing, Fetched::Icon)
}

/// The body of `url` and the address it finally came from (after redirects). A page is read
/// whatever its status below 500; anything else needs a success. `Err` when nothing answered
/// (no connection, refused certificate, timeout), `Ok(None)` for an answer of no use.
fn get(agent: &ureq::Agent, url: &str, page: bool) -> Result<Option<(String, Vec<u8>)>, NoAnswer> {
    use ureq::ResponseExt;
    let accept = if page {
        "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"
    } else {
        "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
    };
    let mut response = agent
        .get(url)
        .header("Accept", accept)
        .call()
        .map_err(|err| no_answer(&err))?;
    let status = response.status().as_u16();
    let fine = if page {
        status < 500
    } else {
        (200..300).contains(&status)
    };
    if !fine {
        return Ok(None);
    }
    let from = response.get_uri().to_string();
    Ok(response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .ok()
        .map(|bytes| (from, bytes)))
}

/// Icon URLs declared in a page's `<link>` tags, best first: Apple touch icons (usually 180 px),
/// then drawings (SVG, sharp at any size), then icons by declared size. Inline data URIs are
/// skipped.
pub fn icon_links(html: &str) -> Vec<String> {
    let mut found: Vec<(u32, String)> = Vec::new();
    for tag in tags(html, "<link") {
        let Some(rel) = attribute(tag, "rel").map(|r| r.to_ascii_lowercase()) else {
            continue;
        };
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        let href_lower = href.to_ascii_lowercase();
        if href_lower.starts_with("data:") {
            continue;
        }
        let svg = href_lower
            .split(['?', '#'])
            .next()
            .is_some_and(|p| p.ends_with(".svg"))
            || attribute(tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("image/svg+xml"));
        let size = attribute(tag, "sizes")
            .and_then(|s| {
                s.split(['x', 'X'])
                    .next()
                    .and_then(|n| n.trim().parse::<u32>().ok())
            })
            .unwrap_or(0);
        let score = if rel.contains("apple-touch-icon") {
            10_000 + size.max(180)
        } else if rel
            .split_whitespace()
            .any(|r| r == "icon" || r == "mask-icon")
        {
            if rel.contains("mask-icon") {
                // A one-colour silhouette for pinned tabs: a last resort.
                1
            } else if svg {
                5_000
            } else {
                size.max(16)
            }
        } else {
            continue;
        };
        found.push((score, href));
    }
    found.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    found.into_iter().map(|(_, href)| href).collect()
}

/// The `href` of the page's `<link rel="manifest">`.
fn manifest_link(html: &str) -> Option<String> {
    tags(html, "<link").find_map(|tag| {
        let rel = attribute(tag, "rel")?.to_ascii_lowercase();
        rel.split_whitespace()
            .any(|r| r == "manifest")
            .then(|| attribute(tag, "href"))
            .flatten()
    })
}

/// The `href` of the page's `<base>` tag, which relative links are resolved against.
fn base_href(html: &str) -> Option<String> {
    tags(html, "<base").find_map(|tag| attribute(tag, "href"))
}

/// Icon sources listed in a web app manifest, biggest first (drawings count as big).
pub fn manifest_icons(json: &[u8]) -> Vec<String> {
    #[derive(Deserialize)]
    struct Manifest {
        #[serde(default)]
        icons: Vec<Icon>,
    }
    #[derive(Deserialize)]
    struct Icon {
        src: String,
        #[serde(default)]
        sizes: String,
        #[serde(default, rename = "type")]
        kind: String,
    }
    let Ok(manifest) = serde_json::from_slice::<Manifest>(json) else {
        return Vec::new();
    };
    let mut icons: Vec<(u32, String)> = manifest
        .icons
        .into_iter()
        .filter(|icon| !icon.src.to_ascii_lowercase().starts_with("data:"))
        .map(|icon| {
            let size = if icon.sizes.eq_ignore_ascii_case("any") || icon.kind.contains("svg") {
                512
            } else {
                icon.sizes
                    .split_whitespace()
                    .filter_map(|s| s.split(['x', 'X']).next()?.parse::<u32>().ok())
                    .max()
                    .unwrap_or(0)
            };
            (size, icon.src)
        })
        .collect();
    icons.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    icons.into_iter().map(|(_, src)| src).collect()
}

/// Each tag of a kind (`"<link"`), up to its `>`.
fn tags<'a>(html: &'a str, open: &'static str) -> impl Iterator<Item = &'a str> + 'a {
    let lower = html.to_ascii_lowercase();
    let mut start = 0;
    std::iter::from_fn(move || {
        loop {
            let offset = lower[start..].find(open)?;
            let tag_start = start + offset;
            let tag_len = lower[tag_start..].find('>')?;
            start = tag_start + tag_len;
            // `<linkfoo` is another tag.
            let next = lower.as_bytes().get(tag_start + open.len()).copied();
            if next.is_some_and(|c| c.is_ascii_whitespace() || c == b'/') {
                return Some(&html[tag_start..tag_start + tag_len]);
            }
        }
    })
}

/// Value of `name="…"`, `name='…'` or `name=…` inside a tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut search = 0;
    while let Some(offset) = lower[search..].find(name) {
        let at = search + offset;
        search = at + name.len();
        let before_ok = at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace();
        let rest = tag[at + name.len()..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let value = rest[1..].trim_start();
        let parsed = match value.chars().next()? {
            quote @ ('"' | '\'') => value[1..].split(quote).next()?.to_owned(),
            _ => value
                .split(|c: char| c.is_whitespace() || c == '/' && value.starts_with("/>"))
                .next()?
                .trim_end_matches('/')
                .to_owned(),
        };
        return Some(parsed.trim().replace("&amp;", "&"));
    }
    None
}

/// Resolves a link found at `base` (the address of the page or manifest), upgrading to HTTPS.
pub fn resolve(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() {
        return None;
    }
    if let Some(rest) = href.strip_prefix("https://") {
        return Some(format!("https://{rest}"));
    }
    if let Some(rest) = href.strip_prefix("http://") {
        return Some(format!("https://{rest}"));
    }
    if let Some(rest) = href.strip_prefix("//") {
        return Some(format!("https://{rest}"));
    }
    if href.contains("://") || href.starts_with('#') {
        return None;
    }
    let base = base.split(['?', '#']).next().unwrap_or(base);
    let after_scheme = base.strip_prefix("https://")?;
    let (authority, path) = match after_scheme.find('/') {
        Some(at) => after_scheme.split_at(at),
        None => (after_scheme, "/"),
    };
    let origin = format!("https://{authority}");
    if href.starts_with('/') {
        return Some(format!("{origin}{href}"));
    }
    // Relative to the base's folder, with `./` and `../` worked out.
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop(); // the file name (or "" after a final slash)
    for segment in href.split('/') {
        match segment {
            "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    Some(if joined.starts_with('/') {
        format!("{origin}{joined}")
    } else {
        format!("{origin}/{joined}")
    })
}

/// Whether a picture this wide and this tall can be an icon. A site's logo with its name
/// written out (a banner) is much wider than tall: shrunk into an icon's square it shows only
/// as a small line of text, so the next candidate is tried instead.
fn icon_shaped(width: f32, height: f32) -> bool {
    width > 0.0
        && height > 0.0
        && width <= height * MAX_ICON_RATIO
        && height <= width * MAX_ICON_RATIO
}

/// How much wider than tall (or taller than wide) an icon may be.
const MAX_ICON_RATIO: f32 = 1.5;

/// Whether 64 × 64 pixels hold a banner rather than an icon: what is drawn (not see-through)
/// is a band much wider than tall, or much taller than wide.
fn is_banner(pixels: &[u8]) -> bool {
    let side = ICON_SIZE as usize;
    let (mut left, mut right, mut top, mut bottom) = (side, 0, side, 0);
    for (index, pixel) in pixels.chunks_exact(4).enumerate() {
        if pixel[3] > 24 {
            let (x, y) = (index % side, index / side);
            left = left.min(x);
            right = right.max(x);
            top = top.min(y);
            bottom = bottom.max(y);
        }
    }
    if left > right || top > bottom {
        return false;
    }
    #[allow(clippy::cast_precision_loss)]
    let (width, height) = ((right - left + 1) as f32, (bottom - top + 1) as f32);
    // Small marks drawn in the middle of a square are fine; a band across it isn't.
    !icon_shaped(width, height) && width.max(height) > (side as f32) * 0.75
}

/// Decodes an untrusted image (PNG, JPEG, GIF, WebP, BMP, ICO or SVG) into a centered
/// 64 × 64 RGBA bitmap. `None` for one that isn't shaped like an icon (a wide logo, even one
/// drawn on a square).
pub fn decode(bytes: &[u8]) -> Option<Vec<u8>> {
    decode_picture(bytes).filter(|pixels| !is_banner(pixels))
}

fn decode_picture(bytes: &[u8]) -> Option<Vec<u8>> {
    if looks_like_svg(bytes) {
        return decode_svg(bytes);
    }
    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(2048);
    limits.max_image_height = Some(2048);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    if decoded.width() < 8 || decoded.height() < 8 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    if !icon_shaped(decoded.width() as f32, decoded.height() as f32) {
        return None;
    }
    let scaled = decoded
        .resize(ICON_SIZE, ICON_SIZE, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    let mut canvas = image::RgbaImage::new(ICON_SIZE, ICON_SIZE);
    let x = i64::from((ICON_SIZE - scaled.width()) / 2);
    let y = i64::from((ICON_SIZE - scaled.height()) / 2);
    image::imageops::overlay(&mut canvas, &scaled, x, y);
    Some(canvas.into_raw())
}

fn looks_like_svg(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]).to_ascii_lowercase();
    head.contains("<svg")
}

/// Draws an SVG icon at 64 × 64. It may not reach anything outside itself: linked pictures and
/// files are refused, and compressed SVG (which could unpack into far more than was
/// downloaded) is not read.
fn decode_svg(bytes: &[u8]) -> Option<Vec<u8>> {
    use resvg::{tiny_skia, usvg};
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return None;
    }
    let options = usvg::Options {
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_data(bytes, &options).ok()?;
    let size = tree.size();
    let longest = size.width().max(size.height());
    if !longest.is_finite() || longest <= 0.0 || !icon_shaped(size.width(), size.height()) {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let side = ICON_SIZE as f32;
    let scale = side / longest;
    let transform = tiny_skia::Transform::from_scale(scale, scale).post_translate(
        (side - size.width() * scale) / 2.0,
        (side - size.height() * scale) / 2.0,
    );
    let mut pixmap = tiny_skia::Pixmap::new(ICON_SIZE, ICON_SIZE)?;
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    let mut pixels = Vec::with_capacity((ICON_SIZE * ICON_SIZE * 4) as usize);
    for pixel in pixmap.pixels() {
        let color = pixel.demultiply();
        pixels.extend([color.red(), color.green(), color.blue(), color.alpha()]);
    }
    // Nothing drawn (an empty or unsupported file) is no icon.
    pixels
        .chunks_exact(4)
        .any(|pixel| pixel[3] != 0)
        .then_some(pixels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_public() {
        for public in ["1.1.1.1", "2606:4700:4700::1111", "64:ff9b::101:101"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.101.102.103",
            "0.0.0.0",
            "224.0.0.1",
            "198.18.0.1",
            "203.0.113.10",
            "::1",
            "::",
            "fe80::1",
            "fd7a:115c:a1e0::1",
            "::ffff:192.168.1.1",
            "64:ff9b::c0a8:101",
            "2002:c0a8:101::1",
            "2001:db8::1",
        ] {
            assert!(!is_public(local.parse().unwrap()), "{local}");
        }
    }

    #[test]
    fn a_local_site_is_reached_where_it_was() {
        let router = Reach::of("192.168.1.1:8443");
        assert_eq!(router.local, Some(vec!["192.168.1.1".parse().unwrap()]));
        assert_eq!(Reach::of("[fd00::1]:8443").host, "fd00::1");
        assert!(Reach::of("[fd00::1]:8443").is_local());
        assert!(!Reach::of("1.1.1.1").is_local());
    }

    #[test]
    fn hosts_and_keys() {
        assert_eq!(
            host_of("https://www.GitHub.com/login?x").as_deref(),
            Some("www.github.com")
        );
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(
            host_of("http://user@bank.example:8443/").as_deref(),
            Some("bank.example:8443"),
            "a site on its own port is asked on that port"
        );
        assert_eq!(
            host_of("https://203.0.113.10:18443/").as_deref(),
            Some("203.0.113.10:18443")
        );
        assert_eq!(
            host_of("https://github.com:443/x").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host_of("https://[fd00::1]:8443/").as_deref(),
            Some("[fd00::1]:8443")
        );
        assert_eq!(host_of("https://bank.example:port/"), None);
        assert_eq!(
            host_of("https://bank.example:/").as_deref(),
            Some("bank.example")
        );
        assert_eq!(host_of("android://hash@com.example.app/"), None);
        assert_eq!(host_of("Expires 12/29"), None);
        assert_eq!(host_of("localhost"), None);
        assert_eq!(cache_key("www.github.com"), "github.com");
    }

    #[test]
    fn finds_and_ranks_icon_links() {
        let html = r#"<html><head>
            <link rel="stylesheet" href="/a.css">
            <link rel="icon" type="image/png" sizes="32x32" href="/icons/32.png">
            <LINK REL='shortcut icon' href=/favicon.ico>
            <link rel="icon" href="/logo.svg" type="image/svg+xml">
            <link rel="icon" href="data:image/png;base64,AAAA">
            <link href="https://cdn.example/apple.png" rel="apple-touch-icon">
            <link rel="icon" sizes="192x192" href="icons/192.png"/>
        </head></html>"#;
        assert_eq!(
            icon_links(html),
            [
                "https://cdn.example/apple.png",
                "/logo.svg",
                "icons/192.png",
                "/icons/32.png",
                "/favicon.ico"
            ]
        );
        assert_eq!(
            manifest_link(r#"<link rel="manifest" href="/site.webmanifest"><linked>"#).as_deref(),
            Some("/site.webmanifest")
        );
        assert_eq!(
            base_href(r#"<head><base href="/app/"></head>"#).as_deref(),
            Some("/app/")
        );
    }

    #[test]
    fn reads_manifest_icons() {
        let json = br#"{"name": "App", "icons": [
            {"src": "icons/192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "icons/512.png", "sizes": "256x256 512x512"},
            {"src": "data:image/png;base64,AAAA", "sizes": "1024x1024"},
            {"src": "logo.svg", "sizes": "any", "type": "image/svg+xml"}
        ]}"#;
        assert_eq!(
            manifest_icons(json),
            ["icons/512.png", "logo.svg", "icons/192.png"]
        );
        assert!(manifest_icons(b"not json").is_empty());
    }

    #[test]
    fn resolves_relative_links() {
        let origin = "https://github.com";
        assert_eq!(
            resolve(origin, "/favicon.ico").unwrap(),
            "https://github.com/favicon.ico"
        );
        assert_eq!(
            resolve(origin, "icons/a.png").unwrap(),
            "https://github.com/icons/a.png"
        );
        assert_eq!(
            resolve(origin, "//cdn.x/a.png").unwrap(),
            "https://cdn.x/a.png"
        );
        assert_eq!(
            resolve(origin, "http://x.example/a.png").unwrap(),
            "https://x.example/a.png"
        );
        assert_eq!(resolve(origin, "javascript://alert(1)"), None);
        // Relative to the page that named it, port kept.
        let page = "https://203.0.113.10:18443/app/login?next=/";
        assert_eq!(
            resolve(page, "favicon.png").unwrap(),
            "https://203.0.113.10:18443/app/favicon.png"
        );
        assert_eq!(
            resolve(page, "../static/i.png").unwrap(),
            "https://203.0.113.10:18443/static/i.png"
        );
        assert_eq!(
            resolve(page, "/i.svg").unwrap(),
            "https://203.0.113.10:18443/i.svg"
        );
        assert_eq!(
            resolve("https://a.example/app/", "./i.png").unwrap(),
            "https://a.example/app/i.png"
        );
    }

    #[test]
    fn decodes_and_rejects() {
        let mut png = Vec::new();
        image::RgbaImage::from_pixel(60, 50, image::Rgba([10, 20, 30, 255]))
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let pixels = decode(&png).unwrap();
        assert_eq!(pixels.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        // Letterboxed: top row transparent, middle row opaque.
        assert_eq!(pixels[3], 0);
        let middle = ((ICON_SIZE / 2) * ICON_SIZE * 4 + (ICON_SIZE / 2) * 4) as usize;
        assert_eq!(&pixels[middle..middle + 4], &[10, 20, 30, 255]);
        assert!(decode(b"<html>not an image</html>").is_none());
    }

    #[test]
    fn a_wide_logo_is_no_icon() {
        // A site's name written out, as a wide picture or drawn across a square one.
        let mut wide = Vec::new();
        image::RgbaImage::from_pixel(200, 60, image::Rgba([200, 30, 30, 255]))
            .write_to(&mut Cursor::new(&mut wide), image::ImageFormat::Png)
            .unwrap();
        assert!(decode(&wide).is_none());
        let band = image::RgbaImage::from_fn(64, 64, |_, y| {
            image::Rgba([200, 30, 30, if (24..40).contains(&y) { 255 } else { 0 }])
        });
        let mut square = Vec::new();
        band.write_to(&mut Cursor::new(&mut square), image::ImageFormat::Png)
            .unwrap();
        assert!(decode(&square).is_none());
        assert!(is_banner(band.as_raw()));
        // One kept by an older version is looked for again, and not shown meanwhile.
        let mut cache = IconCache::default();
        cache.insert("wide.example".into(), Fetched::Icon(band.into_raw()));
        assert!(cache.get("wide.example").is_none());
        assert!(cache.needs_fetch("wide.example"));
    }

    #[test]
    fn draws_svg_icons_without_reaching_out() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 14">
            <rect width="10" height="14" fill="#ff0000"/>
            <image href="file:///C:/Windows/win.ini" width="10" height="10"/>
        </svg>"##;
        let pixels = decode(svg).unwrap();
        assert_eq!(pixels.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        let middle = ((ICON_SIZE / 2) * ICON_SIZE * 4 + (ICON_SIZE / 2) * 4) as usize;
        assert_eq!(&pixels[middle..middle + 4], &[255, 0, 0, 255]);
        // Pillarboxed: the left edge stays transparent.
        assert_eq!(pixels[(ICON_SIZE / 2 * ICON_SIZE * 4 + 3) as usize], 0);
        // Empty or compressed drawings are no icon.
        assert!(
            decode(br#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>"#)
                .is_none()
        );
        assert!(decode(&[0x1f, 0x8b, 8, 0, 0, 0]).is_none());
    }

    #[test]
    fn cache_round_trip_and_missing_entries() {
        let mut cache = IconCache::default();
        cache.insert(
            "github.com".into(),
            Fetched::Icon(vec![1; (ICON_SIZE * ICON_SIZE * 4) as usize]),
        );
        cache.insert("noicon.example".into(), Fetched::Missing);
        cache.insert("bad.example".into(), Fetched::Icon(vec![1, 2, 3]));
        cache.insert("203.0.113.10:18443".into(), Fetched::Untrusted);
        let restored = IconCache::from_bytes(&cache.to_bytes()).unwrap();
        assert!(restored.get("github.com").is_some());
        assert!(!restored.needs_fetch("github.com"));
        assert!(
            !restored.needs_fetch("noicon.example"),
            "recently missing: not retried yet"
        );
        assert!(
            restored.get("bad.example").is_none(),
            "wrong-size data is treated as missing"
        );
        assert!(restored.needs_fetch("never-seen.example"));
        // An untrusted site shows the globe, a drawn 64 × 64 picture.
        let globe = restored.get("203.0.113.10:18443").unwrap();
        assert_eq!(globe.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        assert!(globe.chunks_exact(4).any(|pixel| pixel[3] == 255));
        assert!(!restored.needs_fetch("203.0.113.10:18443"));
    }

    /// Real network request; run manually: `cargo test -p vault-desktop favicon -- --ignored`
    #[test]
    #[ignore = "network"]
    fn fetches_a_real_icon() {
        // VAULT_ICON_SITE=host[:port] tries one more site (for example one of your own).
        assert!(matches!(fetch("github.com"), Fetched::Icon(_)));
        assert_eq!(fetch("self-signed.badssl.com"), Fetched::Untrusted);
        if let Ok(site) = std::env::var("VAULT_ICON_SITE") {
            let site = host_of(&site).expect("a host, maybe with a port");
            let found = fetch(&site);
            println!(
                "{site}: untrusted {}, icon {}",
                found == Fetched::Untrusted,
                matches!(found, Fetched::Icon(_))
            );
        }
    }
}
