//! Website icons — opt-in (Settings → Website icons).
//!
//! Privacy model:
//! - Icons are requested **directly from each site** (no third-party icon service), HTTPS only,
//!   without cookies, one request chain per site, and only for sites saved in the vault.
//! - Results (and "this site has no icon") are cached in a file encrypted with the vault key
//!   (`Vault::seal_local`), so each site is contacted once, and the cache reveals nothing.
//! - Even so, someone watching the network can see which sites were contacted. That is why the
//!   feature is off until the user turns it on.
//!
//! Every downloaded image is untrusted input: size-limited, decoded by pure-Rust decoders with
//! allocation limits, and reduced to a 64 × 64 RGBA bitmap.

use std::{
    collections::BTreeMap,
    io::Cursor,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const ICON_SIZE: u32 = 64;
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;
const MAX_CANDIDATES: usize = 4;
const RETRY_MISSING_AFTER_SECS: u64 = 7 * 24 * 3600;
const USER_AGENT: &str = "Mozilla/5.0 (compatible; vault-desktop icon fetcher)";

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Entry {
    /// 64 × 64 RGBA pixels.
    Rgba(Vec<u8>),
    /// Looked for and not found (retried after a week).
    Missing { checked_at: u64 },
}

/// Icons by host (lowercase, without `www.`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IconCache {
    entries: BTreeMap<String, Entry>,
}

impl IconCache {
    pub fn get(&self, host: &str) -> Option<&[u8]> {
        match self.entries.get(host) {
            Some(Entry::Rgba(pixels)) => Some(pixels),
            _ => None,
        }
    }

    pub fn needs_fetch(&self, host: &str) -> bool {
        match self.entries.get(host) {
            None => true,
            Some(Entry::Missing { checked_at }) => {
                now().saturating_sub(*checked_at) > RETRY_MISSING_AFTER_SECS
            }
            Some(Entry::Rgba(_)) => false,
        }
    }

    pub fn insert(&mut self, host: String, icon: Option<Vec<u8>>) {
        let entry = match icon {
            Some(pixels) if pixels.len() == (ICON_SIZE * ICON_SIZE * 4) as usize => {
                Entry::Rgba(pixels)
            }
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

/// The host part of a URL, lowercase. `None` for anything that isn't a plain web host.
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
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?
        .to_lowercase();
    let valid = !host.is_empty()
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    valid.then_some(host)
}

/// Cache key for a host: `www.github.com` and `github.com` share one icon.
pub fn cache_key(host: &str) -> String {
    host.strip_prefix("www.").unwrap_or(host).to_owned()
}

/// Where a chosen icon comes from: a website (its own icon) or a direct link to a picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconSource {
    /// A host whose icon is looked up like any saved site.
    Site(String),
    /// An `https://` link to a PNG, JPEG, GIF, WebP, BMP or ICO file.
    Image(String),
}

const IMAGE_EXTENSIONS: [&str; 7] = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp"];

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
    pub fn fetch(&self) -> Option<Vec<u8>> {
        match self {
            Self::Site(host) => fetch(host),
            Self::Image(url) => get(&agent(), url).and_then(|bytes| decode(&bytes)),
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(8)))
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// Fetches and decodes the best icon for `host`. Blocking; call from a worker thread.
pub fn fetch(host: &str) -> Option<Vec<u8>> {
    let agent = agent();

    let origin = format!("https://{host}");
    let mut candidates: Vec<String> = Vec::new();
    if let Some(html) = get(&agent, &format!("{origin}/")) {
        let html = String::from_utf8_lossy(&html);
        candidates.extend(
            icon_links(&html)
                .iter()
                .filter_map(|href| resolve(&origin, href)),
        );
    }
    candidates.push(format!("{origin}/favicon.ico"));
    candidates.dedup();

    candidates
        .iter()
        .take(MAX_CANDIDATES)
        .find_map(|url| get(&agent, url).and_then(|bytes| decode(&bytes)))
}

fn get(agent: &ureq::Agent, url: &str) -> Option<Vec<u8>> {
    let mut response = agent.get(url).call().ok()?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .ok()
}

/// Icon URLs declared in a page's `<link>` tags, best first: Apple touch icons (usually 180 px),
/// then icons by declared size. SVG and inline data URIs are skipped.
pub fn icon_links(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<(u32, String)> = Vec::new();
    let mut start = 0;
    while let Some(offset) = lower[start..].find("<link") {
        let tag_start = start + offset;
        let Some(tag_len) = lower[tag_start..].find('>') else {
            break;
        };
        let tag = &html[tag_start..tag_start + tag_len];
        start = tag_start + tag_len;

        let Some(rel) = attribute(tag, "rel").map(|r| r.to_ascii_lowercase()) else {
            continue;
        };
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        let href_lower = href.to_ascii_lowercase();
        if href_lower.starts_with("data:")
            || href_lower
                .split(['?', '#'])
                .next()
                .is_some_and(|p| p.ends_with(".svg"))
        {
            continue;
        }
        let size = attribute(tag, "sizes")
            .and_then(|s| {
                s.split(['x', 'X'])
                    .next()
                    .and_then(|n| n.trim().parse::<u32>().ok())
            })
            .unwrap_or(0);
        let score = if rel.contains("apple-touch-icon") {
            10_000 + size.max(180)
        } else if rel.split_whitespace().any(|r| r == "icon") {
            size.max(16)
        } else {
            continue;
        };
        found.push((score, href));
    }
    found.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    found.into_iter().map(|(_, href)| href).collect()
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
        return Some(parsed.trim().to_owned());
    }
    None
}

/// Resolves an icon `href` against the site origin, upgrading to HTTPS.
pub fn resolve(origin: &str, href: &str) -> Option<String> {
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
    if href.contains("://") {
        return None;
    }
    let path = href.trim_start_matches("./");
    Some(if path.starts_with('/') {
        format!("{origin}{path}")
    } else {
        format!("{origin}/{path}")
    })
}

/// Decodes an untrusted image into a centered 64 × 64 RGBA bitmap.
pub fn decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(1024);
    limits.max_image_height = Some(1024);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    if decoded.width() < 8 || decoded.height() < 8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_keys() {
        assert_eq!(
            host_of("https://www.GitHub.com/login?x").as_deref(),
            Some("www.github.com")
        );
        assert_eq!(host_of("github.com").as_deref(), Some("github.com"));
        assert_eq!(
            host_of("http://user@bank.example:8443/").as_deref(),
            Some("bank.example")
        );
        assert_eq!(host_of("android://hash@com.example.app/"), None);
        assert_eq!(host_of("Expires 12/29"), None);
        assert_eq!(host_of("localhost"), None);
        assert_eq!(cache_key("www.github.com"), "github.com");
    }

    #[test]
    fn icon_sources() {
        assert_eq!(
            IconSource::parse("github.com"),
            Some(IconSource::Site("github.com".into()))
        );
        assert_eq!(
            IconSource::parse("https://nubank.com.br/login"),
            Some(IconSource::Site("nubank.com.br".into()))
        );
        assert_eq!(
            IconSource::parse("http://cdn.example/a/logo.PNG?v=2"),
            Some(IconSource::Image(
                "https://cdn.example/a/logo.PNG?v=2".into()
            ))
        );
        assert_eq!(
            IconSource::parse("cdn.example/logo.webp"),
            Some(IconSource::Image("https://cdn.example/logo.webp".into()))
        );
        // A host that merely ends like an extension is still a website.
        assert_eq!(
            IconSource::parse("logo.png"),
            Some(IconSource::Site("logo.png".into()))
        );
        assert_eq!(IconSource::parse("ftp://x.example/a.png"), None);
        assert_eq!(IconSource::parse(""), None);
        assert_eq!(
            IconSource::parse("https://www.github.com").unwrap().key(),
            "github.com"
        );
        assert_eq!(
            IconSource::parse("https://a.example/i.png").unwrap().key(),
            "img:https://a.example/i.png"
        );
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
                "icons/192.png",
                "/icons/32.png",
                "/favicon.ico"
            ]
        );
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
    }

    #[test]
    fn decodes_and_rejects() {
        let mut png = Vec::new();
        image::RgbaImage::from_pixel(100, 50, image::Rgba([10, 20, 30, 255]))
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
    fn cache_round_trip_and_missing_entries() {
        let mut cache = IconCache::default();
        cache.insert(
            "github.com".into(),
            Some(vec![1; (ICON_SIZE * ICON_SIZE * 4) as usize]),
        );
        cache.insert("noicon.example".into(), None);
        cache.insert("bad.example".into(), Some(vec![1, 2, 3]));
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
    }

    /// Real network request; run manually: `cargo test -p vault-desktop favicon -- --ignored`
    #[test]
    #[ignore = "network"]
    fn fetches_a_real_icon() {
        assert!(fetch("github.com").is_some());
    }
}
