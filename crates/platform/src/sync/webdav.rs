//! A WebDAV collection (Nextcloud, ownCloud, a NAS, any WebDAV host) as a sync target:
//! `<address>/<vault id>/devices/<device>.vault`, Basic authentication over HTTPS. The
//! password comes from the OS credential store and is never written anywhere else.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use quick_xml::{Reader, events::Event};
use ureq::http::{Method, Request, Response};
use vault_core::sync::DeviceId;
use vault_sync_wire as wire;
use zeroize::Zeroizing;

use super::{Listed, Target, http};

pub struct WebDavTarget {
    /// `<address>/<vault>/` and `<address>/<vault>/devices/`.
    vault_url: String,
    devices_url: String,
    authorization: Zeroizing<String>,
    agent: ureq::Agent,
}

impl std::fmt::Debug for WebDavTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavTarget")
            .field("devices_url", &self.devices_url)
            .finish_non_exhaustive()
    }
}

impl WebDavTarget {
    pub fn new(address: &str, vault_id: &str, user: &str, password: &str) -> Result<Self> {
        if !wire::is_id(vault_id) {
            bail!("not a vault id");
        }
        if user.contains(':') || user.chars().any(char::is_control) {
            bail!("the user name can't contain ':'");
        }
        let base = http::check_address(address)?;
        let credentials = Zeroizing::new(format!("{user}:{password}"));
        let authorization = Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
        ));
        let vault_url = format!("{base}/{vault_id}/");
        Ok(Self {
            devices_url: format!("{vault_url}devices/"),
            vault_url,
            authorization,
            agent: http::agent(true),
        })
    }

    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Response<ureq::Body>> {
        let mut request = Request::builder()
            .method(Method::from_bytes(method.as_bytes())?)
            .uri(url)
            .header("authorization", self.authorization.as_str());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.agent
            .run(request.body(body)?)
            .map_err(|err| anyhow!(err).context("the WebDAV server can't be reached"))
    }

    fn url(&self, device: DeviceId) -> String {
        format!("{}{}.vault", self.devices_url, device.to_hex())
    }

    /// Makes the vault's collections if they aren't there yet.
    fn make_collections(&self) -> Result<()> {
        for url in [&self.vault_url, &self.devices_url] {
            let mut response = self.send("MKCOL", url, &[], Vec::new())?;
            // 201 made, 405 already there.
            let status = response.status().as_u16();
            if status != 201 && status != 405 {
                check(&mut response)?;
            }
        }
        Ok(())
    }
}

impl Target for WebDavTarget {
    fn list(&self) -> Result<Vec<Listed>> {
        let body = br#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:getcontentlength/></d:prop></d:propfind>"#;
        let mut response = self.send(
            "PROPFIND",
            &self.devices_url,
            &[("depth", "1"), ("content-type", "application/xml")],
            body.to_vec(),
        )?;
        if response.status().as_u16() == 404 {
            return Ok(Vec::new());
        }
        check(&mut response)?;
        let xml = http::read_body(&mut response, 4 * 1024 * 1024)?;
        let mut listed = parse_listing(&xml)?;
        listed.sort_by_key(|l| l.device);
        listed.dedup_by_key(|l| l.device);
        Ok(listed)
    }

    fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
        let mut response = self.send("GET", &self.url(device), &[], Vec::new())?;
        check(&mut response)?;
        http::read_body(&mut response, wire::MAX_COPY_BYTES)
    }

    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()> {
        if bytes.len() > wire::MAX_COPY_BYTES {
            bail!("this vault is too big to sync");
        }
        self.make_collections()?;
        // Written beside it under a name `list` ignores, then moved over it: readers never
        // see half a copy. A server without MOVE gets the copy written in place.
        let temp = format!("{}.{}.tmp", self.devices_url, own.to_hex());
        let mut response = self.send("PUT", &temp, &[], bytes.to_vec())?;
        check(&mut response)?;
        let target = self.url(own);
        let mut moved = self.send(
            "MOVE",
            &temp,
            &[("destination", target.as_str()), ("overwrite", "T")],
            Vec::new(),
        )?;
        if moved.status().is_success() {
            return Ok(());
        }
        let _ = self.send("DELETE", &temp, &[], Vec::new());
        if !matches!(moved.status().as_u16(), 405 | 501) {
            return check(&mut moved);
        }
        let mut response = self.send("PUT", &target, &[], bytes.to_vec())?;
        check(&mut response)
    }

    fn remove(&self, device: DeviceId) -> Result<()> {
        let mut response = self.send("DELETE", &self.url(device), &[], Vec::new())?;
        if response.status().as_u16() == 404 {
            return Ok(());
        }
        check(&mut response)
    }
}

fn check(response: &mut Response<ureq::Body>) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(match status.as_u16() {
        401 => anyhow!("the WebDAV server refused the user name or password"),
        403 => anyhow!("the WebDAV server doesn't allow this here"),
        404 | 409 => anyhow!("that WebDAV folder doesn't exist"),
        413 | 507 => anyhow!("the WebDAV server has no room for this copy"),
        300..=399 => anyhow!("the WebDAV server sent us to another address (not followed)"),
        _ => anyhow!("the WebDAV server answered {status}"),
    })
}

/// The copies in a PROPFIND answer: each `<response>` whose `<href>` ends in
/// `<32 hex>.vault`, with its ETag.
fn parse_listing(xml: &[u8]) -> Result<Vec<Listed>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut listed = Vec::new();
    let (mut href, mut etag) = (String::new(), String::new());
    let mut field: Option<&'static str> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .context("the WebDAV listing can't be read")?
        {
            Event::Start(e) => match e.local_name().as_ref() {
                b"response" => {
                    href.clear();
                    etag.clear();
                }
                b"href" => field = Some("href"),
                b"getetag" => field = Some("etag"),
                _ => {}
            },
            Event::Text(text) => {
                let text = text.decode().unwrap_or_default();
                match field {
                    Some("href") => href.push_str(&text),
                    Some("etag") => etag.push_str(&text),
                    _ => {}
                }
            }
            Event::End(e) => match e.local_name().as_ref() {
                b"href" | b"getetag" => field = None,
                b"response" => {
                    let name = href.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                    if let Some(device) = name.strip_suffix(".vault").and_then(DeviceId::from_hex) {
                        let tag = etag.trim().trim_start_matches("W/").trim_matches('"');
                        listed.push(Listed {
                            device,
                            tag: (!tag.is_empty()).then(|| tag.to_owned()),
                        });
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_names_the_copies_and_their_tags() {
        let one = "ab".repeat(16);
        let two = "cd".repeat(16);
        let xml = format!(
            r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
 <d:response><d:href>/dav/files/me/sync/x/devices/</d:href>
  <d:propstat><d:prop><d:getetag>"dir"</d:getetag></d:prop></d:propstat></d:response>
 <d:response><d:href>/dav/files/me/sync/x/devices/{one}.vault</d:href>
  <d:propstat><d:prop><d:getetag>"e1"</d:getetag></d:prop></d:propstat></d:response>
 <D:response xmlns:D="DAV:"><D:href>https://host/x/devices/{two}.vault</D:href>
  <D:propstat><D:prop><D:getetag>W/"e2"</D:getetag></D:prop></D:propstat></D:response>
 <d:response><d:href>/x/devices/.{one}.vault.tmp</d:href></d:response>
 <d:response><d:href>/x/devices/{one} (conflicted copy).vault</d:href></d:response>
</d:multistatus>"#
        );
        let listed = parse_listing(xml.as_bytes()).unwrap();
        assert_eq!(
            listed,
            [
                Listed {
                    device: DeviceId::from_hex(&one).unwrap(),
                    tag: Some("e1".into())
                },
                Listed {
                    device: DeviceId::from_hex(&two).unwrap(),
                    tag: Some("e2".into())
                },
            ]
        );
    }

    #[test]
    fn plain_http_and_odd_users_are_refused() {
        let id = "a".repeat(32);
        assert!(WebDavTarget::new("http://example.com/dav", &id, "me", "pw").is_err());
        assert!(WebDavTarget::new("https://example.com/dav", &id, "a:b", "pw").is_err());
        let target = WebDavTarget::new("https://example.com/dav/", &id, "me", "pw").unwrap();
        assert_eq!(
            target.devices_url,
            format!("https://example.com/dav/{id}/devices/")
        );
        assert!(!format!("{target:?}").contains("pw"));
    }
}
