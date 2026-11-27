//! Our own sync server (`vault-server`, SYNC.md §5.3). Every request is signed with this
//! device's key; the server only ever holds sealed copies and public keys.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use sha2::Digest as _;
use ureq::http::{Method, Request, Response, StatusCode};
use vault_core::sync::DeviceId;
use vault_sync_wire::{self as wire, Changes, Copies, DeviceKey, EnrolledDevice, Invite, Refusal};

use super::{Listed, Target, http};

/// A vault on a sync server, as this device.
#[derive(Debug)]
pub struct ServerTarget {
    /// The address as given (with its `#pin=` if any), for invites.
    address: String,
    /// Where requests go.
    base: String,
    vault: String,
    device: DeviceId,
    key: DeviceKey,
    /// Made at the first request: a pinned server's certificate is fetched then, off the
    /// UI thread.
    agent: std::sync::Mutex<Option<ureq::Agent>>,
    /// When the last long-poll was asked (see [`MIN_WAIT_SPACING`]).
    last_wait: std::sync::Mutex<Option<Instant>>,
}

/// The least time between two long-polls. A server answers one at once only when its counter
/// already moved; one that answers every one at once (its counter moving each time or not)
/// would otherwise have this device ask it again and again without a pause.
const MIN_WAIT_SPACING: Duration = Duration::from_secs(1);

impl ServerTarget {
    pub fn new(address: &str, vault_id: &str, device: DeviceId, key: DeviceKey) -> Result<Self> {
        if !wire::is_id(vault_id) {
            bail!("not a vault id");
        }
        let address = http::check_address(address)?;
        Ok(Self {
            base: http::split_pin(&address).0.to_owned(),
            address,
            vault: vault_id.to_owned(),
            device,
            key,
            agent: std::sync::Mutex::default(),
            last_wait: std::sync::Mutex::default(),
        })
    }

    /// Joins vault `vault_id` on the server at `address` with a one-time `invite`: makes this
    /// device's key, enrolls it and returns the target (save [`ServerTarget::key_seed`] in
    /// the credential store before using it).
    pub fn join(
        address: &str,
        vault_id: &str,
        device: DeviceId,
        name: &str,
        invite: &str,
    ) -> Result<Self> {
        let target = Self::new(address, vault_id, device, DeviceKey::generate())?;
        let name: String = name
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(wire::MAX_NAME_CHARS)
            .collect();
        let name = if wire::is_device_name(&name) {
            name
        } else {
            "Device".to_owned()
        };
        let invite = invite.trim().to_ascii_lowercase();
        if !wire::is_id(&invite) {
            bail!("that isn't an invite: it is 32 letters and digits");
        }
        let enroll = target
            .key
            .enroll(&invite, vault_id, &device.to_hex(), &name, unix_now());
        let body = serde_json::to_vec(&enroll)?;
        let request = Request::post(format!("{}/v1/enroll", target.base))
            .header("content-type", "application/json")
            .body(body)?;
        let mut response = target.agent()?.run(request).map_err(unreachable)?;
        check(&mut response)?;
        Ok(target)
    }

    /// This device's secret key seed, for the credential store.
    pub fn key_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.key.seed()
    }

    fn path(&self, rest: &str) -> String {
        format!("/v1/vaults/{}{rest}", self.vault)
    }

    fn send(&self, method: Method, path: &str, body: Vec<u8>) -> Result<Response<ureq::Body>> {
        let signed = self.key.sign_request(
            &self.device.to_hex(),
            method.as_str(),
            path,
            &body,
            unix_now(),
        );
        // The body's digest lets the server check the signature before it reads the body.
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header(wire::header::BODY_SHA256, wire::body_digest(&body));
        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }
        let request = request.body(body)?;
        self.agent()?.run(request).map_err(unreachable)
    }

    fn json<T: serde::de::DeserializeOwned>(&self, method: Method, path: &str) -> Result<T> {
        let mut response = self.send(method, path, Vec::new())?;
        check(&mut response)?;
        let bytes = http::read_body(&mut response, 1024 * 1024)?;
        serde_json::from_slice(&bytes).context("the server's answer can't be read")
    }

    /// The devices enrolled for this vault on the server.
    pub fn enrolled(&self) -> Result<Vec<EnrolledDevice>> {
        self.json(Method::GET, &self.path("/enrolled"))
    }

    /// A one-time invite for one more device (good for an hour). It is shown as a QR code and a
    /// line typed on another device, so what the server hands back must be an invite and
    /// nothing else: the line then carries nothing the server chose.
    pub fn invite(&self) -> Result<Invite> {
        let invite: Invite = self.json(Method::POST, &self.path("/invites"))?;
        if !wire::is_id(&invite.invite) {
            bail!("the server's answer isn't an invite");
        }
        Ok(invite)
    }

    /// The phone app's update on this server, when its owner published one.
    pub fn app_release(&self) -> Result<Option<wire::AppRelease>> {
        let mut response = self.send(Method::GET, &self.path("/app/android"), Vec::new())?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check(&mut response)?;
        let bytes = http::read_body(&mut response, 64 * 1024)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .context("the server's answer can't be read")
    }

    /// The update's package, checked against the release it belongs to (size and SHA-256).
    pub fn app_package(&self, release: &wire::AppRelease) -> Result<Vec<u8>> {
        let mut response =
            self.send(Method::GET, &self.path("/app/android/package"), Vec::new())?;
        check(&mut response)?;
        let bytes = http::read_body(&mut response, wire::MAX_APP_BYTES)?;
        let digest: String = sha2::Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if bytes.len() as u64 != release.size || digest != release.sha256 {
            bail!("the package the server sent doesn't match its release");
        }
        Ok(bytes)
    }

    fn agent(&self) -> Result<ureq::Agent> {
        let mut agent = self.agent.lock().unwrap();
        if let Some(agent) = agent.as_ref() {
            return Ok(agent.clone());
        }
        let made = http::agent_for(&self.address)?;
        *agent = Some(made.clone());
        Ok(made)
    }

    /// The text (and QR code) another device joins with.
    pub fn invite_link(&self, invite: &Invite) -> wire::InviteLink {
        wire::InviteLink {
            server: self.address.clone(),
            vault: self.vault.clone(),
            backup: None,
            invite: invite.invite.clone(),
        }
    }
}

impl Target for ServerTarget {
    fn list(&self) -> Result<Vec<Listed>> {
        let copies: Copies = self.json(Method::GET, &self.path("/devices"))?;
        let mut listed = Vec::new();
        for copy in copies.copies {
            if let Some(device) = DeviceId::from_hex(&copy.device) {
                listed.push(Listed {
                    device,
                    tag: Some(copy.tag),
                });
            }
        }
        listed.sort_by_key(|l| l.device);
        Ok(listed)
    }

    fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
        let path = self.path(&format!("/devices/{}", device.to_hex()));
        let mut response = self.send(Method::GET, &path, Vec::new())?;
        check(&mut response)?;
        http::read_body(&mut response, wire::MAX_COPY_BYTES)
    }

    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()> {
        if bytes.len() > wire::MAX_COPY_BYTES {
            bail!("this vault is too big to sync");
        }
        let path = self.path(&format!("/devices/{}", own.to_hex()));
        let mut response = self.send(Method::PUT, &path, bytes.to_vec())?;
        check(&mut response)
    }

    fn remove(&self, device: DeviceId) -> Result<()> {
        let path = self.path(&format!("/devices/{}", device.to_hex()));
        let mut response = self.send(Method::DELETE, &path, Vec::new())?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        check(&mut response)
    }

    fn wait(&self, after: u64, seconds: u64) -> Option<Result<u64>> {
        let pause = {
            let mut last = self.last_wait.lock().unwrap();
            let pause = last.map_or(Duration::ZERO, |at| {
                MIN_WAIT_SPACING.saturating_sub(at.elapsed())
            });
            *last = Some(Instant::now() + pause);
            pause
        };
        std::thread::sleep(pause);
        let seconds = seconds.min(wire::MAX_WAIT_SECONDS);
        let path = self.path(&format!("/changes?after={after}&wait={seconds}"));
        Some(
            self.json::<Changes>(Method::GET, &path)
                .map(|changes| changes.seq),
        )
    }
}

fn unreachable(err: ureq::Error) -> anyhow::Error {
    anyhow!(err).context("the sync server can't be reached")
}

/// Turns a refusal into an error that says what to do.
fn check(response: &mut Response<ureq::Body>) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let reason = http::read_body(response, 4096)
        .ok()
        .and_then(|b| serde_json::from_slice::<Refusal>(&b).ok())
        .map(|r| r.error)
        .unwrap_or_default();
    Err(match (status.as_u16(), reason.as_str()) {
        (401, "invite") => anyhow!("the invite is wrong, used or expired: make a new one"),
        (401, "clock") => anyhow!("this device's clock is off by more than 5 minutes"),
        // One answer for a device the server doesn't have and for a key that isn't the one it
        // has, so a stranger can't tell them apart.
        (401, "unknown_device") => anyhow!(
            "this device isn't allowed in on the server (it was taken out, or its key isn't the \
             one it joined with): join it again"
        ),
        (401, _) => anyhow!("the server refused this device's signature"),
        (403, "new_vault_only") => anyhow!(
            "that invite only starts a new vault, and this vault is on the server already: use \
             Add a device on a device that syncs it, or vault-server invite --vault <its id>"
        ),
        (403, _) => anyhow!("the server refused: a device writes only its own copy"),
        (404, _) => anyhow!("not on the server"),
        (408, _) => anyhow!("the connection to the server was too slow: try again"),
        (409, "already_enrolled") => {
            anyhow!("this device is already in on that server: stop syncing, then join again")
        }
        (413, _) => anyhow!("too big for the server"),
        (429, _) => anyhow!("the server asks to slow down: try again in a minute"),
        (503, "busy") => anyhow!("the server is busy: try again in a moment"),
        (507, "too_many_devices") => anyhow!("the server allows no more devices for this vault"),
        (507, _) => anyhow!("too many invites are waiting: use one first"),
        (300..=399, _) => anyhow!("the server sent us to another address (not followed)"),
        _ => anyhow!("the sync server answered {status}"),
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
