//! The HTTP API (SYNC.md §5.3). Every route but `/v1/health` and `/v1/enroll` takes a request
//! signed by a device enrolled for that vault.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::request::Parts,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tokio::sync::watch;
use vault_sync_wire::{
    self as wire, Changes, Copies, Copy, Enroll, EnrolledDevice, Invite, Refusal,
};

use crate::store::{self, Device, Store};

/// How long an invite made by a device stays good.
const DEVICE_INVITE_SECONDS: i64 = 60 * 60;
/// How long a nonce is remembered: longer than the clock skew allowed on either side.
const NONCE_SECONDS: i64 = 2 * wire::MAX_CLOCK_SKEW + 60;
/// Long-polls one device may hold open at once.
const MAX_WAITS_PER_DEVICE: usize = 4;
/// `seen_at` is written to disk at most this often per device.
const TOUCH_EVERY: i64 = 10 * 60;

/// Requests allowed per device: a burst, then a steady rate. A device syncing normally makes
/// a few requests a minute.
const DEVICE_BURST: f64 = 120.0;
const DEVICE_PER_SECOND: f64 = 2.0;
/// Failed or unauthenticated requests allowed per address (wrong signatures, enrollments).
const ADDRESS_BURST: f64 = 20.0;
const ADDRESS_PER_SECOND: f64 = 1.0 / 6.0;

#[derive(Debug)]
pub struct Server {
    store: Store,
    vaults: Mutex<HashMap<String, Arc<LiveVault>>>,
    nonces: Mutex<Nonces>,
    devices: Mutex<Buckets>,
    addresses: Mutex<Buckets>,
    waits: Mutex<HashMap<String, usize>>,
    touched: Mutex<HashMap<String, i64>>,
    /// The change counter starts at the server's start time in milliseconds, so it never goes
    /// backwards across restarts and devices need not store anything about the server.
    start_seq: u64,
}

#[derive(Debug)]
struct LiveVault {
    /// One write at a time per vault.
    write: tokio::sync::Mutex<()>,
    seq: watch::Sender<u64>,
    copies: Mutex<Option<Vec<Copy>>>,
}

impl Server {
    pub fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store,
            vaults: Mutex::default(),
            nonces: Mutex::default(),
            devices: Mutex::new(Buckets::new(DEVICE_BURST, DEVICE_PER_SECOND)),
            addresses: Mutex::new(Buckets::new(ADDRESS_BURST, ADDRESS_PER_SECOND)),
            waits: Mutex::default(),
            touched: Mutex::default(),
            start_seq: now_millis(),
        })
    }

    fn live(&self, vault: &str) -> Arc<LiveVault> {
        let mut vaults = self.vaults.lock().unwrap();
        vaults
            .entry(vault.to_owned())
            .or_insert_with(|| {
                Arc::new(LiveVault {
                    write: tokio::sync::Mutex::new(()),
                    seq: watch::Sender::new(self.start_seq),
                    copies: Mutex::new(None),
                })
            })
            .clone()
    }

    fn changed(&self, live: &LiveVault) {
        *live.copies.lock().unwrap() = None;
        live.seq
            .send_modify(|seq| *seq = (*seq + 1).max(now_millis()));
    }
}

pub fn router(server: Arc<Server>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/enroll", post(enroll))
        .route("/v1/vaults/{vault}/devices", get(list))
        .route(
            "/v1/vaults/{vault}/devices/{device}",
            get(get_copy)
                .put(put_copy)
                .delete(remove_device)
                .layer(DefaultBodyLimit::max(wire::MAX_COPY_BYTES)),
        )
        .route("/v1/vaults/{vault}/enrolled", get(enrolled))
        .route("/v1/vaults/{vault}/invites", post(invite))
        .route("/v1/vaults/{vault}/changes", get(changes))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(server)
}

/// A refusal: a status and a short reason.
#[derive(Debug)]
pub struct Refused(StatusCode, &'static str);

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let mut response = (
            self.0,
            Json(Refusal {
                error: self.1.to_owned(),
            }),
        )
            .into_response();
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("10"));
        }
        response
    }
}

impl From<anyhow::Error> for Refused {
    fn from(err: anyhow::Error) -> Self {
        eprintln!("vault-server: {err:#}");
        Refused(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    }
}

impl From<tokio::task::JoinError> for Refused {
    fn from(err: tokio::task::JoinError) -> Self {
        anyhow::Error::from(err).into()
    }
}

type Answer<T> = Result<T, Refused>;

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Answer<T> {
    Ok(tokio::task::spawn_blocking(job).await??)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "protocol": wire::PROTOCOL }))
}

/// Counts a failed or unauthenticated request against its address; refuses once the address
/// has failed too often. Properly signed requests from enrolled devices don't count here (they
/// have their own allowance), so one confused device behind the same proxy can't lock the
/// others out.
fn count_against(server: &Server, address: &SocketAddr) -> Answer<()> {
    if server
        .addresses
        .lock()
        .unwrap()
        .take(&address.ip().to_string())
    {
        Ok(())
    } else {
        Err(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"))
    }
}

/// Checks a signed request and returns the device it came from.
async fn authorize(
    server: &Arc<Server>,
    address: &SocketAddr,
    vault: &str,
    parts: &Parts,
    body: &[u8],
) -> Answer<Device> {
    let result = verify_request(
        server,
        vault,
        &parts.method,
        &parts.uri,
        &parts.headers,
        body,
    )
    .await;
    match result {
        Ok(device) => {
            if !server
                .devices
                .lock()
                .unwrap()
                .take(&format!("{vault}/{}", device.device))
            {
                return Err(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
            }
            let now = unix_now();
            let key = format!("{vault}/{}", device.device);
            let due = {
                let mut touched = server.touched.lock().unwrap();
                let last = touched.get(&key).copied().unwrap_or(device.seen_at);
                let due = now - last >= TOUCH_EVERY;
                if due {
                    touched.insert(key, now);
                }
                due
            };
            if due {
                let (store, vault, id) = (
                    server.store.clone(),
                    vault.to_owned(),
                    device.device.clone(),
                );
                blocking(move || store.touch(&vault, &id, now)).await?;
            }
            Ok(device)
        }
        Err(refused) => {
            count_against(server, address)?;
            Err(refused)
        }
    }
}

async fn verify_request(
    server: &Arc<Server>,
    vault: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Answer<Device> {
    let unauthorized = |why| Refused(StatusCode::UNAUTHORIZED, why);
    if !wire::is_id(vault) {
        return Err(Refused(StatusCode::NOT_FOUND, "not_found"));
    }
    let text = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or(unauthorized("unsigned"))
    };
    let device_id = text(wire::header::DEVICE)?;
    let time: i64 = text(wire::header::TIME)?
        .parse()
        .map_err(|_| unauthorized("unsigned"))?;
    let nonce = text(wire::header::NONCE)?;
    let signature = text(wire::header::SIGNATURE)?;
    if !wire::is_id(device_id) || !wire::is_id(nonce) {
        return Err(unauthorized("unsigned"));
    }
    if (time - unix_now()).abs() > wire::MAX_CLOCK_SKEW {
        return Err(unauthorized("clock"));
    }
    let (store, vault_id, id) = (server.store.clone(), vault.to_owned(), device_id.to_owned());
    let device = blocking(move || store.device(&vault_id, &id))
        .await?
        .ok_or(unauthorized("unknown_device"))?;
    let key = device.public_key().ok_or(unauthorized("unknown_device"))?;
    let path = uri.path_and_query().map_or(uri.path(), |p| p.as_str());
    let message = wire::request_message(method.as_str(), path, device_id, time, nonce, body);
    if !wire::verify(&key, &message, signature) {
        return Err(unauthorized("signature"));
    }
    // Only after the signature: a stranger can't fill the nonce cache.
    if !server
        .nonces
        .lock()
        .unwrap()
        .first_use(&format!("{vault}/{device_id}/{nonce}"), unix_now())
    {
        return Err(unauthorized("replay"));
    }
    Ok(device)
}

async fn enroll(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Answer<Json<serde_json::Value>> {
    // Every enrollment counts against the address, so invites can't be tried at speed (and a
    // 128-bit invite can't be guessed at all).
    count_against(&server, &address)?;
    let bad = |why| Refused(StatusCode::BAD_REQUEST, why);
    let request: Enroll = serde_json::from_slice(&body).map_err(|_| bad("bad_request"))?;
    if !wire::is_id(&request.vault)
        || !wire::is_id(&request.device)
        || !wire::is_device_name(&request.name)
    {
        return Err(bad("bad_request"));
    }
    let key = wire::unhex::<32>(&request.key).ok_or(bad("bad_request"))?;
    if (request.time - unix_now()).abs() > wire::MAX_CLOCK_SKEW {
        return Err(Refused(StatusCode::UNAUTHORIZED, "clock"));
    }
    if !wire::verify(&key, &wire::enroll_message(&request), &request.signature) {
        return Err(Refused(StatusCode::UNAUTHORIZED, "signature"));
    }
    let live = server.live(&request.vault);
    let _write = live.write.lock().await;
    let store = server.store.clone();
    let now = unix_now();
    let (vault, device) = (request.vault.clone(), request.device.clone());
    let outcome = blocking(move || {
        let count = store.devices(&request.vault)?.len();
        let known = store.device(&request.vault, &request.device)?.is_some();
        if count >= store::MAX_DEVICES && !known {
            return Ok(Err(Refused(
                StatusCode::INSUFFICIENT_STORAGE,
                "too_many_devices",
            )));
        }
        if !store.take_invite(&request.vault, &request.invite, now)? {
            return Ok(Err(Refused(StatusCode::UNAUTHORIZED, "invite")));
        }
        store.enroll(
            &request.vault,
            Device {
                device: request.device,
                key: request.key,
                name: request.name,
                added_at: now,
                seen_at: now,
            },
        )?;
        Ok(Ok(()))
    })
    .await?;
    outcome?;
    server.changed(&live);
    Ok(Json(
        serde_json::json!({ "vault": vault, "device": device }),
    ))
}

async fn list(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Answer<Json<Copies>> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    let live = server.live(&vault);
    let seq = *live.seq.borrow();
    let cached = live.copies.lock().unwrap().clone();
    let copies = match cached {
        Some(copies) => copies,
        None => {
            let store = server.store.clone();
            let id = vault.clone();
            let copies = blocking(move || store.copies(&id)).await?;
            *live.copies.lock().unwrap() = Some(copies.clone());
            copies
        }
    };
    Ok(Json(Copies { copies, seq }))
}

async fn get_copy(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path((vault, device)): Path<(String, String)>,
    parts: Parts,
    body: Bytes,
) -> Answer<Response> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    if !wire::is_id(&device) {
        return Err(Refused(StatusCode::NOT_FOUND, "not_found"));
    }
    let store = server.store.clone();
    let bytes = blocking(move || store.get(&vault, &device))
        .await?
        .ok_or(Refused(StatusCode::NOT_FOUND, "not_found"))?;
    let tag = format!("\"{}\"", wire::tag(&bytes));
    let unchanged = parts
        .headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == tag);
    let mut response = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&tag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    Ok(response)
}

async fn put_copy(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path((vault, device)): Path<(String, String)>,
    parts: Parts,
    body: Bytes,
) -> Answer<Json<serde_json::Value>> {
    let signer = authorize(&server, &address, &vault, &parts, &body).await?;
    // A device writes only its own copy.
    if signer.device != device {
        return Err(Refused(StatusCode::FORBIDDEN, "not_your_copy"));
    }
    if body.is_empty() {
        return Err(Refused(StatusCode::BAD_REQUEST, "empty"));
    }
    let live = server.live(&vault);
    let _write = live.write.lock().await;
    let expected = parts
        .headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').to_owned());
    let store = server.store.clone();
    let tag = wire::tag(&body);
    let outcome = blocking(move || {
        if let Some(expected) = expected.filter(|e| e != "*") {
            let current = store.get(&vault, &device)?.map(|b| wire::tag(&b));
            if current.as_deref() != Some(expected.as_str()) {
                return Ok(false);
            }
        }
        store.put(&vault, &device, &body)?;
        Ok(true)
    })
    .await?;
    if !outcome {
        return Err(Refused(StatusCode::PRECONDITION_FAILED, "changed"));
    }
    server.changed(&live);
    Ok(Json(serde_json::json!({ "tag": tag })))
}

async fn remove_device(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path((vault, device)): Path<(String, String)>,
    parts: Parts,
    body: Bytes,
) -> Answer<StatusCode> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    if !wire::is_id(&device) {
        return Err(Refused(StatusCode::NOT_FOUND, "not_found"));
    }
    let live = server.live(&vault);
    let _write = live.write.lock().await;
    let store = server.store.clone();
    blocking(move || store.remove(&vault, &device)).await?;
    server.changed(&live);
    Ok(StatusCode::NO_CONTENT)
}

async fn enrolled(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Answer<Json<Vec<EnrolledDevice>>> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    let store = server.store.clone();
    let devices = blocking(move || store.devices(&vault)).await?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| EnrolledDevice {
                device: d.device,
                name: d.name,
                added_at: d.added_at,
                seen_at: d.seen_at,
            })
            .collect(),
    ))
}

async fn invite(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Answer<Json<Invite>> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    let invite = wire::new_invite();
    let now = unix_now();
    let expires_at = now + DEVICE_INVITE_SECONDS;
    let store = server.store.clone();
    let text = invite.to_string();
    let added = blocking(move || {
        Ok(store
            .add_invite(Some(&vault), &text, expires_at, now)
            .is_ok())
    })
    .await?;
    if !added {
        return Err(Refused(
            StatusCode::INSUFFICIENT_STORAGE,
            "too_many_invites",
        ));
    }
    Ok(Json(Invite {
        invite: invite.to_string(),
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
struct Wait {
    #[serde(default)]
    after: u64,
    #[serde(default)]
    wait: u64,
}

async fn changes(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    Query(wait): Query<Wait>,
    parts: Parts,
    body: Bytes,
) -> Answer<Json<Changes>> {
    let device = authorize(&server, &address, &vault, &parts, &body).await?;
    let key = format!("{vault}/{}", device.device);
    {
        let mut waits = server.waits.lock().unwrap();
        let count = waits.entry(key.clone()).or_default();
        if *count >= MAX_WAITS_PER_DEVICE {
            return Err(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
        }
        *count += 1;
    }
    let _release = Release(&server, key);
    let mut seq = server.live(&vault).seq.subscribe();
    let seconds = wait.wait.min(wire::MAX_WAIT_SECONDS);
    let _ = tokio::time::timeout(
        Duration::from_secs(seconds),
        seq.wait_for(|now| *now != wait.after),
    )
    .await;
    let now = *seq.borrow();
    Ok(Json(Changes { seq: now }))
}

/// Gives back a long-poll slot when the request ends, however it ends.
struct Release<'a>(&'a Server, String);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        let mut waits = self.0.waits.lock().unwrap();
        if let Some(count) = waits.get_mut(&self.1) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                waits.remove(&self.1);
            }
        }
    }
}

/// Nonces seen recently, oldest first.
#[derive(Debug, Default)]
struct Nonces {
    seen: HashMap<String, i64>,
    order: VecDeque<(i64, String)>,
}

impl Nonces {
    /// How many are kept at most: far more than honest devices make in the window.
    const MAX: usize = 200_000;

    fn first_use(&mut self, nonce: &str, now: i64) -> bool {
        while let Some((at, _)) = self.order.front() {
            if now - at <= NONCE_SECONDS && self.order.len() < Self::MAX {
                break;
            }
            let (_, old) = self.order.pop_front().unwrap();
            self.seen.remove(&old);
        }
        if self.seen.contains_key(nonce) {
            return false;
        }
        self.seen.insert(nonce.to_owned(), now);
        self.order.push_back((now, nonce.to_owned()));
        true
    }
}

/// Token buckets, one per key.
#[derive(Debug)]
struct Buckets {
    burst: f64,
    per_second: f64,
    buckets: HashMap<String, (f64, Instant)>,
}

impl Buckets {
    fn new(burst: f64, per_second: f64) -> Self {
        Self {
            burst,
            per_second,
            buckets: HashMap::new(),
        }
    }

    fn level(&mut self, key: &str) -> &mut (f64, Instant) {
        let now = Instant::now();
        if self.buckets.len() > 10_000 {
            let (burst, rate) = (self.burst, self.per_second);
            self.buckets.retain(|_, (level, at)| {
                *level + now.duration_since(*at).as_secs_f64() * rate < burst
            });
        }
        let (burst, rate) = (self.burst, self.per_second);
        let entry = self.buckets.entry(key.to_owned()).or_insert((burst, now));
        entry.0 = (entry.0 + now.duration_since(entry.1).as_secs_f64() * rate).min(burst);
        entry.1 = now;
        entry
    }

    /// Takes one token; false when there was none.
    fn take(&mut self, key: &str) -> bool {
        let entry = self.level(key);
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_used_once_and_forgotten_later() {
        let mut nonces = Nonces::default();
        assert!(nonces.first_use("a", 0));
        assert!(!nonces.first_use("a", 10));
        assert!(nonces.first_use("b", 10));
        assert!(
            nonces.first_use("a", NONCE_SECONDS + 1),
            "outside the window"
        );
    }

    #[test]
    fn a_bucket_runs_dry_and_refills() {
        let mut buckets = Buckets::new(2.0, 1000.0);
        assert!(buckets.take("x"));
        assert!(buckets.take("x"));
        let mut slow = Buckets::new(1.0, 0.0001);
        assert!(slow.take("y"));
        assert!(!slow.take("y"));
        assert!(slow.take("z"));
    }
}
