//! The HTTP API (SYNC.md §5.3). Every route but `/v1/health` and `/v1/enroll` takes a request
//! signed by a device enrolled for that vault.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::request::Parts,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
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
/// Requests in flight at once; more are refused (busy) instead of piling up.
const MAX_IN_FLIGHT: usize = 256;
/// The longest a request may take: a long-poll waits up to a minute.
const REQUEST_TIME: Duration = Duration::from_secs(90);
/// Copies read at once (each up to 64 MB, held in memory until written), and per device.
const UPLOADS: usize = 4;
const UPLOADS_PER_DEVICE: usize = 1;
/// Copies read at once from an older app that doesn't send the body's digest: their signature
/// can only be checked once the copy has arrived, so they get a slot of their own and can't
/// hold up the others.
const UNCHECKED_UPLOADS: usize = 1;
/// The longest a copy may take to arrive.
const UPLOAD_TIME: Duration = Duration::from_secs(60);
/// Copies and app packages held in memory to be sent at once, and per device.
const DOWNLOADS: usize = 4;
const DOWNLOADS_PER_DEVICE: usize = 2;
/// Keys kept by the rate limits before the full ones are dropped; past twice this, all of
/// them are (a flood from many addresses resets the counts rather than the server's memory).
const MAX_BUCKETS: usize = 10_000;

#[derive(Debug)]
pub struct Server {
    store: Store,
    vaults: Mutex<HashMap<String, Arc<LiveVault>>>,
    nonces: Mutex<Nonces>,
    devices: Mutex<Buckets>,
    addresses: Mutex<Buckets>,
    waits: PerKey,
    uploading: PerKey,
    downloading: PerKey,
    touched: Mutex<HashMap<String, i64>>,
    /// The change counter starts at the server's start time in milliseconds, so it never goes
    /// backwards across restarts and devices need not store anything about the server.
    start_seq: u64,
    in_flight: Semaphore,
    uploads: Semaphore,
    unchecked_uploads: Semaphore,
    downloads: Arc<Semaphore>,
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
            waits: PerKey::default(),
            uploading: PerKey::default(),
            downloading: PerKey::default(),
            touched: Mutex::default(),
            start_seq: now_millis(),
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            uploads: Semaphore::new(UPLOADS),
            unchecked_uploads: Semaphore::new(UNCHECKED_UPLOADS),
            downloads: Arc::new(Semaphore::new(DOWNLOADS)),
        })
    }

    /// The live state of a vault. Made only for a request already authorized (or an
    /// enrollment that succeeded), so strangers can't fill this map.
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
        // A copy is read by `put_copy` itself, only once the request is known to come from
        // an enrolled device; every other body is small.
        .route(
            "/v1/vaults/{vault}/devices/{device}",
            get(get_copy).put(put_copy).delete(remove_device),
        )
        .route("/v1/vaults/{vault}/enrolled", get(enrolled))
        .route("/v1/vaults/{vault}/invites", post(invite))
        .route("/v1/vaults/{vault}/changes", get(changes))
        .route("/v1/vaults/{vault}/app/android", get(app_release))
        .route("/v1/vaults/{vault}/app/android/package", get(app_package))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            bounded,
        ))
        .layer(axum::middleware::map_response(plain))
        .with_state(server)
}

/// At most `MAX_IN_FLIGHT` requests at once, each answered within `REQUEST_TIME`: a client
/// that opens many, or sends slowly, holds up no one for long.
async fn bounded(
    State(server): State<Arc<Server>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Ok(_slot) = server.in_flight.try_acquire() else {
        return Refused(StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    };
    match tokio::time::timeout(REQUEST_TIME, next.run(request)).await {
        Ok(response) => response,
        Err(_) => Refused(StatusCode::REQUEST_TIMEOUT, "too_slow").into_response(),
    }
}

/// Every answer: never kept by a cache on the way, never read as anything but what it says.
async fn plain(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
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

/// The address a client is counted by: an IPv4 address itself, an IPv6 address by its /64
/// (one home or phone network gets a whole /64 and may pick any address in it, so counting
/// single IPv6 addresses would count nothing).
pub fn neighbourhood(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
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
        .take(&neighbourhood(address.ip()).to_string())
    {
        Ok(())
    } else {
        Err(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"))
    }
}

/// Gives back what [`count_against`] took, once the request turned out to be a device's.
fn give_back(server: &Server, address: &SocketAddr) {
    server
        .addresses
        .lock()
        .unwrap()
        .give_back(&neighbourhood(address.ip()).to_string());
}

/// Whether a request's time is close enough to the server's clock (computed without
/// overflow, whatever number the request carries).
fn close_to_now(time: i64) -> bool {
    time.abs_diff(unix_now()) <= wire::MAX_CLOCK_SKEW.unsigned_abs()
}

/// Checks a signed request and returns the device it came from.
async fn authorize(
    server: &Arc<Server>,
    address: &SocketAddr,
    vault: &str,
    parts: &Parts,
    body: &[u8],
) -> Answer<Device> {
    authorize_digest(server, address, vault, parts, &wire::body_digest(body)).await
}

/// [`authorize`] for a body known by its digest (one not read yet).
async fn authorize_digest(
    server: &Arc<Server>,
    address: &SocketAddr,
    vault: &str,
    parts: &Parts,
    body_digest: &str,
) -> Answer<Device> {
    let result = verify_request(
        server,
        vault,
        &parts.method,
        &parts.uri,
        &parts.headers,
        body_digest,
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
    body_digest: &str,
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
    if !close_to_now(time) {
        return Err(unauthorized("clock"));
    }
    let (store, vault_id, id) = (server.store.clone(), vault.to_owned(), device_id.to_owned());
    let device = blocking(move || store.device(&vault_id, &id))
        .await?
        .ok_or(unauthorized("unknown_device"))?;
    let key = device.public_key().ok_or(unauthorized("unknown_device"))?;
    let path = uri.path_and_query().map_or(uri.path(), |p| p.as_str());
    let message =
        wire::request_message_for(method.as_str(), path, device_id, time, nonce, body_digest);
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
    if !close_to_now(request.time) {
        return Err(Refused(StatusCode::UNAUTHORIZED, "clock"));
    }
    if !wire::verify(&key, &wire::enroll_message(&request), &request.signature) {
        return Err(Refused(StatusCode::UNAUTHORIZED, "signature"));
    }
    let store = server.store.clone();
    let now = unix_now();
    let (vault, device) = (request.vault.clone(), request.device.clone());
    // The checks, the invite and the enrollment in one step: an invite is never used twice,
    // and an enrolled device's place can't be taken over (it joins again as a new device).
    let outcome = blocking(move || {
        store.enroll_with_invite(
            &request.vault,
            &request.invite,
            Device {
                device: request.device,
                key: request.key,
                name: request.name,
                added_at: now,
                seen_at: now,
            },
            now,
        )
    })
    .await?;
    if let Err(why) = outcome {
        return Err(match why {
            store::Refusal::Invite => Refused(StatusCode::UNAUTHORIZED, "invite"),
            store::Refusal::TooManyDevices => {
                Refused(StatusCode::INSUFFICIENT_STORAGE, "too_many_devices")
            }
            store::Refusal::AlreadyEnrolled => Refused(StatusCode::CONFLICT, "already_enrolled"),
            store::Refusal::NewVaultOnly => Refused(StatusCode::FORBIDDEN, "new_vault_only"),
        });
    }
    // The vault's live state only now that a device is in.
    server.changed(&server.live(&vault));
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

/// A slot to hold a large answer in memory while it is sent: one of `DOWNLOADS` in all and of
/// `DOWNLOADS_PER_DEVICE` for this device, so many requests at once can't fill the memory.
async fn download_slot(server: &Arc<Server>, vault: &str, device: &Device) -> Answer<Sending> {
    let mine = server
        .downloading
        .take(&format!("{vault}/{}", device.device), DOWNLOADS_PER_DEVICE)
        .ok_or(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"))?;
    let slot = server
        .downloads
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Refused(StatusCode::SERVICE_UNAVAILABLE, "busy"))?;
    Ok(Sending {
        _slot: slot,
        _mine: mine,
    })
}

async fn get_copy(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path((vault, device)): Path<(String, String)>,
    parts: Parts,
    body: Bytes,
) -> Answer<Response> {
    let signer = authorize(&server, &address, &vault, &parts, &body).await?;
    if !wire::is_id(&device) {
        return Err(Refused(StatusCode::NOT_FOUND, "not_found"));
    }
    let sending = download_slot(&server, &vault, &signer).await?;
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
        (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            sending.body(bytes),
        )
            .into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&tag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    Ok(response)
}

/// The phone app's update, for an enrolled device: its version, hash and size.
async fn app_release(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Answer<Response> {
    authorize(&server, &address, &vault, &parts, &body).await?;
    let store = server.store.clone();
    let release = blocking(move || store.app_release())
        .await?
        .ok_or(Refused(StatusCode::NOT_FOUND, "no_update"))?;
    Ok(Json(release).into_response())
}

/// The phone app's update package, for an enrolled device.
async fn app_package(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path(vault): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Answer<Response> {
    let signer = authorize(&server, &address, &vault, &parts, &body).await?;
    let sending = download_slot(&server, &vault, &signer).await?;
    let store = server.store.clone();
    let package = blocking(move || store.app_package())
        .await?
        .ok_or(Refused(StatusCode::NOT_FOUND, "no_update"))?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "application/vnd.android.package-archive",
        )],
        sending.body(package),
    )
        .into_response())
}

/// Before a copy is read from an older app that doesn't send the body's digest: the request
/// must name this copy's device, enrolled in this vault, at a time close to now. Its signature
/// can only be checked once the copy has arrived.
async fn before_upload(
    server: &Arc<Server>,
    vault: &str,
    device: &str,
    headers: &HeaderMap,
) -> Answer<()> {
    let unauthorized = |why| Refused(StatusCode::UNAUTHORIZED, why);
    if !wire::is_id(vault) || !wire::is_id(device) {
        return Err(Refused(StatusCode::NOT_FOUND, "not_found"));
    }
    let text = |name| headers.get(name).and_then(|v| v.to_str().ok());
    let signer = text(wire::header::DEVICE).ok_or(unauthorized("unsigned"))?;
    if signer != device {
        return Err(Refused(StatusCode::FORBIDDEN, "not_your_copy"));
    }
    let time: i64 = text(wire::header::TIME)
        .and_then(|t| t.parse().ok())
        .ok_or(unauthorized("unsigned"))?;
    if !close_to_now(time) {
        return Err(unauthorized("clock"));
    }
    let (store, vault, device) = (server.store.clone(), vault.to_owned(), device.to_owned());
    blocking(move || store.device(&vault, &device))
        .await?
        .ok_or(unauthorized("unknown_device"))?;
    Ok(())
}

async fn put_copy(
    State(server): State<Arc<Server>>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Path((vault, device)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Answer<Json<serde_json::Value>> {
    let (parts, body) = request.into_parts();
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|n| n.parse::<usize>().ok());
    if declared.is_some_and(|n| n > wire::MAX_COPY_BYTES) {
        return Err(Refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large"));
    }
    let digest = parts
        .headers
        .get(wire::header::BODY_SHA256)
        .and_then(|v| v.to_str().ok())
        .filter(|d| wire::is_body_digest(d))
        .map(str::to_owned);
    // With the body's digest the whole signature is checked before the copy is read. An older
    // app's copy gets the lighter check, costs its address one try until its signature is
    // checked, and waits for the one slot such copies share.
    let (checked, _mine, _reading) = match &digest {
        Some(digest) => {
            let signer = authorize_digest(&server, &address, &vault, &parts, digest).await?;
            if signer.device != device {
                return Err(Refused(StatusCode::FORBIDDEN, "not_your_copy"));
            }
            let mine = server
                .uploading
                .take(&format!("{vault}/{device}"), UPLOADS_PER_DEVICE)
                .ok_or(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"))?;
            let reading = server
                .uploads
                .acquire()
                .await
                .map_err(|_| Refused(StatusCode::SERVICE_UNAVAILABLE, "busy"))?;
            (Some(signer), Some(mine), reading)
        }
        None => {
            if let Err(refused) = before_upload(&server, &vault, &device, &parts.headers).await {
                count_against(&server, &address)?;
                return Err(refused);
            }
            count_against(&server, &address)?;
            let reading = server
                .unchecked_uploads
                .acquire()
                .await
                .map_err(|_| Refused(StatusCode::SERVICE_UNAVAILABLE, "busy"))?;
            (None, None, reading)
        }
    };
    let body = match tokio::time::timeout(
        UPLOAD_TIME,
        axum::body::to_bytes(body, wire::MAX_COPY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return Err(Refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large")),
        Err(_) => return Err(Refused(StatusCode::REQUEST_TIMEOUT, "too_slow")),
    };
    let signer = match (checked, &digest) {
        // The copy that came must be the one signed.
        (Some(signer), Some(digest)) => {
            if wire::body_digest(&body) != *digest {
                return Err(Refused(StatusCode::BAD_REQUEST, "not_what_was_signed"));
            }
            signer
        }
        _ => {
            let signer = authorize(&server, &address, &vault, &parts, &body).await?;
            give_back(&server, &address);
            signer
        }
    };
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
    let _waiting = server
        .waits
        .take(&format!("{vault}/{}", device.device), MAX_WAITS_PER_DEVICE)
        .ok_or(Refused(StatusCode::TOO_MANY_REQUESTS, "slow_down"))?;
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

/// Requests under way per key (a vault's device), each counted until its [`KeySlot`] drops.
#[derive(Debug, Default, Clone)]
struct PerKey(Arc<Mutex<HashMap<String, usize>>>);

impl PerKey {
    /// One more for `key`, or `None` when it has `max` already.
    fn take(&self, key: &str, max: usize) -> Option<KeySlot> {
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(key.to_owned()).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(KeySlot {
            counts: self.clone(),
            key: key.to_owned(),
        })
    }
}

/// Gives its slot back when the request ends, however it ends.
#[derive(Debug)]
struct KeySlot {
    counts: PerKey,
    key: String,
}

impl Drop for KeySlot {
    fn drop(&mut self) {
        let mut counts = self.counts.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// The slots a large answer holds until it has been handed over whole.
#[derive(Debug)]
struct Sending {
    _slot: OwnedSemaphorePermit,
    _mine: KeySlot,
}

impl Sending {
    /// `bytes` as an answer's body, sent in pieces; the slots go back once the last piece is
    /// handed over (or the client goes away).
    fn body(self, bytes: Vec<u8>) -> Body {
        Body::new(Pieces {
            bytes,
            at: 0,
            _sending: self,
        })
    }
}

/// A body handed to the connection a piece at a time, so the connection asks for the next
/// piece only once it has room, and what is queued never copies the whole.
#[derive(Debug)]
struct Pieces {
    bytes: Vec<u8>,
    at: usize,
    _sending: Sending,
}

impl http_body::Body for Pieces {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        const PIECE: usize = 64 * 1024;
        let this = &mut *self;
        if this.at >= this.bytes.len() {
            return Poll::Ready(None);
        }
        let end = this.bytes.len().min(this.at + PIECE);
        let piece = Bytes::copy_from_slice(&this.bytes[this.at..end]);
        this.at = end;
        Poll::Ready(Some(Ok(http_body::Frame::data(piece))))
    }

    fn is_end_stream(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact((self.bytes.len() - self.at) as u64)
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
        if self.buckets.len() > MAX_BUCKETS {
            let (burst, rate) = (self.burst, self.per_second);
            self.buckets.retain(|_, (level, at)| {
                *level + now.duration_since(*at).as_secs_f64() * rate < burst
            });
            if self.buckets.len() > 2 * MAX_BUCKETS {
                self.buckets.clear();
            }
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

    /// Puts back a token [`Buckets::take`] took.
    fn give_back(&mut self, key: &str) {
        let burst = self.burst;
        let entry = self.level(key);
        entry.0 = (entry.0 + 1.0).min(burst);
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
        slow.give_back("y");
        assert!(slow.take("y"), "given back");
        assert!(slow.take("z"));
    }

    #[test]
    fn an_ipv6_network_counts_as_one_address() {
        let one: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let other: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let elsewhere: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(neighbourhood(one), neighbourhood(other));
        assert_ne!(neighbourhood(one), neighbourhood(elsewhere));
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(neighbourhood(mapped), v4);
        assert_eq!(neighbourhood(v4), v4);
    }

    #[test]
    fn a_time_from_far_away_is_refused_without_overflow() {
        assert!(close_to_now(unix_now()));
        assert!(!close_to_now(i64::MIN));
        assert!(!close_to_now(i64::MAX));
        assert!(!close_to_now(unix_now() - wire::MAX_CLOCK_SKEW - 5));
    }

    #[test]
    fn slots_per_key_are_given_back() {
        let counts = PerKey::default();
        let first = counts.take("d", 1).unwrap();
        assert!(counts.take("d", 1).is_none());
        assert!(counts.take("e", 1).is_some());
        drop(first);
        assert!(counts.take("d", 1).is_some());
    }
}
