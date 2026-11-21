//! `vault-server`: a small self-hosted store for the sealed copies devices sync through
//! (spec: docs/spec/SYNC.md §5.3, docs/SERVER.md).
//!
//! It keeps one sealed copy per device, the public keys of the devices allowed in, and
//! one-time invites (as digests). It never sees a password, a Secret Key, a vault key or a
//! KDF parameter, and it does no hashing, so a small box runs it. Every request but the
//! health check and enrollment is signed by an enrolled device's Ed25519 key.

pub mod api;
pub mod store;
pub mod tls;

use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};

pub use api::{Server, router};
pub use store::Store;
pub use tls::Tls;

/// Serves the API on `listener` until `shutdown` resolves.
pub async fn serve(
    data: &Path,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let server = Server::new(Store::open(data)?);
    axum::serve(
        listener,
        router(server).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("serving")
}

/// Serves the API over the server's own HTTPS (`tls`) on `listener` until `shutdown`
/// resolves. `/v1/certificate` hands out the authority devices pin.
pub async fn serve_tls(
    data: &Path,
    listener: tokio::net::TcpListener,
    tls: std::sync::Arc<Tls>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    use axum::serve::ListenerExt as _;
    let server = Server::new(Store::open(data)?);
    let authority = axum::body::Bytes::from(tls.authority.clone());
    let app = router(server).route(
        "/v1/certificate",
        axum::routing::get(move || {
            let authority = authority.clone();
            async move { ([("content-type", "application/pkix-cert")], authority) }
        }),
    );
    let listener = tls::TlsListener::new(listener, tls)
        .context("listening")?
        // `tap_io` gives axum the client's address for the rate limits.
        .tap_io(|_| {});
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("serving")
}

/// Makes an admin invite: good once, for any vault, until the time returned.
pub fn admin_invite(data: &Path, hours: i64) -> Result<(String, i64)> {
    let store = Store::open(data)?;
    let invite = vault_sync_wire::new_invite();
    let now = api::unix_now();
    let expires_at = now + hours.clamp(1, 24 * 7) * 3600;
    store.add_invite(None, &invite, expires_at, now)?;
    Ok((invite.to_string(), expires_at))
}
