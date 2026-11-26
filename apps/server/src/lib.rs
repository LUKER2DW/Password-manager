//! `vault-server`: a small self-hosted store for the sealed copies devices sync through
//! (spec: docs/spec/SYNC.md §5.3, docs/SERVER.md).
//!
//! It keeps one sealed copy per device, the public keys of the devices allowed in, and
//! one-time invites (as digests). It never sees a password, a Secret Key, a vault key or a
//! KDF parameter, and it does no hashing, so a small box runs it. Every request but the
//! health check and enrollment is signed by an enrolled device's Ed25519 key.

pub mod api;
pub mod connections;
pub mod store;
pub mod tls;
pub mod updates;

use std::path::Path;

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
    connections::serve_on(listener, router(server), shutdown).await;
    Ok(())
}

/// Serves the API over the server's own HTTPS (`tls`) on `listener` until `shutdown`
/// resolves. `/v1/certificate` hands out the authority devices pin.
pub async fn serve_tls(
    data: &Path,
    listener: tokio::net::TcpListener,
    tls: std::sync::Arc<Tls>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let server = Server::new(Store::open(data)?);
    let authority = axum::body::Bytes::from(tls.authority.clone());
    let app = router(server).route(
        "/v1/certificate",
        axum::routing::get(move || {
            let authority = authority.clone();
            async move { ([("content-type", "application/pkix-cert")], authority) }
        }),
    );
    let listener = tls::TlsListener::new(listener, tls).context("listening")?;
    connections::serve_on(listener, app, shutdown).await;
    Ok(())
}

/// Makes an admin invite: good once, for any vault (or only for `vault`), until the time
/// returned.
pub fn admin_invite(data: &Path, hours: i64, vault: Option<&str>) -> Result<(String, i64)> {
    if vault.is_some_and(|v| !vault_sync_wire::is_id(v)) {
        anyhow::bail!("a vault id is 32 letters and digits (vault-server list shows them)");
    }
    let store = Store::open(data)?;
    let invite = vault_sync_wire::new_invite();
    let now = api::unix_now();
    let expires_at = now + hours.clamp(1, 24 * 7) * 3600;
    store.add_invite(vault, &invite, expires_at, now)?;
    Ok((invite.to_string(), expires_at))
}

/// The address a link from `vault-server invite` carries: `address` as given, with the pin of
/// this server's own certificate added when it has one (`serve --tls`) and `pin` is on.
pub fn link_address(data: &Path, address: &str, pin: bool) -> Result<String> {
    use sha2::Digest as _;
    let address = address.trim().trim_end_matches('/');
    if !address.starts_with("https://") && !address.starts_with("http://") {
        anyhow::bail!("the address starts with https:// (or http:// for a Tailscale address)");
    }
    if !pin || address.contains("#pin=") || !address.starts_with("https://") {
        return Ok(address.to_owned());
    }
    match std::fs::read(data.join("tls").join("authority.der")) {
        Ok(authority) => {
            let pin: String = sha2::Sha256::digest(&authority)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Ok(format!("{address}#pin={pin}"))
        }
        Err(_) => Ok(address.to_owned()),
    }
}

/// A QR code of `text` drawn with block characters, two rows of modules per line, for a
/// terminal with a dark background: the light modules are drawn, the dark ones left blank,
/// with a quiet zone around.
pub fn terminal_qr(text: &str) -> String {
    const QUIET: isize = 2;
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L)
    else {
        return String::new();
    };
    let width = code.width();
    let colors = code.to_colors();
    let size = isize::try_from(width).unwrap_or(0);
    let dark = |x: isize, y: isize| {
        (0..size).contains(&x)
            && (0..size).contains(&y)
            && colors[y.unsigned_abs() * width + x.unsigned_abs()] == qrcode::Color::Dark
    };
    let mut out = String::new();
    let mut y = -QUIET;
    while y < size + QUIET {
        for x in -QUIET..size + QUIET {
            out.push(match (!dark(x, y), !dark(x, y + 1)) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    out
}
