//! The connections: how many may be open, how long a client may take to send a request's
//! headers or to read an answer, and the loop that hands each one to the API.
//!
//! Without these a client could open connections and never finish a request (or never read
//! the answer) until the server runs out of them; every limit in `api.rs` applies only once a
//! request has arrived.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use axum::{Router, extract::ConnectInfo};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::api::neighbourhood;

/// Connections open at once, and from one address (an IPv6 /64 counts as one). A proxy in
/// front (`tailscale serve`, Caddy, Docker's published port) is one address for all the
/// devices behind it, hence the generous share.
pub const MAX_CONNECTIONS: usize = 512;
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 128;
/// A request's headers must have arrived within this, and a connection left with no request
/// is closed after it.
const HEADER_TIME: Duration = Duration::from_secs(30);
/// An answer the client stops reading for this long ends the connection.
const WRITE_STALL: Duration = Duration::from_secs(60);
/// How long a stop waits for the requests under way (a long-poll answers within a minute).
const STOP_TIME: Duration = Duration::from_secs(70);
/// Headers one request may have.
const MAX_HEADERS: usize = 64;

/// How many things are open, in all and per address.
#[derive(Debug)]
pub struct Counts {
    total: usize,
    per_address: usize,
    open: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

impl Counts {
    pub fn new(total: usize, per_address: usize) -> Arc<Self> {
        Arc::new(Self {
            total,
            per_address,
            open: Mutex::default(),
        })
    }

    /// One more from `ip`, or `None` when there are too many in all or from there.
    pub fn take(self: &Arc<Self>, ip: IpAddr) -> Option<Counted> {
        let near = neighbourhood(ip);
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let (all, by_address) = &mut *open;
        let here = by_address.get(&near).copied().unwrap_or(0);
        if *all >= self.total || here >= self.per_address {
            return None;
        }
        *all += 1;
        by_address.insert(near, here + 1);
        Some(Counted {
            counts: self.clone(),
            near,
        })
    }
}

/// One open thing, counted until it is dropped.
#[derive(Debug)]
pub struct Counted {
    counts: Arc<Counts>,
    near: IpAddr,
}

impl Drop for Counted {
    fn drop(&mut self) {
        let mut open = self
            .counts
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (all, by_address) = &mut *open;
        *all = all.saturating_sub(1);
        if let Some(here) = by_address.get_mut(&self.near) {
            *here = here.saturating_sub(1);
            if *here == 0 {
                by_address.remove(&self.near);
            }
        }
    }
}

/// Serves `app` on `listener` until `shutdown` resolves, then lets the requests under way
/// finish (for up to [`STOP_TIME`]).
pub async fn serve_on<L>(
    mut listener: L,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) where
    L: axum::serve::Listener<Addr = SocketAddr>,
{
    let counts = Counts::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_ADDRESS);
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (io, address) = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut shutdown => break,
        };
        // Too many open already: this one is closed at once.
        let Some(counted) = counts.take(address.ip()) else {
            continue;
        };
        let app = app.clone();
        let mut stopping = stopping.clone();
        tokio::spawn(async move {
            let _counted = counted;
            // The client's address, for the rate limits (`ConnectInfo` in the handlers).
            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(ConnectInfo(address));
                    tower::ServiceExt::oneshot(app.clone(), request)
                },
            );
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIME)
                .max_headers(MAX_HEADERS);
            let connection = builder.serve_connection(TokioIo::new(Stall::new(io)), service);
            let mut connection = std::pin::pin!(connection);
            let mut stopped = false;
            loop {
                tokio::select! {
                    _ = connection.as_mut() => break,
                    _ = stopping.changed(), if !stopped => {
                        stopped = true;
                        connection.as_mut().graceful_shutdown();
                    }
                }
            }
        });
    }
    drop(listener);
    drop(stopping);
    let _ = stop.send(true);
    let _ = tokio::time::timeout(STOP_TIME, stop.closed()).await;
}

/// A connection whose writes make no progress for [`WRITE_STALL`] (a client that stopped
/// reading its answer) ends with an error instead of holding its slots forever.
struct Stall<Io> {
    io: Io,
    since: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<Io> Stall<Io> {
    fn new(io: Io) -> Self {
        Self { io, since: None }
    }

    /// What a write or flush gave: progress starts the count again; waiting is fine until it
    /// has lasted [`WRITE_STALL`].
    fn progress<T>(
        &mut self,
        done: Poll<io::Result<T>>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<T>> {
        if done.is_ready() {
            self.since = None;
            return done;
        }
        let since = self
            .since
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(WRITE_STALL)));
        match since.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for Stall<Io> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for Stall<Io> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let done = Pin::new(&mut this.io).poll_write(cx, buf);
        this.progress(done, cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let done = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        this.progress(done, cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let done = Pin::new(&mut this.io).poll_flush(cx);
        this.progress(done, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_are_counted_in_all_and_per_address() {
        let counts = Counts::new(3, 2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let first = counts.take(a).unwrap();
        let _second = counts.take(a).unwrap();
        assert!(counts.take(a).is_none(), "two from one address");
        let _third = counts.take(b).unwrap();
        assert!(counts.take(b).is_none(), "three in all");
        drop(first);
        assert!(counts.take(a).is_some(), "one closed, one more");
        // Addresses of one IPv6 network count together.
        let counts = Counts::new(10, 1);
        let _one = counts.take("2001:db8::1".parse().unwrap()).unwrap();
        assert!(counts.take("2001:db8::2".parse().unwrap()).is_none());
    }
}
