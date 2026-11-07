// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! MASQUE CONNECT-UDP (RFC 9298) over [`h3wire_async`].
//!
//! The client opens a tunnel with [`client::connect`]. A server's service calls
//! [`server::accept`], returns [`Pending::response`](server::Pending::response), and
//! awaits [`Pending::tunnel`](server::Pending::tunnel) in a task it spawns: the tunnel
//! exists only once the response has been sent, so awaiting it inside the service
//! deadlocks.
//!
//! h3wire-async is a stable candidate; 1.0 waits for a downstream user outside this
//! workspace.
//!
//! ```no_run
//! use bytes::Bytes;
//! use h3wire_async::body::RecvBody;
//! use h3wire_masque::server::{self, Reject};
//! use h3wire_masque::template::UriTemplate;
//! use http::{Request, Response, StatusCode};
//! use http_body_util::Empty;
//! use std::convert::Infallible;
//! use std::future::{Ready, ready};
//! use std::sync::Arc;
//! use std::task::{Context, Poll};
//! use tower_service::Service;
//!
//! #[derive(Clone)]
//! struct Proxy(Arc<UriTemplate>);
//!
//! impl Service<Request<RecvBody>> for Proxy {
//!     type Response = Response<Empty<Bytes>>;
//!     type Error = Infallible;
//!     type Future = Ready<Result<Self::Response, Infallible>>;
//!
//!     fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
//!         Poll::Ready(Ok(()))
//!     }
//!
//!     fn call(&mut self, mut req: Request<RecvBody>) -> Self::Future {
//!         let status = |s: StatusCode| {
//!             let mut r = Response::new(Empty::new());
//!             *r.status_mut() = s;
//!             r
//!         };
//!         let pending = match server::accept(&mut req, &self.0) {
//!             Ok(p) => p,
//!             Err(Reject::Status(s)) => return ready(Ok(status(s))),
//!             // NotConnectUdp: route it elsewhere. Malformed: already aborted, and this
//!             // response is discarded.
//!             Err(_) => return ready(Ok(status(StatusCode::NOT_FOUND))),
//!         };
//!         // The response first; then `pending` moves into the task.
//!         let resp = pending.response();
//!         tokio::spawn(async move {
//!             let Ok(mut tunnel) = pending.tunnel().await else { return };
//!             // A real proxy resolves `pending.target()`, opens a UDP socket and relays
//!             // (RFC 9298 section 3.1); this one echoes.
//!             while let Ok(Some(p)) = tunnel.recv().await {
//!                 if tunnel.send(p).await.is_err() {
//!                     break;
//!                 }
//!             }
//!         });
//!         ready(Ok(resp))
//!     }
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capsule;
pub mod client;
pub mod server;
pub mod template;
pub mod tunnel;

pub use tunnel::{Carrier, MAX_UDP_PAYLOAD, UdpError, UdpReceiver, UdpSender, UdpTunnel};

use http::HeaderMap;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};

/// A capsule-protocol message carries none of these (RFC 9297 section 3.2).
fn forbidden(h: &HeaderMap) -> bool {
    [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
        .iter()
        .any(|n| h.contains_key(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn forbidden_headers() {
        for name in ["content-length", "content-type", "transfer-encoding"] {
            let mut h = HeaderMap::new();
            h.insert("capsule-protocol", HeaderValue::from_static("?1"));
            h.insert(name, HeaderValue::from_static("0"));
            assert!(forbidden(&h), "{name}");
        }
        let mut h = HeaderMap::new();
        h.insert("capsule-protocol", HeaderValue::from_static("?1"));
        assert!(!forbidden(&h));
    }
}
