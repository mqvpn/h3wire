// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! MASQUE CONNECT-IP (RFC 9484): IP tunnelling over HTTP/3.
//!
//! The client opens a tunnel with [`client::connect`]. A server's service calls
//! [`server::accept`], returns [`IpPending::response`](server::IpPending::response), and
//! awaits [`IpPending::tunnel`](server::IpPending::tunnel) in a task it spawns: the tunnel
//! exists only once the response has been sent, so awaiting it inside the service
//! deadlocks.
//!
//! ```no_run
//! use bytes::Bytes;
//! use h3wire_async::body::RecvBody;
//! use h3wire_masque::ip::{self, AssignedAddress, IpEvent, IpPrefix, IpRange, IpTemplate};
//! use h3wire_masque::ip::ScopeTarget;
//! use h3wire_masque::server::Reject;
//! use http::{Request, Response, StatusCode};
//! use http_body_util::Empty;
//! use std::convert::Infallible;
//! use std::future::{Ready, ready};
//! use std::sync::Arc;
//! use std::task::{Context, Poll};
//! use tower_service::Service;
//!
//! #[derive(Clone)]
//! struct Proxy(Arc<IpTemplate>);
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
//!         let pending = match ip::server::accept(&mut req, &self.0) {
//!             Ok(p) => p,
//!             Err(Reject::Status(s)) => return ready(Ok(status(s))),
//!             // NotConnectIp: route it elsewhere. Malformed: already aborted, and this
//!             // response is discarded.
//!             Err(_) => return ready(Ok(status(StatusCode::NOT_FOUND))),
//!         };
//!         // A host name would have to be resolved before the response (RFC 9484
//!         // section 4.1); this proxy takes IP targets only. Dropping `pending` releases
//!         // the request for an ordinary response.
//!         if matches!(pending.scope().target, ScopeTarget::Host(_)) {
//!             return ready(Ok(status(StatusCode::BAD_REQUEST)));
//!         }
//!         // The response first; then `pending` moves into the task.
//!         let resp = pending.response();
//!         tokio::spawn(async move {
//!             let Ok(mut tunnel) = pending.tunnel().await else { return };
//!             let assigned = AssignedAddress {
//!                 request_id: 0,
//!                 prefix: IpPrefix::new([192, 0, 2, 1].into(), 32).unwrap(),
//!             };
//!             let all = IpRange::new([0; 4].into(), [255; 4].into(), 0).unwrap();
//!             if tunnel.assign(&[assigned]).await.is_err()
//!                 || tunnel.advertise(&[all]).await.is_err()
//!             {
//!                 return;
//!             }
//!             while let Ok(Some(event)) = tunnel.recv().await {
//!                 match event {
//!                     // A real proxy forwards the packet, never beyond the tunnel when it
//!                     // is link-scoped (RFC 9484 section 7.2); this one drops it.
//!                     IpEvent::Packet(_) => {}
//!                     // Every request is answered; `assign` replaces the full list.
//!                     IpEvent::AddressRequest(reqs) => {
//!                         let mut list = vec![assigned];
//!                         list.extend(reqs.iter().map(|r| {
//!                             AssignedAddress::rejection(r.request_id, r.prefix.addr().is_ipv6())
//!                         }));
//!                         if tunnel.assign(&list).await.is_err() {
//!                             break;
//!                         }
//!                     }
//!                     // A proxy accepts nothing a remote-access client offers.
//!                     _ => {}
//!                 }
//!             }
//!         });
//!         ready(Ok(resp))
//!     }
//! }
//! ```

mod capsule;
pub mod client;
mod policy;
mod prefix;
pub mod server;
mod template;
mod tunnel;

pub use capsule::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AssignedAddress, MAX_CONTROL_CAPSULE, ROUTE_ADVERTISEMENT,
    RequestedAddress, RouteError, decode_address_assign, decode_address_request, decode_routes,
    encode_address_assign, encode_address_request, encode_routes,
};
pub use policy::{DropReason, Drops, Policy, Rules};
pub use prefix::{IpPrefix, IpRange, PrefixError};
pub use template::{IpTemplate, Scope, ScopeTarget};
pub use tunnel::{IpError, IpEvent, IpReceiver, IpSender, IpTunnel, MAX_IP_PACKET};
