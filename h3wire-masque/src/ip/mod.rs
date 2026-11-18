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
//! A non-2xx response is [`ConnectError::Failed`](crate::client::ConnectError::Failed),
//! never a tunnel: the error carries the status and headers (`Proxy-Status` included), and
//! the library aborts the request, as RFC 9484 sections 4.1 and 4.5 require.
//!
//! # What the library checks
//!
//! Every received packet is judged by a [`Policy`]. With the default,
//! [`Policy::Enforce`], the IP header must parse and its lengths agree; the source must be
//! an address this end assigned to the peer or lie in a route it accepted from the peer;
//! the destination must be an address the peer assigned to this end (and this end
//! accepted) or lie in a route this end advertised that covers the packet's protocol;
//! the request's `target` and `ipproto` hold; and an ICMP error must
//! quote a packet the receiver could have sent. A refused packet is dropped and counted
//! ([`drops`](IpTunnel::drops)); it never aborts the tunnel. RFC 9484 section 7.2 leaves
//! such checks to local policy ("a forwarding error, not a protocol violation"), so this
//! is a library default, not an RFC requirement. Until the first capsule sets addresses
//! and routes, optimistic packets are dropped.
//!
//! What the peer assigns and advertises are offers: they count for the policy only after
//! [`accept_assigned`](IpTunnel::accept_assigned) and
//! [`accept_routes`](IpTunnel::accept_routes). A new offer withdraws accepted items it no
//! longer covers. Your own [`assign`](IpTunnel::assign) and
//! [`advertise`](IpTunnel::advertise) take effect once the stream took the capsule;
//! `assign` and `advertise` send the full list, and an empty list withdraws everything.
//!
//! [`Policy::Unchecked`] (through [`set_policy`](IpTunnel::set_policy)) turns off the
//! address and route checks, for addresses configured out of band. It keeps header
//! validation, the request scope and the checks on an ICMP error's quotation.
//!
//! # Shared addresses
//!
//! [`check_outgoing`](IpTunnel::check_outgoing) says whether the peer's rules admit a
//! packet from here. It is an eligibility filter, not a tunnel selector: `send` does not
//! apply it, and it cannot tell apart traffic that two tunnels' scopes both admit (an
//! ICMP echo reply to an address two clients share). An application that shares
//! addresses between tunnels MUST run it on every candidate tunnel and MUST resolve
//! several eligible tunnels itself, by giving each tunnel distinct addresses, by bounded
//! flow tracking, or by dropping the packet. It must never broadcast to them: RFC 9484
//! section 11 allows a proxy to forward ICMP on a shared address only to the client whose
//! scope matches the quoted packet.
//!
//! # Other points to know
//!
//! - Offers must be accepted before they count (above).
//! - Packets in `fe80::/10` or to `ff02::/16` pass the policy, so that link-local probes
//!   and replies work. The application must not forward them beyond the tunnel (RFC 9484
//!   section 7.2).
//! - Every [`IpEvent::AddressRequest`] is the application's to answer with
//!   [`assign`](IpTunnel::assign): one entry per request ID, either an assignment or an
//!   [`AssignedAddress::rejection`]. `assign` replaces the full list, so repeat the
//!   addresses assigned earlier, with request ID 0.
//! - IPv6 needs a tunnel MTU of at least 1,280 bytes. With the datagram carrier, set the
//!   transport's initial MTU so that such a packet fits (quinn:
//!   `TransportConfig::initial_mtu(1350)`). If an IPv6 send is refused while a 1,280-byte
//!   packet does not fit in a datagram (the transport's limit is known), the tunnel aborts
//!   the stream with `H3_DATAGRAM_ERROR` and the send returns [`IpError::MtuTooSmall`].
//! - A [`ScopeTarget::Host`] target must be resolved by the application before the
//!   response is returned; the library does not resolve names.
//! - Return [`IpPending::response`](server::IpPending::response) first, then spawn
//!   [`IpPending::tunnel`](server::IpPending::tunnel).
//!
//! # RFC 9484 duties left to the application
//!
//! - An endpoint that needs an address assigned MUST send an `ADDRESS_REQUEST`
//!   ([`request`](IpTunnel::request); section 4.7.1).
//! - The proxy MUST keep the assignments and routes for as long as the request stream is
//!   open, and MUST close the stream when it tears the tunnel down, for instance after
//!   inactivity (section 4.1).
//! - Unless both transports are configured to guarantee an IPv6 MTU of 1,280 bytes, the
//!   application MUST send an ICMPv6 echo request with 1,232 bytes of data and tear the
//!   tunnel down when no reply comes (section 7.2). The library sends no probe; its
//!   policy lets the probe and the reply through.
//! - Decrementing the hop limit on encapsulation (section 7.2) and generating ICMP
//!   errors, Packet Too Big included (sections 7.2.1 and 10.1, SHOULD), belong to the IP
//!   stack behind the tunnel.
//! - Under [`Policy::Unchecked`], source address validation is the application's
//!   (section 11 requires following BCP 38 wherever an endpoint knows the prefixes its
//!   peer may send from).
//!
//! A client opens a tunnel, asks for an address and accepts what the proxy offers:
//!
//! ```no_run
//! use bytes::Bytes;
//! use h3wire_async::SendRequest;
//! use h3wire_masque::ip::{self, IpEvent, IpPrefix, IpTemplate, Scope};
//! use http_body_util::Empty;
//!
//! async fn client(send: &mut SendRequest<Empty<Bytes>>) -> Result<(), Box<dyn std::error::Error>> {
//!     let template = IpTemplate::parse("https://proxy.example/vpn/{target}/{ipproto}/")?;
//!     let mut tunnel = ip::client::connect(send, &template, &Scope::ANY).await?;
//!     // 0.0.0.0/32: any IPv4 address.
//!     tunnel.request(&[IpPrefix::new([0; 4].into(), 32)?]).await?;
//!     while let Some(event) = tunnel.recv().await? {
//!         match event {
//!             IpEvent::AddressAssign(list) => {
//!                 let mine: Vec<_> = list.iter().filter(|a| !a.is_rejection()).map(|a| a.prefix).collect();
//!                 tunnel.accept_assigned(&mine)?;
//!             }
//!             IpEvent::Routes(routes) => tunnel.accept_routes(&routes)?,
//!             // Hand the packet to the TUN device.
//!             IpEvent::Packet(_) => {}
//!             _ => {}
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! A proxy, sketched as a service:
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
