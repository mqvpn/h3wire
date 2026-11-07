// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The h3wire-quinn loopback test support, reused, and CONNECT-UDP setup over it.
#![allow(dead_code)] // each test binary uses a subset

#[path = "../../h3wire-quinn/tests/support/mod.rs"]
mod quinn_support;
pub use quinn_support::*;

use bytes::{Bytes, BytesMut};
use h3wire_async::core::{AbortSource, H3Code};
use h3wire_async::datagram::{DatagramSlot, Datagrams};
use h3wire_async::ext::ConnInfo;
use h3wire_async::upgrade::{self, Tunnel};
use h3wire_async::{Builder, Error, ErrorKind};
use h3wire_masque::capsule::{self, DATAGRAM};
use h3wire_masque::client::{self, ConnectError};
use h3wire_masque::server;
use h3wire_masque::template::{Target, TargetHost, UriTemplate};
use h3wire_masque::{UdpError, UdpTunnel};
use http::uri::Authority;
use http::{Request, Response};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub type Reqs = mpsc::UnboundedReceiver<Handed>;

pub fn aborted(e: &Error, code: H3Code, source: AbortSource) -> bool {
    matches!(e.kind(), ErrorKind::StreamAborted { code: c, source: s, .. } if *c == code && *s == source)
}

pub fn udp_aborted(e: &UdpError, code: H3Code, source: AbortSource) -> bool {
    matches!(e, UdpError::Http(e) if aborted(e, code, source))
}

/// A DATAGRAM capsule with this raw value.
pub fn cap(value: &[u8]) -> Bytes {
    let mut out = BytesMut::new();
    capsule::encode(DATAGRAM, value, &mut out).unwrap();
    out.freeze()
}

/// A context-ID-0 UDP payload, as a datagram payload or a capsule value.
pub fn ctx0(payload: &[u8]) -> Bytes {
    [&[0][..], payload].concat().into()
}

/// The default template on `localhost`.
pub fn template() -> UriTemplate {
    UriTemplate::default_for(&Authority::from_static("localhost"))
}

/// `192.0.2.1:443`.
pub fn target() -> Target {
    Target::new(
        TargetHost::Ip([192, 0, 2, 1].into()),
        443.try_into().unwrap(),
    )
}

/// Loopback endpoints with a fixed path MTU (no PMTU discovery): a stable datagram limit.
pub async fn conns() -> Conns {
    connect_with(|t| {
        t.mtu_discovery_config(None);
    })
    .await
}

/// A transport config with or without QUIC datagrams.
pub fn transport_with(dgrams: bool) -> Arc<quinn::TransportConfig> {
    let mut t = transport();
    if !dgrams {
        t.datagram_receive_buffer_size(None);
    }
    Arc::new(t)
}

/// Loopback endpoints whose transports have no datagrams: tunnels carry capsules.
pub async fn conns_no_datagrams() -> Conns {
    connect_split(transport_with(false), transport_with(false)).await
}

/// A server accepting Extended CONNECT.
pub fn server_builder() -> Builder {
    let mut b = Builder::new();
    b.enable_connect_protocol(true);
    b
}

/// A `Handoff` server and an h3wire-async client built by `cb`.
pub async fn masque_over(conns: Conns, cb: &Builder) -> (Pair, Reqs) {
    let (svc, reqs) = handoff();
    (pair_builders(conns, &server_builder(), cb, svc).await, reqs)
}

pub async fn masque() -> (Pair, Reqs) {
    masque_over(conns().await, &Builder::new()).await
}

/// `client::connect` to [`target`], in a task.
pub fn spawn_connect(p: &Pair) -> JoinHandle<Result<UdpTunnel, ConnectError>> {
    let mut send = p.send.clone();
    tokio::spawn(async move { client::connect(&mut send, &template(), &target()).await })
}

/// The server's tunnel for `req`: accepted, answered with `Pending::response`.
pub async fn serve(mut req: Request<h3wire_async::body::RecvBody>, reply: Reply) -> UdpTunnel {
    let pending = server::accept(&mut req, &template()).unwrap();
    assert_eq!(pending.target(), &target());
    reply.send(pending.response()).unwrap();
    pending.tunnel().await.unwrap()
}

/// Client and server `UdpTunnel`s of one CONNECT-UDP.
pub async fn udp_pair(p: &mut Pair, reqs: &mut Reqs) -> (UdpTunnel, UdpTunnel) {
    let c = spawn_connect(p);
    let (req, reply) = reqs.recv().await.unwrap();
    let s = serve(req, reply).await;
    (c.await.unwrap().unwrap(), s)
}

/// A raw client (tunnel and datagrams, after the server's SETTINGS) and the server's
/// `UdpTunnel`.
pub struct RawClient {
    pub ct: Tunnel,
    pub cd: Option<Datagrams>,
    pub s: UdpTunnel,
}

pub async fn raw_client_with(p: &mut Pair, reqs: &mut Reqs, req: Request<BoxBody>) -> RawClient {
    let resp = tokio::spawn(p.send.send_request(req));
    let (req, reply) = reqs.recv().await.unwrap();
    let s = serve(req, reply).await;
    let mut resp = resp.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["capsule-protocol"], "?1");
    let cd = resp
        .extensions()
        .get::<DatagramSlot>()
        .and_then(|s| s.register());
    let ct = upgrade::on(&mut resp).await.unwrap();
    p.send.settings().await.unwrap();
    RawClient { ct, cd, s }
}

pub async fn raw_client(p: &mut Pair, reqs: &mut Reqs) -> RawClient {
    let req = client::request(&template(), &target()).unwrap();
    raw_client_with(p, reqs, req).await
}

/// The client's `connect` result for a hand-made server that registers datagrams,
/// claims the upgrade and answers with `resp`; the server's upgrade (after the client's
/// SETTINGS) and datagrams.
pub struct RawServer {
    pub c: Result<UdpTunnel, ConnectError>,
    pub st: Result<Tunnel, Error>,
    pub sd: Option<Datagrams>,
}

pub async fn raw_server_with(p: &mut Pair, reqs: &mut Reqs, resp: Response<BoxBody>) -> RawServer {
    let c = spawn_connect(p);
    let (mut req, reply) = reqs.recv().await.unwrap();
    let sd = req
        .extensions()
        .get::<DatagramSlot>()
        .and_then(|s| s.register());
    let on = upgrade::on(&mut req);
    let info = req.extensions().get::<ConnInfo>().unwrap().clone();
    reply.send(resp).unwrap();
    let st = on.await;
    info.settings().await.unwrap();
    RawServer {
        c: c.await.unwrap(),
        st,
        sd,
    }
}

/// [`raw_server_with`] a 200: the client's `UdpTunnel` and the server's raw ends.
pub async fn raw_server(p: &mut Pair, reqs: &mut Reqs) -> (UdpTunnel, Tunnel, Option<Datagrams>) {
    let r = raw_server_with(p, reqs, reply(200, empty())).await;
    (r.c.unwrap(), r.st.unwrap(), r.sd)
}
