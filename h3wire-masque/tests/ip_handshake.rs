// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The CONNECT-IP handshake (spec §2.4): `ip::client::request`/`connect` and
//! `ip::server::accept`/`IpPending` over h3wire-quinn loopback; a hand-made peer on the
//! other side where the test needs control over the wire.

mod packets;
mod support;

use bytes::Bytes;
use h3wire_async::__testing::{CorePeer, PeerObs};
use h3wire_async::core::{AbortSource, Config, Event, H3Code, Role, StreamId};
use h3wire_async::datagram::RegisterDatagrams;
use h3wire_async::ext::Protocol;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::{Builder, ErrorKind};
use h3wire_masque::client::ConnectError;
use h3wire_masque::ip::{self, IpEvent, IpPrefix, IpTemplate, IpTunnel, Scope, ScopeTarget};
use h3wire_masque::server::{self, Reject};
use h3wire_masque::template::TemplateError;
use h3wire_quinn::QuinnConnection;
use http::{HeaderValue, Method, Request, StatusCode};
use http_body::Body;
use std::time::Duration;
use support::*;

const MSG: H3Code = H3Code::MESSAGE_ERROR;
const RC: H3Code = H3Code::REQUEST_CANCELLED;
const S0: StreamId = StreamId(0);

fn connect_ip() -> Request<BoxBody> {
    ip::client::request(&ip_template(), &Scope::ANY).unwrap()
}

fn accept(
    req: &mut Request<h3wire_async::body::RecvBody>,
) -> Result<ip::server::IpPending, Reject> {
    ip::server::accept(req, &ip_template())
}

/// `192.0.2.0/24`, UDP.
fn udp_scope() -> Scope {
    Scope {
        target: ScopeTarget::Prefix(IpPrefix::new([192, 0, 2, 0].into(), 24).unwrap()),
        ipproto: Some(17),
    }
}

/// An IPv4 UDP packet.
fn packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    packets::ipv4(src.into(), dst.into(), 17, &[0; 8])
}

/// Proxy `s` assigns `192.0.2.1` and advertises `198.51.100.0/24`; client `c` accepts
/// both. Packets then flow in both directions.
async fn exchange(c: &mut IpTunnel, s: &mut IpTunnel) {
    let addr = IpPrefix::new([192, 0, 2, 1].into(), 32).unwrap();
    let route = ip::IpRange::from_prefix(IpPrefix::new([198, 51, 100, 0].into(), 24).unwrap(), 0);
    s.assign(&[ip::AssignedAddress {
        request_id: 0,
        prefix: addr,
    }])
    .await
    .unwrap();
    s.advertise(&[route]).await.unwrap();
    assert!(matches!(
        c.recv().await.unwrap(),
        Some(IpEvent::AddressAssign(_))
    ));
    assert!(matches!(c.recv().await.unwrap(), Some(IpEvent::Routes(_))));
    c.accept_assigned(&[addr]).unwrap();
    c.accept_routes(&[route]).unwrap();
    let (up, down) = (
        packet([192, 0, 2, 1], [198, 51, 100, 1]),
        packet([198, 51, 100, 1], [192, 0, 2, 1]),
    );
    c.send(up.clone().into()).await.unwrap();
    assert_eq!(s.recv().await.unwrap(), Some(IpEvent::Packet(up.into())));
    s.send(down.clone().into()).await.unwrap();
    assert_eq!(c.recv().await.unwrap(), Some(IpEvent::Packet(down.into())));
}

#[tokio::test]
async fn ip_request_shape() {
    let r = connect_ip();
    assert_eq!(r.method(), Method::CONNECT);
    assert_eq!(
        r.extensions().get::<Protocol>(),
        Some(&Protocol::from_static("connect-ip"))
    );
    assert_eq!(r.uri(), "https://localhost/.well-known/masque/ip/*/*/");
    assert_eq!(r.headers().len(), 1);
    assert_eq!(r.headers()["capsule-protocol"], "?1");
    assert!(r.extensions().get::<RegisterDatagrams>().is_some());
    assert!(r.body().is_end_stream());
    let r = ip::client::request::<BoxBody>(&ip_template(), &udp_scope()).unwrap();
    assert_eq!(
        r.uri(),
        "https://localhost/.well-known/masque/ip/192.0.2.0%2F24/17/"
    );
    // A scope the template cannot expand.
    let bad = Scope {
        target: ScopeTarget::Host(String::new()),
        ipproto: None,
    };
    assert_eq!(
        ip::client::request::<BoxBody>(&ip_template(), &bad).unwrap_err(),
        TemplateError::BadTarget
    );
    let (mut p, _reqs) = masque().await;
    assert!(matches!(
        ip::client::connect(&mut p.send, &ip_template(), &bad).await,
        Err(ConnectError::Template(TemplateError::BadTarget))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_server_forbidden_headers_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for name in ["content-length", "content-type"] {
            let mut req = connect_ip();
            req.headers_mut()
                .insert(name, HeaderValue::from_static("0"));
            let resp = tokio::spawn(p.send.send_request(req));
            let (mut req, tx) = reqs.recv().await.unwrap();
            assert_eq!(accept(&mut req).unwrap_err(), Reject::Malformed);
            let _ = tx.send(reply(200, empty()));
            let e = resp.await.unwrap().unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{name}: {e:?}");
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_client_forbidden_header_on_2xx_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let mut resp = reply(200, empty());
        resp.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
        let r = raw_ip_server_with(&mut p, &mut reqs, resp).await;
        assert!(matches!(r.c, Err(ConnectError::Malformed)), "{:?}", r.c);
        let e = read_to_end(&mut r.st.unwrap()).await.unwrap_err();
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_client_204_205_206_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for status in [204, 205, 206] {
            let r = raw_ip_server_with(&mut p, &mut reqs, reply(status, empty())).await;
            assert!(matches!(r.c, Err(ConnectError::Malformed)), "{status}");
            let e = read_to_end(&mut r.st.unwrap()).await.unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{status}: {e:?}");
        }
    })
    .await
}

/// A non-2xx is `Rejected` with a readable body and no tunnel. Dropping it before the end
/// of its body cancels the request (RFC 9484 section 4.1: "the client MUST abort the
/// request").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_client_non2xx_rejected_with_body() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let mut resp = reply(403, full("denied"));
        resp.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
        let r = raw_ip_server_with(&mut p, &mut reqs, resp).await;
        let Err(ConnectError::Rejected(resp)) = r.c else {
            panic!("{:?}", r.c)
        };
        assert_eq!(resp.status(), 403);
        assert_eq!(resp.headers()["content-type"], "text/plain");
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "denied");
        assert!(matches!(r.st.unwrap_err().kind(), ErrorKind::NotUpgraded));

        // The server keeps the body open; the client drops the response unread.
        let conns = conns().await;
        let mut cfg = Config::default();
        cfg.enable_connect_protocol = true;
        cfg.h3_datagram = true;
        let mut peer = CorePeer::new(
            Role::Server,
            cfg,
            QuinnConnection::new(conns.server.clone()),
        );
        let (mut send, conn) = h3wire_quinn::client::<BoxBody, _>(
            conns.client.clone(),
            &Builder::new(),
            TokioExecutor,
        )
        .await
        .unwrap();
        let _client = tokio::spawn(conn);
        // `send` comes back: the connection lives while a handle does.
        let c = tokio::spawn(async move {
            let r = ip::client::connect(&mut send, &ip_template(), &Scope::ANY).await;
            (r, send)
        });
        peer.run_until(|p| !p.headers(S0).is_empty()).await;
        peer.send_headers(S0, &[(":status", "403")], false).unwrap();
        peer.send_body(S0, b"more to come", false);
        let (r, _send) = drive(&mut peer, c).await.unwrap();
        let Err(ConnectError::Rejected(resp)) = r else {
            panic!("{r:?}")
        };
        assert_eq!(resp.status(), 403);
        drop(resp);
        let cancelled = |p: &Peer| {
            p.trace().iter().any(|o| match o {
                PeerObs::Reset { stream, code } => *stream == S0 && *code == RC.0,
                PeerObs::Event(Event::SendStopped { stream, code }) => *stream == S0 && *code == RC,
                _ => false,
            })
        };
        // The peer learns of a STOP_SENDING when it writes.
        while !cancelled(&peer) {
            peer.send_body(S0, b"more", false);
            drive(&mut peer, tokio::time::sleep(Duration::from_millis(20))).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_path_mismatch_404() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let other = IpTemplate::parse("https://localhost/ip/{target}/{ipproto}").unwrap();
        let c = spawn_ip_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        let r = ip::server::accept(&mut req, &other).unwrap_err();
        assert_eq!(r, Reject::Status(StatusCode::NOT_FOUND));
        tx.send(reply(404, empty())).unwrap();
        let Err(ConnectError::Rejected(resp)) = c.await.unwrap() else {
            panic!("not rejected")
        };
        assert_eq!(resp.status(), 404);
        // The connection still serves tunnels.
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        exchange(&mut c, &mut s).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_bad_target_or_proto_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for path in ["2001:db8::1/*/", "*/256/", "/*/"] {
            let mut req = connect_ip();
            *req.uri_mut() = format!("https://localhost/.well-known/masque/ip/{path}")
                .parse()
                .unwrap();
            let resp = tokio::spawn(p.send.send_request(req));
            let (mut req, tx) = reqs.recv().await.unwrap();
            assert_eq!(accept(&mut req).unwrap_err(), Reject::Malformed, "{path}");
            // Discarded: the stream is already aborted.
            let _ = tx.send(reply(400, empty()));
            let e = resp.await.unwrap().unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{path}: {e:?}");
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_connect_ip_untouched() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // A GET: answered normally.
        let resp = tokio::spawn(p.send.send_request(get("/x")));
        let (mut req, tx) = reqs.recv().await.unwrap();
        assert_eq!(accept(&mut req).unwrap_err(), Reject::NotConnectIp);
        tx.send(reply(200, full("hello"))).unwrap();
        let resp = resp.await.unwrap().unwrap();
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "hello");
        // A CONNECT-UDP: still there for `server::accept`.
        let c = spawn_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        assert_eq!(accept(&mut req).unwrap_err(), Reject::NotConnectIp);
        let mut s = serve(req, tx).await;
        let mut c = c.await.unwrap().unwrap();
        c.send(Bytes::from_static(b"up")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "up");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_and_ip_on_one_server() {
    with_timeout(async {
        let (p, mut reqs) = masque().await;
        let uc = spawn_connect(&p);
        let ic = spawn_ip_connect(&p);
        let (mut udp, mut ip) = (None, None);
        for _ in 0..2 {
            let (mut req, tx) = reqs.recv().await.unwrap();
            match server::accept(&mut req, &template()) {
                Ok(pending) => {
                    tx.send(pending.response()).unwrap();
                    udp = Some(pending.tunnel().await.unwrap());
                }
                Err(Reject::NotConnectUdp) => {
                    let pending = ip::server::accept(&mut req, &ip_template()).unwrap();
                    tx.send(pending.response()).unwrap();
                    ip = Some(pending.tunnel().await.unwrap());
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        let (mut us, mut is) = (udp.unwrap(), ip.unwrap());
        let mut uc = uc.await.unwrap().unwrap();
        let mut ic = ic.await.unwrap().unwrap();
        uc.send(Bytes::from_static(b"udp")).await.unwrap();
        assert_eq!(us.recv().await.unwrap().unwrap(), "udp");
        exchange(&mut ic, &mut is).await;
    })
    .await
}

/// A raw client sends datagrams with its CONNECT-IP to a path the template does not
/// match, and they reach the server before it answers. With `accept` the 404 is clean;
/// without it (the control) the same datagrams abort the request with
/// `H3_DATAGRAM_ERROR`.
async fn optimistic_datagrams(with_accept: bool) {
    let conns = conns().await;
    let (svc, mut reqs) = handoff();
    let _server = spawn_server(conns.server.clone(), &server_builder(), svc);
    let mut cfg = Config::default();
    cfg.h3_datagram = true;
    let mut peer = CorePeer::new(
        Role::Client,
        cfg,
        QuinnConnection::new(conns.client.clone()),
    );
    peer.run_until(|p| p.core().peer_settings().is_some()).await;
    let s = peer.open_bidi().await.unwrap();
    let fields = [
        (":method", "CONNECT"),
        (":protocol", "connect-ip"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", "/.well-known/masque/ip/*/*/x"),
        ("capsule-protocol", "?1"),
    ];
    peer.send_headers(s, &fields, false).unwrap();
    let (mut req, tx) = drive(&mut peer, reqs.recv()).await.unwrap();
    let early = [&[0][..], &packet([192, 0, 2, 1], [198, 51, 100, 1])].concat();
    for _ in 0..3 {
        peer.send_datagram(s, &early).unwrap();
    }
    drive(&mut peer, tokio::time::sleep(Duration::from_millis(50))).await;
    if with_accept {
        let r = accept(&mut req).unwrap_err();
        assert_eq!(r, Reject::Status(StatusCode::NOT_FOUND));
    }
    tx.send(reply(404, empty())).unwrap();
    let dgram_error = move |p: &Peer| {
        p.trace().iter().any(|o| match o {
            PeerObs::Reset { stream, code } => *stream == s && *code == H3Code::DATAGRAM_ERROR.0,
            PeerObs::Event(Event::StreamAborted { stream, code, .. })
            | PeerObs::Event(Event::SendStopped { stream, code }) => {
                *stream == s && *code == H3Code::DATAGRAM_ERROR
            }
            _ => false,
        })
    };
    if !with_accept {
        peer.run_until(dgram_error).await;
        return;
    }
    peer.run_until(|p| finished(p, s) || dgram_error(p)).await;
    assert!(!dgram_error(&peer), "{:?}", peer.trace());
    assert_eq!(statuses(&peer, s), ["404"]);
    peer.send_datagram(s, &early).unwrap();
    drive(&mut peer, tokio::time::sleep(Duration::from_millis(50))).await;
    assert!(!dgram_error(&peer), "{:?}", peer.trace());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_reject_after_optimistic_datagrams_404() {
    with_timeout(async {
        optimistic_datagrams(false).await;
        optimistic_datagrams(true).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_pending_dropped_releases_claim() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // Released: a 403 is an ordinary response.
        let c = spawn_ip_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        drop(accept(&mut req).unwrap());
        tx.send(reply(403, full("no"))).unwrap();
        let Err(ConnectError::Rejected(resp)) = c.await.unwrap() else {
            panic!("not rejected")
        };
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "no");
        // Released: a 200 nobody claimed is aborted with H3_REQUEST_CANCELLED.
        let c = spawn_ip_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        drop(accept(&mut req).unwrap());
        tx.send(reply(200, empty())).unwrap();
        match c.await.unwrap() {
            Ok(mut t) => {
                let e = t.recv().await.unwrap_err();
                assert!(ip_aborted(&e, RC, AbortSource::Peer), "{e:?}");
            }
            Err(ConnectError::Http(e)) => assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}"),
            Err(e) => panic!("{e:?}"),
        }
        // The connection still serves tunnels.
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        exchange(&mut c, &mut s).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_scope_reported() {
    with_timeout(async {
        let (p, mut reqs) = masque().await;
        let c = spawn_ip_connect_to(&p, udp_scope());
        let (mut req, tx) = reqs.recv().await.unwrap();
        let pending = accept(&mut req).unwrap();
        assert_eq!(pending.scope(), &udp_scope());
        tx.send(pending.response()).unwrap();
        let s = pending.tunnel().await.unwrap();
        let c = c.await.unwrap().unwrap();
        assert_eq!(c.scope(), udp_scope());
        assert_eq!(s.scope(), udp_scope());
    })
    .await
}
