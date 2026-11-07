// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The CONNECT-UDP handshake (spec §2.3): `client::request`/`connect` and
//! `server::accept`/`Pending` over h3wire-quinn loopback; a hand-made peer on the other
//! side where the test needs control over the wire.

mod support;

use bytes::Bytes;
use h3wire_async::__testing::{CorePeer, PeerObs};
use h3wire_async::core::{AbortSource, Config, Event, H3Code, Role, StreamId};
use h3wire_async::datagram::{DatagramSlot, RegisterDatagrams};
use h3wire_async::ext::Protocol;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::upgrade;
use h3wire_async::{Builder, ErrorKind};
use h3wire_masque::Carrier;
use h3wire_masque::client::{self, ConnectError};
use h3wire_masque::server::{Reject, accept};
use h3wire_masque::template::{Target, TargetHost, TemplateError, UriTemplate};
use h3wire_quinn::QuinnConnection;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body::Body;
use std::time::Duration;
use support::*;

const MSG: H3Code = H3Code::MESSAGE_ERROR;
const RC: H3Code = H3Code::REQUEST_CANCELLED;
const S0: StreamId = StreamId(0);

fn connect_udp() -> Request<BoxBody> {
    client::request(&template(), &target()).unwrap()
}

/// `client::connect` failed with this stream abort.
fn connect_aborted(r: Result<h3wire_masque::UdpTunnel, ConnectError>, code: H3Code) -> bool {
    matches!(r, Err(ConnectError::Http(e)) if aborted(&e, code, AbortSource::Local))
}

#[tokio::test]
async fn request_shape() {
    let r = connect_udp();
    assert_eq!(r.method(), Method::CONNECT);
    assert_eq!(
        r.extensions().get::<Protocol>(),
        Some(&Protocol::from_static("connect-udp"))
    );
    assert_eq!(
        r.uri(),
        "https://localhost/.well-known/masque/udp/192.0.2.1/443/"
    );
    assert_eq!(r.headers().len(), 1);
    assert_eq!(r.headers()["capsule-protocol"], "?1");
    assert!(r.extensions().get::<RegisterDatagrams>().is_some());
    assert!(r.body().is_end_stream());
    // A target the template cannot expand.
    let bad = Target::new(TargetHost::Name(String::new()), 443.try_into().unwrap());
    assert_eq!(
        client::request::<BoxBody>(&template(), &bad).unwrap_err(),
        TemplateError::BadHost
    );
    let (mut p, _reqs) = masque().await;
    assert!(matches!(
        client::connect(&mut p.send, &template(), &bad).await,
        Err(ConnectError::Template(TemplateError::BadHost))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_forbidden_headers_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for name in ["content-length", "content-type"] {
            let mut req = connect_udp();
            req.headers_mut()
                .insert(name, HeaderValue::from_static("0"));
            let resp = tokio::spawn(p.send.send_request(req));
            let (mut req, tx) = reqs.recv().await.unwrap();
            assert_eq!(
                accept(&mut req, &template()).unwrap_err(),
                Reject::Malformed
            );
            // Discarded: the stream is already aborted (the service may be gone too).
            let _ = tx.send(reply(200, empty()));
            let e = resp.await.unwrap().unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{name}: {e:?}");
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_forbidden_header_on_2xx_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let mut resp = reply(200, empty());
        resp.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
        let r = raw_server_with(&mut p, &mut reqs, resp).await;
        assert!(matches!(r.c, Err(ConnectError::Malformed)), "{:?}", r.c);
        let e = read_to_end(&mut r.st.unwrap()).await.unwrap_err();
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_204_205_206_malformed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for status in [204, 205, 206] {
            let r = raw_server_with(&mut p, &mut reqs, reply(status, empty())).await;
            assert!(matches!(r.c, Err(ConnectError::Malformed)), "{status}");
            let e = read_to_end(&mut r.st.unwrap()).await.unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{status}: {e:?}");
        }
    })
    .await
}

/// `Transfer-Encoding` never reaches `connect`: the core rejects the response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_transfer_encoding_message_error() {
    with_timeout(async {
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
        let c =
            tokio::spawn(async move { client::connect(&mut send, &template(), &target()).await });
        peer.run_until(|p| !p.headers(S0).is_empty()).await;
        let head = headers_frame(&[(":status", "200"), ("transfer-encoding", "chunked")]);
        peer.send_raw(S0, &head);
        let r = drive(&mut peer, c).await.unwrap();
        assert!(connect_aborted(r, MSG));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_non2xx_rejected_with_body() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let mut resp = reply(403, full("denied"));
        resp.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
        let r = raw_server_with(&mut p, &mut reqs, resp).await;
        let Err(ConnectError::Rejected(resp)) = r.c else {
            panic!("{:?}", r.c)
        };
        assert_eq!(resp.status(), 403);
        assert_eq!(resp.headers()["content-type"], "text/plain");
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "denied");
        assert!(matches!(r.st.unwrap_err().kind(), ErrorKind::NotUpgraded));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_protocol_variants() {
    with_timeout(async {
        const CP: &str = "capsule-protocol";
        let variants: [fn(&mut HeaderMap); 5] = [
            |h| {
                h.remove(CP);
            },
            |h| {
                h.insert(CP, HeaderValue::from_static("?0"));
            },
            |h| {
                h.insert(CP, HeaderValue::from_static("1"));
            },
            |h| {
                h.append(CP, HeaderValue::from_static("?1"));
            },
            |h| {
                h.insert(CP, HeaderValue::from_static("?1;a=b"));
            },
        ];
        let (mut p, mut reqs) = masque().await;
        for (i, v) in variants.iter().enumerate() {
            // On the request: accepted, and the tunnel works.
            let mut req = connect_udp();
            v(req.headers_mut());
            let RawClient { mut ct, mut s, .. } = raw_client_with(&mut p, &mut reqs, req).await;
            ct.send(cap(&ctx0(b"up"))).await.unwrap();
            assert_eq!(s.recv().await.unwrap().unwrap(), "up", "request {i}");
            // On the response.
            let mut resp = reply(200, empty());
            resp.headers_mut()
                .insert(CP, HeaderValue::from_static("?1"));
            v(resp.headers_mut());
            let r = raw_server_with(&mut p, &mut reqs, resp).await;
            let (mut c, mut st) = (r.c.unwrap(), r.st.unwrap());
            st.send(cap(&ctx0(b"down"))).await.unwrap();
            assert_eq!(c.recv().await.unwrap().unwrap(), "down", "response {i}");
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_mismatch_404() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let other =
            UriTemplate::parse("https://localhost/udp/{target_host}/{target_port}").unwrap();
        let c = spawn_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        let r = accept(&mut req, &other).unwrap_err();
        assert_eq!(r, Reject::Status(StatusCode::NOT_FOUND));
        tx.send(reply(404, empty())).unwrap();
        let Err(ConnectError::Rejected(resp)) = c.await.unwrap() else {
            panic!("not rejected")
        };
        assert_eq!(resp.status(), 404);
        // The connection still serves tunnels.
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        c.send(Bytes::from_static(b"ok")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "ok");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_target_400() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        for path in [
            "192.0.2.1/0/",
            "192.0.2.1/x/",
            "%zz/443/",
            "[fe80::1%25eth0]/443/",
        ] {
            let mut req = connect_udp();
            *req.uri_mut() = format!("https://localhost/.well-known/masque/udp/{path}")
                .parse()
                .unwrap();
            let resp = tokio::spawn(p.send.send_request(req));
            let (mut req, tx) = reqs.recv().await.unwrap();
            let r = accept(&mut req, &template()).unwrap_err();
            assert_eq!(r, Reject::Status(StatusCode::BAD_REQUEST), "{path}");
            tx.send(reply(400, empty())).unwrap();
            assert_eq!(resp.await.unwrap().unwrap().status(), 400);
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_connect_udp_untouched() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // A POST: answered normally, its body still readable.
        let resp = tokio::spawn(p.send.send_request(request(Method::POST, "/x", full("hi"))));
        let (mut req, tx) = reqs.recv().await.unwrap();
        assert_eq!(
            accept(&mut req, &template()).unwrap_err(),
            Reject::NotConnectUdp
        );
        assert_eq!(collect(req.into_body()).await.unwrap().0, "hi");
        tx.send(reply(200, full("hello"))).unwrap();
        let resp = resp.await.unwrap().unwrap();
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "hello");
        // A plain CONNECT and another protocol: the upgrade is still there to claim.
        let mut ws = connect_req("example");
        ws.extensions_mut()
            .insert(Protocol::from_static("websocket"));
        for req in [connect_req("example"), ws] {
            let resp = tokio::spawn(p.send.send_request(req));
            let (mut req, tx) = reqs.recv().await.unwrap();
            assert_eq!(
                accept(&mut req, &template()).unwrap_err(),
                Reject::NotConnectUdp
            );
            let on = upgrade::on(&mut req);
            tx.send(reply(200, empty())).unwrap();
            let mut st = on.await.unwrap();
            let mut resp = resp.await.unwrap().unwrap();
            let mut ct = upgrade::on(&mut resp).await.unwrap();
            ct.send(Bytes::from_static(b"raw")).await.unwrap();
            ct.finish().unwrap();
            assert_eq!(read_to_end(&mut st).await.unwrap(), b"raw");
        }
    })
    .await
}

/// A raw client sends datagrams with its CONNECT-UDP to `path`, and they reach the server
/// before it answers. With `accept` the rejection is clean; without it (`accept: false`,
/// the control) the same datagrams abort the request with `H3_DATAGRAM_ERROR`.
async fn optimistic_datagrams(path: &str, want: StatusCode, with_accept: bool) {
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
    let path = format!("/.well-known/masque/udp/{path}");
    let fields = [
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path.as_str()),
        ("capsule-protocol", "?1"),
    ];
    peer.send_headers(s, &fields, false).unwrap();
    // Datagrams before the stream is open at the server are dropped: send them once the
    // request is there, still before the response.
    let (mut req, tx) = drive(&mut peer, reqs.recv()).await.unwrap();
    for _ in 0..3 {
        peer.send_datagram(s, &ctx0(b"early")).unwrap();
    }
    drive(&mut peer, tokio::time::sleep(Duration::from_millis(50))).await;
    if with_accept {
        let r = accept(&mut req, &template()).unwrap_err();
        assert_eq!(r, Reject::Status(want));
    }
    tx.send(reply(want.as_u16(), empty())).unwrap();
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
    assert_eq!(statuses(&peer, s), [want.as_str()]);
    peer.send_datagram(s, &ctx0(b"late")).unwrap();
    drive(&mut peer, tokio::time::sleep(Duration::from_millis(50))).await;
    assert!(!dgram_error(&peer), "{:?}", peer.trace());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_after_optimistic_datagrams_400() {
    with_timeout(async {
        optimistic_datagrams("192.0.2.1/0/", StatusCode::BAD_REQUEST, false).await;
        optimistic_datagrams("192.0.2.1/0/", StatusCode::BAD_REQUEST, true).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_after_optimistic_datagrams_404() {
    with_timeout(async {
        optimistic_datagrams("192.0.2.1/443/x", StatusCode::NOT_FOUND, false).await;
        optimistic_datagrams("192.0.2.1/443/x", StatusCode::NOT_FOUND, true).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_dropped_releases_claim() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // Released: a 403 is an ordinary response.
        let c = spawn_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        drop(accept(&mut req, &template()).unwrap());
        tx.send(reply(403, full("no"))).unwrap();
        let Err(ConnectError::Rejected(resp)) = c.await.unwrap() else {
            panic!("not rejected")
        };
        assert_eq!(collect(resp.into_body()).await.unwrap().0, "no");
        // Released: a 200 nobody claimed is aborted with H3_REQUEST_CANCELLED.
        let c = spawn_connect(&p);
        let (mut req, tx) = reqs.recv().await.unwrap();
        drop(accept(&mut req, &template()).unwrap());
        tx.send(reply(200, empty())).unwrap();
        match c.await.unwrap() {
            Ok(mut t) => {
                let e = t.recv().await.unwrap_err();
                assert!(udp_aborted(&e, RC, AbortSource::Peer), "{e:?}");
            }
            Err(ConnectError::Http(e)) => assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}"),
            Err(e) => panic!("{e:?}"),
        }
        // The connection still serves tunnels.
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        s.send(Bytes::from_static(b"ok")).await.unwrap();
        assert_eq!(c.recv().await.unwrap().unwrap(), "ok");
    })
    .await
}

/// The client's transport takes no datagrams, so the server cannot send any: it
/// advertised no `H3_DATAGRAM` and its requests carry no slot. Not a rejection: the
/// tunnel carries capsules.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_without_slot_capsule_only() {
    with_timeout(async {
        let conns = connect_split(transport_with(true), transport_with(false)).await;
        let (p, mut reqs) = masque_over(conns, &Builder::new()).await;
        let c = spawn_connect(&p);
        let (req, tx) = reqs.recv().await.unwrap();
        assert!(req.extensions().get::<DatagramSlot>().is_none());
        let mut s = serve(req, tx).await;
        let mut c = c.await.unwrap().unwrap();
        assert_eq!(
            (c.carrier(), s.carrier()),
            (Carrier::Capsule, Carrier::Capsule)
        );
        c.send(Bytes::from_static(b"up")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "up");
        s.send(Bytes::from_static(b"down")).await.unwrap();
        assert_eq!(c.recv().await.unwrap().unwrap(), "down");
    })
    .await
}
