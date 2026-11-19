// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The IPv6 minimum-MTU rule of `IpSender::send` (spec §2.5): a refused IPv6 datagram
//! send aborts the tunnel only when the transport limit is below 1280; the path shrinking
//! is noticed by the next refusal.

mod packets;
mod support;

use bytes::Bytes;
use h3wire_async::__testing::{CorePeer, MockConn, MockNet, PeerObs, Side};
use h3wire_async::Builder;
use h3wire_async::core::{AbortSource, Config, Event, H3Code, Role, StreamId};
use h3wire_async::rt::TokioExecutor;
use h3wire_masque::Carrier;
use h3wire_masque::ip::{
    self, AssignedAddress, IpError, IpEvent, IpPrefix, IpRange, IpTunnel, MAX_IP_PACKET, Scope,
};
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv6Addr};
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;
use support::*;

const DG: H3Code = H3Code::DATAGRAM_ERROR;

fn v6(n: usize) -> Bytes {
    // The client's address to a host in the proxy's route; `n` is the whole packet.
    let (a, b): (Ipv6Addr, Ipv6Addr) = (
        "2001:db8::1".parse().unwrap(),
        "2001:db8:1::1".parse().unwrap(),
    );
    packets::ipv6(a, b, 17, &vec![0; n - 40]).into()
}

fn v4(n: usize) -> Bytes {
    let (a, b) = (
        "192.0.2.1".parse().unwrap(),
        "198.51.100.1".parse().unwrap(),
    );
    packets::ipv4(a, b, 17, &vec![0; n - 20]).into()
}

fn pfx(a: &str, len: u8) -> IpPrefix {
    IpPrefix::new(a.parse::<IpAddr>().unwrap(), len).unwrap()
}

/// The proxy assigns the client `from` and advertises `to`; the client accepts both.
async fn setup(c: &mut IpTunnel, s: &mut IpTunnel, from: IpPrefix, to: IpPrefix) {
    let a = [AssignedAddress {
        request_id: 0,
        prefix: from,
    }];
    let r = [IpRange::from_prefix(to, 0)];
    s.assign(&a).await.unwrap();
    s.advertise(&r).await.unwrap();
    assert!(matches!(
        c.recv().await.unwrap(),
        Some(IpEvent::AddressAssign(_))
    ));
    assert!(matches!(c.recv().await.unwrap(), Some(IpEvent::Routes(_))));
    c.accept_assigned(&[from]).unwrap();
    c.accept_routes(&r).unwrap();
}

async fn setup6(c: &mut IpTunnel, s: &mut IpTunnel) {
    setup(c, s, pfx("2001:db8::1", 128), pfx("2001:db8:1::", 48)).await
}

async fn setup4(c: &mut IpTunnel, s: &mut IpTunnel) {
    setup(c, s, pfx("192.0.2.1", 32), pfx("198.51.100.0", 24)).await
}

/// Loopback with a fixed path MTU of `mtu` bytes (no discovery).
async fn conns_mtu(mtu: u16) -> Conns {
    connect_with(|t| {
        t.initial_mtu(mtu).mtu_discovery_config(None);
    })
    .await
}

async fn next_packet(t: &mut IpTunnel) -> Bytes {
    match t.recv().await.unwrap() {
        Some(IpEvent::Packet(b)) => b,
        e => panic!("not a packet: {e:?}"),
    }
}

/// Poll `f` and step `peer` until `f` is ready.
async fn drive_mock<F: Future>(peer: &mut CorePeer<MockConn>, f: F) -> F::Output {
    let mut f = pin!(f);
    poll_fn(|cx| {
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(cx) {
                return Poll::Ready(v);
            }
            if peer.poll_step(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await
}

/// Step `peer` until `pred` holds; the mock transport does not wake it for the
/// client's sends, so poll on a short timer.
async fn until(peer: &mut CorePeer<MockConn>, mut pred: impl FnMut(&CorePeer<MockConn>) -> bool) {
    while !pred(peer) {
        drive_mock(peer, tokio::time::sleep(Duration::from_millis(2))).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_refusal_below_1280_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque_over(conns_mtu(1200).await, &Builder::new()).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        setup6(&mut c, &mut s).await;
        assert!(c.max_payload() < Some(1280), "{:?}", c.max_payload());
        c.send(v6(1000)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v6(1000));
        assert!(matches!(c.send(v6(1300)).await, Err(IpError::MtuTooSmall)));
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, DG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_refusal_through_packet_sender_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque_over(conns_mtu(1200).await, &Builder::new()).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        setup6(&mut c, &mut s).await;
        let h = c.packet_sender();
        assert_eq!(h.max_payload(), c.max_payload());
        h.send(v6(1000)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v6(1000));
        assert!(matches!(h.send(v6(1300)).await, Err(IpError::MtuTooSmall)));
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, DG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_refusal_at_or_above_1280_is_too_large() {
    with_timeout(async {
        let (mut p, mut reqs) = masque_over(conns_mtu(1400).await, &Builder::new()).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        setup6(&mut c, &mut s).await;
        let m = c.max_payload();
        assert!(m >= Some(1280), "{m:?}");
        assert!(matches!(
            c.send(v6(m.unwrap() + 1)).await,
            Err(IpError::TooLarge)
        ));
        c.send(v6(1280)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v6(1280));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv4_refusal_never_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque_over(conns_mtu(1200).await, &Builder::new()).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        setup4(&mut c, &mut s).await;
        assert!(matches!(c.send(v4(1300)).await, Err(IpError::TooLarge)));
        c.send(v4(1000)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v4(1000));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_carrier_has_no_mtu_rule() {
    with_timeout(async {
        let conns = conns_no_datagrams().await;
        let (mut p, mut reqs) = masque_over(conns, &Builder::new()).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Capsule);
        setup6(&mut c, &mut s).await;
        c.send(v6(1300)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v6(1300));
        // Over the packet limit is the only refusal, and it is not an abort.
        assert!(matches!(
            c.send(Bytes::from(vec![0x60; MAX_IP_PACKET + 1])).await,
            Err(IpError::TooLarge)
        ));
        c.send(v6(1000)).await.unwrap();
        assert_eq!(next_packet(&mut s).await, v6(1000));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_payload_values() {
    with_timeout(async {
        let conns = conns_mtu(1400).await;
        let limit = conns.client.max_datagram_size().unwrap();
        let (mut p, mut reqs) = masque_over(conns, &Builder::new()).await;
        let (c, s) = ip_pair(&mut p, &mut reqs).await;
        // The request is stream 0: a one-byte quarter stream ID, then the context ID.
        assert_eq!(c.max_payload(), Some(limit - 1 - 1));
        assert_eq!(s.max_payload(), Some(limit - 1 - 1));

        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &Builder::new()).await;
        let (c, s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(c.max_payload(), Some(MAX_IP_PACKET));
        assert_eq!(s.max_payload(), Some(MAX_IP_PACKET));
    })
    .await
}

/// A client over the mock transport against a hand-made server `CorePeer`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_shrink_detected_by_next_refusal() {
    with_timeout(async {
        const S0: StreamId = StreamId(0);
        let (net, cc, sc) = MockNet::pair();
        net.set_max_datagram_size(Side::Client, Some(1500));
        let (mut send, conn) = Builder::new()
            .handshake::<_, BoxBody, _>(cc, TokioExecutor)
            .await
            .unwrap();
        let _client = tokio::spawn(conn);
        let mut cfg = Config::default();
        cfg.enable_connect_protocol = true;
        cfg.h3_datagram = true;
        let mut peer = CorePeer::new(Role::Server, cfg, sc);
        // Dropping the last `SendRequest` would close the connection and race the reset.
        let _keep = send.clone();
        let connect = tokio::spawn(async move {
            ip::client::connect(&mut send, &ip_template(), &Scope::ANY).await
        });
        peer.run_until(|p| !p.headers(S0).is_empty()).await;
        peer.send_headers(S0, &[(":status", "200"), ("capsule-protocol", "?1")], false)
            .unwrap();
        let mut c = drive_mock(&mut peer, connect).await.unwrap().unwrap();
        assert_eq!(c.carrier(), Carrier::Datagram);
        until(&mut peer, |_| c.max_payload().is_some()).await;
        assert!(c.max_payload() >= Some(1280));

        // The wire datagram is the packet plus the context ID.
        let got = |p: &CorePeer<MockConn>| {
            p.trace()
                .iter()
                .filter(|o| matches!(o, PeerObs::Datagram { stream, len } if *stream == S0 && *len == 1301))
                .count()
        };
        c.send(v6(1300)).await.unwrap();
        until(&mut peer, |p| got(p) == 1).await;

        net.set_max_datagram_size(Side::Client, Some(1200));
        // The driver learns the new limit on its next pass: sends before that are accepted
        // and lost, a later one is refused.
        let mut refused = false;
        for _ in 0..50 {
            match c.send(v6(1300)).await {
                Ok(()) => drive_mock(&mut peer, tokio::time::sleep(Duration::from_millis(5))).await,
                Err(IpError::MtuTooSmall) => {
                    refused = true;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(refused, "no send was refused with MtuTooSmall");
        until(&mut peer, |p| {
            p.trace().iter().any(|o| match o {
                PeerObs::Reset { stream, code } => *stream == S0 && *code == DG.0,
                PeerObs::Event(Event::StreamAborted { stream, code, .. })
                | PeerObs::Event(Event::SendStopped { stream, code }) => {
                    *stream == S0 && *code == DG
                }
                _ => false,
            })
        })
        .await;
        assert_eq!(got(&peer), 1, "a post-shrink packet arrived");
    })
    .await
}

/// A datagram limit that is known but leaves no room after the context ID: `max_payload`
/// is `None`, yet the endpoint knows 1280 bytes cannot fit (RFC 9484 section 7.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_refusal_with_no_room_aborts() {
    with_timeout(async {
        const S0: StreamId = StreamId(0);
        let (net, cc, sc) = MockNet::pair();
        net.set_max_datagram_size(Side::Client, Some(1500));
        let (mut send, conn) = Builder::new()
            .handshake::<_, BoxBody, _>(cc, TokioExecutor)
            .await
            .unwrap();
        let _client = tokio::spawn(conn);
        let mut cfg = Config::default();
        cfg.enable_connect_protocol = true;
        cfg.h3_datagram = true;
        let mut peer = CorePeer::new(Role::Server, cfg, sc);
        // Dropping the last `SendRequest` would close the connection and race the reset.
        let _keep = send.clone();
        let connect = tokio::spawn(async move {
            ip::client::connect(&mut send, &ip_template(), &Scope::ANY).await
        });
        peer.run_until(|p| !p.headers(S0).is_empty()).await;
        peer.send_headers(S0, &[(":status", "200"), ("capsule-protocol", "?1")], false)
            .unwrap();
        let mut c = drive_mock(&mut peer, connect).await.unwrap().unwrap();
        assert_eq!(c.carrier(), Carrier::Datagram);
        until(&mut peer, |_| c.max_payload().is_some()).await;

        // One byte: the quarter stream ID fits, the context ID does not.
        net.set_max_datagram_size(Side::Client, Some(1));
        // The driver learns the new limit on its next pass, which a send triggers. An IPv4
        // refusal is `TooLarge` and leaves the tunnel open.
        let mut refused = false;
        for _ in 0..50 {
            match c.send(v4(100)).await {
                Ok(()) => drive_mock(&mut peer, tokio::time::sleep(Duration::from_millis(5))).await,
                Err(IpError::TooLarge) => {
                    refused = true;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(refused, "no IPv4 send was refused");
        assert_eq!(c.max_payload(), None);
        let r = c.send(v6(100)).await;
        assert!(matches!(r, Err(IpError::MtuTooSmall)), "{r:?}");
        until(&mut peer, |p| {
            p.trace().iter().any(|o| match o {
                PeerObs::Reset { stream, code } => *stream == S0 && *code == DG.0,
                PeerObs::Event(Event::StreamAborted { stream, code, .. })
                | PeerObs::Event(Event::SendStopped { stream, code }) => {
                    *stream == S0 && *code == DG
                }
                _ => false,
            })
        })
        .await;
    })
    .await
}
