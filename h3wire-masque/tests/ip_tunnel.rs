// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `IpTunnel` over h3wire-quinn loopback (spec §2.5), set up with `ip::client::connect`
//! and `ip::server::accept`; a raw `Tunnel`/`Datagrams` plays the peer where the test
//! needs control over the wire.

mod packets;
mod support;

use bytes::{Bytes, BytesMut};
use futures::poll;
use h3wire_async::Builder;
use h3wire_async::core::{AbortSource, H3Code};
use h3wire_masque::Carrier;
use h3wire_masque::capsule;
use h3wire_masque::ip::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AssignedAddress, DropReason, Drops, IpError, IpEvent,
    IpPacketSender, IpPrefix, IpRange, IpTunnel, MAX_IP_PACKET, Policy, ROUTE_ADVERTISEMENT,
    RequestedAddress, encode_address_assign, encode_address_request, encode_routes,
};
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use support::*;

const MSG: H3Code = H3Code::MESSAGE_ERROR;
const LOAD: H3Code = H3Code::EXCESSIVE_LOAD;
const RC: H3Code = H3Code::REQUEST_CANCELLED;

/// A pair whose transports have no datagrams: every tunnel carries capsules.
async fn capsule_masque() -> (Pair, Reqs) {
    masque_over(conns_no_datagrams().await, &Builder::new()).await
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> IpPrefix {
    let (a, l) = s.split_once('/').unwrap();
    IpPrefix::new(ip(a), l.parse().unwrap()).unwrap()
}

fn range(s: &str, proto: u8) -> IpRange {
    IpRange::from_prefix(pfx(s), proto)
}

fn id(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

fn asg(request_id: u64, p: &str) -> AssignedAddress {
    AssignedAddress {
        request_id,
        prefix: pfx(p),
    }
}

/// A UDP packet from `src` to `dst` with `payload`.
fn pkt_with(src: &str, dst: &str, payload: &[u8]) -> Bytes {
    packets::packet(ip(src), ip(dst), 17, payload).into()
}

/// A UDP packet from `src` to `dst` with 8 payload bytes.
fn pkt(src: &str, dst: &str) -> Bytes {
    pkt_with(src, dst, &[0; 8])
}

/// Client to proxy, within the [`setup`] configuration.
fn up() -> Bytes {
    pkt("192.0.2.1", "198.51.100.1")
}

/// Proxy to client, within the [`setup`] configuration.
fn down() -> Bytes {
    pkt("198.51.100.1", "192.0.2.1")
}

/// A capsule of type `ty` with this raw value.
fn ctl(ty: u64, value: &[u8]) -> Bytes {
    let mut b = BytesMut::new();
    capsule::encode(ty, value, &mut b).unwrap();
    b.freeze()
}

fn request_capsule(entries: &[RequestedAddress]) -> Bytes {
    let mut b = BytesMut::new();
    encode_address_request(entries, &mut b).unwrap();
    b.freeze()
}

fn any_v4(n: u64) -> RequestedAddress {
    RequestedAddress {
        request_id: id(n),
        prefix: pfx("0.0.0.0/32"),
    }
}

/// Proxy `s` assigns `addrs` and advertises `routes`; client `c` sees both offers and
/// accepts them.
async fn setup_with(c: &mut IpTunnel, s: &mut IpTunnel, addrs: &[&str], routes: &[IpRange]) {
    let entries: Vec<_> = addrs.iter().map(|a| asg(0, a)).collect();
    s.assign(&entries).await.unwrap();
    s.advertise(routes).await.unwrap();
    assert_eq!(
        c.recv().await.unwrap(),
        Some(IpEvent::AddressAssign(entries.clone()))
    );
    let Some(IpEvent::Routes(got)) = c.recv().await.unwrap() else {
        panic!("no routes")
    };
    let prefixes: Vec<_> = entries.iter().map(|e| e.prefix).collect();
    c.accept_assigned(&prefixes).unwrap();
    c.accept_routes(&got).unwrap();
}

/// The proxy assigns `192.0.2.1/32` and advertises `198.51.100.0/24`; the client accepts.
async fn setup(c: &mut IpTunnel, s: &mut IpTunnel) {
    setup_with(c, s, &["192.0.2.1/32"], &[range("198.51.100.0/24", 0)]).await
}

async fn next_packet(t: &mut IpTunnel) -> Bytes {
    match t.recv().await.unwrap() {
        Some(IpEvent::Packet(b)) => b,
        e => panic!("not a packet: {e:?}"),
    }
}

/// Drive `t`'s receive side until `done(drops)`; any event is a failure.
async fn wait_drops(t: &mut IpTunnel, done: impl Fn(Drops) -> bool) {
    while !done(t.drops()) {
        if let Ok(r) = tokio::time::timeout(Duration::from_millis(20), t.recv()).await {
            panic!("unexpected {r:?}, drops {:?}", t.drops());
        }
    }
}

fn total(d: Drops) -> u64 {
    d.malformed + d.source + d.destination + d.protocol + d.scope + d.icmp + d.context
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packets_both_directions_datagram() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(
            (c.carrier(), s.carrier()),
            (Carrier::Datagram, Carrier::Datagram)
        );
        setup(&mut c, &mut s).await;
        c.send(up()).await.unwrap();
        assert_eq!(next_packet(&mut s).await, up());
        s.send(down()).await.unwrap();
        assert_eq!(next_packet(&mut c).await, down());

        // On the wire: a one-byte context ID 0, then the packet.
        let (mut c, _st, sd) = raw_ip_server(&mut p, &mut reqs).await;
        c.send(up()).await.unwrap();
        assert_eq!(sd.unwrap().recv().await.unwrap().unwrap(), ctx0(&up()));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packets_both_directions_capsule() {
    with_timeout(async {
        let (mut p, mut reqs) = capsule_masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(
            (c.carrier(), s.carrier()),
            (Carrier::Capsule, Carrier::Capsule)
        );
        assert_eq!(c.max_payload(), Some(MAX_IP_PACKET));
        setup_with(
            &mut c,
            &mut s,
            &["192.0.2.1/32", "2001:db8::1/128"],
            &[range("198.51.100.0/24", 0), range("2001:db8:1::/48", 0)],
        )
        .await;
        let big_up: Bytes =
            packets::packet(ip("2001:db8::1"), ip("2001:db8:1::1"), 17, &pattern(65_535)).into();
        let big_down: Bytes =
            packets::packet(ip("2001:db8:1::1"), ip("2001:db8::1"), 17, &pattern(65_535)).into();
        assert_eq!(big_up.len(), MAX_IP_PACKET);
        for (u, d) in [(up(), down()), (big_up, big_down)] {
            c.send(u.clone()).await.unwrap();
            assert_eq!(next_packet(&mut s).await, u);
            s.send(d.clone()).await.unwrap();
            assert_eq!(next_packet(&mut c).await, d);
        }
    })
    .await
}

/// Every control capsule from `from` arrives at `to` as its event.
async fn control_one_way(from: &mut IpTunnel, to: &mut IpTunnel) {
    let entries = [asg(0, "10.0.0.1/32"), asg(0, "2001:db8::/64")];
    from.assign(&entries).await.unwrap();
    assert_eq!(
        to.recv().await.unwrap(),
        Some(IpEvent::AddressAssign(entries.to_vec()))
    );
    let sorted = [
        range("192.0.2.0/24", 0),
        range("198.51.100.0/24", 17),
        range("2001:db8::/32", 0),
    ];
    from.advertise(&[sorted[2], sorted[1], sorted[0]])
        .await
        .unwrap();
    assert_eq!(
        to.recv().await.unwrap(),
        Some(IpEvent::Routes(sorted.to_vec()))
    );
    let ids = from
        .request(&[pfx("0.0.0.0/32"), pfx("::/128")])
        .await
        .unwrap();
    assert_eq!(ids, [id(1), id(2)]);
    let want = vec![
        any_v4(1),
        RequestedAddress {
            request_id: id(2),
            prefix: pfx("::/128"),
        },
    ];
    assert_eq!(
        to.recv().await.unwrap(),
        Some(IpEvent::AddressRequest(want))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_events_both_directions() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        control_one_way(&mut s, &mut c).await;
        control_one_way(&mut c, &mut s).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_capsule_wire_bytes() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut st, _sd) = raw_ip_server(&mut p, &mut reqs).await;
        let entries = [asg(0, "192.0.2.1/32"), asg(0, "2001:db8::1/128")];
        let routes = [range("198.51.100.0/24", 6), range("192.0.2.0/24", 0)];
        c.assign(&entries).await.unwrap();
        c.advertise(&routes).await.unwrap();
        let ids = c.request(&[pfx("0.0.0.0/32")]).await.unwrap();
        c.finish().unwrap();
        let mut want = BytesMut::new();
        encode_address_assign(&entries, &mut want).unwrap();
        encode_routes(&routes, &mut want).unwrap();
        let req = [RequestedAddress {
            request_id: ids[0],
            prefix: pfx("0.0.0.0/32"),
        }];
        encode_address_request(&req, &mut want).unwrap();
        assert_eq!(read_to_end(&mut st).await.unwrap(), want);
    })
    .await
}

/// The proxy's halves run on separate tasks: the sender assigns a fresh address each
/// round, the client answers each assignment at once with a packet from it, and the
/// receiver must deliver every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assign_then_immediate_packet_delivered() {
    const ROUNDS: u32 = 300;
    let addr = |i: u32| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0001 + i));
    let packet =
        |src: IpAddr| -> Bytes { packets::packet(src, ip("198.51.100.1"), 17, &[]).into() };
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, s) = ip_pair(&mut p, &mut reqs).await;
        let (mut tx, mut rx) = s.split();
        tx.advertise(&[range("198.51.100.0/24", 0)]).await.unwrap();
        assert!(matches!(c.recv().await.unwrap(), Some(IpEvent::Routes(_))));
        let client = tokio::spawn(async move {
            for _ in 0..ROUNDS {
                let Some(IpEvent::AddressAssign(e)) = c.recv().await.unwrap() else {
                    panic!("not an assignment")
                };
                c.send(packet(e[0].prefix.addr())).await.unwrap();
            }
            c
        });
        let (ack, mut acks) = tokio::sync::mpsc::unbounded_channel();
        let receiver = tokio::spawn(async move {
            for i in 0..ROUNDS {
                let r = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
                let Ok(Ok(Some(IpEvent::Packet(b)))) = r else {
                    panic!("round {i}: {r:?}, drops {:?}", rx.drops())
                };
                assert_eq!(b, packet(addr(i)), "round {i}");
                ack.send(()).unwrap();
            }
            rx
        });
        for i in 0..ROUNDS {
            tx.assign(&[AssignedAddress {
                request_id: 0,
                prefix: IpPrefix::host(addr(i)),
            }])
            .await
            .unwrap();
            acks.recv().await.unwrap();
        }
        let rx = receiver.await.unwrap();
        assert_eq!(rx.drops().source, 0);
        let _c = client.await.unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn address_request_reply_flow() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        let ids = c
            .request(&[pfx("0.0.0.0/32"), pfx("0.0.0.0/32")])
            .await
            .unwrap();
        assert_eq!(ids, [id(1), id(2)]);
        assert_eq!(
            s.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(vec![any_v4(1), any_v4(2)]))
        );
        assert_eq!(s.pending_requests(), [id(1), id(2)]);
        let reply = [
            asg(1, "192.0.2.1/32"),
            AssignedAddress::rejection(id(2), false),
        ];
        s.assign(&reply).await.unwrap();
        assert_eq!(s.pending_requests(), []);
        let Some(IpEvent::AddressAssign(got)) = c.recv().await.unwrap() else {
            panic!("no assignment")
        };
        assert_eq!(got, reply);
        assert!(!got[0].is_rejection() && got[1].is_rejection());
        assert!(matches!(
            s.assign(&[asg(3, "192.0.2.2/32")]).await,
            Err(IpError::UnknownRequest)
        ));
        let ids = c
            .request(&[pfx("0.0.0.0/32"), pfx("0.0.0.0/32")])
            .await
            .unwrap();
        assert_eq!(ids, [id(3), id(4)]);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drops_counted() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawIpClient { mut ct, cd, mut s } = raw_ip_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        s.assign(&[asg(0, "192.0.2.1/32")]).await.unwrap();
        s.advertise(&[range("198.51.100.0/24", 0), range("203.0.113.0/24", 6)])
            .await
            .unwrap();
        for b in [
            pkt("10.9.9.9", "198.51.100.1"),   // source
            pkt("192.0.2.1", "8.8.8.8"),       // destination
            pkt("192.0.2.1", "203.0.113.1"),   // UDP through a TCP-only route
            Bytes::from_static(&[0x45, 0, 0]), // header
        ] {
            cd.send(ctx0(&b)).unwrap();
        }
        let good_d = pkt_with("192.0.2.1", "198.51.100.1", b"datagram");
        let good_c = pkt_with("192.0.2.1", "198.51.100.1", b"capsule!");
        cd.send([&[2][..], &good_d[..]].concat().into()).unwrap();
        cd.send(ctx0(&good_d)).unwrap();
        ct.send(cap(&[&[2][..], &good_c[..]].concat()))
            .await
            .unwrap();
        ct.send(cap(&ctx0(&vec![0x45; 70_000]))).await.unwrap();
        ct.send(cap(&ctx0(&good_c))).await.unwrap();
        let mut got = [next_packet(&mut s).await, next_packet(&mut s).await];
        got.sort();
        let mut want = [good_d, good_c];
        want.sort();
        assert_eq!(got, want);
        let mut d = Drops::default();
        d.malformed = 2;
        d.source = 1;
        d.destination = 1;
        d.protocol = 1;
        d.context = 2;
        assert_eq!(s.drops(), d);
        // Still delivering.
        cd.send(ctx0(&up())).unwrap();
        assert_eq!(next_packet(&mut s).await, up());
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optimistic_packets_dropped_then_flow() {
    with_timeout(async {
        const N: u64 = 3;
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        for _ in 0..N {
            c.send(up()).await.unwrap();
        }
        wait_drops(&mut s, |d| d.source == N).await;
        setup(&mut c, &mut s).await;
        for _ in 0..N {
            c.send(up()).await.unwrap();
            assert_eq!(next_packet(&mut s).await, up());
        }
        assert_eq!(total(s.drops()), N);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_offer_withdraws_accepted_on_wire() {
    with_timeout(async {
        let (mut p, mut reqs) = capsule_masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        let routes = [range("198.51.100.0/24", 0), range("203.0.113.0/24", 0)];
        setup_with(&mut c, &mut s, &["192.0.2.1/32"], &routes).await;
        let withdrawn = pkt("203.0.113.1", "192.0.2.1");
        assert_eq!(s.check_outgoing(&withdrawn), Ok(()));
        s.send(withdrawn.clone()).await.unwrap();
        assert_eq!(next_packet(&mut c).await, withdrawn);
        s.advertise(&routes[..1]).await.unwrap();
        assert_eq!(
            c.recv().await.unwrap(),
            Some(IpEvent::Routes(routes[..1].to_vec()))
        );
        assert_eq!(s.check_outgoing(&withdrawn), Err(DropReason::Source));
        s.send(withdrawn).await.unwrap();
        s.send(down()).await.unwrap();
        assert_eq!(next_packet(&mut c).await, down());
        assert_eq!(c.drops().source, 1);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recv_fair_under_dropped_flood() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawIpClient { mut ct, cd, mut s } = raw_ip_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flood = tokio::spawn({
            let stop = stop.clone();
            let bad = ctx0(&pkt("10.9.9.9", "198.51.100.1"));
            async move {
                while !stop.load(Ordering::Relaxed) {
                    let _ = cd.send(bad.clone());
                    tokio::task::yield_now().await;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        ct.send(request_capsule(&[any_v4(1)])).await.unwrap();
        ct.finish().unwrap();
        assert_eq!(
            s.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(vec![any_v4(1)]))
        );
        assert_eq!(s.recv().await.unwrap(), None);
        stop.store(true, Ordering::Relaxed);
        flood.await.unwrap();
        assert!(s.drops().source > 0, "no flood seen");
    })
    .await
}

/// Poll `f` a few times; it must stay pending. Then it is dropped.
async fn stays_pending<F: Future>(f: F) {
    let mut f = pin!(f);
    for _ in 0..20 {
        assert!(poll!(f.as_mut()).is_pending());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_cancel_leaves_state() {
    with_timeout(async {
        // Admission only into an empty send queue; the peer does not read.
        let mut cb = Builder::new();
        cb.send_capacity(1);
        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &cb).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Capsule);
        // `c` assigned 10.0.0.2, advertised 192.0.2.0/24, and has a request pending.
        c.assign(&[asg(0, "10.0.0.2/32")]).await.unwrap();
        c.advertise(&[range("192.0.2.0/24", 0)]).await.unwrap();
        s.request(&[pfx("0.0.0.0/32")]).await.unwrap();
        assert!(matches!(
            c.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(_))
        ));
        let to_new = pkt("192.0.2.1", "10.0.0.3");
        let to_old = pkt("192.0.2.1", "10.0.0.2");
        let from_r2 = pkt("203.0.113.1", "10.0.0.2");
        let before = |c: &IpTunnel| {
            assert_eq!(c.pending_requests(), [id(1)]);
            assert_eq!(c.check_outgoing(&to_new), Err(DropReason::Destination));
            assert_eq!(c.check_outgoing(&to_old), Ok(()));
            assert_eq!(c.check_outgoing(&from_r2), Err(DropReason::Source));
        };
        before(&c);

        // Fill the stream until a send stays pending, and drop that send.
        let big = |i: u32| -> Bytes {
            let mut v = pattern(60_000).to_vec();
            v[..4].copy_from_slice(&i.to_be_bytes());
            pkt_with("10.0.0.2", "192.0.2.1", &v)
        };
        let mut sent = 0;
        loop {
            let mut f = pin!(c.send(big(sent)));
            let mut ready = false;
            for _ in 0..50 {
                if let std::task::Poll::Ready(r) = poll!(f.as_mut()) {
                    r.unwrap();
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if !ready {
                break;
            }
            sent += 1;
        }

        // A cancelled assignment answering the request.
        stays_pending(c.assign(&[asg(1, "10.0.0.3/32")])).await;
        before(&c);
        let d0 = c.drops();
        s.send(pkt("10.0.0.3", "192.0.2.1")).await.unwrap();
        s.send(pkt("10.0.0.2", "192.0.2.1")).await.unwrap();
        assert_eq!(next_packet(&mut c).await, pkt("10.0.0.2", "192.0.2.1"));
        assert_eq!(c.drops().source, d0.source + 1);

        // A cancelled advertisement.
        stays_pending(c.advertise(&[range("192.0.2.0/24", 0), range("203.0.113.0/24", 0)])).await;
        before(&c);
        s.send(pkt("10.0.0.2", "203.0.113.1")).await.unwrap();
        s.send(pkt("10.0.0.2", "192.0.2.1")).await.unwrap();
        assert_eq!(next_packet(&mut c).await, pkt("10.0.0.2", "192.0.2.1"));
        assert_eq!(c.drops().destination, d0.destination + 1);

        // The peer drains: neither cancelled capsule arrives, a fresh one does.
        let reader = tokio::spawn(async move {
            let mut events = Vec::new();
            while let Some(e) = s.recv().await.unwrap() {
                if !matches!(e, IpEvent::Packet(_)) {
                    events.push(e);
                }
            }
            (events, s)
        });
        c.assign(&[asg(0, "10.0.0.4/32")]).await.unwrap();
        c.finish().unwrap();
        let (events, s) = reader.await.unwrap();
        assert_eq!(
            events,
            [
                IpEvent::AddressAssign(vec![asg(0, "10.0.0.2/32")]),
                IpEvent::Routes(vec![range("192.0.2.0/24", 0)]),
                IpEvent::AddressAssign(vec![asg(0, "10.0.0.4/32")]),
            ]
        );
        // `c`'s bulk packets are not authorised at `s`.
        assert_eq!(s.drops().source, u64::from(sent));
    })
    .await
}

/// `ty`/`value` from a raw peer aborts the server's tunnel with `code`.
async fn raw_capsule_aborts(p: &mut Pair, reqs: &mut Reqs, wire: Bytes, code: H3Code) {
    let RawIpClient {
        mut ct,
        cd: _cd,
        mut s,
    } = raw_ip_client(p, reqs).await;
    ct.send(wire).await.unwrap();
    let e = s.recv().await.unwrap_err();
    assert!(ip_aborted(&e, code, AbortSource::Local), "{e:?}");
    let e = read_to_end(&mut ct).await.unwrap_err();
    assert!(aborted(&e, code, AbortSource::Peer), "{e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_control_capsule_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let cases = [
            // 192.0.2.1/32, then a trailing byte.
            ctl(ADDRESS_ASSIGN, &[0, 4, 192, 0, 2, 1, 32, 0]),
            ctl(ADDRESS_REQUEST, &[]),
            // 198.51.100.0/24 before 192.0.2.0/24.
            ctl(
                ROUTE_ADVERTISEMENT,
                &[
                    4, 198, 51, 100, 0, 198, 51, 100, 255, 0, 4, 192, 0, 2, 0, 192, 0, 2, 255, 0,
                ],
            ),
        ];
        for wire in cases {
            raw_capsule_aborts(&mut p, &mut reqs, wire, MSG).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_control_capsule_excessive_load() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let wire = ctl(ADDRESS_ASSIGN, &vec![0; 65_537]);
        raw_capsule_aborts(&mut p, &mut reqs, wire, LOAD).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_requests_bounded() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawIpClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_ip_client(&mut p, &mut reqs).await;
        let first: Vec<_> = (1..=1024).map(any_v4).collect();
        ct.send(request_capsule(&first)).await.unwrap();
        assert_eq!(
            s.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(first))
        );
        assert_eq!(s.pending_requests().len(), 1024);
        ct.send(request_capsule(&[any_v4(1025)])).await.unwrap();
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, LOAD, AbortSource::Local), "{e:?}");
        let e = read_to_end(&mut ct).await.unwrap_err();
        assert!(aborted(&e, LOAD, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_capsule_skipped() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawIpClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_ip_client(&mut p, &mut reqs).await;
        s.assign(&[asg(0, "192.0.2.1/32")]).await.unwrap();
        s.advertise(&[range("198.51.100.0/24", 0)]).await.unwrap();
        ct.send(ctl(0x1234, &pattern(1 << 20))).await.unwrap();
        ct.send(cap(&ctx0(&up()))).await.unwrap();
        assert_eq!(next_packet(&mut s).await, up());
        assert_eq!(s.drops(), Drops::default());
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_validation() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, _st, sd) = raw_ip_server(&mut p, &mut reqs).await;
        let mut sd = sd.unwrap();
        assert_eq!(c.carrier(), Carrier::Datagram);
        assert!(matches!(
            c.send(Bytes::new()).await,
            Err(IpError::Malformed)
        ));
        assert!(matches!(
            c.send(Bytes::from_static(&[0x50; 40])).await,
            Err(IpError::Malformed)
        ));
        assert!(matches!(
            c.send(Bytes::from(vec![0x60; MAX_IP_PACKET + 1])).await,
            Err(IpError::TooLarge)
        ));
        // Over the datagram limit.
        let n = c.max_payload().unwrap();
        assert!(n < MAX_IP_PACKET);
        assert!(matches!(
            c.send(Bytes::from(vec![0x45; n + 1])).await,
            Err(IpError::TooLarge)
        ));
        // No policy on send.
        let p = pkt("10.9.9.9", "8.8.8.8");
        assert!(c.check_outgoing(&p).is_err());
        c.send(p.clone()).await.unwrap();
        assert_eq!(sd.recv().await.unwrap().unwrap(), ctx0(&p));
    })
    .await
}

/// `from` sends every candidate; `to` delivers exactly those `from.check_outgoing`
/// accepts and drops the rest. The last candidate must be accepted.
async fn mirror(from: &mut IpTunnel, to: &mut IpTunnel, cands: &[Bytes]) {
    let want: Vec<_> = cands
        .iter()
        .filter(|p| from.check_outgoing(p).is_ok())
        .cloned()
        .collect();
    assert!(want.len() < cands.len());
    assert_eq!(want.last(), cands.last());
    let d0 = total(to.drops());
    for p in cands {
        from.send(p.clone()).await.unwrap();
    }
    let mut got = Vec::new();
    while got.len() < want.len() {
        got.push(next_packet(to).await);
    }
    assert_eq!(got, want);
    assert_eq!(total(to.drops()) - d0, (cands.len() - want.len()) as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_outgoing_mirrors_peer() {
    with_timeout(async {
        let (mut p, mut reqs) = capsule_masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        setup(&mut c, &mut s).await;
        let echo = |a: &str, b: &str| -> Bytes { packets::echo_reply(ip(a), ip(b)).into() };
        mirror(
            &mut s,
            &mut c,
            &[
                pkt("10.0.0.1", "192.0.2.1"),
                pkt("198.51.100.1", "192.0.2.9"),
                Bytes::from_static(&[0x45, 0]),
                echo("198.51.100.7", "192.0.2.1"),
                pkt("2001:db8::1", "2001:db8::2"),
                down(),
            ],
        )
        .await;
        mirror(
            &mut c,
            &mut s,
            &[
                pkt("192.0.2.9", "198.51.100.1"),
                pkt("192.0.2.1", "10.0.0.1"),
                echo("192.0.2.1", "198.51.100.7"),
                up(),
            ],
        )
        .await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchecked_policy_on_wire() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        // Nothing assigned or advertised.
        c.send(up()).await.unwrap();
        wait_drops(&mut s, |d| d.source == 1).await;
        s.set_policy(Policy::Unchecked);
        assert_eq!(s.check_outgoing(&down()), Ok(()));
        c.send(up()).await.unwrap();
        assert_eq!(next_packet(&mut s).await, up());
        // Headers are still checked.
        c.send(Bytes::from_static(&[0x45, 0])).await.unwrap();
        wait_drops(&mut s, |d| d.malformed == 1).await;
        s.set_policy(Policy::Enforce);
        assert_eq!(s.check_outgoing(&down()), Err(DropReason::Source));
        c.send(up()).await.unwrap();
        wait_drops(&mut s, |d| d.source == 2).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_halves_share_state() {
    with_timeout(async {
        let (mut p, mut reqs) = capsule_masque().await;
        let (c, s) = ip_pair(&mut p, &mut reqs).await;
        let (mut stx, mut srx) = s.split();
        let (mut ctx, mut crx) = c.split();
        let route = range("198.51.100.0/24", 0);
        stx.advertise(&[route]).await.unwrap();
        // Not yet assigned: dropped. The request marks where the receiver got to.
        ctx.send(up()).await.unwrap();
        ctx.request(&[pfx("0.0.0.0/32")]).await.unwrap();
        assert!(matches!(
            srx.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(_))
        ));
        assert_eq!(srx.drops().source, 1);
        assert_eq!(stx.pending_requests(), [id(1)]);
        stx.assign(&[asg(1, "192.0.2.1/32")]).await.unwrap();
        assert_eq!(srx.pending_requests(), []);
        ctx.send(up()).await.unwrap();
        assert_eq!(srx.recv().await.unwrap(), Some(IpEvent::Packet(up())));
        assert_eq!(stx.drops(), srx.drops());
        assert_eq!(stx.check_outgoing(&down()), Ok(()));

        // The client's receiver accepts; its sender's `check_outgoing` follows.
        assert!(matches!(
            crx.recv().await.unwrap(),
            Some(IpEvent::Routes(_))
        ));
        assert!(matches!(
            crx.recv().await.unwrap(),
            Some(IpEvent::AddressAssign(_))
        ));
        assert_eq!(ctx.check_outgoing(&up()), Err(DropReason::Source));
        crx.accept_assigned(&[pfx("192.0.2.1/32")]).unwrap();
        assert_eq!(ctx.check_outgoing(&up()), Err(DropReason::Destination));
        crx.accept_routes(&[route]).unwrap();
        assert_eq!(ctx.check_outgoing(&up()), Ok(()));
        ctx.set_policy(Policy::Unchecked);
        assert_eq!(crx.check_outgoing(&pkt("10.9.9.9", "10.9.9.8")), Ok(()));
        assert_eq!(ctx.scope(), crx.scope());
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_half_drop_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // The sender dropped before `finish`.
        let (c, mut st, _sd) = raw_ip_server(&mut p, &mut reqs).await;
        let (tx, _rx) = c.split();
        drop(tx);
        let e = read_to_end(&mut st).await.unwrap_err();
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        // The receiver dropped before EOF.
        let (c, mut st, _sd) = raw_ip_server(&mut p, &mut reqs).await;
        let (mut tx, rx) = c.split();
        drop(rx);
        let e = read_to_end(&mut st).await.unwrap_err();
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        tx.send(up()).await.unwrap_err();
        // Both halves work after a split, and either can abort.
        let (c, mut s) = ip_pair(&mut p, &mut reqs).await;
        let (mut tx, mut rx) = c.split();
        tx.request(&[pfx("0.0.0.0/32")]).await.unwrap();
        assert!(matches!(
            s.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(_))
        ));
        s.request(&[pfx("0.0.0.0/32")]).await.unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            Some(IpEvent::AddressRequest(_))
        ));
        rx.abort(MSG);
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_and_finish() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        c.finish().unwrap();
        assert!(matches!(c.send(up()).await, Err(IpError::Closed)));
        assert!(matches!(
            c.assign(&[asg(0, "10.0.0.1/32")]).await,
            Err(IpError::Closed)
        ));
        assert!(matches!(
            c.advertise(&[range("10.0.0.0/8", 0)]).await,
            Err(IpError::Closed)
        ));
        assert!(matches!(
            c.request(&[pfx("0.0.0.0/32")]).await,
            Err(IpError::Closed)
        ));
        assert_eq!(s.recv().await.unwrap(), None);
        assert_eq!(s.recv().await.unwrap(), None);
        s.finish().unwrap();
        assert_eq!(c.recv().await.unwrap(), None);
        // A failed advertisement changed nothing.
        assert_eq!(
            c.check_outgoing(&pkt("198.51.100.1", "10.0.0.1")),
            Err(DropReason::Source)
        );

        // An abort reaches the peer.
        let (c, mut s) = ip_pair(&mut p, &mut reqs).await;
        c.abort(MSG);
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

/// Packet `tag` of `len` payload bytes, client to proxy within [`setup`].
fn tagged(tag: u16, len: usize) -> Bytes {
    let mut v = pattern(len).to_vec();
    v[..2].copy_from_slice(&tag.to_be_bytes());
    pkt_with("192.0.2.1", "198.51.100.1", &v)
}

/// `tasks` tasks send `n` packets of `len` payload bytes each through clones of one
/// handle; `s` gets every packet whole, each task's in order.
async fn fan_in(c: &IpTunnel, s: &mut IpTunnel, tasks: u16, n: u16, len: usize) {
    let h = c.packet_sender();
    let jobs: Vec<_> = (0..tasks)
        .map(|t| {
            let h = h.clone();
            tokio::spawn(async move {
                for q in 0..n {
                    h.send(tagged(t << 8 | q, len)).await.unwrap();
                }
            })
        })
        .collect();
    let mut next = vec![0; usize::from(tasks)];
    for _ in 0..tasks * n {
        let got = next_packet(s).await;
        let t = (0..tasks)
            .find(|&t| got == tagged(t << 8 | next[usize::from(t)], len))
            .expect("a whole packet, in its task's order");
        next[usize::from(t)] += 1;
    }
    for j in jobs {
        j.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_sender_from_many_tasks() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Datagram);
        setup(&mut c, &mut s).await;
        fan_in(&c, &mut s, 4, 4, 100).await;
        let h = c.packet_sender();
        assert_eq!(h.max_payload(), c.max_payload());
        assert_eq!(h.check_outgoing(&up()), Ok(()));
        assert_eq!(h.check_outgoing(&down()), Err(DropReason::Source));
        assert!(matches!(
            h.send(Bytes::new()).await,
            Err(IpError::Malformed)
        ));
        // The handle does not keep the tunnel open.
        drop(c);
        assert!(matches!(h.send(up()).await, Err(IpError::Closed)));
        assert_eq!(h.max_payload(), None);
        let e = s.recv().await.unwrap_err();
        assert!(ip_aborted(&e, RC, AbortSource::Peer), "{e:?}");

        // Capsules: admission only into an empty send queue, so the senders wait for
        // credit together.
        let mut cb = Builder::new();
        cb.send_capacity(1);
        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &cb).await;
        let (mut c, mut s) = ip_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Capsule);
        setup(&mut c, &mut s).await;
        fan_in(&c, &mut s, 4, 8, 20_000).await;
    })
    .await
}

/// Whether a 60,000-byte packet goes through `h` within half a second; if not, the send
/// is dropped.
async fn goes(h: &IpPacketSender, tag: u16) -> bool {
    let mut f = pin!(h.send(tagged(tag, 60_000)));
    for _ in 0..50 {
        if let std::task::Poll::Ready(r) = poll!(f.as_mut()) {
            r.unwrap();
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// A capsule tunnel whose proxy `s` does not read, a handle on the client's sender, and
/// how many 60,000-byte packets went through the handle before the stream was full.
async fn full_stream(p: &mut Pair, reqs: &mut Reqs) -> (IpTunnel, IpTunnel, IpPacketSender, u16) {
    let (mut c, mut s) = ip_pair(p, reqs).await;
    assert_eq!(c.carrier(), Carrier::Capsule);
    setup(&mut c, &mut s).await;
    let h = c.packet_sender();
    let mut sent = 0;
    while goes(&h, sent).await {
        sent += 1;
    }
    (c, s, h, sent)
}

/// A task waiting for credit in `h.send`.
async fn waiting_send(h: &IpPacketSender) -> tokio::task::JoinHandle<Result<(), IpError>> {
    let h = h.clone();
    let job = tokio::spawn(async move { h.send(up()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!job.is_finished());
    job
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_sender_closed_by_finish() {
    with_timeout(async {
        let mut cb = Builder::new();
        cb.send_capacity(1);
        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &cb).await;
        let (mut c, mut s, h, sent) = full_stream(&mut p, &mut reqs).await;
        let job = waiting_send(&h).await;
        c.finish().unwrap();
        // The waiting task is woken, and nothing goes after the FIN.
        assert!(matches!(job.await.unwrap(), Err(IpError::Closed)));
        assert!(matches!(h.send(up()).await, Err(IpError::Closed)));
        for n in 0..sent {
            assert_eq!(next_packet(&mut s).await, tagged(n, 60_000));
        }
        assert_eq!(s.recv().await.unwrap(), None);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_sender_closed_by_sender_drop() {
    with_timeout(async {
        let mut cb = Builder::new();
        cb.send_capacity(1);
        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &cb).await;
        let (c, mut s, h, _) = full_stream(&mut p, &mut reqs).await;
        let (tx, _rx) = c.split();
        let job = waiting_send(&h).await;
        // A send in progress, not polled again until the peer saw the abort.
        let mut held = pin!(h.send(up()));
        assert!(poll!(held.as_mut()).is_pending());
        drop(tx);
        let e = loop {
            match s.recv().await {
                Ok(Some(_)) => {}
                Ok(None) => panic!("clean EOF"),
                Err(e) => break e,
            }
        };
        assert!(ip_aborted(&e, RC, AbortSource::Peer), "{e:?}");
        assert!(matches!(job.await.unwrap(), Err(IpError::Closed)));
        assert!(matches!(held.await, Err(IpError::Closed)));
        assert_eq!(h.max_payload(), None);
        assert_eq!(h.check_outgoing(&up()), Ok(()));
    })
    .await
}
