// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `UdpTunnel` over h3wire-quinn loopback (spec §2.4), set up with `client::connect` and
//! `server::accept`; a raw `Tunnel`/`Datagrams` plays the peer where the test needs
//! control over the wire.

mod support;

use bytes::Bytes;
use futures::poll;
use h3wire_async::Builder;
use h3wire_async::DatagramError;
use h3wire_async::core::{AbortSource, H3Code};
use h3wire_async::datagram::DatagramSlot;
use h3wire_masque::{Carrier, MAX_UDP_PAYLOAD, UdpError, UdpTunnel};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use support::*;

const MSG: H3Code = H3Code::MESSAGE_ERROR;
const RC: H3Code = H3Code::REQUEST_CANCELLED;

/// A pair whose transports have no datagrams: every tunnel carries capsules.
async fn capsule_masque() -> (Pair, Reqs) {
    masque_over(conns_no_datagrams().await, &Builder::new()).await
}

/// An 8-byte (non-minimal) encoding of context ID 0.
const ZERO8: [u8; 8] = [0xc0, 0, 0, 0, 0, 0, 0, 0];

async fn recv_n(t: &mut UdpTunnel, n: usize) -> Vec<Bytes> {
    let mut got = Vec::new();
    for _ in 0..n {
        got.push(t.recv().await.unwrap().expect("a payload"));
    }
    got.sort();
    got
}

/// Payloads flow both ways; `MAX_UDP_PAYLOAD` too when both carry capsules.
async fn exchange(c: &mut UdpTunnel, s: &mut UdpTunnel, big: bool) {
    let mut msgs = vec![Bytes::from_static(b"ping"), Bytes::new()];
    if big {
        msgs.push(pattern(MAX_UDP_PAYLOAD));
    }
    for m in msgs {
        c.send(m.clone()).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), m);
        s.send(m.clone()).await.unwrap();
        assert_eq!(c.recv().await.unwrap().unwrap(), m);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_carrier_round_trip() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(
            (c.carrier(), s.carrier()),
            (Carrier::Datagram, Carrier::Datagram)
        );
        exchange(&mut c, &mut s, false).await;
        // Datagram sends after `finish` are `Closed`; FIN ends the peer's `recv`.
        c.finish().unwrap();
        assert!(matches!(
            c.send(Bytes::from_static(b"x")).await,
            Err(UdpError::Closed)
        ));
        assert_eq!(s.recv().await.unwrap(), None);
        s.finish().unwrap();
        assert_eq!(c.recv().await.unwrap(), None);

        // On the wire: a one-byte context ID 0, then the payload.
        let (mut c, _st, sd) = raw_server(&mut p, &mut reqs).await;
        let mut sd = sd.unwrap();
        c.send(Bytes::from_static(b"wire")).await.unwrap();
        assert_eq!(sd.recv().await.unwrap().unwrap(), ctx0(b"wire"));

        // Empty and maximum payloads over the capsule carrier (datagrams are MTU-bound).
        let (mut p, mut reqs) = capsule_masque().await;
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(
            (c.carrier(), s.carrier()),
            (Carrier::Capsule, Carrier::Capsule)
        );
        exchange(&mut c, &mut s, true).await;
    })
    .await
}

/// Both sides over a loopback where the server's and the client's transports have
/// datagrams as given; both tunnels carry capsules. `sd` tells whether the server
/// advertised `H3_DATAGRAM` (it has a slot then).
async fn capsule_carrier(server_dgrams: bool, client_dgrams: bool, sd: bool) {
    let conns = connect_split(transport_with(server_dgrams), transport_with(client_dgrams)).await;
    let (p, mut reqs) = masque_over(conns, &Builder::new()).await;
    let c = spawn_connect(&p);
    let (req, reply) = reqs.recv().await.unwrap();
    assert_eq!(req.extensions().get::<DatagramSlot>().is_some(), sd);
    let mut s = serve(req, reply).await;
    let mut c = c.await.unwrap().unwrap();
    assert_eq!(
        (c.carrier(), s.carrier()),
        (Carrier::Capsule, Carrier::Capsule)
    );
    assert_eq!(
        (c.max_payload(), s.max_payload()),
        (Some(MAX_UDP_PAYLOAD), Some(MAX_UDP_PAYLOAD))
    );
    exchange(&mut c, &mut s, true).await;
}

/// Server view: it advertised `H3_DATAGRAM` (QUIC datagrams reach it), the client did
/// not (its own transport offers none).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_carrier_when_peer_disabled() {
    with_timeout(capsule_carrier(false, true, true)).await
}

/// Server view: its transport cannot send datagrams, so it has no slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_carrier_when_local_disabled() {
    with_timeout(capsule_carrier(true, false, false)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsule_carrier_both_disabled() {
    with_timeout(capsule_carrier(false, false, false)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_carriers_on_receive() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient { mut ct, cd, mut s } = raw_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        assert_eq!(s.carrier(), Carrier::Datagram);
        cd.send(ctx0(b"d1")).unwrap();
        ct.send(cap(&ctx0(b"c1"))).await.unwrap();
        cd.send(ctx0(b"d2")).unwrap();
        ct.send(cap(&ctx0(b"c2"))).await.unwrap();
        assert_eq!(recv_n(&mut s, 4).await, ["c1", "c2", "d1", "d2"]);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonzero_context_dropped() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient { mut ct, cd, mut s } = raw_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        // Context IDs 2 and 100 (a two-byte varint), both carriers.
        cd.send(Bytes::from_static(b"\x02x")).unwrap();
        cd.send(Bytes::from_static(b"\x40\x64y")).unwrap();
        // No parseable context ID: dropped too.
        cd.send(Bytes::new()).unwrap();
        cd.send(Bytes::from_static(b"\x40")).unwrap();
        ct.send(cap(b"\x02z")).await.unwrap();
        ct.send(cap(b"\x40\x64w")).await.unwrap();
        cd.send(ctx0(b"d")).unwrap();
        ct.send(cap(&ctx0(b"c"))).await.unwrap();
        assert_eq!(recv_n(&mut s, 2).await, ["c", "d"]);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonzero_context_capsule_skipped_unbuffered() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_client(&mut p, &mut reqs).await;
        // 1 MiB under context ID 100: skipped, whatever its size (the decoder unit test
        // shows nothing of it is buffered).
        let big = [&b"\x40\x64"[..], &pattern(1 << 20)].concat();
        ct.send(cap(&big)).await.unwrap();
        ct.send(cap(&ctx0(b"after"))).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "after");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_minimal_context_id_stripped() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient { mut ct, cd, mut s } = raw_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        cd.send([&ZERO8[..], b"d8"].concat().into()).unwrap();
        cd.send(Bytes::from_static(b"\x40\x00d2")).unwrap();
        ct.send(cap(&[&ZERO8[..], b"c8"].concat())).await.unwrap();
        // The largest valid value: 65,535 bytes, an 8-byte ID and the maximum payload.
        let max = pattern(MAX_UDP_PAYLOAD);
        ct.send(cap(&[&ZERO8[..], &max].concat())).await.unwrap();
        let got = recv_n(&mut s, 4).await;
        let small: Vec<_> = got.iter().filter(|b| b.len() < 8).cloned().collect();
        assert_eq!(small, ["c8", "d2", "d8"]);
        assert!(got.contains(&max));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_payload() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let over = Bytes::from(vec![1; MAX_UDP_PAYLOAD + 1]);
        let (mut c, _s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Datagram);
        assert!(matches!(
            c.send(over.clone()).await,
            Err(UdpError::TooLarge)
        ));
        let (mut cp, mut creqs) = capsule_masque().await;
        let (mut c, _s) = udp_pair(&mut cp, &mut creqs).await;
        assert_eq!(c.carrier(), Carrier::Capsule);
        assert!(matches!(
            c.send(over.clone()).await,
            Err(UdpError::TooLarge)
        ));

        // A peer's 65,528-byte context-0 payload aborts the stream.
        let RawClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_client(&mut p, &mut reqs).await;
        ct.send(cap(&ctx0(&over))).await.unwrap();
        let e = s.recv().await.unwrap_err();
        assert!(udp_aborted(&e, MSG, AbortSource::Local), "{e:?}");
        let e = read_to_end(&mut ct).await.unwrap_err();
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_and_truncated_capsule_abort() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // A value ending inside its context ID; an empty value; FIN inside a capsule.
        let cut = cap(&ctx0(b"cut")).slice(..4);
        for (wire, fin) in [(cap(b"\x40"), false), (cap(b""), false), (cut, true)] {
            let RawClient {
                mut ct,
                cd: _cd,
                mut s,
            } = raw_client(&mut p, &mut reqs).await;
            ct.send(wire).await.unwrap();
            if fin {
                ct.finish().unwrap();
            }
            let e = s.recv().await.unwrap_err();
            assert!(udp_aborted(&e, MSG, AbortSource::Local), "{e:?}");
            let e = read_to_end(&mut ct).await.unwrap_err();
            assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
        }
        // Another tunnel is unaffected.
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        exchange(&mut c, &mut s, false).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_needs_tunnel_fin_and_clean_decoder() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // At FIN the datagram handle ends (`Ok(None)`) while capsules are still
        // buffered: they all arrive, then `recv` ends, and stays ended.
        let RawClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_client(&mut p, &mut reqs).await;
        let mut wire = Vec::new();
        for i in 0..50u8 {
            wire.extend_from_slice(&cap(&ctx0(&[i])));
        }
        ct.send(wire.into()).await.unwrap();
        ct.finish().unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        for i in 0..50u8 {
            assert_eq!(s.recv().await.unwrap().unwrap(), [i][..]);
        }
        assert_eq!(s.recv().await.unwrap(), None);
        assert_eq!(s.recv().await.unwrap(), None);

        // FIN inside a capsule: what came before arrives, then the abort.
        let RawClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_client(&mut p, &mut reqs).await;
        let wire = [&cap(&ctx0(b"whole"))[..], &cap(&ctx0(b"cut"))[..4]].concat();
        ct.send(wire.into()).await.unwrap();
        ct.finish().unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "whole");
        let e = s.recv().await.unwrap_err();
        assert!(udp_aborted(&e, MSG, AbortSource::Local), "{e:?}");
        let e = read_to_end(&mut ct).await.unwrap_err();
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recv_alternates_under_datagram_flood() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient { mut ct, cd, mut s } = raw_client(&mut p, &mut reqs).await;
        let cd = cd.unwrap();
        // Ten capsules are buffered at the server, then a datagram flood fills its queue.
        for i in 0..10u8 {
            ct.send(cap(&ctx0(&[b'c', i]))).await.unwrap();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flood = tokio::spawn({
            let stop = stop.clone();
            async move {
                while !stop.load(Ordering::Relaxed) {
                    let _ = cd.send(ctx0(b"flood"));
                    tokio::task::yield_now().await;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Every other `recv` polls the capsules first.
        let (mut caps, mut dgrams) = (0u8, 0);
        for _ in 0..20 {
            let b = s.recv().await.unwrap().unwrap();
            if b == "flood" {
                dgrams += 1;
            } else {
                assert_eq!(b, [b'c', caps][..]);
                caps += 1;
            }
            if caps == 10 {
                break;
            }
        }
        assert_eq!(caps, 10, "capsules starved ({dgrams} datagrams)");
        assert!(dgrams > 0, "no flood seen");
        // EOF still ends `recv`, the flood running until the FIN (sends after it are
        // refused).
        ct.finish().unwrap();
        while let Some(b) = s.recv().await.unwrap() {
            assert_eq!(b, "flood");
        }
        stop.store(true, Ordering::Relaxed);
        flood.await.unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recv_cancel_mid_capsule_keeps_state() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let RawClient {
            mut ct,
            cd: _cd,
            mut s,
        } = raw_client(&mut p, &mut reqs).await;
        // Head, context ID and two payload bytes: the ID is consumed before the cancel.
        let whole = cap(&ctx0(b"hello, world"));
        ct.send(whole.slice(..5)).await.unwrap();
        {
            let mut f = pin!(s.recv());
            for _ in 0..20 {
                assert!(poll!(f.as_mut()).is_pending());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        ct.send(whole.slice(5..)).await.unwrap();
        ct.send(cap(&ctx0(b"next"))).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "hello, world");
        assert_eq!(s.recv().await.unwrap().unwrap(), "next");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_cancel_writes_nothing() {
    with_timeout(async {
        // Admission only into an empty send queue; the server does not read yet.
        let mut cb = Builder::new();
        cb.send_capacity(1);
        let (mut p, mut reqs) = masque_over(conns_no_datagrams().await, &cb).await;
        let (mut c, mut s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Capsule);
        let msg = |i: u32| {
            let mut v = pattern(60_000).to_vec();
            v[..4].copy_from_slice(&i.to_be_bytes());
            Bytes::from(v)
        };
        // Send until one send stays pending (the stream's windows are full), then drop it.
        let mut sent = 0;
        loop {
            let mut f = pin!(c.send(msg(sent)));
            let mut ready = false;
            for _ in 0..50 {
                if let Poll::Ready(r) = poll!(f.as_mut()) {
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
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while let Some(b) = s.recv().await.unwrap() {
                assert_eq!(b, msg(u32::from_be_bytes(b[..4].try_into().unwrap())));
                got.push(u32::from_be_bytes(b[..4].try_into().unwrap()));
            }
            got
        });
        c.send(msg(u32::MAX)).await.unwrap();
        c.finish().unwrap();
        let want: Vec<u32> = (0..sent).chain([u32::MAX]).collect();
        assert_eq!(reader.await.unwrap(), want);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_too_large_not_resent_as_capsule() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, mut st, sd) = raw_server(&mut p, &mut reqs).await;
        let mut sd = sd.unwrap();
        let n = c.max_payload().unwrap();
        assert!(matches!(
            c.send(Bytes::from(vec![7; n + 1])).await,
            Err(UdpError::Datagram(DatagramError::TooLarge))
        ));
        c.send(Bytes::from(vec![7; n])).await.unwrap();
        assert_eq!(sd.recv().await.unwrap().unwrap(), ctx0(&vec![7; n]));
        // Nothing went over the stream.
        c.finish().unwrap();
        assert_eq!(read_to_end(&mut st).await.unwrap(), b"");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_half_drop_aborts() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        // The sender dropped before `finish`.
        let (c, mut st, _sd) = raw_server(&mut p, &mut reqs).await;
        let (tx, _rx) = c.split();
        drop(tx);
        let e = read_to_end(&mut st).await.unwrap_err();
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        // The receiver dropped before EOF.
        let (c, mut st, _sd) = raw_server(&mut p, &mut reqs).await;
        let (mut tx, rx) = c.split();
        drop(rx);
        let e = read_to_end(&mut st).await.unwrap_err();
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        tx.send(Bytes::new()).await.unwrap_err();
        // Both halves work after a split, and either can abort.
        let (c, mut s) = udp_pair(&mut p, &mut reqs).await;
        let (mut tx, mut rx) = c.split();
        tx.send(Bytes::from_static(b"up")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "up");
        s.send(Bytes::from_static(b"down")).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().unwrap(), "down");
        rx.abort(MSG);
        let e = s.recv().await.unwrap_err();
        assert!(udp_aborted(&e, MSG, AbortSource::Peer), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_payload_values() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (c, s) = udp_pair(&mut p, &mut reqs).await;
        // The transport's limit minus QSID 0's byte and the context ID's.
        let limit = |q: &quinn::Connection| q.max_datagram_size().unwrap() - 2;
        assert_eq!(c.max_payload(), Some(limit(&p.conns.client)));
        assert_eq!(s.max_payload(), Some(limit(&p.conns.server)));
        let (mut p, mut reqs) = capsule_masque().await;
        let (c, _s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(c.max_payload(), Some(MAX_UDP_PAYLOAD));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_after_abort_is_sticky() {
    with_timeout(async {
        for dgrams in [true, false] {
            let (mut p, mut reqs) = if dgrams {
                masque().await
            } else {
                capsule_masque().await
            };
            let RawClient { ct, cd: _cd, mut s } = raw_client(&mut p, &mut reqs).await;
            assert_eq!(s.carrier() == Carrier::Datagram, dgrams);
            ct.abort(MSG);
            // A peer RESET never turns into a clean end on a later call.
            for _ in 0..3 {
                let e = s.recv().await.unwrap_err();
                assert!(udp_aborted(&e, MSG, AbortSource::Peer), "{dgrams}: {e:?}");
            }
        }
    })
    .await
}

/// A datagram-carrier send after the request ended is `Closed`, not a datagram loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_send_after_abort_is_closed() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let (mut c, _s) = udp_pair(&mut p, &mut reqs).await;
        assert_eq!(c.carrier(), Carrier::Datagram);
        c.abort(MSG);
        let r = c.send(Bytes::from_static(b"x")).await;
        assert!(matches!(r, Err(UdpError::Closed)), "{r:?}");
    })
    .await
}
