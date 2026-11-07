// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Many CONNECT-UDP tunnels on one connection, each proxied to its own UDP echo socket.

mod support;

use bytes::Bytes;
use std::time::{Duration, Instant};
use support::*;
use tokio::net::UdpSocket;

const N: u16 = 64;

/// A UDP echo socket's address.
async fn echo() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// The proxy end of one tunnel: forward both ways; either side ending ends both.
fn proxy(mut t: h3wire_masque::UdpTunnel, sock: UdpSocket) {
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                r = t.recv() => match r {
                    Ok(Some(p)) => { if sock.send(&p).await.is_err() { break } }
                    _ => break,
                },
                r = sock.recv(&mut buf) => match r {
                    Ok(n) => { if t.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() { break } }
                    Err(_) => break,
                },
            }
        }
        let _ = t.finish();
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn many_tunnels_with_udp_echo() {
    with_timeout(async {
        let (mut p, mut reqs) = masque().await;
        let mut set = tokio::task::JoinSet::new();
        for i in 0..N {
            let (mut c, s) = udp_pair(&mut p, &mut reqs).await;
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.connect(echo().await).await.unwrap();
            proxy(s, sock);
            set.spawn(async move {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut seq = 0u32;
                let mut echoed = false;
                while !echoed {
                    assert!(Instant::now() < deadline, "tunnel {i}: no echo");
                    seq += 1;
                    let mut msg = i.to_be_bytes().to_vec();
                    msg.extend_from_slice(&seq.to_be_bytes());
                    c.send(msg.into()).await.unwrap();
                    // Wait for an echo, or 50 ms, then retransmit.
                    if let Ok(r) = tokio::time::timeout(Duration::from_millis(50), c.recv()).await {
                        let d = r.expect("recv failed").expect("tunnel ended early");
                        assert!(d.len() >= 2, "tunnel {i}: short echo");
                        let got = u16::from_be_bytes([d[0], d[1]]);
                        assert_eq!(got, i, "tunnel {i} got an echo of tunnel {got}");
                        echoed = true;
                    }
                }
                c.finish().unwrap();
                // Late echoes of retransmissions may precede the end of the stream.
                while let Some(d) = c.recv().await.expect("recv failed") {
                    assert!(d.len() >= 2, "tunnel {i}: short echo");
                    assert_eq!(u16::from_be_bytes([d[0], d[1]]), i);
                }
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
    })
    .await
}
