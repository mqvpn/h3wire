// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A CONNECT-UDP proxy (RFC 9298) over quinn, used by the MASQUE interop cells
//! (`docs/interop.md`).
//!
//! ```text
//! cargo run -p h3wire-masque --example proxy -- \
//!     [--listen ADDR] --cert PEM --key PEM [--template URI]
//! ```
//!
//! `--listen` defaults to `127.0.0.1:4433`, `--template` to the default template
//! (`/.well-known/masque/udp/{target_host}/{target_port}/`) on the listen address.
//!
//! Per tunnel it does the duties RFC 9298 section 3.1 leaves to the proxy:
//! - resolves the target and `connect`s a UDP socket to it **before** the 200 (a failure
//!   is a 502), so the socket only receives packets from the target;
//! - sets the socket's Don't Fragment bit (`IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` =
//!   `DO`) so it never introduces fragmentation; a payload the socket refuses with
//!   `EMSGSIZE` is dropped. Linux only: elsewhere it exits at startup;
//! - ties the socket and the tunnel together: the client finishing the tunnel, or the
//!   tunnel or the socket failing, ends both.
//!
//! Each connection is logged to stderr: `<addr>: accepted`, then `<addr>: closed` or
//! `<addr>: closed with error: ...`.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.
#![forbid(unsafe_code)]

use bytes::Bytes;
use h3wire_async::body::RecvBody;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::{BoxError, Builder, DatagramError};
use h3wire_masque::server::{self, Pending, Reject};
use h3wire_masque::template::{Target, TargetHost, UriTemplate};
use h3wire_masque::{MAX_UDP_PAYLOAD, UdpError, UdpTunnel};
use http::uri::Authority;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls::pki_types::pem::PemObject;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::{self, crypto::ring};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;
use tower_service::Service;

type Body = Empty<Bytes>;
type Fut = Pin<Box<dyn Future<Output = Result<Response<Body>, BoxError>> + Send>>;

const USAGE: &str = "usage: proxy [--listen ADDR] --cert PEM --key PEM [--template URI]";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let (mut listen, mut cert, mut key, mut template) =
        ("127.0.0.1:4433".to_owned(), None, None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().ok_or(USAGE)?,
            "--cert" => cert = args.next(),
            "--key" => key = args.next(),
            "--template" => template = args.next(),
            _ => return Err(format!("unknown argument {a}\n{USAGE}").into()),
        }
    }
    let (Some(cert), Some(key)) = (cert, key) else {
        return Err(USAGE.into());
    };
    // Fail at startup, not per tunnel, where the Don't Fragment bit cannot be set.
    dont_fragment(&std::net::UdpSocket::bind("127.0.0.1:0")?)?;
    let template = Arc::new(match template {
        Some(t) => UriTemplate::parse(&t).map_err(|e| format!("--template: {e:?}"))?,
        None => UriTemplate::default_for(&listen.parse::<Authority>()?),
    });
    let listen: SocketAddr = listen.parse()?;
    let certs = CertificateDer::pem_file_iter(&cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&key)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    // Tunnelled QUIC packets are at least 1200 bytes, so a datagram carrying one needs a
    // larger packet from the start (masque-go's client uses 1350 as well).
    transport.initial_mtu(1350);
    sc.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(sc, listen)?;
    let mut builder = Builder::new();
    builder.enable_connect_protocol(true);
    eprintln!("listening on {listen}");
    while let Some(incoming) = endpoint.accept().await {
        let (builder, template) = (builder.clone(), template.clone());
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            eprintln!("{peer}: accepted");
            let r = match incoming.await {
                Ok(c) => h3wire_quinn::server(c, &builder, Proxy(template), TokioExecutor)
                    .await
                    .map_err(BoxError::from),
                Err(e) => Err(e.into()),
            };
            match r {
                Ok(()) => eprintln!("{peer}: closed"),
                Err(e) => eprintln!("{peer}: closed with error: {e}"),
            }
        });
    }
    Ok(())
}

#[derive(Clone)]
struct Proxy(Arc<UriTemplate>);

impl Service<Request<RecvBody>> for Proxy {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<RecvBody>) -> Fut {
        let template = self.0.clone();
        Box::pin(async move {
            let pending = match server::accept(&mut req, &template) {
                Ok(p) => p,
                Err(Reject::Status(s)) => return Ok(status(s)),
                // NotConnectUdp: nothing else is served. Malformed: already aborted.
                Err(_) => return Ok(status(StatusCode::NOT_FOUND)),
            };
            let sock = match open(pending.target()).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("target {:?}: {e}", pending.target());
                    return Ok(status(StatusCode::BAD_GATEWAY));
                }
            };
            let resp = pending.response();
            tokio::spawn(relay(pending, sock));
            Ok(resp)
        })
    }
}

fn status(s: StatusCode) -> Response<Body> {
    let mut r = Response::new(Empty::new());
    *r.status_mut() = s;
    r
}

/// A UDP socket connected to `target` (so it drops packets from other sources), with the
/// Don't Fragment bit set.
async fn open(target: &Target) -> io::Result<UdpSocket> {
    let port = target.port.get();
    let addr = match &target.host {
        TargetHost::Ip(ip) => SocketAddr::new(*ip, port),
        TargetHost::Name(n) => tokio::net::lookup_host((n.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?,
    };
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()
    .unwrap();
    let sock = UdpSocket::bind(bind).await?;
    dont_fragment(&sock)?;
    sock.connect(addr).await?;
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn dont_fragment(sock: &impl std::os::fd::AsFd) -> io::Result<()> {
    use rustix::net::sockopt::{self, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
    let is_v6 = matches!(
        rustix::net::getsockname(sock)?.address_family(),
        rustix::net::AddressFamily::INET6
    );
    if is_v6 {
        sockopt::set_ipv6_mtu_discover(sock, Ipv6PathMtuDiscovery::DO)?;
    } else {
        sockopt::set_ip_mtu_discover(sock, Ipv4PathMtuDiscovery::DO)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn dont_fragment<S>(_: &S) -> io::Result<()> {
    Err(io::Error::other(
        "fragmentation control unsupported on this platform",
    ))
}

/// The result of sending one payload to the target: `EMSGSIZE` (it would need
/// fragmenting, and DF is set) drops the payload; other errors end the tunnel.
fn sent(r: io::Result<usize>) -> io::Result<()> {
    match r {
        Ok(_) => Ok(()),
        #[cfg(target_os = "linux")]
        Err(e) if rustix::io::Errno::from_io_error(&e) == Some(rustix::io::Errno::MSGSIZE) => {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Relay between the tunnel and the socket until either ends; dropping the socket and
/// an unfinished tunnel half ends the other side too.
async fn relay(pending: Pending, sock: UdpSocket) {
    let tunnel: UdpTunnel = match pending.tunnel().await {
        Ok(t) => t,
        Err(e) => return eprintln!("tunnel: {e}"),
    };
    let (mut tx, mut rx) = tunnel.split();
    let mut buf = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            p = rx.recv() => match p {
                Ok(Some(p)) => {
                    if let Err(e) = sent(sock.send(&p).await) {
                        return eprintln!("target socket: {e}");
                    }
                }
                Ok(None) => {
                    let _ = tx.finish();
                    return;
                }
                Err(e) => return eprintln!("tunnel: {e}"),
            },
            n = sock.recv(&mut buf) => match n {
                Ok(n) => match tx.send(Bytes::copy_from_slice(&buf[..n])).await {
                    // Over the datagram limit: a loss (a full send queue drops the oldest).
                    Ok(()) | Err(UdpError::Datagram(DatagramError::TooLarge)) => {}
                    Err(e) => return eprintln!("tunnel: {e}"),
                },
                Err(e) => return eprintln!("target socket: {e}"),
            },
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::net::sockopt::{self, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
    use std::net::Ipv6Addr;

    fn target(ip: std::net::IpAddr) -> Target {
        Target::new(TargetHost::Ip(ip), 9.try_into().unwrap())
    }

    #[tokio::test]
    async fn target_socket_sets_dont_fragment() {
        let s = open(&target([127, 0, 0, 1].into())).await.unwrap();
        assert_eq!(
            sockopt::ip_mtu_discover(&s).unwrap(),
            Ipv4PathMtuDiscovery::DO
        );
        let s = open(&target(Ipv6Addr::LOCALHOST.into())).await.unwrap();
        assert_eq!(
            sockopt::ipv6_mtu_discover(&s).unwrap(),
            Ipv6PathMtuDiscovery::DO
        );
    }

    #[test]
    fn emsgsize_drops_the_payload() {
        let msgsize = rustix::io::Errno::MSGSIZE.raw_os_error();
        assert!(sent(Err(io::Error::from_raw_os_error(msgsize))).is_ok());
        let refused = rustix::io::Errno::CONNREFUSED.raw_os_error();
        assert!(sent(Err(io::Error::from_raw_os_error(refused))).is_err());
        assert!(sent(Ok(3)).is_ok());
    }
}
