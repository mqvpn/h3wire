// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A CONNECT-IP proxy (RFC 9484) over quinn with a Linux TUN device, configured by the
//! environment of connect-ip-go's `integration/` harness so it can replace that proxy.
//!
//! ```text
//! PROXY_ADDR=194.166.0.2 PROXY_PORT=443 ASSIGN_ADDR=194.166.0.10 \
//! ROUTE=194.166.100.0/24 FILTER_IP_PROTOCOL=0 CERT=cert.pem KEY=key.pem \
//!     cargo run -p h3wire-masque --example ip-proxy
//! ```
//!
//! `TEMPLATE` (optional) defaults to `https://proxy:{PROXY_PORT}/vpn`. It serves one
//! tunnel at a time (it has one address to assign); another request meanwhile gets a 503.
//! Per tunnel it:
//! - resolves a host-name target before the response (RFC 9484 section 4.1; a failure is
//!   a 502 with `proxy-status: h3wire; error=dns_error`) and advertises the resolved
//!   host routes instead of `ROUTE`;
//! - creates a TUN device (`ip link set ... mtu 1280 up`, a route to `ASSIGN_ADDR`),
//!   removed when the tunnel ends;
//! - assigns `ASSIGN_ADDR` and advertises `ROUTE` with protocol `FILTER_IP_PROTOCOL`,
//!   unsolicited, accepts nothing the client offers, and answers every address request;
//! - relays packets between the TUN device and the tunnel, dropping those the client's
//!   rules would refuse.
//!
//! Kernel forwarding and firewall rules are the deployment's. Needs `CAP_NET_ADMIN` and
//! `ip` from iproute2. Linux only: elsewhere it exits with an error.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("ip-proxy needs a Linux TUN device");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use bytes::Bytes;
    use h3wire_async::body::RecvBody;
    use h3wire_async::rt::TokioExecutor;
    use h3wire_async::{BoxError, Builder};
    use h3wire_masque::ip::{
        self, AssignedAddress, IpEvent, IpPrefix, IpRange, IpSender, IpTemplate, IpTunnel,
        MAX_IP_PACKET, RequestedAddress, ScopeTarget,
    };
    use h3wire_masque::server::Reject;
    use http::{HeaderValue, Request, Response, StatusCode};
    use http_body_util::Empty;
    use quinn::crypto::rustls::QuicServerConfig;
    use quinn::rustls::pki_types::pem::PemObject;
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use quinn::rustls::{self, crypto::ring};
    use std::future::Future;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::sync::Mutex;
    use tokio_tun::Tun;
    use tower_service::Service;

    type Body = Empty<Bytes>;
    type Fut = Pin<Box<dyn Future<Output = Result<Response<Body>, BoxError>> + Send>>;

    #[derive(Debug, PartialEq)]
    struct Config {
        listen: SocketAddr,
        assign: IpAddr,
        route: IpPrefix,
        ipproto: u8,
        cert: String,
        key: String,
        template: IpTemplate,
    }

    /// The configuration from `env` (a variable lookup).
    fn config(env: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let var = |k: &str| env(k).ok_or(format!("{k} is not set"));
        let bad = |k: &str| format!("{k}: invalid value");
        let port: u16 = var("PROXY_PORT")?.parse().map_err(|_| bad("PROXY_PORT"))?;
        let template = env("TEMPLATE").unwrap_or(format!("https://proxy:{port}/vpn"));
        Ok(Config {
            listen: SocketAddr::new(
                var("PROXY_ADDR")?.parse().map_err(|_| bad("PROXY_ADDR"))?,
                port,
            ),
            assign: var("ASSIGN_ADDR")?
                .parse()
                .map_err(|_| bad("ASSIGN_ADDR"))?,
            route: parse_prefix(&var("ROUTE")?).ok_or(bad("ROUTE"))?,
            ipproto: var("FILTER_IP_PROTOCOL")?
                .parse()
                .map_err(|_| bad("FILTER_IP_PROTOCOL"))?,
            cert: var("CERT")?,
            key: var("KEY")?,
            template: IpTemplate::parse(&template).map_err(|e| format!("TEMPLATE: {e}"))?,
        })
    }

    /// `ADDR/LEN`, with no host bits set.
    fn parse_prefix(s: &str) -> Option<IpPrefix> {
        let (addr, len) = s.split_once('/')?;
        IpPrefix::new(addr.parse().ok()?, len.parse().ok()?).ok()
    }

    /// The full `ADDRESS_ASSIGN` list answering `reqs`: a request gets `assign` if it asks
    /// for exactly that address or for any address of its family (all-zero, RFC 9484
    /// section 4.7.2), every other one a rejection (each Requested Address SHALL get an
    /// Assigned Address with its ID, ibid.). `assign` stays in the list either way.
    fn answer(assign: IpAddr, reqs: &[RequestedAddress]) -> Vec<AssignedAddress> {
        let host = IpPrefix::host(assign);
        let mut list: Vec<_> = reqs
            .iter()
            .map(|r| {
                let a = r.prefix.addr();
                if r.prefix == host || (a.is_unspecified() && a.is_ipv6() == assign.is_ipv6()) {
                    AssignedAddress {
                        request_id: r.request_id.get(),
                        prefix: host,
                    }
                } else {
                    AssignedAddress::rejection(r.request_id, a.is_ipv6())
                }
            })
            .collect();
        if !list.iter().any(|e| e.prefix == host) {
            list.push(AssignedAddress {
                request_id: 0,
                prefix: host,
            });
        }
        list
    }

    /// The `ip` argument lists that bring `dev` up and route `assign` into it.
    fn ip_commands(dev: &str, assign: IpAddr) -> Vec<Vec<String>> {
        let host = format!("{assign}/{}", if assign.is_ipv6() { 128 } else { 32 });
        [
            vec!["link", "set", "dev", dev, "mtu", "1280", "up"],
            vec!["route", "add", &host, "dev", dev],
        ]
        .map(|c| c.into_iter().map(str::to_owned).collect())
        .into()
    }

    async fn run_ip(args: &[String]) -> io::Result<()> {
        let st = tokio::process::Command::new("ip")
            .args(args)
            .status()
            .await?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("ip {}: {st}", args.join(" "))))
        }
    }

    #[tokio::main]
    pub async fn main() -> ExitCode {
        match run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }

    async fn run() -> Result<(), BoxError> {
        let cfg = config(|k| std::env::var(k).ok())?;
        let certs = CertificateDer::pem_file_iter(&cfg.cert)?.collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&cfg.key)?;
        let mut tls =
            rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        // A 1280-byte IPv6 packet must fit a datagram from the start (RFC 9484 section 7.2).
        transport.initial_mtu(1350);
        sc.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(sc, cfg.listen)?;
        let mut builder = Builder::new();
        builder.enable_connect_protocol(true);
        eprintln!("listening on {}", cfg.listen);
        let proxy = Proxy(Arc::new((cfg, AtomicBool::new(false))));
        while let Some(incoming) = endpoint.accept().await {
            let (builder, proxy) = (builder.clone(), proxy.clone());
            tokio::spawn(async move {
                let peer = incoming.remote_address();
                eprintln!("{peer}: accepted");
                let r = match incoming.await {
                    Ok(c) => h3wire_quinn::server(c, &builder, proxy, TokioExecutor)
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

    /// The configuration and whether a tunnel is live.
    #[derive(Clone)]
    struct Proxy(Arc<(Config, AtomicBool)>);

    /// The claim on the one tunnel slot, released when dropped.
    struct Busy(Arc<(Config, AtomicBool)>);

    impl Drop for Busy {
        fn drop(&mut self) {
            self.0.1.store(false, Ordering::Release);
        }
    }

    impl Service<Request<RecvBody>> for Proxy {
        type Response = Response<Body>;
        type Error = BoxError;
        type Future = Fut;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, mut req: Request<RecvBody>) -> Fut {
            let shared = self.0.clone();
            Box::pin(async move {
                let cfg = &shared.0;
                let pending = match ip::server::accept(&mut req, &cfg.template) {
                    Ok(p) => p,
                    Err(Reject::Status(s)) => return Ok(status(s)),
                    // NotConnectIp: nothing else is served. Malformed: already aborted.
                    Err(_) => return Ok(status(StatusCode::NOT_FOUND)),
                };
                if shared
                    .1
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    return Ok(status(StatusCode::SERVICE_UNAVAILABLE));
                }
                let busy = Busy(shared.clone());
                let routes = match &pending.scope().target {
                    // RFC 9484 section 4.1: a host name is resolved before the response.
                    ScopeTarget::Host(name) => match resolve(name, cfg.ipproto).await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("target {name}: {e}");
                            let mut r = status(StatusCode::BAD_GATEWAY);
                            r.headers_mut().insert(
                                "proxy-status",
                                HeaderValue::from_static("h3wire; error=dns_error"),
                            );
                            return Ok(r);
                        }
                    },
                    _ => vec![IpRange::from_prefix(cfg.route, cfg.ipproto)],
                };
                let tun = match open_tun(cfg.assign).await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("TUN device: {e}");
                        return Ok(status(StatusCode::INTERNAL_SERVER_ERROR));
                    }
                };
                let (resp, assign) = (pending.response(), cfg.assign);
                tokio::spawn(async move {
                    match pending.tunnel().await {
                        Ok(t) => relay(t, &tun, assign, &routes).await,
                        Err(e) => eprintln!("tunnel: {e}"),
                    }
                    // The device goes before the slot is free, so the next one can take
                    // its route.
                    drop(tun);
                    drop(busy);
                });
                Ok(resp)
            })
        }
    }

    fn status(s: StatusCode) -> Response<Body> {
        let mut r = Response::new(Empty::new());
        *r.status_mut() = s;
        r
    }

    /// One host route per address `name` resolves to.
    async fn resolve(name: &str, ipproto: u8) -> io::Result<Vec<IpRange>> {
        let mut addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
            .await?
            .map(|a| a.ip().to_canonical())
            .collect();
        addrs.sort();
        addrs.dedup();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no address"));
        }
        Ok(addrs
            .into_iter()
            .map(|a| IpRange::from_prefix(IpPrefix::host(a), ipproto))
            .collect())
    }

    async fn open_tun(assign: IpAddr) -> io::Result<Tun> {
        let tun = Tun::builder().build_one()?;
        for c in ip_commands(tun.name(), assign) {
            run_ip(&c).await?;
        }
        Ok(tun)
    }

    /// Configure the tunnel, then relay until it or the device ends. The two directions
    /// run side by side, so one waiting for credit never stops the other.
    async fn relay(mut tunnel: IpTunnel, tun: &Tun, assign: IpAddr, routes: &[IpRange]) {
        let host = AssignedAddress {
            request_id: 0,
            prefix: IpPrefix::host(assign),
        };
        if let Err(e) = tunnel.assign(&[host]).await {
            return eprintln!("tunnel: {e}");
        }
        if let Err(e) = tunnel.advertise(routes).await {
            return eprintln!("tunnel: {e}");
        }
        let (tx, mut rx) = tunnel.split();
        let tx = Mutex::new(tx);
        // `true`: the client finished the tunnel.
        let up = async {
            loop {
                match rx.recv().await {
                    Ok(Some(IpEvent::Packet(p))) => {
                        if let Err(e) = tun.send(&p[..]).await {
                            eprintln!("TUN device: {e}");
                            return false;
                        }
                    }
                    Ok(Some(IpEvent::AddressRequest(reqs))) => {
                        if let Err(e) = tx.lock().await.assign(&answer(assign, &reqs)).await {
                            eprintln!("tunnel: {e}");
                            return false;
                        }
                    }
                    // A proxy accepts nothing a remote-access client offers.
                    Ok(Some(_)) => {}
                    Ok(None) => return true,
                    Err(e) => {
                        eprintln!("tunnel: {e}");
                        return false;
                    }
                }
            }
        };
        let down = async {
            let mut buf = vec![0; MAX_IP_PACKET];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(p) => p.len(),
                    Err(e) => return eprintln!("TUN device: {e}"),
                };
                if forward(&tx, &buf[..n]).await.is_err() {
                    return;
                }
            }
        };
        let fin = tokio::select! {
            fin = up => fin,
            () = down => false,
        };
        if fin {
            let _ = tx.lock().await.finish();
        }
    }

    /// Send `packet` if the client's rules admit it; only a tunnel failure is an error.
    async fn forward(tx: &Mutex<IpSender>, packet: &[u8]) -> Result<(), ()> {
        let mut tx = tx.lock().await;
        if tx.check_outgoing(packet).is_err() {
            return Ok(());
        }
        match tx.send(Bytes::copy_from_slice(packet)).await {
            // Too large for a datagram: a loss.
            Ok(()) | Err(ip::IpError::TooLarge) => Ok(()),
            Err(e) => {
                eprintln!("tunnel: {e}");
                Err(())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashMap;
        use std::num::NonZeroU64;

        fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
            let m: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k| m.get(k).cloned()
        }

        const V4: [(&str, &str); 7] = [
            ("PROXY_ADDR", "194.166.0.2"),
            ("PROXY_PORT", "443"),
            ("ASSIGN_ADDR", "194.166.0.10"),
            ("ROUTE", "194.166.100.0/24"),
            ("FILTER_IP_PROTOCOL", "0"),
            ("CERT", "cert.pem"),
            ("KEY", "key.pem"),
        ];

        fn pfx(s: &str) -> IpPrefix {
            parse_prefix(s).unwrap()
        }

        fn req(id: u64, p: &str) -> RequestedAddress {
            RequestedAddress {
                request_id: NonZeroU64::new(id).unwrap(),
                prefix: pfx(p),
            }
        }

        fn rej(id: u64, v6: bool) -> AssignedAddress {
            AssignedAddress::rejection(NonZeroU64::new(id).unwrap(), v6)
        }

        fn asg(id: u64, p: &str) -> AssignedAddress {
            AssignedAddress {
                request_id: id,
                prefix: pfx(p),
            }
        }

        #[test]
        fn env_parsing() {
            assert_eq!(
                config(env(&V4)).unwrap(),
                Config {
                    listen: "194.166.0.2:443".parse().unwrap(),
                    assign: "194.166.0.10".parse().unwrap(),
                    route: pfx("194.166.100.0/24"),
                    ipproto: 0,
                    cert: "cert.pem".into(),
                    key: "key.pem".into(),
                    template: IpTemplate::parse("https://proxy:443/vpn").unwrap(),
                }
            );
            let v6 = [
                ("PROXY_ADDR", "2001:db8:1::2"),
                ("PROXY_PORT", "4433"),
                ("ASSIGN_ADDR", "2001:db8:1::10"),
                ("ROUTE", "2001:db8:2::/64"),
                ("FILTER_IP_PROTOCOL", "6"),
                ("CERT", "c"),
                ("KEY", "k"),
                ("TEMPLATE", "https://proxy:4433/ip/{target}/{ipproto}"),
            ];
            let c = config(env(&v6)).unwrap();
            assert_eq!(c.listen, "[2001:db8:1::2]:4433".parse().unwrap());
            assert_eq!(c.assign, "2001:db8:1::10".parse::<IpAddr>().unwrap());
            assert_eq!(c.route, pfx("2001:db8:2::/64"));
            assert_eq!(c.ipproto, 6);
            assert_eq!(
                c.template,
                IpTemplate::parse("https://proxy:4433/ip/{target}/{ipproto}").unwrap()
            );
            for (k, v) in [
                ("PROXY_ADDR", "proxy"),
                ("PROXY_PORT", "70000"),
                ("ASSIGN_ADDR", "194.166.0"),
                ("ROUTE", "194.166.100.0"),
                ("ROUTE", "194.166.100.1/24"),
                ("ROUTE", "194.166.100.0/33"),
                ("ROUTE", "2001:db8:2::/129"),
                ("FILTER_IP_PROTOCOL", "256"),
                ("FILTER_IP_PROTOCOL", "-1"),
                ("TEMPLATE", "http://proxy/vpn"),
            ] {
                let mut e: Vec<_> = V4.iter().filter(|(n, _)| *n != k).copied().collect();
                e.push((k, v));
                assert!(config(env(&e)).is_err(), "{k}={v} accepted");
            }
            for k in V4.map(|(k, _)| k) {
                let e: Vec<_> = V4.iter().filter(|(n, _)| *n != k).copied().collect();
                assert!(config(env(&e)).is_err(), "{k} missing accepted");
            }
        }

        #[test]
        fn address_request_answer() {
            let a: IpAddr = "194.166.0.10".parse().unwrap();
            let host = "194.166.0.10/32";
            assert_eq!(
                answer(a, &[req(1, host), req(2, "198.51.100.7/32")]),
                [asg(1, host), rej(2, false)]
            );
            // No preference (RFC 9484 section 4.7.2), at any prefix length.
            assert_eq!(answer(a, &[req(1, "0.0.0.0/32")]), [asg(1, host)]);
            assert_eq!(answer(a, &[req(3, "0.0.0.0/24")]), [asg(3, host)]);
            assert_eq!(answer(a, &[req(1, "::/128")]), [rej(1, true), asg(0, host)]);
            assert_eq!(
                answer(a, &[req(1, "194.166.0.11/32"), req(2, "194.166.0.0/24")]),
                [rej(1, false), rej(2, false), asg(0, host)]
            );
            let a6: IpAddr = "2001:db8:1::10".parse().unwrap();
            let host6 = "2001:db8:1::10/128";
            assert_eq!(
                answer(a6, &[req(4, "::/64"), req(5, "0.0.0.0/32")]),
                [asg(4, host6), rej(5, false)]
            );
        }

        #[test]
        fn ip_commands() {
            let v = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            assert_eq!(
                super::ip_commands("tun0", "194.166.0.10".parse().unwrap()),
                [
                    v(&["link", "set", "dev", "tun0", "mtu", "1280", "up"]),
                    v(&["route", "add", "194.166.0.10/32", "dev", "tun0"]),
                ]
            );
            assert_eq!(
                super::ip_commands("tun1", "2001:db8:1::10".parse().unwrap()),
                [
                    v(&["link", "set", "dev", "tun1", "mtu", "1280", "up"]),
                    v(&["route", "add", "2001:db8:1::10/128", "dev", "tun1"]),
                ]
            );
        }
    }
}
