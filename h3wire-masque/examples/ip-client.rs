// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A CONNECT-IP client (RFC 9484) over quinn with a Linux TUN device, configured by the
//! environment of connect-ip-go's `integration/` harness so it can replace that client.
//!
//! ```text
//! PROXY_ADDR=194.166.0.2 PROXY_PORT=443 SERVER_ADDR=194.166.100.3 TESTCASE=ping \
//! CA=ca.pem cargo run -p h3wire-masque --example ip-client
//! ```
//!
//! It connects to the proxy as `proxy` (the certificate must chain to `CA`), opens a
//! tunnel with scope `*`/`*` through `TEMPLATE` (default `https://proxy:{PROXY_PORT}/vpn`)
//! and requests an address of `SERVER_ADDR`'s family. Within 10 s it takes the first
//! assigned address and the advertised routes, brings a TUN device up with them (MTU
//! 1280), and relays packets between the device and the tunnel. Address requests from
//! the proxy are rejected (it has no pool).
//!
//! With `REQUEST_ADDRS` (comma-separated prefixes, at least two; empty is unset) it then
//! requests them and requires the answer to assign the first and reject the second,
//! printing `address-request: ok ids=<a>,<b>`. Then it runs `TESTCASE`: `ping` (50
//! echo requests to `SERVER_ADDR`, passing only if all 50 were sent and answered, as
//! connect-ip-go's client requires) or `http` (`GET /hello` from `SERVER_ADDR` port 80,
//! which must return `Hello, World!\n`). The exit status is the test's. It refuses to
//! run the test when no advertised route contains `SERVER_ADDR`, since the traffic
//! would then bypass the tunnel.
//!
//! Needs `CAP_NET_ADMIN`, `ip` from iproute2 and `ping`. Linux only: elsewhere it exits
//! with an error.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("ip-client needs a Linux TUN device");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
mod linux {
    use bytes::Bytes;
    use h3wire_async::rt::TokioExecutor;
    use h3wire_async::{BoxError, Builder};
    use h3wire_masque::ip::{
        self, AssignedAddress, IpError, IpEvent, IpPrefix, IpRange, IpReceiver, IpSender,
        IpTemplate, IpTunnel, MAX_IP_PACKET, RequestedAddress, Scope,
    };
    use http_body_util::Empty;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::rustls::pki_types::CertificateDer;
    use quinn::rustls::pki_types::pem::PemObject;
    use quinn::rustls::{self, RootCertStore, crypto::ring};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::num::NonZeroU64;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
    use tokio::time::timeout;
    use tokio_tun::Tun;

    const WAIT: Duration = Duration::from_secs(10);

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum TestCase {
        Ping,
        Http,
    }

    #[derive(Debug, PartialEq)]
    struct Config {
        proxy: SocketAddr,
        server: IpAddr,
        testcase: TestCase,
        ca: String,
        template: IpTemplate,
        request: Option<Vec<IpPrefix>>,
    }

    /// The configuration from `env` (a variable lookup).
    fn config(env: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let var = |k: &str| env(k).ok_or(format!("{k} is not set"));
        let bad = |k: &str| format!("{k}: invalid value");
        let port: u16 = var("PROXY_PORT")?.parse().map_err(|_| bad("PROXY_PORT"))?;
        let template = env("TEMPLATE").unwrap_or(format!("https://proxy:{port}/vpn"));
        // Set but empty is unset (compose passes the variable to every cell).
        let request = match env("REQUEST_ADDRS").filter(|s| !s.is_empty()) {
            None => None,
            Some(s) => {
                let v: Vec<_> = s
                    .split(',')
                    .map(parse_prefix)
                    .collect::<Option<_>>()
                    .ok_or(bad("REQUEST_ADDRS"))?;
                if v.len() < 2 {
                    return Err("REQUEST_ADDRS: at least two prefixes".into());
                }
                Some(v)
            }
        };
        Ok(Config {
            proxy: SocketAddr::new(
                var("PROXY_ADDR")?.parse().map_err(|_| bad("PROXY_ADDR"))?,
                port,
            ),
            server: var("SERVER_ADDR")?
                .parse()
                .map_err(|_| bad("SERVER_ADDR"))?,
            testcase: match var("TESTCASE")?.as_str() {
                "ping" => TestCase::Ping,
                "http" => TestCase::Http,
                _ => return Err(bad("TESTCASE")),
            },
            ca: var("CA")?,
            template: IpTemplate::parse(&template).map_err(|e| format!("TEMPLATE: {e}"))?,
            request,
        })
    }

    /// `ADDR/LEN`, with no host bits set.
    fn parse_prefix(s: &str) -> Option<IpPrefix> {
        let (addr, len) = s.split_once('/')?;
        IpPrefix::new(addr.parse().ok()?, len.parse().ok()?).ok()
    }

    /// The prefix that is exactly `r`, if there is one.
    fn range_to_cidr(r: &IpRange) -> Option<IpPrefix> {
        let (width, s, e) = match (r.start(), r.end()) {
            (IpAddr::V4(s), IpAddr::V4(e)) => (32, u32::from(s).into(), u32::from(e).into()),
            (IpAddr::V6(s), IpAddr::V6(e)) => (128, u128::from(s), u128::from(e)),
            _ => return None,
        };
        // The bits where start and end differ must be all zero in start, all one in end.
        let host = 128 - (s ^ e).leading_zeros();
        let mask = u128::MAX.checked_shr(128 - host).unwrap_or(0);
        if s & mask != 0 || e & mask != mask {
            return None;
        }
        IpPrefix::new(r.start(), (width - host) as u8).ok()
    }

    /// The answer to the proxy's address requests: each one rejected (RFC 9484 section
    /// 4.7.2: each Requested Address SHALL get an Assigned Address with its ID).
    fn reject_all(reqs: &[RequestedAddress]) -> Vec<AssignedAddress> {
        reqs.iter()
            .map(|r| AssignedAddress::rejection(r.request_id, r.prefix.addr().is_ipv6()))
            .collect()
    }

    /// Whether `list` answers requests `ids` for `want` as expected: the first assigned
    /// with the requested prefix, the second rejected. `None`: `list` does not answer both.
    fn correlate(
        ids: &[NonZeroU64],
        want: &[IpPrefix],
        list: &[AssignedAddress],
    ) -> Option<Result<(), String>> {
        let find = |id: NonZeroU64| list.iter().find(|e| e.request_id == id.get());
        let (a, b) = (find(ids[0])?, find(ids[1])?);
        Some(
            if a.prefix == want[0] && !a.is_rejection() && b.is_rejection() {
                Ok(())
            } else {
                Err(format!("unexpected answer {a:?}, {b:?}"))
            },
        )
    }

    /// The `ip` argument lists that give `dev` the assigned prefixes, bring it up and
    /// route `routes` into it.
    fn ip_commands(dev: &str, addrs: &[IpPrefix], routes: &[IpPrefix]) -> Vec<Vec<String>> {
        fn cmd(c: &[&str]) -> Vec<String> {
            c.iter().map(|s| s.to_string()).collect()
        }
        let p = |p: &IpPrefix| format!("{}/{}", p.addr(), p.prefix_len());
        addrs
            .iter()
            .map(|a| cmd(&["addr", "add", &p(a), "dev", dev]))
            .chain([cmd(&["link", "set", "dev", dev, "mtu", "1280", "up"])])
            .chain(
                routes
                    .iter()
                    .map(|r| cmd(&["route", "add", &p(r), "dev", dev])),
            )
            .collect()
    }

    /// An HTTP/1.x 200 whose body is `Hello, World!\n`.
    fn http_response_check(resp: &[u8]) -> Result<(), String> {
        let s = std::str::from_utf8(resp).map_err(|_| "response is not UTF-8")?;
        let (head, body) = s.split_once("\r\n\r\n").ok_or("no end of the header")?;
        let line = head.lines().next().unwrap_or("");
        let mut parts = line.split(' ');
        if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) || parts.next() != Some("200") {
            return Err(format!("status line {line:?}"));
        }
        if body != "Hello, World!\n" {
            return Err(format!("body {body:?}"));
        }
        Ok(())
    }

    /// Whether one of `routes` contains `server`, so its traffic goes through the tunnel.
    fn routes_to(routes: &[IpRange], server: IpAddr) -> bool {
        routes.iter().any(|r| r.contains(server))
    }

    /// The transmitted and received counts of ping's summary line
    /// (`50 packets transmitted, 49 received, ...`).
    fn ping_counts(out: &str) -> Option<(u32, u32)> {
        let line = out.lines().find(|l| l.contains(" packets transmitted, "))?;
        let mut f = line.split(", ");
        let sent = f
            .next()?
            .strip_suffix(" packets transmitted")?
            .parse()
            .ok()?;
        let got = f.next()?.strip_suffix(" received")?.parse().ok()?;
        Some((sent, got))
    }

    /// The non-rejection prefixes of an `ADDRESS_ASSIGN` list.
    fn assigned(list: &[AssignedAddress]) -> Vec<IpPrefix> {
        list.iter()
            .filter(|e| !e.is_rejection())
            .map(|e| e.prefix)
            .collect()
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
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }

    /// `Ok(false)`: the test case failed (already reported).
    async fn run() -> Result<bool, BoxError> {
        let cfg = config(|k| std::env::var(k).ok())?;
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_file_iter(&cfg.ca)? {
            roots.add(c?)?;
        }
        let mut tls =
            rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        // A 1280-byte IPv6 packet must fit a datagram from the start (RFC 9484 section 7.2).
        transport.initial_mtu(1350);
        cc.transport_config(Arc::new(transport));
        let bind: SocketAddr = if cfg.proxy.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(cc);
        let conn = endpoint.connect(cfg.proxy, "proxy")?.await?;
        let (mut send, driver) =
            h3wire_quinn::client::<Empty<Bytes>, _>(conn, &Builder::new(), TokioExecutor).await?;
        tokio::spawn(driver);

        let mut tunnel = ip::client::connect(&mut send, &cfg.template, &Scope::ANY).await?;
        let any: IpAddr = match cfg.server {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        // RFC 9484 section 4.7.1: an endpoint expecting an address assignment MUST send an
        // ADDRESS_REQUEST; all-zero is no preference (section 4.7.2).
        tunnel.request(&[IpPrefix::host(any)]).await?;
        let (addrs, routes) = timeout(WAIT, configure(&mut tunnel))
            .await
            .map_err(|_| "no address assignment and routes within 10 s")??;
        if !routes_to(&routes, cfg.server) {
            let list: Vec<_> = routes
                .iter()
                .map(|r| format!("{}-{}", r.start(), r.end()))
                .collect();
            return Err(format!(
                "SERVER_ADDR {} is in none of the advertised routes [{}]",
                cfg.server,
                list.join(", ")
            )
            .into());
        }
        let mut cidrs = Vec::new();
        for r in &routes {
            let c = range_to_cidr(r)
                .ok_or_else(|| format!("route {}-{} is not one prefix", r.start(), r.end()))?;
            // The same range may come once per protocol.
            if !cidrs.contains(&c) {
                cidrs.push(c);
            }
        }
        let tun = Tun::builder().build_one()?;
        for c in ip_commands(tun.name(), &addrs, &cidrs) {
            run_ip(&c).await?;
        }
        eprintln!("{} up", tun.name());

        let (tx, mut rx) = tunnel.split();
        let tx = Mutex::new(tx);
        let (assigns_tx, mut assigns) = unbounded_channel();
        if cfg.request.is_none() {
            assigns.close();
        }
        let test = async {
            if let Some(want) = &cfg.request {
                correlation(&tx, want, &mut assigns).await?;
                // Nothing reads later lists; the relay's sends are dropped from here on.
                assigns.close();
            }
            testcase(cfg.testcase, cfg.server).await
        };
        tokio::select! {
            r = test => r,
            () = relay(&tx, &mut rx, &tun, assigns_tx) => Err("the tunnel ended".into()),
        }
    }

    /// Wait for an assigned address and the routes, accepting both; the proxy's address
    /// requests are answered meanwhile, packets dropped.
    async fn configure(t: &mut IpTunnel) -> Result<(Vec<IpPrefix>, Vec<IpRange>), BoxError> {
        let (mut addrs, mut routes) = (Vec::new(), None);
        loop {
            match t.recv().await? {
                Some(IpEvent::AddressAssign(l)) => {
                    addrs = assigned(&l);
                    t.accept_assigned(&addrs)?;
                }
                Some(IpEvent::Routes(r)) => {
                    t.accept_routes(&r)?;
                    routes = Some(r);
                }
                Some(IpEvent::AddressRequest(q)) => t.assign(&reject_all(&q)).await?,
                Some(_) => {}
                None => return Err("the proxy finished the tunnel".into()),
            }
            if let (false, Some(r)) = (addrs.is_empty(), &routes) {
                return Ok((addrs, r.clone()));
            }
        }
    }

    /// Request `want` and check the answer, which `relay` hands over through `assigns`.
    async fn correlation(
        tx: &Mutex<IpSender>,
        want: &[IpPrefix],
        assigns: &mut UnboundedReceiver<Vec<AssignedAddress>>,
    ) -> Result<(), BoxError> {
        let ids = tx.lock().await.request(want).await?;
        let answer = async {
            while let Some(l) = assigns.recv().await {
                if let Some(r) = correlate(&ids, want, &l) {
                    return r;
                }
            }
            Err("the tunnel ended".into())
        };
        match timeout(WAIT, answer).await {
            Ok(Ok(())) => {
                println!("address-request: ok ids={},{}", ids[0], ids[1]);
                Ok(())
            }
            Ok(Err(e)) => Err(format!("address-request: {e}").into()),
            Err(_) => Err("address-request: no answer within 10 s".into()),
        }
    }

    /// Relay until the tunnel or the device ends. The two directions run side by side, so
    /// one waiting for credit never stops the other.
    async fn relay(
        tx: &Mutex<IpSender>,
        rx: &mut IpReceiver,
        tun: &Tun,
        assigns: UnboundedSender<Vec<AssignedAddress>>,
    ) {
        let up = async {
            let mut buf = vec![0; MAX_IP_PACKET];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(p) => p.len(),
                    Err(e) => return eprintln!("TUN device: {e}"),
                };
                let mut tx = tx.lock().await;
                // What the proxy's rules would refuse (router solicitations, say) is dropped.
                if tx.check_outgoing(&buf[..n]).is_err() {
                    continue;
                }
                match tx.send(Bytes::copy_from_slice(&buf[..n])).await {
                    // Too large for a datagram: a loss.
                    Ok(()) | Err(IpError::TooLarge) => {}
                    Err(e) => return eprintln!("tunnel: {e}"),
                }
            }
        };
        let down = async {
            loop {
                let r = match rx.recv().await {
                    Ok(Some(IpEvent::Packet(p))) => tun
                        .send(&p[..])
                        .await
                        .map_err(|e| format!("TUN device: {e}")),
                    Ok(Some(IpEvent::AddressAssign(l))) => {
                        let r = rx.accept_assigned(&assigned(&l));
                        let _ = assigns.send(l);
                        r.map_err(|e| format!("tunnel: {e}"))
                    }
                    Ok(Some(IpEvent::Routes(r))) => {
                        rx.accept_routes(&r).map_err(|e| format!("tunnel: {e}"))
                    }
                    Ok(Some(IpEvent::AddressRequest(q))) => {
                        let r = tx.lock().await.assign(&reject_all(&q)).await;
                        r.map_err(|e| format!("tunnel: {e}"))
                    }
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err("the proxy finished the tunnel".into()),
                    Err(e) => Err(format!("tunnel: {e}")),
                };
                if let Err(e) = r {
                    return eprintln!("{e}");
                }
            }
        };
        tokio::select! {
            () = up => {}
            () = down => {}
        }
    }

    async fn testcase(t: TestCase, server: IpAddr) -> Result<bool, BoxError> {
        match t {
            TestCase::Ping => {
                let out = tokio::process::Command::new("ping")
                    .args(["-c", "50", "-i", "0.05", &server.to_string()])
                    .output()
                    .await?;
                let text = String::from_utf8_lossy(&out.stdout);
                eprint!("{text}{}", String::from_utf8_lossy(&out.stderr));
                // As connect-ip-go's client: all 50 sent, every one answered.
                match ping_counts(&text) {
                    Some((50, 50)) => {
                        println!("ping: ok 50/50");
                        Ok(true)
                    }
                    Some((sent, got)) => {
                        eprintln!("ping: {sent} transmitted, {got} received; want 50 and 50");
                        Ok(false)
                    }
                    None => {
                        eprintln!("ping: no summary line ({})", out.status);
                        Ok(false)
                    }
                }
            }
            TestCase::Http => {
                let to = SocketAddr::new(server, 80);
                let get = async {
                    let mut s = tokio::net::TcpStream::connect(to).await?;
                    let req = format!("GET /hello HTTP/1.0\r\nHost: {to}\r\n\r\n");
                    s.write_all(req.as_bytes()).await?;
                    let mut resp = Vec::new();
                    s.read_to_end(&mut resp).await?;
                    Ok::<_, io::Error>(resp)
                };
                let resp = timeout(WAIT, get)
                    .await
                    .map_err(|_| "http: no response within 10 s")??;
                match http_response_check(&resp) {
                    Ok(()) => {
                        println!("http: ok");
                        Ok(true)
                    }
                    Err(e) => {
                        eprintln!("http: {e}");
                        Ok(false)
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashMap;

        fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
            let m: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k| m.get(k).cloned()
        }

        const V4: [(&str, &str); 5] = [
            ("PROXY_ADDR", "194.166.0.2"),
            ("PROXY_PORT", "443"),
            ("SERVER_ADDR", "194.166.100.3"),
            ("TESTCASE", "ping"),
            ("CA", "ca.pem"),
        ];

        fn pfx(s: &str) -> IpPrefix {
            parse_prefix(s).unwrap()
        }

        fn rej(id: u64, v6: bool) -> AssignedAddress {
            AssignedAddress::rejection(NonZeroU64::new(id).unwrap(), v6)
        }

        fn range(a: &str, b: &str) -> IpRange {
            IpRange::new(a.parse().unwrap(), b.parse().unwrap(), 0).unwrap()
        }

        #[test]
        fn env_parsing() {
            assert_eq!(
                config(env(&V4)).unwrap(),
                Config {
                    proxy: "194.166.0.2:443".parse().unwrap(),
                    server: "194.166.100.3".parse().unwrap(),
                    testcase: TestCase::Ping,
                    ca: "ca.pem".into(),
                    template: IpTemplate::parse("https://proxy:443/vpn").unwrap(),
                    request: None,
                }
            );
            let v6 = [
                ("PROXY_ADDR", "2001:db8:1::2"),
                ("PROXY_PORT", "4433"),
                ("SERVER_ADDR", "2001:db8:2::3"),
                ("TESTCASE", "http"),
                ("CA", "ca.pem"),
                ("TEMPLATE", "https://proxy:4433/ip/{target}/{ipproto}"),
                ("REQUEST_ADDRS", "2001:db8:1::10/128,2001:db8:1::99/128"),
            ];
            let c = config(env(&v6)).unwrap();
            assert_eq!(c.proxy, "[2001:db8:1::2]:4433".parse().unwrap());
            assert_eq!(c.server, "2001:db8:2::3".parse::<IpAddr>().unwrap());
            assert_eq!(c.testcase, TestCase::Http);
            assert_eq!(
                c.template,
                IpTemplate::parse("https://proxy:4433/ip/{target}/{ipproto}").unwrap()
            );
            assert_eq!(
                c.request,
                Some(vec![pfx("2001:db8:1::10/128"), pfx("2001:db8:1::99/128")])
            );
            // Set but empty, as compose passes `REQUEST_ADDRS=${REQUEST_ADDRS:-}`: no request.
            let mut e = V4.to_vec();
            e.push(("REQUEST_ADDRS", ""));
            assert_eq!(config(env(&e)).unwrap().request, None);
            for (k, v) in [
                ("PROXY_ADDR", "proxy"),
                ("PROXY_PORT", "x"),
                ("SERVER_ADDR", "194.166.100"),
                ("TESTCASE", "filtertcp"),
                ("TEMPLATE", "https://proxy/{port}"),
                ("REQUEST_ADDRS", "194.166.0.10/32"),
                ("REQUEST_ADDRS", "194.166.0.10/32,194.166.0.11"),
                ("REQUEST_ADDRS", "194.166.0.10/32,194.166.0.1/24"),
                ("REQUEST_ADDRS", "194.166.0.10/32,::/129"),
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
        fn range_to_cidr() {
            let f = super::range_to_cidr;
            assert_eq!(
                f(&range("198.51.100.0", "198.51.100.255")),
                Some(pfx("198.51.100.0/24"))
            );
            assert_eq!(f(&range("198.51.100.0", "198.51.100.5")), None);
            assert_eq!(f(&range("198.51.100.1", "198.51.100.255")), None);
            assert_eq!(
                f(&range("198.51.100.0", "198.51.101.255")),
                Some(pfx("198.51.100.0/23"))
            );
            assert_eq!(
                f(&range("198.51.100.7", "198.51.100.7")),
                Some(pfx("198.51.100.7/32"))
            );
            assert_eq!(
                f(&range("0.0.0.0", "255.255.255.255")),
                Some(pfx("0.0.0.0/0"))
            );
            assert_eq!(
                f(&range("2001:db8:2::", "2001:db8:2::ffff:ffff:ffff:ffff")),
                Some(pfx("2001:db8:2::/64"))
            );
            assert_eq!(
                f(&range("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
                Some(pfx("::/0"))
            );
            assert_eq!(f(&range("2001:db8:2::", "2001:db8:2::2")), None);
        }

        #[test]
        fn address_request_answer() {
            let reqs = [
                RequestedAddress {
                    request_id: NonZeroU64::new(1).unwrap(),
                    prefix: pfx("0.0.0.0/32"),
                },
                RequestedAddress {
                    request_id: NonZeroU64::new(2).unwrap(),
                    prefix: pfx("2001:db8:1::10/128"),
                },
            ];
            let a = reject_all(&reqs);
            assert_eq!(a, [rej(1, false), rej(2, true)]);
            assert!(a.iter().all(AssignedAddress::is_rejection));
        }

        #[test]
        fn request_correlation() {
            let ids = [NonZeroU64::new(3).unwrap(), NonZeroU64::new(4).unwrap()];
            let want = [pfx("194.166.0.10/32"), pfx("194.166.0.99/32")];
            let asg = |id, p| AssignedAddress {
                request_id: id,
                prefix: pfx(p),
            };
            // Not the answer yet.
            assert_eq!(correlate(&ids, &want, &[asg(0, "194.166.0.10/32")]), None);
            assert_eq!(correlate(&ids, &want, &[asg(3, "194.166.0.10/32")]), None);
            let ok = [
                asg(0, "194.166.0.10/32"),
                rej(4, false),
                asg(3, "194.166.0.10/32"),
            ];
            assert_eq!(correlate(&ids, &want, &ok), Some(Ok(())));
            let swapped = [rej(3, false), asg(4, "194.166.0.99/32")];
            assert!(matches!(correlate(&ids, &want, &swapped), Some(Err(_))));
            let other = [asg(3, "194.166.0.11/32"), rej(4, false)];
            assert!(matches!(correlate(&ids, &want, &other), Some(Err(_))));
        }

        #[test]
        fn ip_commands() {
            let v = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            assert_eq!(
                super::ip_commands(
                    "tun0",
                    &[pfx("194.166.0.10/32")],
                    &[pfx("194.166.100.0/24")]
                ),
                [
                    v(&["addr", "add", "194.166.0.10/32", "dev", "tun0"]),
                    v(&["link", "set", "dev", "tun0", "mtu", "1280", "up"]),
                    v(&["route", "add", "194.166.100.0/24", "dev", "tun0"]),
                ]
            );
            assert_eq!(
                super::ip_commands(
                    "tun1",
                    &[pfx("2001:db8:1::10/128")],
                    &[pfx("2001:db8:2::/64"), pfx("2001:db8:3::/48")]
                ),
                [
                    v(&["addr", "add", "2001:db8:1::10/128", "dev", "tun1"]),
                    v(&["link", "set", "dev", "tun1", "mtu", "1280", "up"]),
                    v(&["route", "add", "2001:db8:2::/64", "dev", "tun1"]),
                    v(&["route", "add", "2001:db8:3::/48", "dev", "tun1"]),
                ]
            );
        }

        #[test]
        fn ping_summary() {
            let line = |s: &str| format!("--- 194.166.100.3 ping statistics ---\n{s}\nrtt ...\n");
            let f = |s: &str| ping_counts(&line(s));
            assert_eq!(
                f("50 packets transmitted, 50 received, 0% packet loss, time 2456ms"),
                Some((50, 50))
            );
            assert_eq!(
                f("50 packets transmitted, 49 received, 2% packet loss, time 2456ms"),
                Some((50, 49))
            );
            assert_eq!(
                f("50 packets transmitted, 0 received, 100% packet loss, time 2456ms"),
                Some((50, 0))
            );
            assert_eq!(
                f("50 packets transmitted, 48 received, +2 errors, 4% packet loss, time 2456ms"),
                Some((50, 48))
            );
            assert_eq!(ping_counts("ping: connect: Network is unreachable\n"), None);
            assert_eq!(ping_counts(""), None);
        }

        #[test]
        fn server_route_check() {
            let routes = [range("194.166.100.0", "194.166.100.255")];
            assert!(routes_to(&routes, "194.166.100.3".parse().unwrap()));
            assert!(!routes_to(&routes, "194.166.101.3".parse().unwrap()));
            let v6 = [range("2001:db8:2::", "2001:db8:2::ffff:ffff:ffff:ffff")];
            assert!(!routes_to(&v6, "194.166.100.3".parse().unwrap()));
            assert!(routes_to(&v6, "2001:db8:2::3".parse().unwrap()));
            assert!(!routes_to(&routes, "::ffff:194.166.100.3".parse().unwrap()));
            assert!(!routes_to(&[], "194.166.100.3".parse().unwrap()));
        }

        #[test]
        fn http_response_check() {
            let f = super::http_response_check;
            let ok = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!\n";
            assert_eq!(f(ok), Ok(()));
            assert_eq!(f(b"HTTP/1.1 200 OK\r\n\r\nHello, World!\n"), Ok(()));
            assert!(f(b"HTTP/1.0 404 Not Found\r\n\r\nHello, World!\n").is_err());
            assert!(f(b"HTTP/1.0 2000 OK\r\n\r\nHello, World!\n").is_err());
            assert!(f(b"HTTP/1.0 200 OK\r\n\r\nHello, World!").is_err());
            assert!(f(b"HTTP/1.0 200 OK\r\n\r\nHello, World!\n\n").is_err());
            assert!(f(b"HTTP/1.0 200 OK\r\nHello, World!\n").is_err());
            assert!(f(b"").is_err());
        }
    }
}
