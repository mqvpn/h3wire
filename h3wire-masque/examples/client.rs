// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A CONNECT-UDP client (RFC 9298) over quinn, used by the MASQUE interop cells
//! (`docs/interop.md`).
//!
//! ```text
//! cargo run -p h3wire-masque --example masque-client -- \
//!     --ca PEM --template URI --target HOST:PORT [--count N] [--expect-echo]
//! ```
//!
//! Opens a tunnel to `--target` through the proxy that `--template` names, sends `N`
//! (default 10) numbered probes `probe <i>`, and prints each payload that comes back
//! until all `N` did or none arrived for 2 s. The proxy's certificate must chain to
//! `--ca`. With `--expect-echo` it exits non-zero unless at least one payload came back
//! and every one is a probe it sent. The tunnel is finished and the connection closed
//! gracefully before exit.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.
#![forbid(unsafe_code)]

use bytes::Bytes;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::{BoxError, Builder, Error};
use h3wire_masque::client;
use h3wire_masque::template::{Target, TargetHost, UriTemplate};
use http_body_util::Empty;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::CertificateDer;
use quinn::rustls::pki_types::pem::PemObject;
use quinn::rustls::{self, RootCertStore, crypto::ring};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: client --ca PEM --template URI --target HOST:PORT [--count N] \
                     [--expect-echo]";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `Ok(false)`: the echo check failed (already reported).
async fn run() -> Result<bool, BoxError> {
    let (mut ca, mut template, mut target, mut count, mut expect) =
        (None, None, None, 10usize, false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ca" => ca = args.next(),
            "--template" => template = args.next(),
            "--target" => target = args.next(),
            "--count" => count = args.next().ok_or(USAGE)?.parse()?,
            "--expect-echo" => expect = true,
            _ => return Err(format!("unknown argument {a}\n{USAGE}").into()),
        }
    }
    let (Some(ca), Some(template), Some(target)) = (ca, template, target) else {
        return Err(USAGE.into());
    };
    let template = UriTemplate::parse(&template).map_err(|e| format!("--template: {e}"))?;
    let target = parse_target(&target)?;

    // The proxy is the expanded URI's authority.
    let uri = template.expand(&target)?;
    let host = uri.host().ok_or("the template has no host")?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let addr = (host.as_str(), uri.port_u16().unwrap_or(443))
        .to_socket_addrs()?
        .next()
        .ok_or("the proxy did not resolve")?;
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&ca)? {
        roots.add(c?)?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(cc);
    let conn = endpoint.connect(addr, &host)?.await?;
    let (mut send, driver) =
        h3wire_quinn::client::<Empty<Bytes>, _>(conn, &Builder::new(), TokioExecutor).await?;
    let driver = tokio::spawn(driver);

    let mut tunnel = client::connect(&mut send, &template, &target).await?;
    eprintln!("tunnel open, carrier {:?}", tunnel.carrier());
    let probes: Vec<Bytes> = (0..count).map(|i| format!("probe {i}").into()).collect();
    for p in &probes {
        tunnel.send(p.clone()).await?;
    }
    let (mut echoes, mut ok) = (0, true);
    while echoes < count {
        match tokio::time::timeout(Duration::from_secs(2), tunnel.recv()).await {
            Ok(Ok(Some(p))) => {
                echoes += 1;
                let known = probes.contains(&p);
                println!(
                    "echo {:?}{}",
                    String::from_utf8_lossy(&p),
                    if known { "" } else { " (not a probe)" }
                );
                ok &= known;
            }
            Ok(Ok(None)) => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        }
    }
    println!("{echoes}/{count} echoes");
    if expect && (echoes == 0 || !ok) {
        eprintln!("error: expected at least one echo, each a probe");
        return Ok(false);
    }

    // Finish, then wait for the proxy to finish too: dropping an unfinished receiving
    // half would cancel the request.
    tunnel.finish()?;
    let drain = async { while let Ok(Some(_)) = tunnel.recv().await {} };
    let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
    drop(tunnel);
    // Dropping the last `SendRequest` starts the graceful shutdown.
    drop(send);
    match tokio::time::timeout(Duration::from_secs(10), driver).await {
        Ok(r) => r?.map_err(|e: Error| format!("connection: {e}"))?,
        Err(_) => return Err("graceful shutdown timed out".into()),
    }
    endpoint.wait_idle().await;
    Ok(true)
}

/// `HOST:PORT`, with an IPv6 literal in brackets.
fn parse_target(s: &str) -> Result<Target, BoxError> {
    let (host, port) = s.rsplit_once(':').ok_or("--target: not HOST:PORT")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host.parse() {
        Ok(ip) => TargetHost::Ip(ip),
        Err(_) => TargetHost::Name(host.to_owned()),
    };
    Ok(Target::new(host, port.parse()?))
}
