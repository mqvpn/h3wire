// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Server side of the CONNECT-UDP handshake (RFC 9298 section 3, design spec §2.3).
//!
//! [`accept`] identifies a CONNECT-UDP request, registers its datagrams and claims its
//! upgrade **before** any validation (a client may send datagrams optimistically, and an
//! unregistered request answered with 400/404 would be aborted with
//! `H3_DATAGRAM_ERROR`), then checks headers, path and target. Return
//! [`Pending::response`] from the service and **then** await [`Pending::tunnel`] in a
//! spawned task: awaiting it inside the service before returning deadlocks.

use crate::template::{Target, TemplateError, UriTemplate};
use crate::tunnel::UdpTunnel;
use h3wire_async::Error;
use h3wire_async::body::RecvBody;
use h3wire_async::core::H3Code;
use h3wire_async::datagram::{DatagramSlot, Datagrams};
use h3wire_async::ext::{ConnInfo, Protocol};
use h3wire_async::upgrade::{self, OnUpgrade};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use std::future::Future;

/// What to do with a request [`accept`] did not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reject {
    /// Not a CONNECT-UDP request; it is untouched, route it elsewhere.
    NotConnectUdp,
    /// A malformed CONNECT-UDP request: already aborted with `H3_MESSAGE_ERROR`; any
    /// response the service returns is discarded.
    Malformed,
    /// Return a response with this status: 400 for a bad target, 404 for a path that
    /// does not fit the template.
    Status(StatusCode),
}

/// An accepted CONNECT-UDP request, waiting for its response to be sent.
#[derive(Debug)]
pub struct Pending {
    target: Target,
    on: OnUpgrade,
    dgrams: Option<Datagrams>,
    info: Option<ConnInfo>,
}

/// Take a CONNECT-UDP request for `template`. Dropping the [`Pending`] before the
/// response releases the claim.
pub fn accept(req: &mut Request<RecvBody>, template: &UriTemplate) -> Result<Pending, Reject> {
    let protocol = req.extensions().get::<Protocol>().map(Protocol::as_bytes);
    if req.method() != Method::CONNECT || protocol != Some(b"connect-udp") {
        return Err(Reject::NotConnectUdp);
    }
    let dgrams = req
        .extensions()
        .get::<DatagramSlot>()
        .and_then(DatagramSlot::register);
    let on = upgrade::on(req);
    if crate::forbidden(req.headers()) {
        on.abort(H3Code::MESSAGE_ERROR);
        return Err(Reject::Malformed);
    }
    let target = template.match_target(req.uri()).map_err(|e| {
        Reject::Status(match e {
            TemplateError::BadHost | TemplateError::BadPort => StatusCode::BAD_REQUEST,
            _ => StatusCode::NOT_FOUND,
        })
    })?;
    Ok(Pending {
        target,
        on,
        dgrams,
        info: req.extensions().get::<ConnInfo>().cloned(),
    })
}

impl Pending {
    /// The requested target. Resolving it, opening the UDP socket, checking packet
    /// sources and tying the socket's lifetime to the tunnel's are the application's
    /// duties (RFC 9298 section 3.1).
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// A 200 with `capsule-protocol: ?1` and an empty body.
    pub fn response<B: Default>(&self) -> Response<B> {
        let mut r = Response::new(B::default());
        r.headers_mut()
            .insert("capsule-protocol", HeaderValue::from_static("?1"));
        r
    }

    /// The tunnel, once the 2xx has been sent and the peer's SETTINGS arrived. Spawn or
    /// await it **after** the service returned the response; awaiting it inside the
    /// service deadlocks. A non-2xx response resolves it to `NotUpgraded`.
    #[allow(clippy::manual_async_fn)] // the signature promises `Send`
    pub fn tunnel(self) -> impl Future<Output = Result<UdpTunnel, Error>> + Send {
        async move {
            let tunnel = self.on.await?;
            let settings_ok = match &self.info {
                Some(i) => i.settings().await.is_some(),
                None => false,
            };
            Ok(UdpTunnel::new(tunnel, self.dgrams, settings_ok))
        }
    }
}
