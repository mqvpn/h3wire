// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Server side of the CONNECT-IP handshake (RFC 9484 section 4).
//!
//! [`accept`] identifies a CONNECT-IP request, registers its datagrams and claims its
//! upgrade **before** any validation, as [`server::accept`](crate::server::accept) does
//! for CONNECT-UDP, then checks headers, path and scope. A `target` or `ipproto` value
//! that does not parse makes the request malformed (RFC 9484 section 4.1). Return
//! [`IpPending::response`] from the service and **then** await [`IpPending::tunnel`] in a
//! spawned task: awaiting it inside the service before returning deadlocks.

use super::{IpTemplate, IpTunnel, Scope};
use crate::server::Reject;
use crate::template::TemplateError;
use h3wire_async::Error;
use h3wire_async::body::RecvBody;
use h3wire_async::core::H3Code;
use h3wire_async::datagram::{DatagramSlot, Datagrams};
use h3wire_async::ext::{ConnInfo, Protocol};
use h3wire_async::upgrade::{self, OnUpgrade};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use std::future::Future;

/// An accepted CONNECT-IP request, waiting for its response to be sent.
#[derive(Debug)]
pub struct IpPending {
    scope: Scope,
    on: OnUpgrade,
    dgrams: Option<Datagrams>,
    info: Option<ConnInfo>,
}

/// Take a CONNECT-IP request for `template`. Not CONNECT with `:protocol connect-ip`:
/// [`Reject::NotConnectIp`], the request untouched. A forbidden header or a `target` /
/// `ipproto` that does not parse: [`Reject::Malformed`], already aborted with
/// `H3_MESSAGE_ERROR`. A path that does not fit the template: `Reject::Status(404)`.
/// Dropping the [`IpPending`] before the response releases the claim.
pub fn accept(req: &mut Request<RecvBody>, template: &IpTemplate) -> Result<IpPending, Reject> {
    let protocol = req.extensions().get::<Protocol>().map(Protocol::as_bytes);
    if req.method() != Method::CONNECT || protocol != Some(b"connect-ip") {
        return Err(Reject::NotConnectIp);
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
    let scope = match template.match_scope(req.uri()) {
        Ok(s) => s,
        Err(TemplateError::BadTarget | TemplateError::BadProto) => {
            on.abort(H3Code::MESSAGE_ERROR);
            return Err(Reject::Malformed);
        }
        Err(_) => return Err(Reject::Status(StatusCode::NOT_FOUND)),
    };
    Ok(IpPending {
        scope,
        on,
        dgrams,
        info: req.extensions().get::<ConnInfo>().cloned(),
    })
}

impl IpPending {
    /// The requested scope. Resolving a [`Host`](super::ScopeTarget::Host) target before
    /// the response (RFC 9484 section 4.1), and deciding what to assign and advertise,
    /// are the application's duties.
    pub fn scope(&self) -> &Scope {
        &self.scope
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
    /// service deadlocks. A non-2xx response resolves it to `NotUpgraded`. A request
    /// reset before the SETTINGS resolves it to that error; a FIN (or a lot of tunnel
    /// data) before them gives a capsule-carrier tunnel.
    #[allow(clippy::manual_async_fn)] // the signature promises `Send`
    pub fn tunnel(self) -> impl Future<Output = Result<IpTunnel, Error>> + Send {
        async move {
            let tunnel = self.on.await?;
            let settings = async {
                match &self.info {
                    Some(i) => i.settings().await.is_some(),
                    None => false,
                }
            };
            IpTunnel::open(tunnel, self.dgrams, settings, self.scope, true).await
        }
    }
}
