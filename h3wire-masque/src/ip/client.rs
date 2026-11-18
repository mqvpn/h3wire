// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Client side of the CONNECT-IP handshake (RFC 9484 section 4).

use super::{IpTemplate, IpTunnel, Scope};
use crate::client::{ConnectError, malformed};
use crate::template::TemplateError;
use h3wire_async::core::H3Code;
use h3wire_async::datagram::{DatagramSlot, RegisterDatagrams};
use h3wire_async::ext::Protocol;
use h3wire_async::upgrade;
use h3wire_async::{BoxError, SendRequest};
use http::{HeaderValue, Method, Request};
use http_body::Body;

/// A CONNECT-IP request for `scope`: `CONNECT`, `:protocol connect-ip`, the expanded
/// URI, `capsule-protocol: ?1` and [`RegisterDatagrams`]. `B::default()` must be an empty
/// body (`is_end_stream`), e.g. `http_body_util::Empty<Bytes>`.
pub fn request<B: Default>(
    template: &IpTemplate,
    scope: &Scope,
) -> Result<Request<B>, TemplateError> {
    let mut r = Request::new(B::default());
    *r.method_mut() = Method::CONNECT;
    *r.uri_mut() = template.expand(scope)?;
    r.headers_mut()
        .insert("capsule-protocol", HeaderValue::from_static("?1"));
    r.extensions_mut()
        .insert(Protocol::from_static("connect-ip"));
    r.extensions_mut().insert(RegisterDatagrams);
    Ok(r)
}

/// Open a CONNECT-IP tunnel for `scope`: request, response, validation, upgrade, then the
/// peer's SETTINGS (to choose the carrier). A non-2xx response is
/// [`ConnectError::Rejected`] and no tunnel exists; dropping that response before the end
/// of its body cancels the request with `H3_REQUEST_CANCELLED`.
#[allow(clippy::result_large_err)] // `Rejected` hands the response back unboxed
pub async fn connect<B>(
    send: &mut SendRequest<B>,
    template: &IpTemplate,
    scope: &Scope,
) -> Result<IpTunnel, ConnectError>
where
    B: Body + Default + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let req = request(template, scope).map_err(ConnectError::Template)?;
    let mut resp = send.send_request(req).await.map_err(ConnectError::Http)?;
    if !resp.status().is_success() {
        return Err(ConnectError::Rejected(resp));
    }
    let on = upgrade::on(&mut resp);
    if malformed(resp.status(), resp.headers()) {
        on.abort(H3Code::MESSAGE_ERROR);
        return Err(ConnectError::Malformed);
    }
    let dgrams = resp
        .extensions()
        .get::<DatagramSlot>()
        .and_then(DatagramSlot::register);
    let tunnel = on.await.map_err(ConnectError::Http)?;
    let settings = async { send.settings().await.is_some() };
    IpTunnel::open(tunnel, dgrams, settings, scope.clone(), false)
        .await
        .map_err(ConnectError::Http)
}
