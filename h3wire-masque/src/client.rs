// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Client side of the CONNECT-UDP handshake (RFC 9298 section 3, design spec §2.3).

use crate::template::{Target, TemplateError, UriTemplate};
use crate::tunnel::UdpTunnel;
use h3wire_async::body::RecvBody;
use h3wire_async::core::H3Code;
use h3wire_async::datagram::{DatagramSlot, RegisterDatagrams};
use h3wire_async::ext::Protocol;
use h3wire_async::upgrade;
use h3wire_async::{BoxError, Error, SendRequest};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body;
use std::fmt;

/// Why [`connect`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The target does not expand in the template.
    Template(TemplateError),
    /// The request or the connection failed.
    Http(Error),
    /// A non-2xx response, to read.
    Rejected(Response<RecvBody>),
    /// A 204/205/206, or a 2xx with `Content-Length`, `Content-Type` or
    /// `Transfer-Encoding`; the request was aborted with `H3_MESSAGE_ERROR`.
    Malformed,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(e) => write!(f, "URI template: {e:?}"),
            Self::Http(e) => e.fmt(f),
            Self::Rejected(r) => write!(f, "CONNECT-UDP rejected: {}", r.status()),
            Self::Malformed => f.write_str("malformed CONNECT-UDP response"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(e) => Some(e),
            _ => None,
        }
    }
}

/// A CONNECT-UDP request for `target`: `CONNECT`, `:protocol connect-udp`, the expanded
/// URI, `capsule-protocol: ?1` and [`RegisterDatagrams`]. `B::default()` must be an empty
/// body (`is_end_stream`), e.g. `http_body_util::Empty<Bytes>`.
pub fn request<B: Default>(
    template: &UriTemplate,
    target: &Target,
) -> Result<Request<B>, TemplateError> {
    let mut r = Request::new(B::default());
    *r.method_mut() = Method::CONNECT;
    *r.uri_mut() = template.expand(target)?;
    r.headers_mut()
        .insert("capsule-protocol", HeaderValue::from_static("?1"));
    r.extensions_mut()
        .insert(Protocol::from_static("connect-udp"));
    r.extensions_mut().insert(RegisterDatagrams);
    Ok(r)
}

/// Open a CONNECT-UDP tunnel to `target`: request, response, validation, upgrade, then
/// the peer's SETTINGS (to choose the carrier).
#[allow(clippy::result_large_err)] // `Rejected` hands the response back unboxed
pub async fn connect<B>(
    send: &mut SendRequest<B>,
    template: &UriTemplate,
    target: &Target,
) -> Result<UdpTunnel, ConnectError>
where
    B: Body + Default + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let req = request(template, target).map_err(ConnectError::Template)?;
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
    let settings_ok = send.settings().await.is_some();
    Ok(UdpTunnel::new(tunnel, dgrams, settings_ok))
}

/// A 2xx that cannot start a capsule-protocol tunnel (RFC 9297 section 3.2, RFC 9114
/// section 4.1.2).
fn malformed(status: StatusCode, h: &HeaderMap) -> bool {
    matches!(status.as_u16(), 204..=206) || crate::forbidden(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad(status: u16, h: &HeaderMap) -> bool {
        malformed(StatusCode::from_u16(status).unwrap(), h)
    }

    #[test]
    fn forbidden_headers_and_statuses_malformed() {
        for name in ["content-length", "content-type", "transfer-encoding"] {
            let mut h = HeaderMap::new();
            h.insert(name, HeaderValue::from_static("0"));
            assert!(bad(200, &h), "{name}");
        }
        let h = HeaderMap::new();
        for s in [204, 205, 206] {
            assert!(bad(s, &h), "{s}");
        }
        for s in [200, 201, 207, 299] {
            assert!(!bad(s, &h), "{s}");
        }
    }
}
