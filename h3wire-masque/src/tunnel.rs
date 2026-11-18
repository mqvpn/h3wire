// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! One CONNECT-UDP tunnel (RFC 9298): UDP payloads in, UDP payloads out, over HTTP
//! Datagrams or DATAGRAM capsules.
//!
//! - **Carrier.** Chosen once when the tunnel is built: [`Carrier::Datagram`] when the
//!   request has a datagram handle whose `max_payload` is known after the peer's
//!   SETTINGS, [`Carrier::Capsule`] otherwise. Receiving accepts both carriers in
//!   either mode.
//! - **Context IDs.** Only context ID 0 carries UDP payloads; other IDs are dropped.
//!   Non-minimal encodings of 0 are accepted.
//! - **Errors.** A malformed or truncated capsule, or a context-0 payload over
//!   [`MAX_UDP_PAYLOAD`], aborts the request with `H3_MESSAGE_ERROR`.
//! - **Lifetime.** As the v0.2 [`Tunnel`] halves: dropping a half before its direction
//!   ended aborts with `H3_REQUEST_CANCELLED`.
//! - **Threads.** [`UdpTunnel`], [`UdpSender`] and [`UdpReceiver`] are `Send` and `Sync`.

use crate::carrier::{self, Limits, Raw, Rx, Step, Tx, TxError};
use bytes::Bytes;
use h3wire_async::core::H3Code;
use h3wire_async::datagram::Datagrams;
use h3wire_async::upgrade::Tunnel;
use h3wire_async::{DatagramError, Error};
use std::fmt;
use std::future::{Future, poll_fn};

/// The largest UDP payload a context-ID-0 tunnel carries (RFC 9298 section 5).
pub const MAX_UDP_PAYLOAD: usize = 65_527;

/// How a tunnel sends its payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// HTTP Datagrams (RFC 9297 section 2).
    Datagram,
    /// DATAGRAM capsules on the request stream (RFC 9297 section 3.5).
    Capsule,
}

/// Why a tunnel operation failed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum UdpError {
    /// The payload is over [`MAX_UDP_PAYLOAD`].
    TooLarge,
    /// The sending side was finished, or the request ended.
    Closed,
    /// The datagram carrier refused the payload (e.g. over the transport's limit).
    Datagram(DatagramError),
    /// The request stream or connection failed, including a local abort.
    Http(Error),
}

impl fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("UDP payload too large"),
            Self::Closed => f.write_str("tunnel send side finished"),
            Self::Datagram(e) => write!(f, "datagram refused: {e}"),
            Self::Http(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for UdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(e) => Some(e),
            Self::Http(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for UdpError {
    fn from(e: Error) -> Self {
        Self::Http(e)
    }
}

impl From<TxError> for UdpError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::Closed => Self::Closed,
            TxError::Datagram(e) => Self::Datagram(e),
            TxError::Http(e) => Self::Http(e),
        }
    }
}

/// A CONNECT-UDP tunnel; [`split`](Self::split) gives independent halves.
#[derive(Debug)]
pub struct UdpTunnel {
    send: UdpSender,
    recv: UdpReceiver,
}

impl UdpTunnel {
    /// Wait for `settings` (`true`: the peer's SETTINGS arrived) to choose the carrier;
    /// see [`carrier::open`].
    pub(crate) async fn open(
        tunnel: Tunnel,
        dgrams: Option<Datagrams>,
        settings: impl Future<Output = bool>,
    ) -> Result<Self, Error> {
        let limits = Limits {
            max_payload: MAX_UDP_PAYLOAD,
            control: |_| false,
            max_control: 0,
        };
        let (tx, rx) = carrier::open(tunnel, dgrams, settings, limits).await?;
        Ok(UdpTunnel {
            send: UdpSender { tx },
            recv: UdpReceiver { rx },
        })
    }

    /// See [`UdpSender::send`].
    pub async fn send(&mut self, payload: Bytes) -> Result<(), UdpError> {
        self.send.send(payload).await
    }

    /// See [`UdpReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<Bytes>, UdpError> {
        self.recv.recv().await
    }

    /// See [`UdpSender::finish`].
    pub fn finish(&mut self) -> Result<(), UdpError> {
        self.send.finish()
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.send.abort(code)
    }

    /// See [`UdpSender::max_payload`].
    pub fn max_payload(&self) -> Option<usize> {
        self.send.max_payload()
    }

    /// See [`UdpSender::carrier`].
    pub fn carrier(&self) -> Carrier {
        self.send.carrier()
    }

    /// The two halves.
    pub fn split(self) -> (UdpSender, UdpReceiver) {
        (self.send, self.recv)
    }
}

/// The sending half of a [`UdpTunnel`].
#[derive(Debug)]
pub struct UdpSender {
    tx: Tx,
}

impl UdpSender {
    /// Send one UDP payload (empty is valid). Over [`MAX_UDP_PAYLOAD`] is `TooLarge`;
    /// after [`finish`](Self::finish), `Closed`. The datagram carrier returns `Closed`
    /// once the request ended, otherwise the transport's refusal (e.g.
    /// `Datagram(TooLarge)`), and never falls back to a capsule. The capsule carrier
    /// waits for stream credit; cancel-safe: a dropped pending send wrote nothing.
    pub async fn send(&mut self, payload: Bytes) -> Result<(), UdpError> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(UdpError::TooLarge);
        }
        Ok(self.tx.send_payload(payload).await?)
    }

    /// Finish the stream after every payload accepted so far.
    pub fn finish(&mut self) -> Result<(), UdpError> {
        Ok(self.tx.finish()?)
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.tx.abort(code)
    }

    /// The largest payload [`send`](Self::send) accepts now: the datagram limit minus the
    /// context ID byte, at most [`MAX_UDP_PAYLOAD`] (as of the async driver's last pass);
    /// `Some(MAX_UDP_PAYLOAD)` for the capsule carrier. `None` with [`Carrier::Datagram`]
    /// when the datagram limit is unknown now or leaves no room for a payload.
    pub fn max_payload(&self) -> Option<usize> {
        self.tx.max_payload(MAX_UDP_PAYLOAD)
    }

    /// The carrier chosen when the tunnel was built.
    pub fn carrier(&self) -> Carrier {
        self.tx.carrier()
    }
}

/// The receiving half of a [`UdpTunnel`].
#[derive(Debug)]
pub struct UdpReceiver {
    rx: Rx,
}

impl UdpReceiver {
    /// The next UDP payload from either carrier; `Ok(None)` once the peer finished the
    /// stream on a capsule boundary. Cancel-safe: the decoder state lives here.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, UdpError> {
        self.rx.start();
        poll_fn(|cx| {
            self.rx.poll_recv(cx, |raw| match raw {
                Raw::Payload(b) => Step::Yield(b),
                // RFC 9298 section 5, RFC 9297 section 3.3.
                Raw::Oversized => Step::Fail(H3Code::MESSAGE_ERROR),
                _ => Step::Drop,
            })
        })
        .await
        .map_err(UdpError::from)
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.rx.abort(code)
    }
}

const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<UdpTunnel>();
    send_sync::<UdpSender>();
    send_sync::<UdpReceiver>();
};
