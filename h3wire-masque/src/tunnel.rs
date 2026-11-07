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

use crate::capsule::{self, CapsuleError, DATAGRAM, Decoder};
use bytes::{Bytes, BytesMut};
use h3wire_async::core::{AbortSource, H3Code, varint};
use h3wire_async::datagram::{DatagramReceiver, DatagramSender, Datagrams};
use h3wire_async::upgrade::{Tunnel, TunnelRecv, TunnelSend};
use h3wire_async::{DatagramError, Error, ErrorKind};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::{Context, Poll};

/// Progress steps per carrier in one `recv` poll before yielding.
const MAX_STEPS: usize = 32;

/// Stream bytes a tunnel buffers while it waits for the peer's SETTINGS; past this it
/// stops waiting and carries capsules.
const SETTINGS_WAIT_BYTES: usize = 64 * 1024;

/// The largest UDP payload a context-ID-0 tunnel carries (RFC 9298 section 5).
pub const MAX_UDP_PAYLOAD: usize = 65_527;

/// How a tunnel sends UDP payloads.
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

/// A CONNECT-UDP tunnel; [`split`](Self::split) gives independent halves.
#[derive(Debug)]
pub struct UdpTunnel {
    send: UdpSender,
    recv: UdpReceiver,
}

impl UdpTunnel {
    /// Wait for `settings` (`true`: the peer's SETTINGS arrived) to choose the carrier.
    /// The stream is read meanwhile, so the wait cannot outlive the request: its bytes go
    /// to the capsule decoder, a reset or error is returned, and a FIN or more than
    /// [`SETTINGS_WAIT_BYTES`] received settles without SETTINGS (capsule carrier).
    pub(crate) async fn open(
        tunnel: Tunnel,
        dgrams: Option<Datagrams>,
        settings: impl Future<Output = bool>,
    ) -> Result<Self, Error> {
        let (tx, mut rx) = tunnel.split();
        let mut capsules = Capsules::default();
        let mut eof = false;
        let mut settings = pin!(settings);
        let settings_ok = poll_fn(|cx| {
            if let Poll::Ready(ok) = settings.as_mut().poll(cx) {
                return Poll::Ready(Ok(ok));
            }
            while !eof && capsules.dec.buffered() <= SETTINGS_WAIT_BYTES {
                match pin!(rx.recv()).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(Some(b))) => capsules.dec.push(b),
                    Poll::Ready(Ok(None)) => eof = true,
                }
            }
            Poll::Ready(Ok(false))
        })
        .await?;
        let (dtx, drx) = match dgrams.map(Datagrams::split) {
            Some((s, r)) => (Some(s), Some(r)),
            None => (None, None),
        };
        let dtx = dtx.filter(|d| settings_ok && d.max_payload().is_some());
        Ok(UdpTunnel {
            send: UdpSender {
                tunnel: tx,
                dgrams: dtx,
                finished: false,
            },
            recv: UdpReceiver {
                tunnel: rx,
                dgrams: drx,
                capsules,
                dgram_first: false,
                eof,
                end: None,
            },
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
    tunnel: TunnelSend,
    /// `Some` iff the carrier is datagrams.
    dgrams: Option<DatagramSender>,
    finished: bool,
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
        if self.finished {
            return Err(UdpError::Closed);
        }
        // Context ID 0, one byte.
        let value = Bytes::from([&[0][..], &payload].concat());
        if let Some(d) = &self.dgrams {
            return d.send(value).map_err(|e| match e {
                DatagramError::Closed => UdpError::Closed,
                e => UdpError::Datagram(e),
            });
        }
        // One `TunnelSend::send` call per capsule: it takes the `Bytes` whole or not at
        // all, so a cancelled send never leaves half a capsule on the stream.
        let mut b = BytesMut::new();
        capsule::encode(DATAGRAM, &value, &mut b).expect("within varint range");
        Ok(self.tunnel.send(b.freeze()).await?)
    }

    /// Finish the stream after every payload accepted so far.
    pub fn finish(&mut self) -> Result<(), UdpError> {
        self.tunnel.finish()?;
        self.finished = true;
        Ok(())
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.tunnel.abort(code)
    }

    /// The largest payload [`send`](Self::send) accepts now: the datagram limit minus the
    /// context ID byte, at most [`MAX_UDP_PAYLOAD`] (as of the async driver's last pass);
    /// `Some(MAX_UDP_PAYLOAD)` for the capsule carrier. `None` with [`Carrier::Datagram`]
    /// when the datagram limit is unknown now or leaves no room for a payload.
    pub fn max_payload(&self) -> Option<usize> {
        match &self.dgrams {
            Some(d) => d
                .max_payload()?
                .checked_sub(1)
                .map(|n| n.min(MAX_UDP_PAYLOAD)),
            None => Some(MAX_UDP_PAYLOAD),
        }
    }

    /// The carrier chosen when the tunnel was built.
    pub fn carrier(&self) -> Carrier {
        match self.dgrams {
            Some(_) => Carrier::Datagram,
            None => Carrier::Capsule,
        }
    }
}

/// The receiving half of a [`UdpTunnel`].
#[derive(Debug)]
pub struct UdpReceiver {
    tunnel: TunnelRecv,
    /// `None` without datagrams or once the handle ended.
    dgrams: Option<DatagramReceiver>,
    capsules: Capsules,
    /// Which carrier the next `recv` polls first; flips every call.
    dgram_first: bool,
    /// The tunnel's FIN arrived.
    eof: bool,
    /// The terminal result `recv` returned (`Ok(None)` or an error), repeated after.
    end: Option<Result<Option<Bytes>, UdpError>>,
}

impl UdpReceiver {
    /// The next UDP payload from either carrier; `Ok(None)` once the peer finished the
    /// stream on a capsule boundary. Cancel-safe: the decoder state lives here.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, UdpError> {
        self.dgram_first = !self.dgram_first;
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.tunnel.abort(code)
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, UdpError>> {
        if let Some(r) = &self.end {
            return Poll::Ready(r.clone());
        }
        let mut busy = false;
        for dgram in [self.dgram_first, !self.dgram_first] {
            // Retry a carrier that made progress (a pushed chunk may complete a capsule),
            // a bounded number of times so a flood of dropped input cannot hog the poll.
            let mut steps = 0;
            loop {
                let r = if dgram {
                    self.poll_dgram(cx)
                } else {
                    self.poll_capsule(cx)
                };
                match r {
                    Poll::Ready(Some(r)) => {
                        // Errors are terminal too: the async layer reports an abort once.
                        if !matches!(r, Ok(Some(_))) {
                            self.end = Some(r.clone());
                        }
                        return Poll::Ready(r);
                    }
                    Poll::Ready(None) if steps < MAX_STEPS => steps += 1,
                    Poll::Ready(None) => {
                        busy = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
        if busy {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    /// `Ready(None)`: something was consumed but there is nothing to return yet.
    fn poll_dgram(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Option<Bytes>, UdpError>>> {
        let Some(d) = &mut self.dgrams else {
            return Poll::Pending;
        };
        let r = pin!(d.recv()).poll(cx);
        match r {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(Ok(None)) => {
                self.dgrams = None;
                Poll::Ready(None)
            }
            Poll::Ready(Ok(Some(b))) => match varint::decode(&b) {
                Some((0, n)) if b.len() - n > MAX_UDP_PAYLOAD => {
                    Poll::Ready(Some(Err(self.fail())))
                }
                Some((0, n)) => Poll::Ready(Some(Ok(Some(b.slice(n..))))),
                // Another context, or no context ID at all: dropped.
                _ => Poll::Ready(None),
            },
        }
    }

    fn poll_capsule(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Option<Bytes>, UdpError>>> {
        match self.capsules.next() {
            Err(_) => return Poll::Ready(Some(Err(self.fail()))),
            Ok(Some(p)) => return Poll::Ready(Some(Ok(Some(p)))),
            Ok(None) => {}
        }
        if self.eof {
            return Poll::Ready(Some(match self.capsules.dec.finish() {
                Ok(()) => Ok(None),
                Err(_) => Err(self.fail()),
            }));
        }
        match pin!(self.tunnel.recv()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(Ok(Some(b))) => {
                self.capsules.dec.push(b);
                Poll::Ready(None)
            }
            Poll::Ready(Ok(None)) => {
                self.eof = true;
                Poll::Ready(None)
            }
        }
    }

    /// Abort with `H3_MESSAGE_ERROR` (RFC 9298 section 5, RFC 9297 section 3.3); the
    /// error the caller sees.
    fn fail(&self) -> UdpError {
        self.tunnel.abort(H3Code::MESSAGE_ERROR);
        UdpError::Http(
            ErrorKind::StreamAborted {
                code: H3Code::MESSAGE_ERROR,
                source: AbortSource::Local,
                retryable: false,
            }
            .into(),
        )
    }
}

const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<UdpTunnel>();
    send_sync::<UdpSender>();
    send_sync::<UdpReceiver>();
};

/// Where the capsule decoder stands in the current capsule.
#[derive(Clone, Copy, Debug, Default)]
enum At {
    #[default]
    Head,
    /// A DATAGRAM capsule: its context ID is next.
    Context,
    /// Context ID 0 was consumed: the payload is next.
    Payload,
    /// Another capsule type or context: drop the rest.
    Skip,
}

/// The capsule carrier's receive state: plain data, so a cancelled `recv` loses nothing.
#[derive(Debug, Default)]
struct Capsules {
    dec: Decoder,
    at: At,
}

impl Capsules {
    /// The next context-0 payload the pushed bytes complete.
    fn next(&mut self) -> Result<Option<Bytes>, CapsuleError> {
        loop {
            match self.at {
                At::Head => match self.dec.next()? {
                    None => return Ok(None),
                    Some(h) if h.ty == DATAGRAM => self.at = At::Context,
                    Some(_) => self.at = At::Skip,
                },
                At::Context => match self.dec.peek_varint()? {
                    None => return Ok(None),
                    Some(0) => self.at = At::Payload,
                    Some(_) => self.at = At::Skip,
                },
                At::Payload => match self.dec.take(MAX_UDP_PAYLOAD)? {
                    None => return Ok(None),
                    Some(p) => {
                        self.at = At::Head;
                        return Ok(Some(p));
                    }
                },
                At::Skip => {
                    if !self.dec.skip()? {
                        return Ok(None);
                    }
                    self.at = At::Head;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(value: &[u8]) -> Bytes {
        let mut b = BytesMut::new();
        capsule::encode(DATAGRAM, value, &mut b).unwrap();
        b.freeze()
    }

    #[test]
    fn nonzero_context_capsule_never_buffered() {
        let mut c = Capsules::default();
        let big = cap(&[&[0x40, 0x64][..], &vec![9; 1 << 20]].concat());
        for part in big.chunks(4096) {
            c.dec.push(Bytes::copy_from_slice(part));
            assert_eq!(c.next(), Ok(None));
            assert_eq!(c.dec.buffered(), 0);
        }
        c.dec.push(cap(b"\x00ok"));
        assert_eq!(c.next(), Ok(Some(Bytes::from_static(b"ok"))));
        assert_eq!(c.dec.finish(), Ok(()));
    }

    #[test]
    fn oversized_context_zero_capsule_too_large() {
        let mut c = Capsules::default();
        c.dec.push(cap(&vec![0; MAX_UDP_PAYLOAD + 2]));
        assert_eq!(c.next(), Err(CapsuleError::TooLarge));
    }
}
