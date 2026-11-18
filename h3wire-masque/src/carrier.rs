// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The carrier shared by the MASQUE tunnels: HTTP Datagrams or DATAGRAM capsules with
//! context ID 0, the SETTINGS wait at open, fair polling of the two receive sources, and
//! sticky EOF and errors. Callers decide what a payload means and which capsules besides
//! DATAGRAM they want whole.

use crate::capsule::{self, CapsuleError, DATAGRAM, Decoder};
use crate::tunnel::Carrier;
use bytes::{Bytes, BytesMut};
use h3wire_async::core::{AbortSource, H3Code, varint};
use h3wire_async::datagram::{DatagramReceiver, DatagramSender, Datagrams};
use h3wire_async::upgrade::{Tunnel, TunnelRecv, TunnelSend};
use h3wire_async::{DatagramError, Error, ErrorKind};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::{Context, Poll};

/// Progress steps per carrier in one `recv` poll before yielding.
const MAX_STEPS: usize = 32;

/// Stream bytes a tunnel buffers while it waits for the peer's SETTINGS; past this it
/// stops waiting and carries capsules.
const SETTINGS_WAIT_BYTES: usize = 64 * 1024;

/// What a tunnel type accepts.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // `control` and `max_control` are used by IpTunnel
pub(crate) struct Limits {
    /// The largest context-0 payload.
    pub(crate) max_payload: usize,
    /// Which non-DATAGRAM capsule types are taken whole; all others are skipped unbuffered.
    pub(crate) control: fn(u64) -> bool,
    /// The largest value of a `control` capsule.
    pub(crate) max_control: usize,
}

/// One item from a receive source, before the caller's policy.
#[derive(Debug)]
#[allow(dead_code)] // `Control` is used by IpTunnel
pub(crate) enum Raw {
    /// A context-0 payload within the limit.
    Payload(Bytes),
    /// A context-0 payload over `max_payload` (a capsule's is skipped unbuffered).
    Oversized,
    /// A datagram or DATAGRAM capsule with another context ID, or none.
    OtherContext,
    /// A whole non-DATAGRAM capsule the `control` limit accepts.
    Control { ty: u64, value: Bytes },
}

/// What the caller does with a [`Raw`].
pub(crate) enum Step<T> {
    /// Return this from `recv`.
    Yield(T),
    /// Drop the item; it counts as a progress step.
    Drop,
    /// Abort the request with this code; the same local abort is returned from now on.
    Fail(H3Code),
}

/// Why a send failed.
#[derive(Debug)]
pub(crate) enum TxError {
    /// The sending side was finished, or the request ended.
    Closed,
    /// The datagram carrier refused the payload.
    Datagram(DatagramError),
    /// The request stream or connection failed.
    Http(Error),
}

impl From<Error> for TxError {
    fn from(e: Error) -> Self {
        Self::Http(e)
    }
}

/// Wait for `settings` (`true`: the peer's SETTINGS arrived) to choose the carrier. The
/// stream is read meanwhile, so the wait cannot outlive the request: its bytes go to the
/// capsule decoder, a reset or error is returned, and a FIN or more than
/// [`SETTINGS_WAIT_BYTES`] received settles without SETTINGS (capsule carrier).
pub(crate) async fn open(
    tunnel: Tunnel,
    dgrams: Option<Datagrams>,
    settings: impl Future<Output = bool>,
    limits: Limits,
) -> Result<(Tx, Rx), Error> {
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
    Ok((
        Tx {
            tunnel: tx,
            dgrams: dtx,
            finished: false,
        },
        Rx {
            tunnel: rx,
            dgrams: drx,
            capsules,
            limits,
            dgram_first: false,
            eof,
            end: None,
        },
    ))
}

/// The sending half of a carrier.
#[derive(Debug)]
pub(crate) struct Tx {
    tunnel: TunnelSend,
    /// `Some` iff the carrier is datagrams.
    dgrams: Option<DatagramSender>,
    finished: bool,
}

impl Tx {
    /// Send `payload` under context ID 0, as a datagram or one DATAGRAM capsule. No size
    /// check. Cancel-safe: a dropped pending send wrote nothing.
    pub(crate) async fn send_payload(&mut self, payload: Bytes) -> Result<(), TxError> {
        if self.finished {
            return Err(TxError::Closed);
        }
        // Context ID 0, one byte.
        let value = Bytes::from([&[0][..], &payload].concat());
        if let Some(d) = &self.dgrams {
            return d.send(value).map_err(|e| match e {
                DatagramError::Closed => TxError::Closed,
                e => TxError::Datagram(e),
            });
        }
        let mut b = BytesMut::new();
        capsule::encode(DATAGRAM, &value, &mut b).expect("within varint range");
        self.send_capsule(b.freeze()).await
    }

    /// Write an already framed capsule (type, length, value) as is. One
    /// `TunnelSend::send` call takes the `Bytes` whole or not at all, so a cancelled send
    /// never leaves half a capsule on the stream.
    #[allow(dead_code)] // used by IpTunnel
    pub(crate) async fn send_capsule(&mut self, capsule: Bytes) -> Result<(), TxError> {
        if self.finished {
            return Err(TxError::Closed);
        }
        Ok(self.tunnel.send(capsule).await?)
    }

    /// Finish the stream after everything sent so far.
    pub(crate) fn finish(&mut self) -> Result<(), TxError> {
        self.tunnel.finish()?;
        self.finished = true;
        Ok(())
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub(crate) fn abort(&self, code: H3Code) {
        self.tunnel.abort(code)
    }

    /// The largest payload [`send_payload`](Self::send_payload) takes now: the datagram
    /// limit minus the context ID byte, at most `cap`; `Some(cap)` for the capsule
    /// carrier. `None` with datagrams when the limit is unknown or leaves no room.
    pub(crate) fn max_payload(&self, cap: usize) -> Option<usize> {
        match &self.dgrams {
            Some(d) => d.max_payload()?.checked_sub(1).map(|n| n.min(cap)),
            None => Some(cap),
        }
    }

    /// The carrier chosen at open.
    pub(crate) fn carrier(&self) -> Carrier {
        match self.dgrams {
            Some(_) => Carrier::Datagram,
            None => Carrier::Capsule,
        }
    }
}

/// The receiving half of a carrier.
#[derive(Debug)]
pub(crate) struct Rx {
    tunnel: TunnelRecv,
    /// `None` without datagrams or once the handle ended.
    dgrams: Option<DatagramReceiver>,
    capsules: Capsules,
    limits: Limits,
    /// Which carrier the next `recv` polls first.
    dgram_first: bool,
    /// The tunnel's FIN arrived.
    eof: bool,
    /// The terminal result (`Ok(())` for EOF, or an error), repeated after.
    end: Option<Result<(), Error>>,
}

type Polled<T> = Poll<Option<Result<Option<T>, Error>>>;

impl Rx {
    /// Flip which carrier is polled first; call once per `recv`.
    pub(crate) fn start(&mut self) {
        self.dgram_first = !self.dgram_first;
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub(crate) fn abort(&self, code: H3Code) {
        self.tunnel.abort(code)
    }

    /// The next item `on` yields from either carrier; `Ok(None)` once the peer finished
    /// the stream on a capsule boundary. Cancel-safe: the decoder state lives here.
    pub(crate) fn poll_recv<T>(
        &mut self,
        cx: &mut Context<'_>,
        mut on: impl FnMut(Raw) -> Step<T>,
    ) -> Poll<Result<Option<T>, Error>> {
        if let Some(r) = &self.end {
            return Poll::Ready(r.clone().map(|()| None));
        }
        let dgram_first = self.dgram_first;
        let r = poll_fair(dgram_first, cx, |dgram, cx| {
            if dgram {
                self.poll_dgram(cx, &mut on)
            } else {
                self.poll_capsule(cx, &mut on)
            }
        });
        // Errors are terminal too: the async layer reports an abort once.
        if let Poll::Ready(r) = &r {
            match r {
                Ok(None) => self.end = Some(Ok(())),
                Err(e) => self.end = Some(Err(e.clone())),
                Ok(Some(_)) => {}
            }
        }
        r
    }

    /// `Ready(None)`: something was consumed but there is nothing to return yet.
    fn poll_dgram<T>(
        &mut self,
        cx: &mut Context<'_>,
        on: &mut impl FnMut(Raw) -> Step<T>,
    ) -> Polled<T> {
        let Some(d) = &mut self.dgrams else {
            return Poll::Pending;
        };
        let r = pin!(d.recv()).poll(cx);
        match r {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(None)) => {
                self.dgrams = None;
                Poll::Ready(None)
            }
            Poll::Ready(Ok(Some(b))) => {
                let raw = match varint::decode(&b) {
                    Some((0, n)) if b.len() - n > self.limits.max_payload => Raw::Oversized,
                    Some((0, n)) => Raw::Payload(b.slice(n..)),
                    // Another context, or no context ID at all.
                    _ => Raw::OtherContext,
                };
                self.step(raw, on)
            }
        }
    }

    fn poll_capsule<T>(
        &mut self,
        cx: &mut Context<'_>,
        on: &mut impl FnMut(Raw) -> Step<T>,
    ) -> Polled<T> {
        match self.capsules.next(&self.limits) {
            Err(code) => return Poll::Ready(Some(Err(self.fail(code)))),
            Ok(Some(raw)) => return self.step(raw, on),
            Ok(None) => {}
        }
        if self.eof {
            return Poll::Ready(Some(match self.capsules.dec.finish() {
                Ok(()) => Ok(None),
                Err(_) => Err(self.fail(H3Code::MESSAGE_ERROR)),
            }));
        }
        match pin!(self.tunnel.recv()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
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

    fn step<T>(&self, raw: Raw, on: &mut impl FnMut(Raw) -> Step<T>) -> Polled<T> {
        match on(raw) {
            Step::Yield(t) => Poll::Ready(Some(Ok(Some(t)))),
            Step::Drop => Poll::Ready(None),
            Step::Fail(code) => Poll::Ready(Some(Err(self.fail(code)))),
        }
    }

    /// Abort with `code`; the error the caller sees.
    fn fail(&self, code: H3Code) -> Error {
        self.tunnel.abort(code);
        ErrorKind::StreamAborted {
            code,
            source: AbortSource::Local,
            retryable: false,
        }
        .into()
    }
}

/// Poll both sources, `dgram_first` first. `poll_one(true)` is the datagram source.
/// A source that made progress is retried a bounded number of times (a pushed chunk may
/// complete a capsule), so a flood of dropped input cannot hog the poll.
fn poll_fair<R>(
    dgram_first: bool,
    cx: &mut Context<'_>,
    mut poll_one: impl FnMut(bool, &mut Context<'_>) -> Poll<Option<R>>,
) -> Poll<R> {
    let mut busy = false;
    for dgram in [dgram_first, !dgram_first] {
        let mut steps = 0;
        loop {
            match poll_one(dgram, cx) {
                Poll::Ready(Some(r)) => return Poll::Ready(r),
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

/// Where the capsule decoder stands in the current capsule.
#[derive(Clone, Copy, Debug, Default)]
enum At {
    #[default]
    Head,
    /// A DATAGRAM capsule: its context ID is next.
    Context,
    /// Context ID 0 was consumed: the payload is next.
    Payload,
    /// A `control` capsule of this type: its whole value is next.
    Control(u64),
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
    /// The next item the pushed bytes complete; `Err` is the abort code.
    fn next(&mut self, lim: &Limits) -> Result<Option<Raw>, H3Code> {
        let bad = |_: CapsuleError| H3Code::MESSAGE_ERROR;
        loop {
            match self.at {
                At::Head => match self.dec.next().map_err(bad)? {
                    None => return Ok(None),
                    Some(h) if h.ty == DATAGRAM => self.at = At::Context,
                    Some(h) if (lim.control)(h.ty) => self.at = At::Control(h.ty),
                    Some(_) => self.at = At::Skip,
                },
                At::Context => match self.dec.peek_varint().map_err(bad)? {
                    None => return Ok(None),
                    Some(0) => self.at = At::Payload,
                    Some(_) => {
                        self.at = At::Skip;
                        return Ok(Some(Raw::OtherContext));
                    }
                },
                At::Payload => match self.dec.take(lim.max_payload) {
                    Ok(None) => return Ok(None),
                    Ok(Some(p)) => {
                        self.at = At::Head;
                        return Ok(Some(Raw::Payload(p)));
                    }
                    Err(CapsuleError::TooLarge) => {
                        self.at = At::Skip;
                        return Ok(Some(Raw::Oversized));
                    }
                    Err(e) => return Err(bad(e)),
                },
                At::Control(ty) => match self.dec.take(lim.max_control) {
                    Ok(None) => return Ok(None),
                    Ok(Some(value)) => {
                        self.at = At::Head;
                        return Ok(Some(Raw::Control { ty, value }));
                    }
                    Err(CapsuleError::TooLarge) => return Err(H3Code::EXCESSIVE_LOAD),
                    Err(e) => return Err(bad(e)),
                },
                At::Skip => {
                    if !self.dec.skip().map_err(bad)? {
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
    use std::task::Waker;

    const LIMITS: Limits = Limits {
        max_payload: 100,
        control: |ty| ty == 1,
        max_control: 64 * 1024,
    };

    fn cap(ty: u64, value: &[u8]) -> Bytes {
        let mut b = BytesMut::new();
        capsule::encode(ty, value, &mut b).unwrap();
        b.freeze()
    }

    /// Everything `next` yields until it needs more bytes.
    fn drain(c: &mut Capsules) -> Vec<Raw> {
        let mut out = Vec::new();
        while let Some(r) = c.next(&LIMITS).unwrap() {
            out.push(r);
        }
        out
    }

    #[test]
    fn nonzero_context_capsule_never_buffered() {
        let mut c = Capsules::default();
        let big = cap(DATAGRAM, &[&[0x40, 0x64][..], &vec![9; 1 << 20]].concat());
        for part in big.chunks(4096) {
            c.dec.push(Bytes::copy_from_slice(part));
            assert!(drain(&mut c).iter().all(|r| matches!(r, Raw::OtherContext)));
            assert_eq!(c.dec.buffered(), 0);
        }
        c.dec.push(cap(DATAGRAM, b"\x00ok"));
        assert!(matches!(c.next(&LIMITS), Ok(Some(Raw::Payload(p))) if p == "ok"));
        assert_eq!(c.dec.finish(), Ok(()));
    }

    #[test]
    fn oversized_payload_reported_not_buffered() {
        let mut c = Capsules::default();
        let big = cap(DATAGRAM, &[0; 102]);
        c.dec.push(big.slice(..4));
        assert!(matches!(c.next(&LIMITS), Ok(Some(Raw::Oversized))));
        assert!(c.dec.buffered() < 16);
        c.dec.push(big.slice(4..));
        c.dec.push(cap(DATAGRAM, b"\x00ok"));
        assert!(matches!(c.next(&LIMITS), Ok(Some(Raw::Payload(p))) if p == "ok"));
    }

    #[test]
    fn control_capsule_taken_whole() {
        let mut c = Capsules::default();
        let wire = cap(1, b"hello");
        for byte in wire.iter() {
            c.dec.push(Bytes::copy_from_slice(&[*byte]));
        }
        let got = drain(&mut c);
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0], Raw::Control { ty: 1, value } if value == "hello"));
    }

    #[test]
    fn control_capsule_over_bound_is_excessive_load() {
        let mut c = Capsules::default();
        let wire = cap(1, &vec![0; 64 * 1024 + 1]);
        c.dec.push(wire.slice(..8));
        assert_eq!(c.next(&LIMITS).err(), Some(H3Code::EXCESSIVE_LOAD));
        assert!(c.dec.buffered() < 16);
    }

    #[test]
    fn unknown_capsule_skipped_unbuffered() {
        let mut c = Capsules::default();
        let big = cap(7, &vec![9; 1 << 20]);
        for part in big.chunks(4096) {
            c.dec.push(Bytes::copy_from_slice(part));
            assert!(c.next(&LIMITS).unwrap().is_none());
            assert_eq!(c.dec.buffered(), 0);
        }
        c.dec.push(cap(DATAGRAM, b"\x00ok"));
        assert!(matches!(c.next(&LIMITS), Ok(Some(Raw::Payload(p))) if p == "ok"));
    }

    #[test]
    fn dropped_steps_yield_to_other_carrier() {
        let mut cx = Context::from_waker(Waker::noop());
        // The datagram source always has an item to drop; the stream has a result.
        let mut polled = Vec::new();
        let r = poll_fair(true, &mut cx, |dgram, _| {
            polled.push(dgram);
            if dgram {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some("eof"))
            }
        });
        assert_eq!(r, Poll::Ready("eof"));
        assert_eq!(polled.iter().filter(|d| **d).count(), MAX_STEPS + 1);
        assert_eq!(polled.last(), Some(&false));
    }
}
