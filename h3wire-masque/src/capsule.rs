// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The HTTP capsule codec (RFC 9297 section 3.2).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3wire_async::core::varint;
use std::collections::VecDeque;
use std::fmt;

/// The DATAGRAM capsule type (RFC 9297 section 3.5).
pub const DATAGRAM: u64 = 0x00;

/// A capsule codec error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapsuleError {
    /// A type or length above the varint maximum, `2^62 - 1`.
    OutOfRange,
    /// A value larger than the caller's limit.
    TooLarge,
    /// The stream ended inside a capsule.
    Truncated,
    /// The value is shorter than its leading varint.
    Malformed,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutOfRange => "capsule type or length out of varint range",
            Self::TooLarge => "capsule value too large",
            Self::Truncated => "stream ended inside a capsule",
            Self::Malformed => "capsule value shorter than its leading varint",
        })
    }
}

impl std::error::Error for CapsuleError {}

/// The encoded size of a capsule with type `ty` and a value of `len` bytes.
pub fn encoded_len(ty: u64, len: u64) -> Result<usize, CapsuleError> {
    if ty > varint::MAX || len > varint::MAX {
        return Err(CapsuleError::OutOfRange);
    }
    usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_add(varint::len(ty) + varint::len(len)))
        .ok_or(CapsuleError::OutOfRange)
}

/// Append one capsule to `out`; on error `out` is unchanged.
pub fn encode(ty: u64, value: &[u8], out: &mut BytesMut) -> Result<(), CapsuleError> {
    let total = encoded_len(ty, value.len() as u64)?;
    out.reserve(total);
    let mut b = [0u8; 8];
    for v in [ty, value.len() as u64] {
        let n = varint::encode_to(v, &mut b);
        out.put_slice(&b[..n]);
    }
    out.put_slice(value);
    Ok(())
}

/// A capsule's type and value length, as soon as both are known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The capsule type.
    pub ty: u64,
    /// The value length in bytes.
    pub len: u64,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Head,
    /// Inside a value: bytes of it not yet consumed.
    Value {
        remaining: u64,
    },
}

/// Incremental capsule decoder. Feed it with [`push`](Self::push); [`next`](Self::next)
/// yields a [`Head`], then exactly one of [`take`](Self::take) or [`skip`](Self::skip)
/// (optionally after [`peek_varint`](Self::peek_varint)) consumes the value. Non-minimal
/// varints are accepted. Skipped values are never buffered.
#[derive(Debug)]
pub struct Decoder {
    chunks: VecDeque<Bytes>,
    buffered: usize,
    state: State,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            chunks: VecDeque::new(),
            buffered: 0,
            state: State::Head,
        }
    }
}

impl Decoder {
    /// Add bytes read from the stream.
    pub fn push(&mut self, b: Bytes) {
        self.buffered += b.len();
        if !b.is_empty() {
            self.chunks.push_back(b);
        }
    }

    /// Bytes pushed but not yet consumed.
    #[doc(hidden)]
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Copy up to `out.len()` bytes from the front without consuming; the count copied.
    fn peek_into(&self, out: &mut [u8]) -> usize {
        let mut n = 0;
        for c in &self.chunks {
            let k = c.len().min(out.len() - n);
            out[n..n + k].copy_from_slice(&c[..k]);
            n += k;
            if n == out.len() {
                break;
            }
        }
        n
    }

    fn consume(&mut self, mut n: usize) {
        self.buffered -= n;
        while n > 0 {
            let front = self.chunks.front_mut().expect("n <= buffered");
            let k = n.min(front.len());
            front.advance(k);
            n -= k;
            if front.is_empty() {
                self.chunks.pop_front();
            }
        }
    }

    /// The next capsule's head; `None` means more bytes are needed. A value the caller
    /// has not finished is skipped first.
    #[allow(clippy::should_implement_trait)] // fallible and stateful, not an Iterator
    pub fn next(&mut self) -> Result<Option<Head>, CapsuleError> {
        if matches!(self.state, State::Value { .. }) && !self.skip()? {
            return Ok(None);
        }
        let mut b = [0u8; 16];
        let have = self.peek_into(&mut b);
        let Some((ty, n)) = varint::decode(&b[..have]) else {
            return Ok(None);
        };
        let Some((len, m)) = varint::decode(&b[n..have]) else {
            return Ok(None);
        };
        self.consume(n + m);
        self.state = State::Value { remaining: len };
        Ok(Some(Head { ty, len }))
    }

    /// Consume one varint at the current position of the value; `None` means more bytes
    /// are needed. `Malformed` if the value ends before the varint does.
    pub fn peek_varint(&mut self) -> Result<Option<u64>, CapsuleError> {
        let State::Value { remaining } = self.state else {
            return Ok(None);
        };
        let mut b = [0u8; 8];
        let have = self.peek_into(&mut b);
        let Some(&first) = b[..have].first() else {
            return Ok(None);
        };
        let width = 1usize << (first >> 6);
        if remaining < width as u64 {
            return Err(CapsuleError::Malformed);
        }
        let Some((v, n)) = varint::decode(&b[..have]) else {
            return Ok(None);
        };
        self.consume(n);
        self.state = State::Value {
            remaining: remaining - n as u64,
        };
        Ok(Some(v))
    }

    /// The rest of the value (after any peeked varint) once all of it has arrived;
    /// `None` means more bytes are needed. `TooLarge` if it exceeds `max`, decided from
    /// the length alone, before anything is buffered.
    pub fn take(&mut self, max: usize) -> Result<Option<Bytes>, CapsuleError> {
        let State::Value { remaining } = self.state else {
            return Ok(None);
        };
        if remaining > max as u64 {
            return Err(CapsuleError::TooLarge);
        }
        // `remaining <= max` fits usize.
        let n = remaining as usize;
        if self.buffered < n {
            return Ok(None);
        }
        let out = match self.chunks.front() {
            _ if n == 0 => Bytes::new(),
            Some(f) if f.len() >= n => f.slice(..n),
            _ => {
                let mut buf = vec![0u8; n];
                self.peek_into(&mut buf);
                Bytes::from(buf)
            }
        };
        self.consume(n);
        self.state = State::Head;
        Ok(Some(out))
    }

    /// `true` once the rest of the value has been dropped, without buffering it.
    pub fn skip(&mut self) -> Result<bool, CapsuleError> {
        let State::Value { remaining } = self.state else {
            return Ok(false);
        };
        let n = remaining.min(self.buffered as u64);
        self.consume(n as usize);
        if n == remaining {
            self.state = State::Head;
            return Ok(true);
        }
        self.state = State::Value {
            remaining: remaining - n,
        };
        Ok(false)
    }

    /// At a clean end of stream: `Truncated` unless it fell between capsules.
    pub fn finish(&self) -> Result<(), CapsuleError> {
        match self.state {
            State::Head if self.buffered == 0 => Ok(()),
            State::Value { remaining: 0 } => Ok(()),
            _ => Err(CapsuleError::Truncated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn wire(caps: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = BytesMut::new();
        for (ty, v) in caps {
            encode(*ty, v, &mut out).unwrap();
        }
        out.to_vec()
    }

    /// Drive `d` as far as the pushed bytes allow, taking every value.
    fn drain(d: &mut Decoder, cur: &mut Option<Head>, out: &mut Vec<(u64, Bytes)>) {
        loop {
            match *cur {
                None => match d.next().unwrap() {
                    Some(h) => *cur = Some(h),
                    None => return,
                },
                Some(h) => match d.take(usize::MAX).unwrap() {
                    Some(v) => {
                        out.push((h.ty, v));
                        *cur = None;
                    }
                    None => return,
                },
            }
        }
    }

    #[test]
    fn encode_rejects_out_of_range() {
        let mut out = BytesMut::from(&b"x"[..]);
        assert_eq!(
            encode(1 << 62, b"v", &mut out),
            Err(CapsuleError::OutOfRange)
        );
        assert_eq!(&out[..], b"x");
        assert_eq!(encoded_len(0, 1 << 62), Err(CapsuleError::OutOfRange));
        encode((1 << 62) - 1, b"v", &mut out).unwrap();
        assert_eq!(encoded_len(0, 5), Ok(7));
    }

    proptest! {
        #[test]
        fn decode_split_everywhere(
            caps in prop::collection::vec(
                (prop_oneof![Just(0u64), 0..70_000u64, Just((1u64 << 62) - 1)],
                 prop::collection::vec(any::<u8>(), 0..200)),
                0..6),
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8),
        ) {
            let w = wire(&caps);
            let mut at: Vec<usize> = cuts.iter().map(|i| i.index(w.len() + 1)).collect();
            at.push(0);
            at.push(w.len());
            at.sort();
            let (mut d, mut cur, mut got) = (Decoder::default(), None, Vec::new());
            for p in at.windows(2) {
                d.push(Bytes::copy_from_slice(&w[p[0]..p[1]]));
                drain(&mut d, &mut cur, &mut got);
            }
            let want: Vec<_> = caps.iter().map(|(t, v)| (*t, Bytes::from(v.clone()))).collect();
            prop_assert_eq!(got, want);
            prop_assert_eq!(d.finish(), Ok(()));
        }
    }

    #[test]
    fn unknown_skipped_unbuffered() {
        let mut w = BytesMut::new();
        encode(0x2a, &vec![7u8; 1 << 20], &mut w).unwrap();
        encode(DATAGRAM, b"after", &mut w).unwrap();
        let w = w.freeze();
        let mut d = Decoder::default();
        let mut peak = 0;
        let mut head = None;
        let mut got = None;
        for chunk in w.chunks(4096) {
            d.push(Bytes::copy_from_slice(chunk));
            peak = peak.max(d.buffered());
            loop {
                match head {
                    None => match d.next().unwrap() {
                        Some(h) => head = Some(h),
                        None => break,
                    },
                    Some(h) if h.ty == 0x2a => {
                        if !d.skip().unwrap() {
                            break;
                        }
                        head = None;
                    }
                    Some(_) => match d.take(100).unwrap() {
                        Some(v) => {
                            got = Some(v);
                            head = None;
                        }
                        None => break,
                    },
                }
            }
            // Everything but an unfinished head or a taken value is dropped at once.
            assert!(d.buffered() <= 16 + 5, "retained {}", d.buffered());
        }
        assert_eq!(peak, 4096);
        assert_eq!(got.as_deref(), Some(&b"after"[..]));
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn non_minimal_varints_accepted() {
        // Type 0x2a, length 3, and a leading value varint 5, each as 8 bytes.
        let eight = |v: u8| [0xc0, 0, 0, 0, 0, 0, 0, v];
        let mut w = eight(0x2a).to_vec();
        w.extend(eight(8));
        w.extend(eight(5));
        let mut d = Decoder::default();
        d.push(Bytes::from(w));
        assert_eq!(d.next(), Ok(Some(Head { ty: 0x2a, len: 8 })));
        assert_eq!(d.peek_varint(), Ok(Some(5)));
        assert_eq!(d.take(0), Ok(Some(Bytes::new())));
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn truncated_at_eof() {
        let mut w = BytesMut::new();
        encode(0x2a, b"abcd", &mut w).unwrap();
        let mut d = Decoder::default();
        assert_eq!(d.finish(), Ok(()));
        // Inside the head: type present, length missing.
        d.push(Bytes::copy_from_slice(&[0x40, 0x2a]));
        assert_eq!(d.next(), Ok(None));
        assert_eq!(d.finish(), Err(CapsuleError::Truncated));
        let mut d = Decoder::default();
        d.push(w.clone().freeze().slice(..4));
        assert!(d.next().unwrap().is_some());
        assert_eq!(d.take(10), Ok(None));
        assert_eq!(d.finish(), Err(CapsuleError::Truncated));
        let mut d = Decoder::default();
        d.push(w.freeze());
        d.next().unwrap();
        assert_eq!(d.skip(), Ok(true));
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn take_too_large_before_buffering() {
        let mut d = Decoder::default();
        let mut w = BytesMut::new();
        encode(DATAGRAM, &[0; 100], &mut w).unwrap();
        // Head plus 2 value bytes only: the verdict does not wait for the rest.
        d.push(w.freeze().slice(..5));
        assert_eq!(d.next(), Ok(Some(Head { ty: 0, len: 100 })));
        assert_eq!(d.take(99), Err(CapsuleError::TooLarge));
        assert_eq!(d.buffered(), 2);
        assert_eq!(d.skip(), Ok(false));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn peek_varint_split() {
        // Value: a 4-byte varint (494878333) then "xy"; pushed a byte at a time.
        let mut w = BytesMut::new();
        encode(DATAGRAM, &[0x9d, 0x7f, 0x3e, 0x7d, b'x', b'y'], &mut w).unwrap();
        let mut d = Decoder::default();
        let (mut head, mut v, mut rest) = (None, None, None);
        for b in w.iter() {
            d.push(Bytes::copy_from_slice(&[*b]));
            if head.is_none() {
                head = d.next().unwrap();
            }
            if head.is_some() && v.is_none() {
                v = d.peek_varint().unwrap();
            }
            if v.is_some() && rest.is_none() {
                rest = d.take(usize::MAX).unwrap();
            }
        }
        assert_eq!(v, Some(494_878_333));
        assert_eq!(rest.as_deref(), Some(&b"xy"[..]));
        // A value shorter than its varint.
        let mut d = Decoder::default();
        d.push(Bytes::from_static(&[0x00, 0x01, 0x40]));
        d.next().unwrap();
        assert_eq!(d.peek_varint(), Err(CapsuleError::Malformed));
    }
}
