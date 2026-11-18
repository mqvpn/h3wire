// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The CONNECT-IP control capsules (RFC 9484 section 4.7).
//!
//! Encoders append one complete capsule (type, length, value); decoders take the capsule
//! value only, as handed out by [`crate::capsule::Decoder`].

use super::prefix::num;
use super::{IpPrefix, IpRange};
use crate::capsule::{self, CapsuleError};
use bytes::BytesMut;
use h3wire_async::core::varint;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

/// The ADDRESS_ASSIGN capsule type.
pub const ADDRESS_ASSIGN: u64 = 0x01;
/// The ADDRESS_REQUEST capsule type.
pub const ADDRESS_REQUEST: u64 = 0x02;
/// The ROUTE_ADVERTISEMENT capsule type.
pub const ROUTE_ADVERTISEMENT: u64 = 0x03;
/// The largest control capsule value, in bytes.
pub const MAX_CONTROL_CAPSULE: usize = 64 * 1024;

/// One entry of an ADDRESS_ASSIGN capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    /// The request this answers, or 0 for an unsolicited assignment.
    pub request_id: u64,
    /// The assigned prefix.
    pub prefix: IpPrefix,
}

impl AssignedAddress {
    /// The entry that rejects request `request_id`: `0.0.0.0/32` or `::/128`.
    pub fn rejection(request_id: NonZeroU64, v6: bool) -> Self {
        let addr = if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        Self {
            request_id: request_id.get(),
            prefix: IpPrefix::host(addr),
        }
    }

    /// Whether this entry rejects a request: a non-zero ID with an all-zero host prefix.
    pub fn is_rejection(&self) -> bool {
        self.request_id != 0 && self.prefix.addr().is_unspecified() && {
            let (w, _) = num(self.prefix.addr());
            self.prefix.prefix_len() == w
        }
    }
}

/// One entry of an ADDRESS_REQUEST capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedAddress {
    /// The request ID; never 0.
    pub request_id: NonZeroU64,
    /// The requested prefix.
    pub prefix: IpPrefix,
}

/// Why [`encode_routes`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteError {
    /// Two ranges overlap (same protocol, or protocol 0 with another).
    Overlap,
    /// The capsule could not be built.
    Capsule(CapsuleError),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overlap => f.write_str("overlapping route ranges"),
            Self::Capsule(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RouteError {}

impl From<CapsuleError> for RouteError {
    fn from(e: CapsuleError) -> Self {
        Self::Capsule(e)
    }
}

fn put_varint(v: u64, out: &mut Vec<u8>) {
    let mut b = [0u8; 8];
    let n = varint::encode_to(v, &mut b);
    out.extend_from_slice(&b[..n]);
}

fn put_addr(a: IpAddr, out: &mut Vec<u8>) {
    match a {
        IpAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(6);
            out.extend_from_slice(&a.octets());
        }
    }
}

fn finish(ty: u64, value: &[u8], out: &mut BytesMut) -> Result<(), CapsuleError> {
    if value.len() > MAX_CONTROL_CAPSULE {
        return Err(CapsuleError::TooLarge);
    }
    capsule::encode(ty, value, out)
}

fn encode_addresses(
    ty: u64,
    entries: impl Iterator<Item = (u64, IpPrefix)>,
    out: &mut BytesMut,
) -> Result<(), CapsuleError> {
    let mut v = Vec::new();
    for (id, p) in entries {
        if id > varint::MAX {
            return Err(CapsuleError::OutOfRange);
        }
        put_varint(id, &mut v);
        put_addr(p.addr(), &mut v);
        v.push(p.prefix_len());
    }
    finish(ty, &v, out)
}

/// Append an ADDRESS_ASSIGN capsule. An empty list is legal.
pub fn encode_address_assign(
    entries: &[AssignedAddress],
    out: &mut BytesMut,
) -> Result<(), CapsuleError> {
    encode_addresses(
        ADDRESS_ASSIGN,
        entries.iter().map(|e| (e.request_id, e.prefix)),
        out,
    )
}

/// Append an ADDRESS_REQUEST capsule; an empty list is `Malformed`.
pub fn encode_address_request(
    entries: &[RequestedAddress],
    out: &mut BytesMut,
) -> Result<(), CapsuleError> {
    if entries.is_empty() {
        return Err(CapsuleError::Malformed);
    }
    encode_addresses(
        ADDRESS_REQUEST,
        entries.iter().map(|e| (e.request_id.get(), e.prefix)),
        out,
    )
}

fn is_v6(r: &IpRange) -> bool {
    r.start().is_ipv6()
}

fn sort_key(r: &IpRange) -> (bool, u8, u128) {
    (is_v6(r), r.ipproto(), num(r.start()).1)
}

/// Whether `routes` obey the section 4.7.3 order, overlap nowhere within a protocol, and
/// never overlap a protocol-0 range with another protocol (an extra rule of ours).
fn routes_valid(routes: &[IpRange]) -> bool {
    for w in routes.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        let (ka, kb) = (sort_key(a), sort_key(b));
        let ok = if (ka.0, ka.1) == (kb.0, kb.1) {
            num(a.end()).1 < kb.2
        } else {
            (ka.0, ka.1) < (kb.0, kb.1)
        };
        if !ok {
            return false;
        }
    }
    // Per family, the protocol-0 ranges come first and are disjoint, so their ends ascend.
    let split = routes.partition_point(|r| !is_v6(r));
    for fam in [&routes[..split], &routes[split..]] {
        let z = fam.partition_point(|r| r.ipproto() == 0);
        let (zeros, rest) = fam.split_at(z);
        for r in rest {
            let (s, e) = (num(r.start()).1, num(r.end()).1);
            let i = zeros.partition_point(|x| num(x.end()).1 < s);
            if zeros.get(i).is_some_and(|x| num(x.start()).1 <= e) {
                return false;
            }
        }
    }
    true
}

/// Append a ROUTE_ADVERTISEMENT capsule, sorting `routes` into wire order first.
/// `Overlap` if any two ranges overlap (see the module rules).
pub fn encode_routes(routes: &[IpRange], out: &mut BytesMut) -> Result<(), RouteError> {
    let mut sorted = routes.to_vec();
    sorted.sort_by_key(sort_key);
    if !routes_valid(&sorted) {
        return Err(RouteError::Overlap);
    }
    let mut v = Vec::new();
    for r in &sorted {
        put_addr(r.start(), &mut v);
        // The end address follows without its own version byte.
        let e = match r.end() {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        v.extend_from_slice(&e);
        v.push(r.ipproto());
    }
    Ok(finish(ROUTE_ADVERTISEMENT, &v, out)?)
}

/// A cursor over a capsule value; every shortfall is `Malformed`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CapsuleError> {
        let (h, t) = self.0.split_at_checked(n).ok_or(CapsuleError::Malformed)?;
        self.0 = t;
        Ok(h)
    }

    fn u8(&mut self) -> Result<u8, CapsuleError> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, CapsuleError> {
        let (v, n) = varint::decode(self.0).ok_or(CapsuleError::Malformed)?;
        self.take(n)?;
        Ok(v)
    }

    fn addr(&mut self, v6: bool) -> Result<IpAddr, CapsuleError> {
        Ok(if v6 {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(self.take(16)?).unwrap(),
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap()))
        })
    }

    fn version(&mut self) -> Result<bool, CapsuleError> {
        match self.u8()? {
            4 => Ok(false),
            6 => Ok(true),
            _ => Err(CapsuleError::Malformed),
        }
    }
}

fn decode_addresses(value: &[u8]) -> Result<Vec<(u64, IpPrefix)>, CapsuleError> {
    let mut r = Reader(value);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let id = r.varint()?;
        let v6 = r.version()?;
        let addr = r.addr(v6)?;
        let len = r.u8()?;
        let p = IpPrefix::new(addr, len).map_err(|_| CapsuleError::Malformed)?;
        out.push((id, p));
    }
    Ok(out)
}

/// Decode the value of an ADDRESS_ASSIGN capsule.
pub fn decode_address_assign(value: &[u8]) -> Result<Vec<AssignedAddress>, CapsuleError> {
    Ok(decode_addresses(value)?
        .into_iter()
        .map(|(request_id, prefix)| AssignedAddress { request_id, prefix })
        .collect())
}

/// Decode the value of an ADDRESS_REQUEST capsule; request ID 0 or no entries is `Malformed`.
pub fn decode_address_request(value: &[u8]) -> Result<Vec<RequestedAddress>, CapsuleError> {
    let v = decode_addresses(value)?
        .into_iter()
        .map(|(id, prefix)| {
            Ok(RequestedAddress {
                request_id: NonZeroU64::new(id).ok_or(CapsuleError::Malformed)?,
                prefix,
            })
        })
        .collect::<Result<Vec<_>, CapsuleError>>()?;
    if v.is_empty() {
        return Err(CapsuleError::Malformed);
    }
    Ok(v)
}

/// Decode the value of a ROUTE_ADVERTISEMENT capsule, enforcing the wire order and the
/// overlap rules; any violation is `Malformed`.
pub fn decode_routes(value: &[u8]) -> Result<Vec<IpRange>, CapsuleError> {
    let mut r = Reader(value);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let v6 = r.version()?;
        let (s, e) = (r.addr(v6)?, r.addr(v6)?);
        let proto = r.u8()?;
        out.push(IpRange::new(s, e, proto).map_err(|_| CapsuleError::Malformed)?);
    }
    if !routes_valid(&out) {
        return Err(CapsuleError::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str, len: u8) -> IpPrefix {
        IpPrefix::new(ip(s), len).unwrap()
    }

    fn nz(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    fn rng(a: &str, b: &str, p: u8) -> IpRange {
        IpRange::new(ip(a), ip(b), p).unwrap()
    }

    /// Frame through the stream decoder and return (type, value).
    fn unframe(w: &[u8]) -> (u64, Bytes) {
        let mut d = capsule::Decoder::default();
        d.push(Bytes::copy_from_slice(w));
        let h = d.next().unwrap().unwrap();
        let v = d.take(usize::MAX).unwrap().unwrap();
        assert_eq!(d.finish(), Ok(()));
        (h.ty, v)
    }

    fn routes_bytes(rs: &[IpRange]) -> Result<Vec<u8>, RouteError> {
        let mut o = BytesMut::new();
        encode_routes(rs, &mut o)?;
        Ok(o.to_vec())
    }

    #[test]
    fn assign_round_trip_bytes() {
        let es = [
            AssignedAddress {
                request_id: 0,
                prefix: pfx("192.0.2.1", 32),
            },
            AssignedAddress {
                request_id: 5,
                prefix: pfx("2001:db8::", 32),
            },
        ];
        let mut o = BytesMut::new();
        encode_address_assign(&es, &mut o).unwrap();
        let mut want = vec![0x01, 7 + 19, 0, 4, 192, 0, 2, 1, 32, 5, 6];
        want.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        want.extend_from_slice(&[0; 12]);
        want.push(32);
        assert_eq!(&o[..], &want[..]);
        let (ty, v) = unframe(&o);
        assert_eq!(ty, ADDRESS_ASSIGN);
        assert_eq!(decode_address_assign(&v).unwrap(), es);
    }

    #[test]
    fn rejection_entries() {
        let a = AssignedAddress::rejection(nz(7), false);
        let b = AssignedAddress::rejection(nz(7), true);
        assert_eq!((a.prefix, b.prefix), (pfx("0.0.0.0", 32), pfx("::", 128)));
        assert!(a.is_rejection() && b.is_rejection());
        let zero_id = AssignedAddress {
            request_id: 0,
            prefix: pfx("0.0.0.0", 32),
        };
        assert!(!zero_id.is_rejection());
        let not = AssignedAddress {
            request_id: 7,
            prefix: pfx("0.0.0.0", 24),
        };
        assert!(!not.is_rejection());
    }

    #[test]
    fn assign_empty_is_legal() {
        let mut o = BytesMut::new();
        encode_address_assign(&[], &mut o).unwrap();
        assert_eq!(&o[..], &[0x01, 0]);
        assert_eq!(decode_address_assign(&[]), Ok(vec![]));
    }

    #[test]
    fn decode_malformed() {
        let good = [0u8, 4, 192, 0, 2, 1, 32];
        assert!(decode_address_assign(&good).is_ok());
        let m = CapsuleError::Malformed;
        let mut bad = good;
        bad[1] = 5;
        assert_eq!(decode_address_assign(&bad).unwrap_err(), m);
        assert_eq!(decode_address_assign(&good[..6]).unwrap_err(), m);
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(decode_address_assign(&long).unwrap_err(), m);
        let mut bad = good;
        bad[6] = 33;
        assert_eq!(decode_address_assign(&bad).unwrap_err(), m);
        let mut v6 = vec![0u8, 6];
        v6.extend_from_slice(&[0; 16]);
        v6.push(129);
        assert_eq!(decode_address_assign(&v6).unwrap_err(), m);
        let mut bad = good;
        bad[6] = 24; // 192.0.2.1/24 has host bits
        assert_eq!(decode_address_assign(&bad).unwrap_err(), m);
        assert_eq!(decode_address_request(&good).unwrap_err(), m); // ID 0
        assert_eq!(decode_address_request(&[]).unwrap_err(), m);
        let mut o = BytesMut::new();
        assert_eq!(encode_address_request(&[], &mut o).unwrap_err(), m);
        assert!(o.is_empty());
        // start > end
        let mut r = vec![4, 192, 0, 2, 9, 192, 0, 2, 1, 0];
        assert_eq!(decode_routes(&r).unwrap_err(), m);
        r[4] = 1;
        assert!(decode_routes(&r).is_ok());
    }

    #[test]
    fn request_id_beyond_varint_rejected() {
        let mut o = BytesMut::from(&b"x"[..]);
        let a = AssignedAddress {
            request_id: u64::MAX,
            prefix: pfx("192.0.2.1", 32),
        };
        assert_eq!(
            encode_address_assign(&[a], &mut o),
            Err(CapsuleError::OutOfRange)
        );
        let r = RequestedAddress {
            request_id: nz(u64::MAX),
            prefix: pfx("192.0.2.1", 32),
        };
        assert_eq!(
            encode_address_request(&[r], &mut o),
            Err(CapsuleError::OutOfRange)
        );
        assert_eq!(&o[..], b"x");
    }

    #[test]
    fn request_round_trip() {
        let es = [RequestedAddress {
            request_id: nz(1),
            prefix: pfx("0.0.0.0", 0),
        }];
        let mut o = BytesMut::new();
        encode_address_request(&es, &mut o).unwrap();
        let (ty, v) = unframe(&o);
        assert_eq!(ty, ADDRESS_REQUEST);
        assert_eq!(decode_address_request(&v).unwrap(), es);
    }

    #[test]
    fn routes_sorted_by_encoder() {
        let rs = [
            rng("2001:db8::", "2001:db8::ff", 0),
            rng("10.0.0.0", "10.0.0.255", 17),
            rng("192.0.2.0", "192.0.2.255", 6),
            rng("10.0.0.0", "10.0.0.255", 6),
            rng("11.0.0.0", "11.0.0.255", 6),
        ];
        let w = routes_bytes(&rs).unwrap();
        let (ty, v) = unframe(&w);
        assert_eq!(ty, ROUTE_ADVERTISEMENT);
        let got = decode_routes(&v).unwrap();
        assert_eq!(got, [rs[3], rs[4], rs[2], rs[1], rs[0]]);
    }

    fn rbytes(rs: &[IpRange]) -> Vec<u8> {
        let mut v = Vec::new();
        for r in rs {
            put_addr(r.start(), &mut v);
            match r.end() {
                IpAddr::V4(a) => v.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => v.extend_from_slice(&a.octets()),
            }
            v.push(r.ipproto());
        }
        v
    }

    #[test]
    fn routes_out_of_order_rejected() {
        let m = CapsuleError::Malformed;
        let a4 = rng("10.0.0.0", "10.0.0.1", 6);
        let a6 = rng("::", "::1", 6);
        assert!(decode_routes(&rbytes(&[a4, a6])).is_ok());
        // version descends
        assert_eq!(decode_routes(&rbytes(&[a6, a4])).unwrap_err(), m);
        // protocol descends
        let p17 = rng("10.0.0.0", "10.0.0.1", 17);
        assert!(decode_routes(&rbytes(&[a4, p17])).is_ok());
        assert_eq!(decode_routes(&rbytes(&[p17, a4])).unwrap_err(), m);
        // same protocol: start descends / touches the previous end
        let hi = rng("10.0.1.0", "10.0.1.1", 6);
        assert!(decode_routes(&rbytes(&[a4, hi])).is_ok());
        assert_eq!(decode_routes(&rbytes(&[hi, a4])).unwrap_err(), m);
        let touch = rng("10.0.0.1", "10.0.0.2", 6);
        assert_eq!(decode_routes(&rbytes(&[a4, touch])).unwrap_err(), m);
        assert_eq!(decode_routes(&rbytes(&[a4, a4])).unwrap_err(), m);
    }

    #[test]
    fn routes_overlap_rules() {
        let ov = RouteError::Overlap;
        let m = CapsuleError::Malformed;
        let both = |rs: &[IpRange], ok: bool| {
            let enc = routes_bytes(rs);
            assert_eq!(enc.is_ok(), ok, "{rs:?}");
            if let Err(e) = enc {
                assert_eq!(e, ov);
            }
            // Decode in encoder order when valid; otherwise in the given order.
            let mut s = rs.to_vec();
            s.sort_by_key(sort_key);
            assert_eq!(decode_routes(&rbytes(&s)).is_ok(), ok);
            if !ok {
                assert_eq!(decode_routes(&rbytes(&s)).unwrap_err(), m);
            }
        };
        let r = |a, b, p| rng(a, b, p);
        both(
            &[r("10.0.0.0", "10.0.0.9", 6), r("10.0.0.5", "10.0.0.20", 6)],
            false,
        );
        both(
            &[r("10.0.0.0", "10.0.0.9", 0), r("10.0.0.5", "10.0.0.20", 6)],
            false,
        );
        // a later non-zero range reaching back into an earlier protocol-0 range
        both(
            &[
                r("10.0.0.0", "10.0.0.9", 0),
                r("10.0.0.20", "10.0.0.30", 0),
                r("10.0.0.25", "10.0.0.26", 17),
            ],
            false,
        );
        both(
            &[r("10.0.0.0", "10.0.0.9", 0), r("10.0.0.10", "10.0.0.20", 6)],
            true,
        );
        both(
            &[r("10.0.0.0", "10.0.0.9", 6), r("10.0.0.0", "10.0.0.9", 17)],
            true,
        );
        both(
            &[r("10.0.0.0", "10.0.0.9", 6), r("10.0.0.10", "10.0.0.20", 6)],
            true,
        );
        both(
            &[r("0.0.0.0", "255.255.255.255", 0), r("::", "::1", 6)],
            true,
        );
        both(
            &[r("0.0.0.0", "255.255.255.255", 6), r("::", "::1", 0)],
            true,
        );
    }

    fn prefix_strat() -> impl Strategy<Value = IpPrefix> {
        prop_oneof![
            (any::<u32>(), 0..=32u8).prop_map(|(a, l)| {
                let m = u32::MAX.checked_shl(32 - u32::from(l)).unwrap_or(0);
                IpPrefix::new(Ipv4Addr::from(a & m).into(), l).unwrap()
            }),
            (any::<u128>(), 0..=128u8).prop_map(|(a, l)| {
                let m = u128::MAX.checked_shl(128 - u32::from(l)).unwrap_or(0);
                IpPrefix::new(Ipv6Addr::from(a & m).into(), l).unwrap()
            }),
        ]
    }

    fn range_strat() -> impl Strategy<Value = IpRange> {
        let p = prop_oneof![Just(0u8), Just(6), Just(17)];
        prop_oneof![
            (any::<u32>(), 0..1000u32, p.clone()).prop_map(|(a, d, p)| {
                let s = a.min(u32::MAX - d);
                IpRange::new(Ipv4Addr::from(s).into(), Ipv4Addr::from(s + d).into(), p).unwrap()
            }),
            (any::<u128>(), 0..1000u128, p).prop_map(|(a, d, p)| {
                let s = a.min(u128::MAX - d);
                IpRange::new(Ipv6Addr::from(s).into(), Ipv6Addr::from(s + d).into(), p).unwrap()
            }),
        ]
    }

    proptest! {
        #[test]
        fn capsule_round_trip(
            assigns in prop::collection::vec((0..(1u64 << 62), prefix_strat()), 0..6),
            reqs in prop::collection::vec((1..(1u64 << 62), prefix_strat()), 1..6),
            routes in prop::collection::vec(range_strat(), 0..6),
        ) {
            let assigns: Vec<_> = assigns.into_iter()
                .map(|(request_id, prefix)| AssignedAddress { request_id, prefix }).collect();
            let mut o = BytesMut::new();
            encode_address_assign(&assigns, &mut o).unwrap();
            let (ty, v) = unframe(&o);
            prop_assert_eq!(ty, ADDRESS_ASSIGN);
            prop_assert_eq!(decode_address_assign(&v).unwrap(), assigns);

            let reqs: Vec<_> = reqs.into_iter()
                .map(|(i, prefix)| RequestedAddress { request_id: nz(i), prefix }).collect();
            let mut o = BytesMut::new();
            encode_address_request(&reqs, &mut o).unwrap();
            let (ty, v) = unframe(&o);
            prop_assert_eq!(ty, ADDRESS_REQUEST);
            prop_assert_eq!(decode_address_request(&v).unwrap(), reqs);

            let mut o = BytesMut::new();
            prop_assume!(encode_routes(&routes, &mut o).is_ok());
            let (ty, v) = unframe(&o);
            prop_assert_eq!(ty, ROUTE_ADVERTISEMENT);
            let mut want = routes;
            want.sort_by_key(sort_key);
            prop_assert_eq!(decode_routes(&v).unwrap(), want);
        }
    }
}
