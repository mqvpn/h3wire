// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Address and route lists with a search index, so a lookup is a binary search.
//!
//! A set is built when its list changes (a control capsule or an accept call) and only
//! read after that; packets never rebuild anything.

use super::prefix::num;
use super::{IpPrefix, IpRange};
use std::net::IpAddr;

/// Sorted, pairwise disjoint inclusive intervals.
#[derive(Debug, Clone, Default)]
struct Spans<T>(Vec<(T, T)>);

impl<T: Ord + Copy> Spans<T> {
    /// Sorts `items` and merges the ones that overlap.
    fn build(mut items: Vec<(T, T)>) -> Self {
        items.sort_unstable();
        let mut out: Vec<(T, T)> = Vec::with_capacity(items.len());
        for (s, e) in items {
            match out.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => out.push((s, e)),
            }
        }
        Self(out)
    }

    /// The interval holding `a`.
    fn find(&self, a: T) -> Option<(T, T)> {
        let i = self.0.partition_point(|&(_, e)| e < a);
        self.0.get(i).copied().filter(|&(s, _)| s <= a)
    }

    fn contains(&self, a: T) -> bool {
        self.find(a).is_some()
    }

    /// Whether one interval holds all of `s..=e`.
    fn covers(&self, s: T, e: T) -> bool {
        self.find(s).is_some_and(|(_, end)| e <= end)
    }
}

/// A list of prefixes and the index over it.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct AddrSet {
    items: Vec<IpPrefix>,
    v4: Spans<u32>,
    v6: Spans<u128>,
}

impl AddrSet {
    /// Indexes `items`; they may nest and repeat.
    pub fn new(items: Vec<IpPrefix>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for p in &items {
            let (s, e) = p.bounds();
            match p.addr() {
                // Bounds of an IPv4 prefix fit 32 bits.
                IpAddr::V4(_) => v4.push((s as u32, e as u32)),
                IpAddr::V6(_) => v6.push((s, e)),
            }
        }
        Self {
            items,
            v4: Spans::build(v4),
            v6: Spans::build(v6),
        }
    }

    /// The list as given to [`Self::new`].
    pub fn items(&self) -> &[IpPrefix] {
        &self.items
    }

    /// Whether some prefix holds `addr`. Never true across families.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.v4.contains(a.into()),
            IpAddr::V6(a) => self.v6.contains(a.into()),
        }
    }

    /// Whether some prefix holds all of `p`. Prefixes nest or are disjoint, so a merged
    /// interval is always one prefix of the list.
    pub(crate) fn covers(&self, p: &IpPrefix) -> bool {
        let (s, e) = p.bounds();
        match p.addr() {
            IpAddr::V4(_) => self.v4.covers(s as u32, e as u32),
            IpAddr::V6(_) => self.v6.covers(s, e),
        }
    }

    /// Drops the items `keep` refuses; re-indexes only if one was dropped.
    pub(crate) fn retain(&mut self, keep: impl Fn(&IpPrefix) -> bool) {
        if !self.items.iter().all(&keep) {
            let mut items = std::mem::take(&mut self.items);
            items.retain(&keep);
            *self = Self::new(items);
        }
    }
}

/// The routes of one family.
#[derive(Debug, Clone, Default)]
struct Routes<T> {
    /// Every range, the protocol ignored.
    any: Spans<T>,
    /// Keyed `(protocol, address)`: an interval never spans two protocols.
    by_proto: Spans<(u8, T)>,
}

impl<T: Ord + Copy> Routes<T> {
    fn build(items: &[(u8, T, T)]) -> Self {
        Self {
            any: Spans::build(items.iter().map(|&(_, s, e)| (s, e)).collect()),
            by_proto: Spans::build(items.iter().map(|&(p, s, e)| ((p, s), (p, e))).collect()),
        }
    }

    fn allows(&self, a: T, proto: Option<u8>) -> bool {
        self.by_proto.contains((0, a)) || proto.is_some_and(|p| self.by_proto.contains((p, a)))
    }

    fn covers(&self, p: u8, s: T, e: T) -> bool {
        self.by_proto.covers((0, s), (0, e)) || (p != 0 && self.by_proto.covers((p, s), (p, e)))
    }
}

/// A list of routes and the index over it.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct RouteSet {
    items: Vec<IpRange>,
    v4: Routes<u32>,
    v6: Routes<u128>,
}

impl RouteSet {
    /// Indexes `items`; they may overlap and come in any order.
    pub fn new(items: Vec<IpRange>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for r in &items {
            let (s, e) = (num(r.start()).1, num(r.end()).1);
            match r.start() {
                // Bounds of an IPv4 range fit 32 bits.
                IpAddr::V4(_) => v4.push((r.ipproto(), s as u32, e as u32)),
                IpAddr::V6(_) => v6.push((r.ipproto(), s, e)),
            }
        }
        Self {
            items,
            v4: Routes::build(&v4),
            v6: Routes::build(&v6),
        }
    }

    /// The list as given to [`Self::new`].
    pub fn items(&self) -> &[IpRange] {
        &self.items
    }

    /// Whether some range holds `addr`, whatever its protocol. Never true across families.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.v4.any.contains(a.into()),
            IpAddr::V6(a) => self.v6.any.contains(a.into()),
        }
    }

    /// Whether some range holds `addr` and is for all protocols or for `proto`.
    pub fn allows(&self, addr: IpAddr, proto: Option<u8>) -> bool {
        match addr {
            IpAddr::V4(a) => self.v4.allows(a.into(), proto),
            IpAddr::V6(a) => self.v6.allows(a.into(), proto),
        }
    }

    /// Whether one range covers `r` ([`IpRange::covers`]). Only for a list that came out
    /// of `decode_routes`: there nothing overlaps within a protocol or with protocol 0, so
    /// no ranges were merged. On other lists two overlapping ranges would count as one.
    pub(crate) fn covers(&self, r: &IpRange) -> bool {
        let (p, s, e) = (r.ipproto(), num(r.start()).1, num(r.end()).1);
        match r.start() {
            IpAddr::V4(_) => self.v4.covers(p, s as u32, e as u32),
            IpAddr::V6(_) => self.v6.covers(p, s, e),
        }
    }

    /// Drops the items `keep` refuses; re-indexes only if one was dropped.
    pub(crate) fn retain(&mut self, keep: impl Fn(&IpRange) -> bool) {
        if !self.items.iter().all(&keep) {
            let mut items = std::mem::take(&mut self.items);
            items.retain(&keep);
            *self = Self::new(items);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::encode_routes;
    use bytes::BytesMut;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn spans_merge_and_find() {
        let none = Spans::<u32>::build(vec![]);
        assert!(!none.contains(0) && !none.covers(0, 0));

        let s = Spans::build(vec![
            (20u32, 30),
            (0, 0),
            (22, 25),
            (28, 40),
            (20, 30),
            (41, 50),
        ]);
        // Nested, overlapping and duplicate intervals merge; touching ones do not.
        assert_eq!(s.0, [(0, 0), (20, 40), (41, 50)]);
        for a in [0, 20, 33, 40, 41, 50] {
            assert!(s.contains(a), "{a}");
        }
        for a in [1, 19, 51, u32::MAX] {
            assert!(!s.contains(a), "{a}");
        }
        assert!(s.covers(20, 40) && s.covers(41, 41));
        assert!(!s.covers(30, 45) && !s.covers(0, 1) && !s.covers(10, 25));

        let top = Spans::build(vec![(u32::MAX - 1, u32::MAX)]);
        assert!(top.contains(u32::MAX) && !top.contains(u32::MAX - 2));
    }

    /// A value from a small space plus the top of the family, so lists collide often.
    fn bits() -> impl Strategy<Value = u128> {
        prop_oneof![0..48u128, (0..4u128).prop_map(|d| u128::MAX - d)]
    }

    fn to_addr(v6: bool, n: u128) -> IpAddr {
        if v6 {
            Ipv6Addr::from(n).into()
        } else {
            Ipv4Addr::from(n as u32).into()
        }
    }

    fn addr() -> impl Strategy<Value = IpAddr> {
        (any::<bool>(), bits()).prop_map(|(v6, n)| to_addr(v6, n))
    }

    /// A prefix with up to 6 host bits, or the whole family.
    fn prefix() -> impl Strategy<Value = IpPrefix> {
        (addr(), 0..8u8).prop_map(|(a, h)| {
            let (width, n) = num(a);
            let host = if h == 7 { width } else { h };
            let n = n & !u128::MAX.checked_shr(128 - u32::from(host)).unwrap_or(0);
            IpPrefix::new(to_addr(a.is_ipv6(), n), width - host).unwrap()
        })
    }

    fn proto() -> impl Strategy<Value = u8> {
        prop::sample::select(vec![0, 0, 6, 17])
    }

    fn range() -> impl Strategy<Value = IpRange> {
        (any::<bool>(), bits(), bits(), proto()).prop_map(|(v6, a, b, p)| {
            IpRange::new(to_addr(v6, a.min(b)), to_addr(v6, a.max(b)), p).unwrap()
        })
    }

    /// A list `encode_routes` takes, so `decode_routes` accepts it: ranges disjoint by
    /// address, each for all protocols or for one or two single protocols.
    fn offer() -> impl Strategy<Value = Vec<IpRange>> {
        prop::collection::vec((range(), 0..4u8), 0..12).prop_map(|picks| {
            let mut out: Vec<IpRange> = Vec::new();
            for (r, kind) in picks {
                if out
                    .iter()
                    .any(|o| o.contains(r.start()) || r.contains(o.start()))
                {
                    continue;
                }
                let protos: &[u8] = [&[0][..], &[6], &[17], &[6, 17]][usize::from(kind)];
                out.extend(
                    protos
                        .iter()
                        .map(|&p| IpRange::new(r.start(), r.end(), p).unwrap()),
                );
            }
            let mut buf = BytesMut::new();
            encode_routes(&out, &mut buf).expect("disjoint by construction");
            out
        })
    }

    proptest! {
        #[test]
        fn addr_set_matches_linear_scan(
            items in prop::collection::vec(prefix(), 0..12),
            a in addr(),
            q in prefix(),
        ) {
            let set = AddrSet::new(items.clone());
            prop_assert_eq!(set.contains(a), items.iter().any(|p| p.contains(a)));
            prop_assert_eq!(set.covers(&q), items.iter().any(|p| p.covers(&q)));
        }

        #[test]
        fn route_set_matches_linear_scan(
            items in prop::collection::vec(range(), 0..12),
            a in addr(),
            p in prop::sample::select(vec![None, Some(0), Some(6), Some(17), Some(58)]),
        ) {
            let set = RouteSet::new(items.clone());
            prop_assert_eq!(set.contains(a), items.iter().any(|r| r.contains(a)));
            let allowed = items
                .iter()
                .any(|r| r.contains(a) && (r.ipproto() == 0 || Some(r.ipproto()) == p));
            prop_assert_eq!(set.allows(a, p), allowed);
        }

        #[test]
        fn route_cover_matches_linear_scan_on_offers(items in offer(), q in range()) {
            let set = RouteSet::new(items.clone());
            prop_assert_eq!(set.covers(&q), items.iter().any(|r| r.covers(&q)));
        }

        #[test]
        fn retain_matches_vec_retain(items in prop::collection::vec(range(), 0..12), a in addr()) {
            let mut set = RouteSet::new(items.clone());
            set.retain(|r| !r.contains(a));
            let kept: Vec<_> = items.iter().copied().filter(|r| !r.contains(a)).collect();
            prop_assert_eq!(set.items(), &kept[..]);
            prop_assert_eq!(set.contains(a), false);
        }
    }
}
