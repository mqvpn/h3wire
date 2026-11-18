// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use arbitrary::Arbitrary;
use h3wire_masque::ip::{AddrSet, IpPrefix, IpRange, Policy, RouteSet, Rules, Scope, ScopeTarget};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Arbitrary, Debug)]
struct Addr {
    v6: bool,
    bits: u128,
}

impl Addr {
    fn ip(&self) -> IpAddr {
        if self.v6 {
            Ipv6Addr::from(self.bits).into()
        } else {
            Ipv4Addr::from(self.bits as u32).into()
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Prefix(Addr, u8);

impl Prefix {
    // Length clamped to the family, host bits cleared.
    fn build(&self) -> IpPrefix {
        let width = if self.0.v6 { 128 } else { 32 };
        let len = self.1 % (width + 1);
        let mask = u128::MAX.checked_shl(u32::from(width - len)).unwrap_or(0);
        let bits = (self.0.bits & mask) & (u128::MAX >> (128 - u32::from(width)));
        let addr = Addr { bits, ..self.0 };
        IpPrefix::new(addr.ip(), len).unwrap()
    }
}

#[derive(Arbitrary, Debug)]
struct Range(Addr, Addr, u8);

impl Range {
    // Bounds forced into one family and ordered.
    fn build(&self) -> IpRange {
        let b = Addr {
            v6: self.0.v6,
            bits: self.1.bits,
        };
        let (mut lo, mut hi) = (self.0.ip(), b.ip());
        if matches!((lo, hi), (IpAddr::V4(l), IpAddr::V4(h)) if l > h)
            || matches!((lo, hi), (IpAddr::V6(l), IpAddr::V6(h)) if l > h)
        {
            std::mem::swap(&mut lo, &mut hi);
        }
        IpRange::new(lo, hi, self.2).unwrap()
    }
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    assigned: Vec<Prefix>,
    routes: Vec<Range>,
    peer_assigned: Vec<Prefix>,
    peer_routes: Vec<Range>,
    target: Option<Prefix>,
    ipproto: Option<u8>,
    proxy: bool,
    packet: &'a [u8],
}

// No panic; whatever Enforce accepts, Unchecked accepts; outgoing is incoming on the
// peer's view.
fuzz_target!(|i: Input| {
    let prefixes = |v: &[Prefix]| AddrSet::new(v.iter().map(Prefix::build).collect());
    let ranges = |v: &[Range]| RouteSet::new(v.iter().map(Range::build).collect());
    let (a, r) = (prefixes(&i.assigned), ranges(&i.routes));
    let (pa, pr) = (prefixes(&i.peer_assigned), ranges(&i.peer_routes));
    let scope = Scope {
        target: i
            .target
            .as_ref()
            .map_or(ScopeTarget::Any, |t| ScopeTarget::Prefix(t.build())),
        ipproto: i.ipproto,
    };
    let rules = |policy| Rules {
        assigned: &a,
        routes: &r,
        peer_assigned: &pa,
        peer_routes: &pr,
        scope: &scope,
        proxy: i.proxy,
        policy,
    };
    let (enforce, unchecked) = (rules(Policy::Enforce), rules(Policy::Unchecked));
    for rules in [&enforce, &unchecked] {
        let mirror = Rules {
            assigned: &pa,
            routes: &pr,
            peer_assigned: &a,
            peer_routes: &r,
            proxy: !i.proxy,
            ..*rules
        };
        assert_eq!(rules.outgoing(i.packet), mirror.incoming(i.packet));
        let _ = rules.incoming(i.packet);
    }
    if enforce.incoming(i.packet).is_ok() {
        assert!(unchecked.incoming(i.packet).is_ok());
    }
    if enforce.outgoing(i.packet).is_ok() {
        assert!(unchecked.outgoing(i.packet).is_ok());
    }
});
