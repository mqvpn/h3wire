// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Address prefixes and address ranges.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an [`IpPrefix`] or [`IpRange`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefixError {
    /// The prefix length exceeds the address width (32 or 128 bits).
    Length,
    /// The address has bits set beyond the prefix length.
    HostBits,
    /// The two addresses of a range belong to different families.
    Family,
    /// The start of a range is greater than its end.
    Order,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "prefix length exceeds the address width",
            Self::HostBits => "address has bits set beyond the prefix length",
            Self::Family => "range bounds are of different address families",
            Self::Order => "range start is greater than its end",
        })
    }
}

impl std::error::Error for PrefixError {}

/// Address width in bits and numeric value; the family is part of the width.
fn num(addr: IpAddr) -> (u8, u128) {
    match addr {
        IpAddr::V4(a) => (32, u32::from(a).into()),
        IpAddr::V6(a) => (128, a.into()),
    }
}

/// Inverse of [`num`] for a given width.
fn addr_of(width: u8, n: u128) -> IpAddr {
    if width == 32 {
        // Only called with values that came from a 32-bit address.
        IpAddr::V4(Ipv4Addr::from(n as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(n))
    }
}

/// The low `host_bits` bits set.
fn host_mask(host_bits: u8) -> u128 {
    u128::MAX
        .checked_shr(128 - u32::from(host_bits))
        .unwrap_or(0)
}

/// An IP address prefix: a network address and a length, with no host bits set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// Builds a prefix; `addr` must have no bits set beyond `len`.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let (width, n) = num(addr);
        if len > width {
            return Err(PrefixError::Length);
        }
        if n & host_mask(width - len) != 0 {
            return Err(PrefixError::HostBits);
        }
        Ok(Self { addr, len })
    }

    /// The full-length prefix holding exactly `addr`.
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            len: num(addr).0,
        }
    }

    /// The network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// Whether `addr` lies inside the prefix. Never true across families,
    /// IPv4-mapped IPv6 addresses included.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let (width, base) = num(self.addr);
        let (w, n) = num(addr);
        w == width && (n ^ base) & !host_mask(width - self.len) & host_mask(width) == 0
    }

    /// Whether `other` lies entirely inside `self` (same family).
    pub fn covers(&self, other: &IpPrefix) -> bool {
        self.len <= other.len && self.contains(other.addr)
    }

    fn bounds(&self) -> (u128, u128) {
        let (width, n) = num(self.addr);
        (n, n | host_mask(width - self.len))
    }
}

/// An inclusive address range with an IP protocol filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    start: IpAddr,
    end: IpAddr,
    ipproto: u8,
}

impl IpRange {
    /// Builds a range; both bounds must share a family and `start <= end`.
    /// `ipproto` 0 means every protocol.
    pub fn new(start: IpAddr, end: IpAddr, ipproto: u8) -> Result<Self, PrefixError> {
        let ((ws, s), (we, e)) = (num(start), num(end));
        if ws != we {
            return Err(PrefixError::Family);
        }
        if s > e {
            return Err(PrefixError::Order);
        }
        Ok(Self {
            start,
            end,
            ipproto,
        })
    }

    /// The range spanning exactly `prefix`.
    pub fn from_prefix(prefix: IpPrefix, ipproto: u8) -> Self {
        let width = num(prefix.addr).0;
        let (s, e) = prefix.bounds();
        Self {
            start: addr_of(width, s),
            end: addr_of(width, e),
            ipproto,
        }
    }

    /// The first address of the range.
    pub fn start(&self) -> IpAddr {
        self.start
    }

    /// The last address of the range (inclusive).
    pub fn end(&self) -> IpAddr {
        self.end
    }

    /// The IP protocol number the range applies to; 0 means all protocols.
    pub fn ipproto(&self) -> u8 {
        self.ipproto
    }

    /// Whether `addr` lies inside the bounds (the protocol is not considered).
    /// Never true across families.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let ((w, s), (_, e), (wa, n)) = (num(self.start), num(self.end), num(addr));
        w == wa && (s..=e).contains(&n)
    }

    /// Whether `other` lies inside `self`: same family, bounds inside, and
    /// `self` is for all protocols or for the same one.
    pub fn covers(&self, other: &IpRange) -> bool {
        self.contains(other.start)
            && self.contains(other.end)
            && (self.ipproto == 0 || self.ipproto == other.ipproto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str, len: u8) -> IpPrefix {
        IpPrefix::new(ip(s), len).unwrap()
    }

    #[test]
    fn prefix_new_rules() {
        assert_eq!(IpPrefix::new(ip("192.0.2.0"), 33), Err(PrefixError::Length));
        assert_eq!(
            IpPrefix::new(ip("2001:db8::"), 129),
            Err(PrefixError::Length)
        );
        assert_eq!(
            IpPrefix::new(ip("192.0.2.1"), 24),
            Err(PrefixError::HostBits)
        );
        assert_eq!(
            IpPrefix::new(ip("2001:db8::1"), 32),
            Err(PrefixError::HostBits)
        );
        assert!(IpPrefix::new(ip("0.0.0.0"), 0).is_ok());
        assert!(IpPrefix::new(ip("192.0.2.1"), 32).is_ok());
        assert!(IpPrefix::new(ip("::1"), 128).is_ok());
        assert!(IpPrefix::new(ip("::"), 0).is_ok());
        let h = IpPrefix::host(ip("192.0.2.1"));
        assert_eq!((h.addr(), h.prefix_len()), (ip("192.0.2.1"), 32));
        assert_eq!(IpPrefix::host(ip("::1")).prefix_len(), 128);
    }

    #[test]
    fn prefix_contains() {
        let p = pfx("192.0.2.0", 25);
        assert!(p.contains(ip("192.0.2.0")));
        assert!(p.contains(ip("192.0.2.127")));
        assert!(!p.contains(ip("192.0.2.128")));
        assert!(!p.contains(ip("192.0.1.255")));
        let p = pfx("2001:db8::", 32);
        assert!(p.contains(ip("2001:db8::")));
        assert!(p.contains(ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!p.contains(ip("2001:db9::")));
        assert!(!p.contains(ip("2001:db7:ffff::")));
        let all = pfx("0.0.0.0", 0);
        assert!(all.contains(ip("0.0.0.0")) && all.contains(ip("255.255.255.255")));
        let all6 = pfx("::", 0);
        assert!(all6.contains(ip("::")) && all6.contains(ip("ffff::1")));
    }

    #[test]
    fn prefix_covers() {
        let a = pfx("192.0.2.0", 24);
        assert!(a.covers(&a));
        assert!(a.covers(&pfx("192.0.2.128", 25)));
        assert!(!pfx("192.0.2.128", 25).covers(&a));
        assert!(!a.covers(&pfx("192.0.3.0", 24)));
        assert!(pfx("0.0.0.0", 0).covers(&a));
        assert!(!pfx("0.0.0.0", 0).covers(&pfx("::", 0)));
        assert!(pfx("::", 0).covers(&pfx("2001:db8::", 32)));
        assert!(!pfx("2001:db8::", 32).covers(&pfx("2001:db9::", 32)));
    }

    #[test]
    fn range_new_rules() {
        assert_eq!(
            IpRange::new(ip("192.0.2.1"), ip("::1"), 0),
            Err(PrefixError::Family)
        );
        assert_eq!(
            IpRange::new(ip("192.0.2.2"), ip("192.0.2.1"), 0),
            Err(PrefixError::Order)
        );
        assert_eq!(
            IpRange::new(ip("::2"), ip("::1"), 0),
            Err(PrefixError::Order)
        );
        let r = IpRange::new(ip("192.0.2.1"), ip("192.0.2.1"), 17).unwrap();
        assert_eq!(
            (r.start(), r.end(), r.ipproto()),
            (ip("192.0.2.1"), ip("192.0.2.1"), 17)
        );
    }

    #[test]
    fn range_from_prefix_bounds() {
        let r = IpRange::from_prefix(pfx("198.51.100.0", 24), 0);
        assert_eq!(
            (r.start(), r.end()),
            (ip("198.51.100.0"), ip("198.51.100.255"))
        );
        let r = IpRange::from_prefix(pfx("::", 0), 6);
        assert_eq!(
            (r.start(), r.end(), r.ipproto()),
            (ip("::"), ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 6)
        );
        let r = IpRange::from_prefix(pfx("0.0.0.0", 0), 0);
        assert_eq!(r.end(), ip("255.255.255.255"));
    }

    #[test]
    fn range_covers_protocol() {
        let r = |p| IpRange::new(ip("192.0.2.0"), ip("192.0.2.255"), p).unwrap();
        assert!(r(0).covers(&r(6)));
        assert!(r(6).covers(&r(6)));
        assert!(!r(6).covers(&r(0)));
        assert!(!r(6).covers(&r(17)));
        let inner = IpRange::new(ip("192.0.2.5"), ip("192.0.2.9"), 6).unwrap();
        assert!(r(0).covers(&inner));
        assert!(!inner.covers(&r(6)));
        let v6 = IpRange::new(ip("::"), ip("::ff"), 0).unwrap();
        assert!(!r(0).covers(&v6) && !v6.covers(&r(0)));
        assert!(r(6).contains(ip("192.0.2.77")) && !r(6).contains(ip("192.0.3.0")));
    }

    #[test]
    fn family_mismatch_never_contains() {
        let v4 = pfx("0.0.0.0", 0);
        assert!(!v4.contains(ip("::1")));
        assert!(!v4.contains(ip("::ffff:192.0.2.1")));
        assert!(!pfx("::", 0).contains(ip("192.0.2.1")));
        let r4 = IpRange::from_prefix(v4, 0);
        assert!(!r4.contains(ip("::1")) && !r4.contains(ip("::ffff:192.0.2.1")));
        assert!(!IpRange::from_prefix(pfx("::", 0), 0).contains(ip("192.0.2.1")));
    }
}
