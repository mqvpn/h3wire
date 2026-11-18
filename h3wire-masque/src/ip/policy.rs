// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Which IP packets may enter or leave a CONNECT-IP tunnel (RFC 9484 sections 4.6, 4.7, 7, 11).

use super::{IpPrefix, IpRange, Scope, ScopeTarget};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether a tunnel authorizes packets by address and route.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Check sources and destinations against the assigned addresses and the routes.
    #[default]
    Enforce,
    /// Skip the address and route checks, for addresses configured out of band. Header
    /// validation, the request scope and the ICMP quotation checks still apply.
    Unchecked,
}

/// Why the policy refused a packet.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The IP header or IPv6 extension chain does not parse, or the lengths disagree.
    Malformed,
    /// The source is not an address the sender may use.
    Source,
    /// The destination is in no assigned address or route.
    Destination,
    /// A route holds the destination, but none for the packet's protocol.
    Protocol,
    /// The packet is outside the request's protocol or target.
    Scope,
    /// An ICMP error whose quotation is missing, unparseable, not bound to the outer
    /// destination, or something the receiver could not have sent.
    Icmp,
}

/// Dropped packets, counted per reason.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops {
    /// [`DropReason::Malformed`], and payloads too large for an IP packet.
    pub malformed: u64,
    /// [`DropReason::Source`].
    pub source: u64,
    /// [`DropReason::Destination`].
    pub destination: u64,
    /// [`DropReason::Protocol`].
    pub protocol: u64,
    /// [`DropReason::Scope`].
    pub scope: u64,
    /// [`DropReason::Icmp`].
    pub icmp: u64,
    /// Datagrams with a context ID other than 0.
    pub context: u64,
}

/// The state a packet is judged against, from this endpoint's point of view.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct Rules<'a> {
    /// *A*: the prefixes I assigned to the peer.
    pub assigned: &'a [IpPrefix],
    /// *R*: the ranges I advertised.
    pub routes: &'a [IpRange],
    /// *A'*: the peer's assignments to me that I accepted.
    pub peer_assigned: &'a [IpPrefix],
    /// *R'*: the peer's routes that I accepted.
    pub peer_routes: &'a [IpRange],
    /// The request scope.
    pub scope: &'a Scope,
    /// Whether this endpoint is the proxy.
    pub proxy: bool,
    /// Whether the address and route checks run.
    pub policy: Policy,
}

impl Rules<'_> {
    /// Whether the peer may send `packet` to me.
    pub fn incoming(&self, packet: &[u8]) -> Result<(), DropReason> {
        let h = parse(packet, false).ok_or(DropReason::Malformed)?;
        let error = h.first
            && is_icmp(h.dst, h.proto)
            && packet.get(h.upper).is_some_and(|&t| match h.dst {
                IpAddr::V4(_) => matches!(t, 3 | 4 | 5 | 11 | 12),
                IpAddr::V6(_) => matches!(t, 1..=4),
            });
        if !error {
            return self.check(h.src, h.dst, h.proto);
        }
        // An ICMP error stands or falls with its quotation: no ordinary-packet fallback.
        let q = packet
            .get(h.upper + 8..)
            .and_then(|q| parse(q, true))
            .ok_or(DropReason::Icmp)?;
        if q.src != h.dst {
            return Err(DropReason::Icmp);
        }
        self.mirror()
            .check(q.src, q.dst, q.proto)
            .map_err(|_| DropReason::Icmp)
    }

    /// Whether the peer accepts `packet` from me: [`Self::incoming`] on the mirrored rules.
    pub fn outgoing(&self, packet: &[u8]) -> Result<(), DropReason> {
        self.mirror().incoming(packet)
    }

    /// The peer's view: *A* and *A'*, *R* and *R'* swapped, the other role.
    fn mirror(&self) -> Self {
        Self {
            assigned: self.peer_assigned,
            routes: self.peer_routes,
            peer_assigned: self.assigned,
            peer_routes: self.routes,
            proxy: !self.proxy,
            ..*self
        }
    }

    /// Rules 7, 3, 4 (with rule 5) for a packet the peer sends to me.
    fn check(&self, src: IpAddr, dst: IpAddr, proto: Option<u8>) -> Result<(), DropReason> {
        let icmp = is_icmp(dst, proto);
        let link_dst = is_link_local(dst) || is_ff02(dst);
        let dst_assigned = self.peer_assigned.iter().any(|p| p.contains(dst));
        let link_scoped = link_dst || (is_link_local(src) && dst_assigned);

        if self
            .scope
            .ipproto
            .is_some_and(|p| proto != Some(p) && !icmp)
        {
            return Err(DropReason::Scope);
        }
        if let ScopeTarget::Prefix(t) = &self.scope.target {
            let remote = if self.proxy { dst } else { src };
            if !link_scoped && !t.contains(remote) {
                return Err(DropReason::Scope);
            }
        }
        if self.policy == Policy::Unchecked {
            return Ok(());
        }

        // Route protocol does not restrict sources: it describes traffic sent to a range.
        let src_ok = self.assigned.iter().any(|p| p.contains(src))
            || self.peer_routes.iter().any(|r| r.contains(src))
            || (is_link_local(src) && link_scoped);
        if !src_ok {
            return Err(DropReason::Source);
        }
        if link_dst || dst_assigned {
            return Ok(());
        }
        let mut covered = false;
        for r in self.routes.iter().filter(|r| r.contains(dst)) {
            if r.ipproto() == 0 || Some(r.ipproto()) == proto || icmp {
                return Ok(());
            }
            covered = true;
        }
        Err(if covered {
            DropReason::Protocol
        } else {
            DropReason::Destination
        })
    }
}

fn is_icmp(addr: IpAddr, proto: Option<u8>) -> bool {
    proto == Some(if addr.is_ipv4() { 1 } else { 58 })
}

/// `fe80::/10`.
fn is_link_local(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
}

/// `ff02::/16`.
fn is_ff02(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(a) if a.segments()[0] == 0xff02)
}

/// What the policy reads from an IP header.
struct Header {
    src: IpAddr,
    dst: IpAddr,
    /// The upper-layer protocol; `None` when unknown (a cut quotation, or a later fragment
    /// whose Fragment header names an extension).
    proto: Option<u8>,
    /// Offset of the upper-layer header.
    upper: usize,
    /// Unfragmented or the first fragment.
    first: bool,
}

/// Parses a full packet, or with `quoted` the quotation inside an ICMP error: no length
/// equality, and a cut IPv6 extension chain gives an unknown protocol instead of failing.
fn parse(p: &[u8], quoted: bool) -> Option<Header> {
    match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            if p.len() < 20 || ihl < 20 || ihl > p.len() {
                return None;
            }
            if !quoted && usize::from(u16::from_be_bytes([p[2], p[3]])) != p.len() {
                return None;
            }
            let addr = |i: usize| IpAddr::V4(Ipv4Addr::new(p[i], p[i + 1], p[i + 2], p[i + 3]));
            Some(Header {
                src: addr(12),
                dst: addr(16),
                proto: Some(p[9]),
                upper: ihl,
                first: u16::from_be_bytes([p[6], p[7]]) & 0x1fff == 0,
            })
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            if !quoted && usize::from(u16::from_be_bytes([p[4], p[5]])) + 40 != p.len() {
                return None;
            }
            let addr = |i: usize| {
                let b: [u8; 16] = p[i..i + 16].try_into().expect("16 bytes");
                IpAddr::V6(Ipv6Addr::from(b))
            };
            let (proto, upper, first) = match walk(p, p[6]) {
                Some(found) => found,
                None if quoted => (None, p.len(), true),
                None => return None,
            };
            Some(Header {
                src: addr(8),
                dst: addr(24),
                proto,
                upper,
                first,
            })
        }
        _ => None,
    }
}

fn is_extension(next: u8) -> bool {
    matches!(next, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140)
}

/// Walks the IPv6 extension chain from `next`: (protocol, upper-layer offset, first
/// fragment), or `None` when the chain runs past the end. ESP (50) ends the walk.
fn walk(p: &[u8], mut next: u8) -> Option<(Option<u8>, usize, bool)> {
    let mut off = 40;
    while is_extension(next) {
        let h = p.get(off..off + 2)?;
        let len = match next {
            44 => 8,
            51 => (usize::from(h[1]) + 2) * 4,
            _ => (usize::from(h[1]) + 1) * 8,
        };
        let h = p.get(off..off + len)?;
        if next == 44 && u16::from_be_bytes([h[2], h[3]]) >> 3 != 0 {
            // A later fragment: no upper-layer header here, and no reassembly.
            let proto = (!is_extension(h[0])).then_some(h[0]);
            return Some((proto, off + len, false));
        }
        next = h[0];
        off += len;
    }
    Some((Some(next), off, true))
}
