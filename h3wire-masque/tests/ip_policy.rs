// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The CONNECT-IP packet policy (spec §2.5 rules 1–7), on rule sets built by hand.

mod packets;

use DropReason::{Destination, Icmp, Malformed, Protocol, Scope as ScopeDrop, Source};
use h3wire_masque::ip::{
    AddrSet, DropReason, IpPrefix, IpRange, Policy, RouteSet, Rules, Scope, ScopeTarget,
};
use packets::*;
use proptest::prelude::*;
use proptest::sample::Index;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn pfx(s: &str, len: u8) -> IpPrefix {
    IpPrefix::new(ip(s), len).unwrap()
}

fn route(s: &str, len: u8, proto: u8) -> IpRange {
    IpRange::from_prefix(pfx(s, len), proto)
}

/// A rule set that owns its lists.
#[derive(Debug, Clone)]
struct Set {
    assigned: Vec<IpPrefix>,
    routes: Vec<IpRange>,
    peer_assigned: Vec<IpPrefix>,
    peer_routes: Vec<IpRange>,
    scope: Scope,
    proxy: bool,
    policy: Policy,
}

impl Set {
    fn judge(&self, p: &[u8], incoming: bool) -> Result<(), DropReason> {
        let rules = Rules {
            assigned: &AddrSet::new(self.assigned.clone()),
            routes: &RouteSet::new(self.routes.clone()),
            peer_assigned: &AddrSet::new(self.peer_assigned.clone()),
            peer_routes: &RouteSet::new(self.peer_routes.clone()),
            scope: &self.scope,
            proxy: self.proxy,
            policy: self.policy,
        };
        if incoming {
            rules.incoming(p)
        } else {
            rules.outgoing(p)
        }
    }

    fn inc(&self, p: &[u8]) -> Result<(), DropReason> {
        self.judge(p, true)
    }

    fn out(&self, p: &[u8]) -> Result<(), DropReason> {
        self.judge(p, false)
    }

    fn scoped(self, ipproto: Option<u8>) -> Self {
        Self {
            scope: Scope {
                ipproto,
                ..self.scope
            },
            ..self
        }
    }

    fn target(self, target: IpPrefix) -> Self {
        Self {
            scope: Scope {
                target: ScopeTarget::Prefix(target),
                ..self.scope
            },
            ..self
        }
    }

    fn policy(self, policy: Policy) -> Self {
        Self { policy, ..self }
    }
}

fn empty() -> Set {
    Set {
        assigned: vec![],
        routes: vec![],
        peer_assigned: vec![],
        peer_routes: vec![],
        scope: Scope::ANY,
        proxy: false,
        policy: Policy::Enforce,
    }
}

// The client is assigned P; the proxy routes 198.51.100.0/24 (holding D) to it.
const P: &str = "192.0.2.1";
const Q: &str = "192.0.2.2"; // not assigned
const D: &str = "198.51.100.7";
const X: &str = "203.0.113.1"; // in no list
const P6: &str = "2001:db8:1::1";
const D6: &str = "2001:db8:d::7";

/// The remote-access client: accepted the proxy's assignment of P and its route.
fn client() -> Set {
    Set {
        peer_assigned: vec![pfx(P, 32)],
        peer_routes: vec![route("198.51.100.0", 24, 0)],
        ..empty()
    }
}

/// The remote-access proxy: assigned P, advertised the route.
fn proxy() -> Set {
    Set {
        assigned: vec![pfx(P, 32)],
        routes: vec![route("198.51.100.0", 24, 0)],
        proxy: true,
        ..empty()
    }
}

fn client6() -> Set {
    Set {
        peer_assigned: vec![pfx(P6, 128)],
        peer_routes: vec![route("2001:db8:d::", 48, 0)],
        ..empty()
    }
}

fn proxy6() -> Set {
    Set {
        assigned: vec![pfx(P6, 128)],
        routes: vec![route("2001:db8:d::", 48, 0)],
        proxy: true,
        ..empty()
    }
}

/// A proxy whose only route to D (or D6) carries protocol `proto`.
fn proto_route(proto: u8) -> Set {
    Set {
        assigned: vec![pfx(P, 32), pfx(P6, 128)],
        routes: vec![route(D, 32, proto), route(D6, 128, proto)],
        proxy: true,
        ..empty()
    }
}

fn udp(src: &str, dst: &str) -> Vec<u8> {
    packet(ip(src), ip(dst), 17, &[0; 8])
}

fn tcp(src: &str, dst: &str) -> Vec<u8> {
    packet(ip(src), ip(dst), 6, &[0; 20])
}

fn unreach(src: &str, dst: &str, quote: &[u8]) -> Vec<u8> {
    unreachable(ip(src), ip(dst), quote)
}

#[test]
fn header_rules() {
    let s = empty().policy(Policy::Unchecked);
    let good = ipv4(v4(P), v4(D), 17, &[0; 8]);
    assert_eq!(s.inc(&good), Ok(()));
    assert_eq!(s.inc(&[]), Err(Malformed));
    assert_eq!(s.inc(&good[..19]), Err(Malformed), "19 bytes");
    let mut b = good.clone();
    b[0] = 0x44;
    assert_eq!(s.inc(&b), Err(Malformed), "IHL 4");
    b[0] = 0x48; // 32 bytes of header in a 28-byte packet
    assert_eq!(s.inc(&b), Err(Malformed), "IHL past the end");
    let mut b = good.clone();
    b[3] += 1;
    assert_eq!(s.inc(&b), Err(Malformed), "Total Length > length");
    assert_eq!(s.inc(&good[..27]), Err(Malformed), "Total Length < length");
    let mut b = good.clone();
    b[0] = 0x55;
    assert_eq!(s.inc(&b), Err(Malformed), "version 5");

    let good6 = ipv6(v6(P6), v6(D6), 17, &[0; 8]);
    assert_eq!(s.inc(&good6), Ok(()));
    assert_eq!(s.inc(&good6[..39]), Err(Malformed), "39 bytes");
    let mut b = good6.clone();
    b[5] += 1;
    assert_eq!(s.inc(&b), Err(Malformed), "Payload Length mismatch");
    assert_eq!(
        s.inc(&ipv6(v6(P6), v6(D6), 59, &[])),
        Ok(()),
        "40 bytes, PL 0"
    );
    let mut b = good6.clone();
    b[4] = 0;
    b[5] = 0;
    assert_eq!(s.inc(&b), Err(Malformed), "longer packet, PL 0");
}

#[test]
fn ipv6_extension_chain() {
    let (p, d) = (v6(P6), v6(D6));
    let chain = ipv6_chain(p, d, &[0, 43, 44, 60, 51, 135, 139, 140], 6, &[0; 20]);
    assert_eq!(proto_route(6).inc(&chain), Ok(()));
    assert_eq!(proto_route(17).inc(&chain), Err(Protocol));

    let esp = ipv6_chain(p, d, &[0], 50, &[6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(proto_route(50).inc(&esp), Ok(()));
    assert_eq!(proto_route(6).inc(&esp), Err(Protocol));

    let s = proto_route(0);
    assert_eq!(
        s.inc(&ipv6_raw(p, d, 0, &ext_header(0, 43))),
        Err(Malformed)
    );
    assert_eq!(s.inc(&ipv6_raw(p, d, 0, &[43, 0, 0, 0])), Err(Malformed));
    assert_eq!(
        s.inc(&ipv6_raw(p, d, 51, &ext_header(51, 6)[..12])),
        Err(Malformed)
    );
    assert_eq!(s.inc(&ipv6_raw(p, d, 44, &[17, 0, 0])), Err(Malformed));
}

#[test]
fn fragments() {
    let later = ipv4_frag(v4(P), v4(D), 17, 100, &[0; 8]);
    assert_eq!(proto_route(17).inc(&later), Ok(()));
    assert_eq!(proto_route(6).inc(&later), Err(Protocol));

    let (p, d) = (v6(P6), v6(D6));
    let udp_later = ipv6_fragment(p, d, 17, 100, &[0; 8]);
    assert_eq!(proto_route(17).inc(&udp_later), Ok(()));
    assert_eq!(proto_route(6).inc(&udp_later), Err(Protocol));

    let ext_later = ipv6_fragment(p, d, 60, 100, &[0; 8]);
    assert_eq!(proto_route(0).inc(&ext_later), Ok(()));
    assert_eq!(proto_route(60).inc(&ext_later), Err(Protocol));
    assert_eq!(proto_route(17).inc(&ext_later), Err(Protocol));

    // A first fragment is walked through to its upper layer.
    let first = ipv6_fragment(p, d, 17, 0, &[0; 8]);
    assert_eq!(proto_route(17).inc(&first), Ok(()));
    assert_eq!(proto_route(6).inc(&first), Err(Protocol));
}

#[test]
fn remote_access_client_side() {
    let c = client();
    assert_eq!(c.inc(&udp(D, P)), Ok(()));
    assert_eq!(c.inc(&udp(X, P)), Err(Source));
    assert_eq!(c.inc(&udp(D, Q)), Err(Destination));
    assert_eq!(c.out(&udp(P, D)), Ok(()));
    assert_eq!(c.out(&udp(Q, D)), Err(Source));
    assert_eq!(c.out(&udp(P, X)), Err(Destination));
}

#[test]
fn remote_access_proxy_side() {
    let s = proxy();
    assert_eq!(s.inc(&udp(P, D)), Ok(()));
    assert_eq!(s.inc(&udp(Q, D)), Err(Source));
    assert_eq!(s.inc(&udp(P, X)), Err(Destination));
    assert_eq!(s.out(&udp(D, P)), Ok(()));
    assert_eq!(s.out(&udp(X, P)), Err(Source));
    assert_eq!(s.out(&udp(D, Q)), Err(Destination));
}

/// Site 1 advertises 10.1/16 for TCP only and accepted site 2's 10.2/16 for UDP only.
fn site() -> Set {
    Set {
        routes: vec![route("10.1.0.0", 16, 6)],
        peer_routes: vec![route("10.2.0.0", 16, 17)],
        ..empty()
    }
}

#[test]
fn site_to_site_protocol_routes() {
    let s = site();
    let (there, here) = ("10.2.0.5", "10.1.0.5");
    // The source lies in a UDP-only route: route protocol never restricts the source.
    assert_eq!(s.inc(&tcp(there, here)), Ok(()));
    assert_eq!(s.inc(&udp(there, here)), Err(Protocol));
    assert_eq!(s.inc(&echo_request(ip(there), ip(here))), Ok(()));
    assert_eq!(s.out(&udp(here, there)), Ok(()));
    assert_eq!(s.out(&tcp(here, there)), Err(Protocol));
    assert_eq!(s.out(&echo_request(ip(here), ip(there))), Ok(()));
}

#[test]
fn unaccepted_peer_routes_never_widen_sources() {
    let s = Set {
        peer_routes: vec![],
        ..site()
    };
    assert_eq!(s.inc(&tcp("10.2.0.5", "10.1.0.5")), Err(Source));
}

#[test]
fn before_any_capsule_everything_drops() {
    let s = empty();
    assert_eq!(s.inc(&udp(D, P)), Err(Source));
    assert_eq!(s.out(&udp(P, D)), Err(Source));
    assert_eq!(s.inc(&udp(D6, P6)), Err(Source));
    assert_eq!(s.out(&udp(P6, D6)), Err(Source));
}

#[test]
fn link_scope() {
    let (c, s) = (client6(), proxy6());
    let probe = echo_request(ip(P6), ip("ff02::1"));
    let reply = echo_reply(ip("fe80::1"), ip(P6));
    assert_eq!(c.out(&probe), Ok(()));
    assert_eq!(s.inc(&probe), Ok(()));
    assert_eq!(c.inc(&reply), Ok(()));
    assert_eq!(s.out(&reply), Ok(()));
    assert_eq!(s.inc(&udp("fe80::1", D6)), Err(Source), "routed, not link");

    // The echo is ICMPv6, so a TCP scope does not stop it.
    let (ct, st) = (client6().scoped(Some(6)), proxy6().scoped(Some(6)));
    assert_eq!(ct.out(&probe), Ok(()));
    assert_eq!(st.inc(&probe), Ok(()));
    assert_eq!(ct.inc(&reply), Ok(()));
    assert_eq!(st.out(&reply), Ok(()));

    // Target 2001:db8:d:7::/64; P6 and the proxy's PX are global and outside it.
    let target = pfx("2001:db8:d:7::", 64);
    let px = "2001:db8:d::1";
    let global = "2001:db8:d::9";
    for policy in [Policy::Enforce, Policy::Unchecked] {
        let (c, s) = (
            client6().target(target).policy(policy),
            proxy6().target(target).policy(policy),
        );
        assert_eq!(c.out(&probe), Ok(()), "client probes");
        assert_eq!(s.inc(&probe), Ok(()), "client probes");
        let probe_px = echo_request(ip(px), ip("ff02::1"));
        assert_eq!(s.out(&probe_px), Ok(()), "proxy probes");
        assert_eq!(c.inc(&probe_px), Ok(()), "proxy probes");
        assert_eq!(s.out(&reply), Ok(()), "link-local reply");
        assert_eq!(c.inc(&reply), Ok(()), "link-local reply");
        let escape = udp("fe80::1", global);
        assert_eq!(s.inc(&escape), Err(ScopeDrop), "{policy:?}");
        assert_eq!(c.inc(&escape), Err(ScopeDrop), "{policy:?}");
    }
    assert_eq!(proxy6().inc(&udp("fe80::1", global)), Err(Source));
}

#[test]
fn scope_ipproto_both_directions() {
    let (c, s) = (client().scoped(Some(6)), proxy().scoped(Some(6)));
    assert_eq!(c.inc(&udp(D, P)), Err(ScopeDrop));
    assert_eq!(s.out(&udp(D, P)), Err(ScopeDrop));
    assert_eq!(c.out(&udp(P, D)), Err(ScopeDrop));
    assert_eq!(s.inc(&udp(P, D)), Err(ScopeDrop));
    for pkt in [tcp(D, P), echo_reply(ip(D), ip(P))] {
        assert_eq!(c.inc(&pkt), Ok(()));
        assert_eq!(s.out(&pkt), Ok(()));
    }
}

#[test]
fn scope_prefix_target() {
    let outside = "198.51.100.8"; // routed, not the target
    let c = client().target(pfx(D, 32));
    assert_eq!(c.inc(&udp(D, P)), Ok(()));
    assert_eq!(c.inc(&udp(outside, P)), Err(ScopeDrop));
    assert_eq!(c.out(&udp(P, outside)), Err(ScopeDrop));
    let s = proxy().target(pfx(D, 32));
    assert_eq!(s.inc(&udp(P, D)), Ok(()));
    assert_eq!(s.inc(&udp(P, outside)), Err(ScopeDrop));
    assert_eq!(s.out(&udp(outside, P)), Err(ScopeDrop));
}

#[test]
fn scope_host_target_not_enforced() {
    let host = Scope {
        target: ScopeTarget::Host("example.com".into()),
        ipproto: None,
    };
    let c = Set {
        scope: host.clone(),
        ..client()
    };
    let s = Set {
        scope: host,
        ..proxy()
    };
    assert_eq!(c.inc(&udp("198.51.100.8", P)), Ok(()));
    assert_eq!(s.inc(&udp(P, "198.51.100.8")), Ok(()));
    assert_eq!(c.inc(&udp(X, P)), Err(Source), "routes still apply");
}

#[test]
fn icmp_error_from_off_route_router() {
    let err = unreach(X, P, &udp(P, D));
    assert_eq!(client().inc(&err), Ok(()));
    assert_eq!(proxy().out(&err), Ok(()));
}

#[test]
fn icmp_error_router_inside_route_outside_target() {
    let err = unreach("198.51.100.1", P, &udp(P, D));
    assert_eq!(client().target(pfx(D, 32)).inc(&err), Ok(()));
    assert_eq!(proxy().target(pfx(D, 32)).out(&err), Ok(()));
}

#[test]
fn icmp_quotation_28_bytes_of_1500() {
    let sent = ipv4(v4(P), v4(D), 17, &[0; 1480]);
    assert_eq!(sent.len(), 1500);
    let err = unreach(X, P, &sent[..28]);
    assert_eq!(client().inc(&err), Ok(()));
}

#[test]
fn icmp6_truncated_packet_too_big() {
    let sent = ipv6_chain(v6(P6), v6(D6), &[0, 60], 6, &[0; 1200]);
    let cut = &sent[..44]; // inside the Hop-by-Hop header
    let err = icmp(ip("2001:db8:ffff::1"), ip(P6), 2, cut);
    let full = icmp(ip("2001:db8:ffff::1"), ip(P6), 2, &sent[..80]);
    let tcp_only = Set {
        peer_routes: vec![route("2001:db8:d::", 48, 6)],
        ..client6()
    };
    assert_eq!(client6().inc(&err), Ok(()));
    assert_eq!(tcp_only.inc(&err), Err(Icmp));
    assert_eq!(tcp_only.inc(&full), Ok(()), "chain present: TCP");
}

#[test]
fn icmp_port_unreachable_for_link_local_udp() {
    let c = Set {
        peer_routes: vec![],
        ..client6()
    };
    let err = unreach("fe80::1", P6, &udp(P6, "fe80::1"));
    assert_eq!(c.inc(&err), Ok(()));
}

#[test]
fn icmp_quoted_source_must_be_outer_destination() {
    assert_eq!(client().inc(&unreach(X, P, &udp(Q, D))), Err(Icmp));
    assert_eq!(client().inc(&unreach(D, P, &udp(Q, D))), Err(Icmp));
    assert_eq!(proxy().out(&unreach(D, P, &udp(Q, D))), Err(Icmp));
}

#[test]
fn icmp_quoting_out_of_scope_packet_dropped() {
    let quote = udp(P, D);
    for policy in [Policy::Enforce, Policy::Unchecked] {
        let c = client().scoped(Some(6)).policy(policy);
        let s = proxy().scoped(Some(6)).policy(policy);
        for outer in [D, X] {
            let err = unreach(outer, P, &quote);
            assert_eq!(c.inc(&err), Err(Icmp), "{policy:?} from {outer}");
            assert_eq!(s.out(&err), Err(Icmp), "{policy:?} from {outer}");
        }
    }
}

#[test]
fn icmp_no_ordinary_fallback() {
    let c = client();
    assert_eq!(c.inc(&unreach(D, P, &[0x45, 0, 0])), Err(Icmp));
    assert_eq!(c.inc(&unreach(D, P, &[])), Err(Icmp));
    assert_eq!(c.inc(&packet(ip(D), ip(P), 1, &[3, 0, 0, 0])), Err(Icmp));
    assert_eq!(client6().inc(&unreach(D6, P6, &[0x60; 39])), Err(Icmp));
}

#[test]
fn icmp_non_first_fragment_is_ordinary() {
    let mut body = vec![3, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&[0xff; 12]);
    let c = client();
    assert_eq!(c.inc(&ipv4_frag(v4(D), v4(P), 1, 100, &body)), Ok(()));
    assert_eq!(c.inc(&ipv4_frag(v4(X), v4(P), 1, 100, &body)), Err(Source));
    let mut body6 = vec![1, 0, 0, 0, 0, 0, 0, 0];
    body6.extend_from_slice(&[0xff; 12]);
    let c6 = client6();
    let frag = ipv6_fragment(v6(D6), v6(P6), 58, 100, &body6);
    assert_eq!(c6.inc(&frag), Ok(()));
}

#[test]
fn shared_address_eligibility() {
    let t = proxy().scoped(Some(6));
    let u = proxy().scoped(Some(17));
    let eligible = |p: &[u8]| (t.out(p).is_ok(), u.out(p).is_ok());
    assert_eq!(eligible(&tcp(D, P)), (true, false));
    assert_eq!(eligible(&udp(D, P)), (false, true));
    assert_eq!(eligible(&unreach(X, P, &tcp(P, D))), (true, false));
    assert_eq!(eligible(&unreach(X, P, &udp(P, D))), (false, true));
    assert_eq!(eligible(&echo_reply(ip(D), ip(P))), (true, true));
    let ping = echo_request(ip(P), ip(D));
    assert_eq!(eligible(&unreach(X, P, &ping)), (true, true));
}

#[test]
fn unchecked_keeps_format_and_scope() {
    let s = empty().policy(Policy::Unchecked).scoped(Some(6));
    assert_eq!(s.inc(&tcp(X, Q)), Ok(()));
    assert_eq!(s.out(&tcp(X, Q)), Ok(()));
    assert_eq!(s.inc(&tcp(D6, P6)), Ok(()));
    assert_eq!(s.inc(&tcp(X, Q)[..19]), Err(Malformed));
    assert_eq!(s.inc(&udp(X, Q)), Err(ScopeDrop));
    assert_eq!(s.out(&udp(X, Q)), Err(ScopeDrop));
    assert_eq!(s.inc(&unreach(X, Q, &[1, 2, 3])), Err(Icmp));
    assert_eq!(s.inc(&unreach(X, Q, &tcp(P, D))), Err(Icmp), "binding");
    assert_eq!(s.inc(&unreach(X, Q, &tcp(Q, D))), Ok(()));
}

#[test]
fn v4_mapped_is_ipv6() {
    let mapped = "::ffff:192.0.2.1";
    let s = Set {
        assigned: vec![pfx("192.0.2.1", 32)],
        routes: vec![route("::", 0, 0)],
        proxy: true,
        ..empty()
    };
    assert_eq!(s.inc(&udp(mapped, D6)), Err(Source));
    let c = Set {
        peer_assigned: vec![pfx("192.0.2.1", 32)],
        peer_routes: vec![route("::", 0, 0)],
        ..empty()
    };
    assert_eq!(c.inc(&udp(D6, mapped)), Err(Destination));
    let scoped = proxy6().target(pfx("192.0.2.0", 24));
    assert_eq!(scoped.inc(&udp(P6, mapped)), Err(ScopeDrop));
}

// ---- reference model ----------------------------------------------------------------------

/// An address as (is IPv6, integer).
fn num(a: IpAddr) -> (bool, u128) {
    match a {
        IpAddr::V4(v) => (false, u128::from(u32::from(v))),
        IpAddr::V6(v) => (true, u128::from(v)),
    }
}

/// Inclusive [first, last] bounds of a prefix.
fn prefix_bounds(p: &IpPrefix) -> (bool, u128, u128) {
    let (v6, n) = num(p.addr());
    let width = if v6 { 128 } else { 32 };
    let host = u32::from(width - p.prefix_len());
    let mask = if host == 0 {
        0
    } else {
        u128::MAX >> (128 - host)
    };
    (v6, n, n | mask)
}

fn range_bounds(r: &IpRange) -> (bool, u128, u128) {
    (num(r.start()).0, num(r.start()).1, num(r.end()).1)
}

fn within(b: (bool, u128, u128), a: IpAddr) -> bool {
    let (v6, n) = num(a);
    b.0 == v6 && b.1 <= n && n <= b.2
}

fn in_prefixes(list: &[IpPrefix], a: IpAddr) -> bool {
    let mut hit = false;
    for p in list {
        if within(prefix_bounds(p), a) {
            hit = true;
        }
    }
    hit
}

/// The spec's rules 3, 4, 5 and 7 for a plain (non-ICMP-error) packet, from the text.
fn reference(
    s: &Set,
    outgoing: bool,
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
) -> Result<(), DropReason> {
    // outgoing: A <-> A', R <-> R', proxy flipped.
    let (a, r, a2, r2, proxy) = if outgoing {
        (
            &s.peer_assigned,
            &s.peer_routes,
            &s.assigned,
            &s.routes,
            !s.proxy,
        )
    } else {
        (
            &s.assigned,
            &s.routes,
            &s.peer_assigned,
            &s.peer_routes,
            s.proxy,
        )
    };
    let v6 = num(src).0;
    let icmp = (!v6 && proto == 1) || (v6 && proto == 58);
    let fe80 = (true, 0xfe80 << 112, (0xfe80 << 112) | (u128::MAX >> 10));
    let ff02 = (true, 0xff02 << 112, (0xff02 << 112) | (u128::MAX >> 16));
    let link_dst = within(fe80, dst) || within(ff02, dst);
    let link_src = within(fe80, src);
    let dst_in_a2 = in_prefixes(a2, dst);
    let link_scoped = link_dst || (link_src && dst_in_a2);

    // Rule 7.
    if let Some(p) = s.scope.ipproto {
        if proto != p && !icmp {
            return Err(ScopeDrop);
        }
    }
    if let ScopeTarget::Prefix(t) = &s.scope.target {
        let remote = if proxy { dst } else { src };
        if !link_scoped && !within(prefix_bounds(t), remote) {
            return Err(ScopeDrop);
        }
    }
    if s.policy == Policy::Unchecked {
        return Ok(());
    }

    // Rule 3 (with rule 5's link-local source).
    let mut src_ok = in_prefixes(a, src);
    for route in r2 {
        if within(range_bounds(route), src) {
            src_ok = true;
        }
    }
    if link_src && (link_dst || dst_in_a2) {
        src_ok = true;
    }
    if !src_ok {
        return Err(Source);
    }

    // Rule 4 (with rule 5's link-scoped destination).
    if link_dst || dst_in_a2 {
        return Ok(());
    }
    let mut covered = false;
    for route in r {
        if within(range_bounds(route), dst) {
            if route.ipproto() == 0 || route.ipproto() == proto || icmp {
                return Ok(());
            }
            covered = true;
        }
    }
    Err(if covered { Protocol } else { Destination })
}

fn addr_of(v6: bool, n: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(n))
    } else {
        IpAddr::V4(Ipv4Addr::from(n as u32))
    }
}

fn arb_prefix() -> impl Strategy<Value = IpPrefix> {
    (any::<bool>(), any::<u128>(), 0u8..=128).prop_map(|(v6, n, len)| {
        let width = if v6 { 128 } else { 32 };
        let len = len % (width + 1);
        let n = if v6 { n } else { n & u128::from(u32::MAX) };
        let host = u32::from(width - len);
        let mask = if host == 0 {
            0
        } else {
            u128::MAX >> (128 - host)
        };
        IpPrefix::new(addr_of(v6, n & !mask), len).unwrap()
    })
}

fn arb_proto() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0u8), Just(1), Just(6), Just(17), Just(58), any::<u8>()]
}

fn arb_range() -> impl Strategy<Value = IpRange> {
    (arb_prefix(), any::<u128>(), arb_proto()).prop_map(|(p, span, proto)| {
        let (v6, lo, hi) = prefix_bounds(&p);
        // A range inside the prefix, so bounds land off the bit grid as well.
        let start = lo + (hi - lo).checked_add(1).map_or(span, |n| span % n);
        IpRange::new(addr_of(v6, start), addr_of(v6, hi), proto).unwrap()
    })
}

fn arb_set() -> impl Strategy<Value = Set> {
    let lists = (
        prop::collection::vec(arb_prefix(), 0..5),
        prop::collection::vec(arb_range(), 0..5),
        prop::collection::vec(arb_prefix(), 0..5),
        prop::collection::vec(arb_range(), 0..5),
    );
    let scope = (
        prop::option::weighted(0.25, arb_prefix()),
        prop::option::weighted(0.25, arb_proto()),
    );
    (lists, scope, any::<bool>(), any::<bool>()).prop_map(
        |((assigned, routes, peer_assigned, peer_routes), (target, ipproto), proxy, unchecked)| {
            Set {
                assigned,
                routes,
                peer_assigned,
                peer_routes,
                scope: Scope {
                    target: target.map_or(ScopeTarget::Any, ScopeTarget::Prefix),
                    ipproto,
                },
                proxy,
                policy: if unchecked {
                    Policy::Unchecked
                } else {
                    Policy::Enforce
                },
            }
        },
    )
}

/// Addresses on and next to every list boundary, plus link-scoped and edge addresses.
fn candidates(s: &Set) -> Vec<IpAddr> {
    let mut bounds: Vec<(bool, u128, u128)> = Vec::new();
    for p in s.assigned.iter().chain(&s.peer_assigned) {
        bounds.push(prefix_bounds(p));
    }
    for r in s.routes.iter().chain(&s.peer_routes) {
        bounds.push(range_bounds(r));
    }
    if let ScopeTarget::Prefix(t) = &s.scope.target {
        bounds.push(prefix_bounds(t));
    }
    let mut out: Vec<IpAddr> = [
        "0.0.0.0",
        "255.255.255.255",
        "::",
        "fe80::1",
        "ff02::1",
        "fec0::1",
    ]
    .into_iter()
    .map(ip)
    .collect();
    for (v6, lo, hi) in bounds {
        let max = if v6 { u128::MAX } else { u128::from(u32::MAX) };
        for n in [lo.wrapping_sub(1), lo, hi, hi.wrapping_add(1)] {
            if n <= max {
                out.push(addr_of(v6, n));
            }
        }
    }
    out
}

proptest! {
    // Cheap cases, and the Protocol outcome needs many of them to show up.
    #![proptest_config(ProptestConfig::with_cases(2048))]
    #[test]
    fn agrees_with_reference(
        s in arb_set(),
        outgoing in any::<bool>(),
        src in any::<Index>(),
        dst in any::<Index>(),
        proto in arb_proto(),
    ) {
        let all = candidates(&s);
        let src = *src.get(&all);
        let same: Vec<IpAddr> = all.into_iter().filter(|a| a.is_ipv4() == src.is_ipv4()).collect();
        let dst = *dst.get(&same);
        // Plain packets only: an IPv6 extension type here would start a chain.
        let ext = [0, 43, 44, 51, 60, 135, 139, 140];
        let proto = if src.is_ipv6() && ext.contains(&proto) { 17 } else { proto };
        // Eight zero bytes: never an ICMP error type, never a malformed header.
        let pkt = packet(src, dst, proto, &[0; 8]);
        let expected = reference(&s, outgoing, src, dst, proto);
        let got = if outgoing { s.out(&pkt) } else { s.inc(&pkt) };
        prop_assert_eq!(got, expected, "{} -> {} proto {}", src, dst, proto);
    }
}
