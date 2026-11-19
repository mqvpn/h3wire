// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! What one CONNECT-IP tunnel knows: what was assigned and advertised, what the peer
//! offered and what was accepted, pending address requests, and the drop counters. No
//! I/O: the tunnel's halves share one `State` behind a mutex.

use super::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AddrSet, AssignedAddress, DropReason, Drops, IpError, IpEvent,
    IpPrefix, IpRange, Policy, ROUTE_ADVERTISEMENT, RouteSet, Rules, Scope, decode_address_assign,
    decode_address_request, decode_routes,
};
use h3wire_async::core::H3Code;
use std::collections::BTreeSet;
use std::num::NonZeroU64;

/// How many of the peer's address requests may await an answer.
const MAX_PENDING: usize = 1024;

/// What a tunnel knows about addresses and routes, and the drops it counted.
#[derive(Debug)]
pub(crate) struct State {
    scope: Scope,
    proxy: bool,
    policy: Policy,
    /// *A*: what I assigned to the peer.
    assigned: AddrSet,
    /// *R*: what I advertised.
    routes: RouteSet,
    /// *A* and *R* plus the list of a send in flight; receive-only until committed.
    staged_assigned: Option<AddrSet>,
    staged_routes: Option<RouteSet>,
    /// The peer's latest offers.
    offered_assigned: AddrSet,
    offered_routes: RouteSet,
    /// *A'* and *R'*: the offers I accepted.
    peer_assigned: AddrSet,
    peer_routes: RouteSet,
    pending: BTreeSet<NonZeroU64>,
    last_request_id: u64,
    drops: Drops,
}

/// The non-rejection prefixes of an assignment list.
fn prefixes(entries: &[AssignedAddress]) -> Vec<IpPrefix> {
    entries
        .iter()
        .filter(|e| !e.is_rejection())
        .map(|e| e.prefix)
        .collect()
}

impl State {
    pub(crate) fn new(scope: Scope, proxy: bool) -> Self {
        Self {
            scope,
            proxy,
            policy: Policy::default(),
            assigned: AddrSet::default(),
            routes: RouteSet::default(),
            staged_assigned: None,
            staged_routes: None,
            offered_assigned: AddrSet::default(),
            offered_routes: RouteSet::default(),
            peer_assigned: AddrSet::default(),
            peer_routes: RouteSet::default(),
            pending: BTreeSet::new(),
            last_request_id: 0,
            drops: Drops::default(),
        }
    }

    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    pub(crate) fn drops(&self) -> Drops {
        self.drops
    }

    pub(crate) fn count_context(&mut self) {
        self.drops.context += 1;
    }

    pub(crate) fn count_malformed(&mut self) {
        self.drops.malformed += 1;
    }

    fn rules<'a>(&'a self, assigned: &'a AddrSet, routes: &'a RouteSet) -> Rules<'a> {
        Rules {
            assigned,
            routes,
            peer_assigned: &self.peer_assigned,
            peer_routes: &self.peer_routes,
            scope: &self.scope,
            proxy: self.proxy,
            policy: self.policy,
        }
    }

    /// Judges a received packet with *A* and *R* widened by the staged entries; counts a
    /// drop and returns `false`.
    pub(crate) fn on_payload(&mut self, packet: &[u8]) -> bool {
        let rules = self.rules(
            self.staged_assigned.as_ref().unwrap_or(&self.assigned),
            self.staged_routes.as_ref().unwrap_or(&self.routes),
        );
        let Err(why) = rules.incoming(packet) else {
            return true;
        };
        let d = &mut self.drops;
        *match why {
            DropReason::Malformed => &mut d.malformed,
            DropReason::Source => &mut d.source,
            DropReason::Destination => &mut d.destination,
            DropReason::Protocol => &mut d.protocol,
            DropReason::Scope => &mut d.scope,
            DropReason::Icmp => &mut d.icmp,
        } += 1;
        false
    }

    pub(crate) fn check_outgoing(&self, packet: &[u8]) -> Result<(), DropReason> {
        self.rules(&self.assigned, &self.routes).outgoing(packet)
    }

    /// Takes only the three control types the carrier selects; any other type is
    /// `MESSAGE_ERROR`, so other capsules must be skipped before they get here.
    pub(crate) fn on_control(&mut self, ty: u64, value: &[u8]) -> Result<IpEvent, H3Code> {
        let bad = |_| H3Code::MESSAGE_ERROR;
        match ty {
            ADDRESS_ASSIGN => {
                let entries = decode_address_assign(value).map_err(bad)?;
                self.offered_assigned = AddrSet::new(prefixes(&entries));
                let offered = &self.offered_assigned;
                self.peer_assigned.retain(|a| offered.covers(a));
                Ok(IpEvent::AddressAssign(entries))
            }
            ADDRESS_REQUEST => {
                let entries = decode_address_request(value).map_err(bad)?;
                self.pending.extend(entries.iter().map(|e| e.request_id));
                if self.pending.len() > MAX_PENDING {
                    return Err(H3Code::EXCESSIVE_LOAD);
                }
                Ok(IpEvent::AddressRequest(entries))
            }
            ROUTE_ADVERTISEMENT => {
                let routes = decode_routes(value).map_err(bad)?;
                self.offered_routes = RouteSet::new(routes.clone());
                let offered = &self.offered_routes;
                self.peer_routes.retain(|a| offered.covers(a));
                Ok(IpEvent::Routes(routes))
            }
            _ => Err(H3Code::MESSAGE_ERROR),
        }
    }

    pub(crate) fn check_assign(&self, entries: &[AssignedAddress]) -> Result<(), IpError> {
        let known = |e: &AssignedAddress| {
            e.request_id == 0
                || NonZeroU64::new(e.request_id).is_some_and(|n| self.pending.contains(&n))
        };
        if entries.iter().all(known) {
            Ok(())
        } else {
            Err(IpError::UnknownRequest)
        }
    }

    pub(crate) fn stage_assign(&mut self, entries: &[AssignedAddress]) {
        let mut all = self.assigned.items().to_vec();
        all.extend(prefixes(entries));
        self.staged_assigned = Some(AddrSet::new(all));
    }

    pub(crate) fn commit_assign(&mut self, entries: &[AssignedAddress]) {
        self.assigned = AddrSet::new(prefixes(entries));
        self.staged_assigned = None;
        for n in entries.iter().filter_map(|e| NonZeroU64::new(e.request_id)) {
            self.pending.remove(&n);
        }
    }

    pub(crate) fn stage_advertise(&mut self, routes: &[IpRange]) {
        let mut all = self.routes.items().to_vec();
        all.extend(routes);
        self.staged_routes = Some(RouteSet::new(all));
    }

    pub(crate) fn commit_advertise(&mut self, routes: &[IpRange]) {
        self.routes = RouteSet::new(routes.to_vec());
        self.staged_routes = None;
    }

    pub(crate) fn unstage(&mut self) {
        self.staged_assigned = None;
        self.staged_routes = None;
    }

    pub(crate) fn next_request_ids(&mut self, n: usize) -> Vec<NonZeroU64> {
        (0..n)
            .map(|_| {
                self.last_request_id += 1;
                NonZeroU64::new(self.last_request_id).expect("counter starts at 1")
            })
            .collect()
    }

    pub(crate) fn pending_requests(&self) -> Vec<NonZeroU64> {
        self.pending.iter().copied().collect()
    }

    pub(crate) fn accept_assigned(&mut self, items: &[IpPrefix]) -> Result<(), IpError> {
        if !items.iter().all(|i| self.offered_assigned.covers(i)) {
            return Err(IpError::NotOffered);
        }
        self.peer_assigned = AddrSet::new(items.to_vec());
        Ok(())
    }

    pub(crate) fn accept_routes(&mut self, items: &[IpRange]) -> Result<(), IpError> {
        if !items.iter().all(|i| self.offered_routes.covers(i)) {
            return Err(IpError::NotOffered);
        }
        self.peer_routes = RouteSet::new(items.to_vec());
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/packets/mod.rs"]
mod packets;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{
        RequestedAddress, ScopeTarget, encode_address_assign, encode_address_request, encode_routes,
    };
    use bytes::BytesMut;
    use std::net::IpAddr;

    use super::packets;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pfx(s: &str) -> IpPrefix {
        let (a, l) = s.split_once('/').unwrap();
        IpPrefix::new(ip(a), l.parse().unwrap()).unwrap()
    }

    fn range(s: &str, proto: u8) -> IpRange {
        IpRange::from_prefix(pfx(s), proto)
    }

    fn id(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    fn asg(request_id: u64, p: &str) -> AssignedAddress {
        AssignedAddress {
            request_id,
            prefix: pfx(p),
        }
    }

    /// A packet from `src` to `dst` with a UDP protocol number and 8 payload bytes.
    fn pkt(src: &str, dst: &str) -> Vec<u8> {
        packets::packet(ip(src), ip(dst), 17, &[0; 8])
    }

    /// The value of the one small capsule `f` encodes.
    fn value(f: impl FnOnce(&mut BytesMut)) -> Vec<u8> {
        let mut b = BytesMut::new();
        f(&mut b);
        assert!(b.len() < 66, "type and length take two bytes");
        b[2..].to_vec()
    }

    fn assign_value(entries: &[AssignedAddress]) -> Vec<u8> {
        value(|b| encode_address_assign(entries, b).unwrap())
    }

    fn routes_value(routes: &[IpRange]) -> Vec<u8> {
        value(|b| encode_routes(routes, b).unwrap())
    }

    /// A proxy that assigned `10.0.0.2/32` and advertised `192.0.2.0/24`.
    fn proxy() -> State {
        let mut s = State::new(Scope::ANY, true);
        s.commit_assign(&[asg(0, "10.0.0.2/32")]);
        s.commit_advertise(&[range("192.0.2.0/24", 0)]);
        s
    }

    #[test]
    fn request_ids_start_at_one_never_reused() {
        let mut s = State::new(Scope::ANY, false);
        assert_eq!(s.next_request_ids(2), [id(1), id(2)]);
        assert_eq!(s.next_request_ids(0), []);
        assert_eq!(s.next_request_ids(1), [id(3)]);
    }

    #[test]
    fn pending_tracks_requests_and_replies() {
        let mut s = State::new(Scope::ANY, true);
        let req = [5, 9].map(|n| RequestedAddress {
            request_id: id(n),
            prefix: pfx("0.0.0.0/0"),
        });
        let v = value(|b| encode_address_request(&req, b).unwrap());
        assert_eq!(
            s.on_control(ADDRESS_REQUEST, &v),
            Ok(IpEvent::AddressRequest(req.to_vec()))
        );
        assert_eq!(s.pending_requests(), [id(5), id(9)]);
        assert!(matches!(
            s.check_assign(&[asg(7, "10.0.0.2/32")]),
            Err(IpError::UnknownRequest)
        ));
        let reply = [
            asg(5, "10.0.0.2/32"),
            AssignedAddress::rejection(id(9), false),
        ];
        s.check_assign(&reply).unwrap();
        s.commit_assign(&reply);
        assert_eq!(s.pending_requests(), []);
        assert_eq!(s.assigned.items(), [pfx("10.0.0.2/32")]);
    }

    #[test]
    fn reply_keeps_earlier_assignments() {
        let mut s = State::new(Scope::ANY, true);
        let v = value(|b| {
            let r = RequestedAddress {
                request_id: id(1),
                prefix: pfx("0.0.0.0/0"),
            };
            encode_address_request(&[r], b).unwrap()
        });
        s.on_control(ADDRESS_REQUEST, &v).unwrap();
        s.commit_assign(&[asg(0, "10.0.0.2/32")]);
        let second = [asg(0, "10.0.0.2/32"), asg(1, "10.0.0.3/32")];
        s.check_assign(&second).unwrap();
        s.commit_assign(&second);
        assert_eq!(s.assigned.items(), [pfx("10.0.0.2/32"), pfx("10.0.0.3/32")]);
        assert_eq!(s.pending_requests(), []);
    }

    #[test]
    fn pending_over_1024_is_excessive_load() {
        let mut s = State::new(Scope::ANY, true);
        let req = |n: u64| {
            let r = RequestedAddress {
                request_id: id(n),
                prefix: pfx("0.0.0.0/0"),
            };
            value(|b| encode_address_request(&[r], b).unwrap())
        };
        for n in 1..=1024 {
            assert!(s.on_control(ADDRESS_REQUEST, &req(n)).is_ok(), "{n}");
        }
        assert_eq!(
            s.on_control(ADDRESS_REQUEST, &req(1025)),
            Err(H3Code::EXCESSIVE_LOAD)
        );
    }

    #[test]
    fn offers_need_acceptance() {
        let mut s = State::new(Scope::ANY, false);
        let a = [asg(0, "10.1.0.1/32")];
        let r = [range("172.16.0.0/16", 0)];
        assert_eq!(
            s.on_control(ADDRESS_ASSIGN, &assign_value(&a)),
            Ok(IpEvent::AddressAssign(a.to_vec()))
        );
        assert_eq!(
            s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&r)),
            Ok(IpEvent::Routes(r.to_vec()))
        );
        let p = pkt("172.16.0.5", "10.1.0.1");
        assert!(!s.on_payload(&p));
        s.accept_assigned(&[pfx("10.1.0.1/32")]).unwrap();
        assert!(!s.on_payload(&p));
        s.accept_routes(&r).unwrap();
        assert!(s.on_payload(&p));
        assert_eq!(s.drops().source, 2);
    }

    #[test]
    fn accept_outside_offer_is_not_offered() {
        let mut s = State::new(Scope::ANY, false);
        let a = [asg(0, "10.1.0.0/24")];
        let r = [range("172.16.0.0/16", 6)];
        s.on_control(ADDRESS_ASSIGN, &assign_value(&a)).unwrap();
        s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&r))
            .unwrap();
        s.accept_assigned(&[pfx("10.1.0.1/32")]).unwrap();
        s.accept_routes(&[range("172.16.1.0/24", 6)]).unwrap();
        for bad in ["10.0.0.0/16", "fd00::/64"] {
            assert!(matches!(
                s.accept_assigned(&[pfx(bad)]),
                Err(IpError::NotOffered)
            ));
        }
        // One bad item spoils the whole list.
        assert!(matches!(
            s.accept_assigned(&[pfx("10.1.0.2/32"), pfx("10.2.0.0/24")]),
            Err(IpError::NotOffered)
        ));
        for bad in [range("172.16.0.0/16", 0), range("172.16.0.0/12", 6)] {
            assert!(matches!(s.accept_routes(&[bad]), Err(IpError::NotOffered)));
        }
        assert_eq!(s.peer_assigned.items(), [pfx("10.1.0.1/32")]);
        assert_eq!(s.peer_routes.items(), [range("172.16.1.0/24", 6)]);
    }

    #[test]
    fn accept_sub_prefix_of_offer() {
        let mut s = State::new(Scope::ANY, false);
        s.on_control(ADDRESS_ASSIGN, &assign_value(&[asg(0, "10.1.0.0/24")]))
            .unwrap();
        s.accept_assigned(&[pfx("10.1.0.0/25"), pfx("10.1.0.200/32")])
            .unwrap();
        assert_eq!(s.peer_assigned.items().len(), 2);
        // Replaced, not merged.
        s.accept_assigned(&[]).unwrap();
        assert!(s.peer_assigned.items().is_empty());
    }

    #[test]
    fn new_offer_withdraws_accepted() {
        let mut s = State::new(Scope::ANY, false);
        let both = [asg(0, "10.1.0.1/32"), asg(0, "10.2.0.1/32")];
        s.on_control(ADDRESS_ASSIGN, &assign_value(&both)).unwrap();
        s.accept_assigned(&[pfx("10.1.0.1/32"), pfx("10.2.0.1/32")])
            .unwrap();
        s.on_control(ADDRESS_ASSIGN, &assign_value(&both[..1]))
            .unwrap();
        assert_eq!(s.peer_assigned.items(), [pfx("10.1.0.1/32")]);

        let routes = [range("172.16.0.0/16", 0), range("172.17.0.0/16", 0)];
        s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&routes))
            .unwrap();
        s.accept_routes(&routes).unwrap();
        s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&routes[1..]))
            .unwrap();
        assert_eq!(s.peer_routes.items(), [routes[1]]);
    }

    #[test]
    fn empty_lists_withdraw() {
        let mut s = proxy();
        s.commit_assign(&[]);
        s.commit_advertise(&[]);
        assert!(s.assigned.items().is_empty() && s.routes.items().is_empty());
        assert!(!s.on_payload(&pkt("10.0.0.2", "192.0.2.1")));

        s.on_control(ADDRESS_ASSIGN, &assign_value(&[asg(0, "10.1.0.1/32")]))
            .unwrap();
        s.accept_assigned(&[pfx("10.1.0.1/32")]).unwrap();
        assert_eq!(
            s.on_control(ADDRESS_ASSIGN, &assign_value(&[])),
            Ok(IpEvent::AddressAssign(vec![]))
        );
        assert!(s.offered_assigned.items().is_empty() && s.peer_assigned.items().is_empty());
    }

    #[test]
    fn staged_lists_widen_receive_only() {
        let mut s = proxy();
        let old = pkt("10.0.0.2", "192.0.2.1");
        let new = pkt("10.0.0.3", "192.0.2.1");
        let reply_old = pkt("192.0.2.1", "10.0.0.2");
        let reply_new = pkt("192.0.2.1", "10.0.0.3");
        assert!(!s.on_payload(&new));

        s.stage_assign(&[asg(0, "10.0.0.3/32")]);
        assert!(s.on_payload(&new));
        assert!(s.on_payload(&old));
        assert_eq!(s.check_outgoing(&reply_new), Err(DropReason::Destination));
        assert_eq!(s.check_outgoing(&reply_old), Ok(()));
        s.unstage();
        assert!(!s.on_payload(&new));
        assert!(s.on_payload(&old));
        assert_eq!(s.assigned.items(), [pfx("10.0.0.2/32")]);

        s.stage_assign(&[asg(0, "10.0.0.3/32")]);
        s.commit_assign(&[asg(0, "10.0.0.3/32")]);
        assert!(s.on_payload(&new));
        assert!(!s.on_payload(&old));
        assert_eq!(s.check_outgoing(&reply_new), Ok(()));

        // Routes.
        let to_new = pkt("10.0.0.3", "192.0.3.1");
        let back = pkt("192.0.3.1", "10.0.0.3");
        assert!(!s.on_payload(&to_new));
        s.stage_advertise(&[range("192.0.3.0/24", 0)]);
        assert!(s.on_payload(&to_new));
        assert!(s.on_payload(&new));
        assert_eq!(s.check_outgoing(&back), Err(DropReason::Source));
        s.unstage();
        assert!(!s.on_payload(&to_new));
        assert!(s.on_payload(&new));
        s.stage_advertise(&[range("192.0.3.0/24", 0)]);
        s.commit_advertise(&[range("192.0.3.0/24", 0)]);
        assert!(s.on_payload(&to_new));
        assert!(!s.on_payload(&new));
        assert_eq!(s.check_outgoing(&back), Ok(()));
    }

    #[test]
    fn empty_and_repeated_stage() {
        let mut s = proxy();
        let old = pkt("10.0.0.2", "192.0.2.1");
        let third = pkt("10.0.0.3", "192.0.2.1");
        let fourth = pkt("10.0.0.4", "192.0.2.1");

        // A withdrawal in flight keeps the old entries valid until it commits.
        s.stage_assign(&[]);
        s.stage_advertise(&[]);
        assert!(s.on_payload(&old));
        s.commit_assign(&[]);
        assert!(!s.on_payload(&old));
        s.commit_advertise(&[]);

        // A later stage replaces the earlier one.
        let mut s = proxy();
        s.stage_assign(&[asg(0, "10.0.0.3/32")]);
        s.stage_assign(&[asg(0, "10.0.0.4/32")]);
        assert!(!s.on_payload(&third));
        assert!(s.on_payload(&fourth));
        assert!(s.on_payload(&old));
        s.stage_advertise(&[range("192.0.3.0/24", 0)]);
        s.stage_advertise(&[range("192.0.4.0/24", 0)]);
        assert!(!s.on_payload(&pkt("10.0.0.2", "192.0.3.1")));
        assert!(s.on_payload(&pkt("10.0.0.2", "192.0.4.1")));
    }

    #[test]
    fn rejection_reported_not_offered() {
        let mut s = State::new(Scope::ANY, false);
        let entries = [
            AssignedAddress::rejection(id(4), false),
            asg(0, "10.1.0.1/32"),
        ];
        assert_eq!(
            s.on_control(ADDRESS_ASSIGN, &assign_value(&entries)),
            Ok(IpEvent::AddressAssign(entries.to_vec()))
        );
        assert_eq!(s.offered_assigned.items(), [pfx("10.1.0.1/32")]);
        assert!(matches!(
            s.accept_assigned(&[pfx("0.0.0.0/32")]),
            Err(IpError::NotOffered)
        ));
    }

    #[test]
    fn malformed_control_is_message_error() {
        let mut s = State::new(Scope::ANY, true);
        for ty in [ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT] {
            assert_eq!(
                s.on_control(ty, &[7, 1, 2]),
                Err(H3Code::MESSAGE_ERROR),
                "{ty}"
            );
        }
        // An ADDRESS_REQUEST with no entries.
        assert_eq!(
            s.on_control(ADDRESS_REQUEST, &[]),
            Err(H3Code::MESSAGE_ERROR)
        );
    }

    #[test]
    fn drop_counters() {
        let scope = Scope {
            target: ScopeTarget::Prefix(pfx("192.0.0.0/16")),
            ipproto: Some(17),
        };
        let mut s = State::new(scope, true);
        s.commit_assign(&[asg(0, "10.0.0.2/32")]);
        s.commit_advertise(&[range("192.0.2.0/24", 6)]);
        let icmp = packets::unreachable(ip("192.0.2.1"), ip("10.0.0.2"), &[]);
        for p in [
            vec![0xff],
            pkt("10.9.9.9", "192.0.2.9"),
            pkt("10.0.0.2", "192.0.3.1"),
            pkt("10.0.0.2", "192.0.2.9"),
            pkt("10.0.0.2", "8.8.8.8"),
            icmp,
        ] {
            assert!(!s.on_payload(&p));
        }
        s.count_context();
        let one = Drops {
            malformed: 1,
            source: 1,
            destination: 1,
            protocol: 1,
            scope: 1,
            icmp: 1,
            context: 1,
        };
        assert_eq!(s.drops(), one);
        s.count_malformed();
        assert_eq!(s.drops().malformed, 2);
    }
}
