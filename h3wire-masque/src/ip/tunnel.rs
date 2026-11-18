// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! One CONNECT-IP tunnel (RFC 9484): IP packets and control capsules over the carrier
//! shared with CONNECT-UDP, and the tunnel's state: what was assigned and advertised,
//! what the peer offered and what was accepted, pending address requests, and the drop
//! counters.

use super::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AssignedAddress, DropReason, Drops, IpPrefix, IpRange,
    MAX_CONTROL_CAPSULE, Policy, ROUTE_ADVERTISEMENT, RequestedAddress, RouteError, Rules, Scope,
    decode_address_assign, decode_address_request, decode_routes, encode_address_assign,
    encode_address_request, encode_routes,
};
use crate::capsule::CapsuleError;
use crate::carrier::{self, Limits, Raw, Rx, Step, Tx, TxError};
use crate::tunnel::Carrier;
use bytes::{Bytes, BytesMut};
use h3wire_async::core::H3Code;
use h3wire_async::datagram::Datagrams;
use h3wire_async::upgrade::Tunnel;
use h3wire_async::{DatagramError, Error};
use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The largest IP packet a tunnel carries: a 40-byte IPv6 header and 65,535 bytes.
pub const MAX_IP_PACKET: usize = 65_575;

/// The IPv6 minimum link MTU (RFC 8200 section 5).
const IPV6_MIN_MTU: usize = 1280;

/// How many of the peer's address requests may await an answer.
const MAX_PENDING: usize = 1024;

/// Something a CONNECT-IP tunnel received.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpEvent {
    /// An IP packet that passed the policy.
    Packet(Bytes),
    /// The peer's `ADDRESS_ASSIGN`: an offer until accepted. Rejections are included.
    AddressAssign(Vec<AssignedAddress>),
    /// The peer's `ADDRESS_REQUEST`, to be answered with an assignment or a rejection.
    AddressRequest(Vec<RequestedAddress>),
    /// The peer's `ROUTE_ADVERTISEMENT`: an offer until accepted.
    Routes(Vec<IpRange>),
}

/// Why a CONNECT-IP tunnel operation failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum IpError {
    /// The packet is over [`MAX_IP_PACKET`], or over the datagram carrier's limit.
    TooLarge,
    /// The packet is empty or is neither IPv4 nor IPv6.
    Malformed,
    /// The datagram carrier cannot hold an IPv6 packet of the minimum MTU, 1280 bytes.
    MtuTooSmall,
    /// An assignment answers a request ID that is not pending.
    UnknownRequest,
    /// The item is not covered by a current offer from the peer.
    NotOffered,
    /// A control capsule could not be encoded.
    Capsule(CapsuleError),
    /// A route list could not be encoded.
    Route(RouteError),
    /// The sending side was finished, or the request ended.
    Closed,
    /// The datagram carrier refused the packet.
    Datagram(DatagramError),
    /// The request stream or connection failed, including a local abort.
    Http(Error),
}

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("IP packet too large"),
            Self::Malformed => f.write_str("not an IP packet"),
            Self::MtuTooSmall => f.write_str("path too small for IPv6 minimum MTU"),
            Self::UnknownRequest => f.write_str("no pending address request with that ID"),
            Self::NotOffered => f.write_str("not covered by an offer from the peer"),
            Self::Capsule(e) => write!(f, "capsule: {e}"),
            Self::Route(e) => write!(f, "routes: {e}"),
            Self::Closed => f.write_str("tunnel send side finished"),
            Self::Datagram(e) => write!(f, "datagram refused: {e}"),
            Self::Http(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for IpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capsule(e) => Some(e),
            Self::Route(e) => Some(e),
            Self::Datagram(e) => Some(e),
            Self::Http(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TxError> for IpError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::Closed => Self::Closed,
            TxError::Datagram(DatagramError::TooLarge) => Self::TooLarge,
            TxError::Datagram(e) => Self::Datagram(e),
            TxError::Http(e) => Self::Http(e),
        }
    }
}

/// The three control types are taken whole; every other capsule type is skipped
/// unbuffered (RFC 9297 section 3.2).
const LIMITS: Limits = Limits {
    max_payload: MAX_IP_PACKET,
    control: |ty| matches!(ty, ADDRESS_ASSIGN | ADDRESS_REQUEST | ROUTE_ADVERTISEMENT),
    max_control: MAX_CONTROL_CAPSULE,
};

/// Each lock is for one short step: never across an `.await` or while a future is polled.
fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Unstages when dropped uncommitted, so a cancelled or failed control send leaves the
/// state as it was. Sound because assign and advertise take `&mut` on the one sender: at
/// most one list is staged at a time.
struct Staged<'a>(&'a Mutex<State>);

impl Staged<'_> {
    fn commit(self, f: impl FnOnce(&mut State)) {
        f(&mut lock(self.0));
        std::mem::forget(self);
    }
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        lock(self.0).unstage();
    }
}

/// The state methods of [`IpTunnel`], [`IpSender`] and [`IpReceiver`]; the halves share
/// one state.
macro_rules! state_methods {
    () => {
        /// Accept `items` as addresses the peer assigned to this end (*A'*), replacing
        /// those accepted before. Each must lie in the peer's current `ADDRESS_ASSIGN`
        /// offer, else `NotOffered` and nothing changes. A new offer from the peer drops
        /// accepted items it no longer covers.
        pub fn accept_assigned(&self, items: &[IpPrefix]) -> Result<(), IpError> {
            lock(self.state()).accept_assigned(items)
        }

        /// Accept `items` as the peer's routes (*R'*), replacing those accepted before.
        /// Each must lie in the peer's current `ROUTE_ADVERTISEMENT`, else `NotOffered`
        /// and nothing changes. A new offer drops accepted items it no longer covers.
        pub fn accept_routes(&self, items: &[IpRange]) -> Result<(), IpError> {
            lock(self.state()).accept_routes(items)
        }

        /// Whether the peer's rules, as this end knows them, admit `packet` from here. An
        /// eligibility filter, not a tunnel selector; `send` does not apply it.
        pub fn check_outgoing(&self, packet: &[u8]) -> Result<(), DropReason> {
            lock(self.state()).check_outgoing(packet)
        }

        /// The received packets dropped so far, by reason.
        pub fn drops(&self) -> Drops {
            lock(self.state()).drops()
        }

        /// The peer's address request IDs no `assign` has answered yet, ascending.
        pub fn pending_requests(&self) -> Vec<NonZeroU64> {
            lock(self.state()).pending_requests()
        }

        /// Set whether addresses and routes are checked, on receive and in
        /// `check_outgoing`. The default is [`Policy::Enforce`].
        pub fn set_policy(&self, policy: Policy) {
            lock(self.state()).set_policy(policy)
        }

        /// The request scope: what the client requested, or what the proxy matched.
        pub fn scope(&self) -> Scope {
            lock(self.state()).scope().clone()
        }
    };
}

/// A CONNECT-IP tunnel; [`split`](Self::split) gives independent halves sharing one
/// state.
#[derive(Debug)]
pub struct IpTunnel {
    send: IpSender,
    recv: IpReceiver,
}

impl IpTunnel {
    /// Wait for `settings` (`true`: the peer's SETTINGS arrived) to choose the carrier;
    /// `proxy` is this end's role.
    pub(crate) async fn open(
        tunnel: Tunnel,
        dgrams: Option<Datagrams>,
        settings: impl Future<Output = bool>,
        scope: Scope,
        proxy: bool,
    ) -> Result<Self, Error> {
        let (tx, rx) = carrier::open(tunnel, dgrams, settings, LIMITS).await?;
        let state = Arc::new(Mutex::new(State::new(scope, proxy)));
        Ok(Self {
            send: IpSender {
                tx,
                state: state.clone(),
            },
            recv: IpReceiver { rx, state },
        })
    }

    fn state(&self) -> &Mutex<State> {
        &self.send.state
    }

    /// See [`IpSender::send`].
    pub async fn send(&mut self, packet: Bytes) -> Result<(), IpError> {
        self.send.send(packet).await
    }

    /// See [`IpSender::assign`].
    pub async fn assign(&mut self, entries: &[AssignedAddress]) -> Result<(), IpError> {
        self.send.assign(entries).await
    }

    /// See [`IpSender::advertise`].
    pub async fn advertise(&mut self, routes: &[IpRange]) -> Result<(), IpError> {
        self.send.advertise(routes).await
    }

    /// See [`IpSender::request`].
    pub async fn request(&mut self, prefixes: &[IpPrefix]) -> Result<Vec<NonZeroU64>, IpError> {
        self.send.request(prefixes).await
    }

    /// See [`IpReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<IpEvent>, IpError> {
        self.recv.recv().await
    }

    /// See [`IpSender::finish`].
    pub fn finish(&mut self) -> Result<(), IpError> {
        self.send.finish()
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.send.abort(code)
    }

    /// See [`IpSender::max_payload`].
    pub fn max_payload(&self) -> Option<usize> {
        self.send.max_payload()
    }

    /// See [`IpSender::carrier`].
    pub fn carrier(&self) -> Carrier {
        self.send.carrier()
    }

    state_methods!();

    /// The two halves.
    pub fn split(self) -> (IpSender, IpReceiver) {
        (self.send, self.recv)
    }
}

/// The sending half of an [`IpTunnel`].
#[derive(Debug)]
pub struct IpSender {
    tx: Tx,
    state: Arc<Mutex<State>>,
}

impl IpSender {
    fn state(&self) -> &Mutex<State> {
        &self.state
    }

    /// Send one IP packet. Empty, or a first nibble other than 4 or 6: `Malformed`. Over
    /// [`MAX_IP_PACKET`], or refused as too large by the datagram carrier: `TooLarge`. No
    /// address policy applies ([`check_outgoing`](Self::check_outgoing) is the
    /// application's to call). After [`finish`](Self::finish), `Closed`. The datagram
    /// carrier never falls back to a capsule; the capsule carrier waits for stream credit.
    /// An IPv6 packet the datagram carrier refuses while [`max_payload`](Self::max_payload)
    /// is below 1280 aborts the stream with `H3_DATAGRAM_ERROR` and returns `MtuTooSmall`
    /// (RFC 9484 section 7.2). Cancel-safe: a dropped pending send wrote nothing.
    pub async fn send(&mut self, packet: Bytes) -> Result<(), IpError> {
        if !matches!(packet.first().map(|b| b >> 4), Some(4 | 6)) {
            return Err(IpError::Malformed);
        }
        if packet.len() > MAX_IP_PACKET {
            return Err(IpError::TooLarge);
        }
        let v6 = packet[0] >> 4 == 6;
        match self.tx.send_payload(packet).await {
            // RFC 9484 section 7.2: an IPv6 packet refused while 1280 cannot fit.
            Err(TxError::Datagram(DatagramError::TooLarge))
                if v6 && self.max_payload().is_some_and(|m| m < IPV6_MIN_MTU) =>
            {
                self.abort(H3Code::DATAGRAM_ERROR);
                Err(IpError::MtuTooSmall)
            }
            r => Ok(r?),
        }
    }

    /// Send `ADDRESS_ASSIGN` with the full list of addresses assigned to the peer (*A*);
    /// an empty list withdraws them all. A non-zero request ID must be pending (else
    /// `UnknownRequest`) and answers it; rejections are not assigned. The state changes
    /// once the stream took the capsule; until then received packets are judged against
    /// the old and the new list together. Cancel-safe: a dropped pending call wrote
    /// nothing and changed nothing.
    pub async fn assign(&mut self, entries: &[AssignedAddress]) -> Result<(), IpError> {
        lock(&self.state).check_assign(entries)?;
        let mut b = BytesMut::new();
        encode_address_assign(entries, &mut b).map_err(IpError::Capsule)?;
        lock(&self.state).stage_assign(entries);
        let staged = Staged(&self.state);
        self.tx.send_capsule(b.freeze()).await?;
        staged.commit(|s| s.commit_assign(entries));
        Ok(())
    }

    /// Send `ROUTE_ADVERTISEMENT` with the full list of this end's routes (*R*), sorted
    /// into wire order; an empty list withdraws them all. Overlapping ranges: `Route`.
    /// State changes and cancel safety as [`assign`](Self::assign).
    pub async fn advertise(&mut self, routes: &[IpRange]) -> Result<(), IpError> {
        let mut b = BytesMut::new();
        encode_routes(routes, &mut b).map_err(IpError::Route)?;
        lock(&self.state).stage_advertise(routes);
        let staged = Staged(&self.state);
        self.tx.send_capsule(b.freeze()).await?;
        staged.commit(|s| s.commit_advertise(routes));
        Ok(())
    }

    /// Send `ADDRESS_REQUEST` for `prefixes`, one request each; returns their request IDs
    /// in order. IDs start at 1 and are never reused, not even after a failed or
    /// cancelled call (RFC 9484 section 4.7.2). An empty list: `Capsule(Malformed)`.
    /// Cancel-safe: a dropped pending call wrote nothing.
    pub async fn request(&mut self, prefixes: &[IpPrefix]) -> Result<Vec<NonZeroU64>, IpError> {
        let ids = lock(&self.state).next_request_ids(prefixes.len());
        let entries: Vec<_> = ids
            .iter()
            .zip(prefixes)
            .map(|(&request_id, &prefix)| RequestedAddress { request_id, prefix })
            .collect();
        let mut b = BytesMut::new();
        encode_address_request(&entries, &mut b).map_err(IpError::Capsule)?;
        self.tx.send_capsule(b.freeze()).await?;
        Ok(ids)
    }

    /// Finish the stream after everything sent so far.
    pub fn finish(&mut self) -> Result<(), IpError> {
        Ok(self.tx.finish()?)
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.tx.abort(code)
    }

    /// The largest packet [`send`](Self::send) accepts now: the datagram limit minus the
    /// context ID byte, at most [`MAX_IP_PACKET`] (as of the async driver's last pass);
    /// `Some(MAX_IP_PACKET)` for the capsule carrier. `None` with [`Carrier::Datagram`]
    /// when the datagram limit is unknown now or leaves no room for a packet.
    pub fn max_payload(&self) -> Option<usize> {
        self.tx.max_payload(MAX_IP_PACKET)
    }

    /// The carrier chosen when the tunnel was built.
    pub fn carrier(&self) -> Carrier {
        self.tx.carrier()
    }

    state_methods!();
}

/// The receiving half of an [`IpTunnel`].
#[derive(Debug)]
pub struct IpReceiver {
    rx: Rx,
    state: Arc<Mutex<State>>,
}

impl IpReceiver {
    fn state(&self) -> &Mutex<State> {
        &self.state
    }

    /// The next packet that passed the policy, or control capsule, from either carrier;
    /// `Ok(None)` once the peer finished the stream on a capsule boundary. Packets the
    /// policy refuses, other context IDs and payloads over [`MAX_IP_PACKET`] are dropped
    /// and counted in [`drops`](Self::drops). A malformed control capsule aborts with
    /// `H3_MESSAGE_ERROR`; one over 64 KiB, or more than 1024 pending requests, with
    /// `H3_EXCESSIVE_LOAD`. Cancel-safe: the decoder state lives here.
    pub async fn recv(&mut self) -> Result<Option<IpEvent>, IpError> {
        self.rx.start();
        let (rx, state) = (&mut self.rx, &self.state);
        poll_fn(|cx| rx.poll_recv(cx, |raw| on_raw(&mut lock(state), raw)))
            .await
            .map_err(IpError::Http)
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        self.rx.abort(code)
    }

    state_methods!();
}

fn on_raw(s: &mut State, raw: Raw) -> Step<IpEvent> {
    match raw {
        Raw::Payload(b) => {
            if s.on_payload(&b) {
                Step::Yield(IpEvent::Packet(b))
            } else {
                Step::Drop
            }
        }
        // A forwarding error, not a protocol violation (RFC 9484 section 7.2).
        Raw::Oversized => {
            s.count_malformed();
            Step::Drop
        }
        Raw::OtherContext => {
            s.count_context();
            Step::Drop
        }
        Raw::Control { ty, value } => match s.on_control(ty, &value) {
            Ok(e) => Step::Yield(e),
            Err(code) => Step::Fail(code),
        },
    }
}

const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<IpTunnel>();
    send_sync::<IpSender>();
    send_sync::<IpReceiver>();
};

/// What a tunnel knows about addresses and routes, and the drops it counted.
#[derive(Debug)]
pub(crate) struct State {
    scope: Scope,
    proxy: bool,
    policy: Policy,
    /// *A*: what I assigned to the peer.
    assigned: Vec<IpPrefix>,
    /// *R*: what I advertised.
    routes: Vec<IpRange>,
    /// Staged by a send in flight; receive-only until committed.
    staged_assigned: Vec<IpPrefix>,
    staged_routes: Vec<IpRange>,
    /// The peer's latest offers.
    offered_assigned: Vec<IpPrefix>,
    offered_routes: Vec<IpRange>,
    /// *A'* and *R'*: the offers I accepted.
    peer_assigned: Vec<IpPrefix>,
    peer_routes: Vec<IpRange>,
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
            assigned: Vec::new(),
            routes: Vec::new(),
            staged_assigned: Vec::new(),
            staged_routes: Vec::new(),
            offered_assigned: Vec::new(),
            offered_routes: Vec::new(),
            peer_assigned: Vec::new(),
            peer_routes: Vec::new(),
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

    fn rules<'a>(&'a self, assigned: &'a [IpPrefix], routes: &'a [IpRange]) -> Rules<'a> {
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
        let (a, r);
        let rules = if self.staged_assigned.is_empty() && self.staged_routes.is_empty() {
            self.rules(&self.assigned, &self.routes)
        } else {
            a = [&self.assigned[..], &self.staged_assigned].concat();
            r = [&self.routes[..], &self.staged_routes].concat();
            self.rules(&a, &r)
        };
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
                self.offered_assigned = prefixes(&entries);
                let offered = &self.offered_assigned;
                self.peer_assigned
                    .retain(|a| offered.iter().any(|o| o.covers(a)));
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
                self.offered_routes = routes.clone();
                let offered = &self.offered_routes;
                self.peer_routes
                    .retain(|a| offered.iter().any(|o| o.covers(a)));
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
        self.staged_assigned = prefixes(entries);
    }

    pub(crate) fn commit_assign(&mut self, entries: &[AssignedAddress]) {
        self.assigned = prefixes(entries);
        self.staged_assigned.clear();
        for n in entries.iter().filter_map(|e| NonZeroU64::new(e.request_id)) {
            self.pending.remove(&n);
        }
    }

    pub(crate) fn stage_advertise(&mut self, routes: &[IpRange]) {
        self.staged_routes = routes.to_vec();
    }

    pub(crate) fn commit_advertise(&mut self, routes: &[IpRange]) {
        self.routes = routes.to_vec();
        self.staged_routes.clear();
    }

    pub(crate) fn unstage(&mut self) {
        self.staged_assigned.clear();
        self.staged_routes.clear();
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
        let offered = &self.offered_assigned;
        if !items.iter().all(|i| offered.iter().any(|o| o.covers(i))) {
            return Err(IpError::NotOffered);
        }
        self.peer_assigned = items.to_vec();
        Ok(())
    }

    pub(crate) fn accept_routes(&mut self, items: &[IpRange]) -> Result<(), IpError> {
        let offered = &self.offered_routes;
        if !items.iter().all(|i| offered.iter().any(|o| o.covers(i))) {
            return Err(IpError::NotOffered);
        }
        self.peer_routes = items.to_vec();
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/packets/mod.rs"]
mod packets;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{ScopeTarget, encode_address_assign, encode_address_request, encode_routes};
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
        assert_eq!(s.assigned, [pfx("10.0.0.2/32")]);
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
        assert_eq!(s.assigned, [pfx("10.0.0.2/32"), pfx("10.0.0.3/32")]);
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
        assert_eq!(s.peer_assigned, [pfx("10.1.0.1/32")]);
        assert_eq!(s.peer_routes, [range("172.16.1.0/24", 6)]);
    }

    #[test]
    fn accept_sub_prefix_of_offer() {
        let mut s = State::new(Scope::ANY, false);
        s.on_control(ADDRESS_ASSIGN, &assign_value(&[asg(0, "10.1.0.0/24")]))
            .unwrap();
        s.accept_assigned(&[pfx("10.1.0.0/25"), pfx("10.1.0.200/32")])
            .unwrap();
        assert_eq!(s.peer_assigned.len(), 2);
        // Replaced, not merged.
        s.accept_assigned(&[]).unwrap();
        assert!(s.peer_assigned.is_empty());
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
        assert_eq!(s.peer_assigned, [pfx("10.1.0.1/32")]);

        let routes = [range("172.16.0.0/16", 0), range("172.17.0.0/16", 0)];
        s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&routes))
            .unwrap();
        s.accept_routes(&routes).unwrap();
        s.on_control(ROUTE_ADVERTISEMENT, &routes_value(&routes[1..]))
            .unwrap();
        assert_eq!(s.peer_routes, [routes[1]]);
    }

    #[test]
    fn empty_lists_withdraw() {
        let mut s = proxy();
        s.commit_assign(&[]);
        s.commit_advertise(&[]);
        assert!(s.assigned.is_empty() && s.routes.is_empty());
        assert!(!s.on_payload(&pkt("10.0.0.2", "192.0.2.1")));

        s.on_control(ADDRESS_ASSIGN, &assign_value(&[asg(0, "10.1.0.1/32")]))
            .unwrap();
        s.accept_assigned(&[pfx("10.1.0.1/32")]).unwrap();
        assert_eq!(
            s.on_control(ADDRESS_ASSIGN, &assign_value(&[])),
            Ok(IpEvent::AddressAssign(vec![]))
        );
        assert!(s.offered_assigned.is_empty() && s.peer_assigned.is_empty());
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
        assert_eq!(s.assigned, [pfx("10.0.0.2/32")]);

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
        assert_eq!(s.offered_assigned, [pfx("10.1.0.1/32")]);
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
