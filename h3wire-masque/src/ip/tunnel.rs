// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! One CONNECT-IP tunnel (RFC 9484): IP packets and control capsules over the carrier
//! shared with CONNECT-UDP. What the tunnel knows lives in [`State`].

use super::state::State;
use super::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AssignedAddress, DropReason, Drops, IpPrefix, IpRange,
    MAX_CONTROL_CAPSULE, Policy, ROUTE_ADVERTISEMENT, RequestedAddress, RouteError, Scope,
    encode_address_assign, encode_address_request, encode_routes,
};
use crate::capsule::CapsuleError;
use crate::carrier::{self, Limits, Raw, Rx, Step, Tx, TxError};
use crate::tunnel::Carrier;
use bytes::{Bytes, BytesMut};
use h3wire_async::core::H3Code;
use h3wire_async::datagram::Datagrams;
use h3wire_async::upgrade::Tunnel;
use h3wire_async::{DatagramError, Error};
use std::fmt;
use std::future::{Future, poll_fn};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The largest IP packet a tunnel carries: a 40-byte IPv6 header and 65,535 bytes.
pub const MAX_IP_PACKET: usize = 65_575;

/// The IPv6 minimum link MTU (RFC 8200 section 5).
const IPV6_MIN_MTU: usize = 1280;

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
    /// An IPv6 packet the datagram carrier refuses while the datagram limit is known and a
    /// 1,280-byte packet does not fit in a datagram aborts the stream with
    /// `H3_DATAGRAM_ERROR` and returns `MtuTooSmall` (RFC 9484 section 7.2). Cancel-safe:
    /// a dropped pending send wrote nothing.
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
                if v6 && self.tx.datagram_cannot_fit(IPV6_MIN_MTU) =>
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
