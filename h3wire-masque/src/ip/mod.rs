// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! MASQUE CONNECT-IP (RFC 9484): IP tunnelling over HTTP/3.

mod capsule;
mod prefix;

pub use capsule::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AssignedAddress, MAX_CONTROL_CAPSULE, ROUTE_ADVERTISEMENT,
    RequestedAddress, RouteError, decode_address_assign, decode_address_request, decode_routes,
    encode_address_assign, encode_address_request, encode_routes,
};
pub use prefix::{IpPrefix, IpRange, PrefixError};
