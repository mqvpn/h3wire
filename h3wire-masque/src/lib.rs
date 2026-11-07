// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! MASQUE CONNECT-UDP (RFC 9298) over [`h3wire_async`].
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capsule;
pub mod template;
pub mod tunnel;

pub use tunnel::{Carrier, MAX_UDP_PAYLOAD, UdpError, UdpReceiver, UdpSender, UdpTunnel};
