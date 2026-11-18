// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! IPv4 / IPv6 packet builders for the CONNECT-IP tests and fuzz seeds. std only.
#![allow(dead_code)] // each user takes a subset

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 packet with a 20-byte header; `frag_offset` is in 8-byte units.
pub fn ipv4_frag(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    frag_offset: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).expect("IPv4 packet too long");
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0]); // identification
    p.extend_from_slice(&(frag_offset & 0x1fff).to_be_bytes());
    p.extend_from_slice(&[64, proto, 0, 0]); // TTL, protocol, checksum (not checked)
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// An unfragmented IPv4 packet.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_frag(src, dst, proto, 0, payload)
}

/// An IPv6 packet whose header names `next`; `rest` is everything after the fixed header.
pub fn ipv6_raw(src: Ipv6Addr, dst: Ipv6Addr, next: u8, rest: &[u8]) -> Vec<u8> {
    let len = u16::try_from(rest.len()).expect("IPv6 payload too long");
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(rest);
    p
}

/// A minimal extension header of type `ty` followed by `next`: AH (51) is 16 bytes, a
/// Fragment header (44) is a first fragment, every other type is 8 bytes.
pub fn ext_header(ty: u8, next: u8) -> Vec<u8> {
    match ty {
        51 => {
            let mut h = vec![next, 2]; // (2 + 2) * 4 = 16 bytes
            h.resize(16, 0);
            h
        }
        44 => vec![next, 0, 0, 0, 0, 0, 0, 1],
        _ => vec![next, 0, 0, 0, 0, 0, 0, 0],
    }
}

/// An IPv6 packet carrying the extension headers `chain` in order, then `upper` and `payload`.
pub fn ipv6_chain(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    chain: &[u8],
    upper: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut rest = Vec::new();
    for (i, &ty) in chain.iter().enumerate() {
        rest.extend(ext_header(ty, chain.get(i + 1).copied().unwrap_or(upper)));
    }
    rest.extend_from_slice(payload);
    ipv6_raw(src, dst, chain.first().copied().unwrap_or(upper), &rest)
}

/// An IPv6 packet with no extension headers.
pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv6_raw(src, dst, proto, payload)
}

/// An IPv6 fragment: a Fragment header naming `next` at `offset` (8-byte units), then `payload`.
pub fn ipv6_fragment(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    offset: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut rest = vec![next, 0];
    rest.extend_from_slice(&((offset << 3) | 1).to_be_bytes());
    rest.extend_from_slice(&[0, 0, 0, 1]); // identification
    rest.extend_from_slice(payload);
    ipv6_raw(src, dst, 44, &rest)
}

/// An unfragmented packet of either family. Panics if the families differ.
pub fn packet(src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4(s, d, proto, payload),
        (IpAddr::V6(s), IpAddr::V6(d)) => ipv6(s, d, proto, payload),
        _ => panic!("address families differ"),
    }
}

/// An ICMP (IPv4) or ICMPv6 message of type `ty`: the 8-byte ICMP header, then `body`.
/// For an error type, `body` is the quotation; pass a slice of any length to truncate it.
pub fn icmp(src: IpAddr, dst: IpAddr, ty: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![ty, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(body);
    let proto = if src.is_ipv4() { 1 } else { 58 };
    packet(src, dst, proto, &m)
}

/// Destination Unreachable (IPv4 type 3, ICMPv6 type 1) quoting `quote`.
pub fn unreachable(src: IpAddr, dst: IpAddr, quote: &[u8]) -> Vec<u8> {
    icmp(src, dst, if src.is_ipv4() { 3 } else { 1 }, quote)
}

/// Echo Request (IPv4 type 8, ICMPv6 type 128).
pub fn echo_request(src: IpAddr, dst: IpAddr) -> Vec<u8> {
    icmp(src, dst, if src.is_ipv4() { 8 } else { 128 }, &[])
}

/// Echo Reply (IPv4 type 0, ICMPv6 type 129).
pub fn echo_reply(src: IpAddr, dst: IpAddr) -> Vec<u8> {
    icmp(src, dst, if src.is_ipv4() { 0 } else { 129 }, &[])
}
