# h3wire-masque

MASQUE for [h3wire-async](https://crates.io/crates/h3wire-async): CONNECT-UDP
(RFC 9298) and CONNECT-IP (RFC 9484) tunnels over HTTP/3, built on the HTTP capsule
protocol (RFC 9297). The
crate is runtime-neutral and QUIC-stack-neutral: it depends only on h3wire-async's
public API.

> **Note:** h3wire-async is a stable candidate; 1.0 waits for a downstream user outside this workspace.

## CONNECT-IP

The `ip` module tunnels IP packets (RFC 9484): `ip::client::connect` and
`ip::server::accept` run the handshake, and an `IpTunnel` carries packets and the
`ADDRESS_ASSIGN`, `ADDRESS_REQUEST` and `ROUTE_ADVERTISEMENT` capsules. Spawn
`IpPending::tunnel()` after returning the response. Its examples `ip-proxy` and `ip-client`
(Linux, TUN device) are checked against connect-ip-go; the matrix is in
[docs/interop.md](https://github.com/mqvpn/h3wire/blob/main/docs/interop.md).

- **Policy.** By default every received packet is checked against the assigned addresses,
  the advertised routes and the request's `target` and `ipproto`; refused packets are
  dropped and counted, never fatal. RFC 9484 section 7.2 leaves this to local policy, so it
  is a library default. The peer's assignments and routes are offers that count only after
  `accept_assigned` and `accept_routes`. `Policy::Unchecked` turns off the address and route
  checks and keeps header validation, the request scope and the ICMP quotation checks.
- **Shared addresses.** `check_outgoing` is an eligibility filter, not a tunnel selector.
  An application that shares addresses MUST run it on every candidate tunnel and MUST
  resolve several eligible tunnels itself (distinct addresses, bounded flow tracking, or
  dropping the packet), never broadcast.
- **Link-scoped packets** (`fe80::/10`, `ff02::/16`) pass the policy and must not be
  forwarded beyond the tunnel.
- **Address requests.** Answer every `IpEvent::AddressRequest` with `assign`, which sends
  the full list: repeat earlier assignments with request ID 0.
- **IPv6 MTU.** Configure the transport so a 1,280-byte packet fits in a datagram (quinn:
  `initial_mtu(1350)`). An IPv6 send refused while `max_payload()` is below 1,280 aborts the
  stream with `H3_DATAGRAM_ERROR` and returns `MtuTooSmall`.
- **Host targets** are resolved by the application before the response.

### RFC 9484 duties left to the application

- An endpoint that needs an address assigned MUST send an `ADDRESS_REQUEST` (`request`,
  section 4.7.1).
- The proxy MUST keep assignments and routes while the request stream is open, and MUST
  close the stream when it tears the tunnel down (section 4.1).
- Unless both transports guarantee an IPv6 MTU of 1,280 bytes, the application MUST probe
  with an ICMPv6 echo request carrying 1,232 bytes of data and tear the tunnel down when no
  reply comes (section 7.2). The library sends no probe; its policy lets the probe and the
  reply through.
- Hop-limit decrement on encapsulation, and ICMP error generation (Packet Too Big
  included), belong to the IP stack behind the tunnel (sections 7.2, 7.2.1, 10.1).
- Under `Policy::Unchecked`, source address validation is the application's (section 11).
- A rejected request (`ConnectError::Rejected`) is over and never a tunnel. The error
  carries the response; the request side is already finished, and dropping the response
  before the end of its body cancels the stream with `H3_REQUEST_CANCELLED` (sections 4.1,
  4.5).

The [`ip` module documentation](https://docs.rs/h3wire-masque/latest/h3wire_masque/ip/)
has a client snippet and the details.

## 0.2.0

- New `ip` module: CONNECT-IP (RFC 9484).
- `TemplateError` gains `BadTarget` and `BadProto`, and `server::Reject` gains
  `NotConnectIp`; both enums are `#[non_exhaustive]`.
- No behaviour change for CONNECT-UDP.

See the [API documentation](https://docs.rs/h3wire-masque).

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
