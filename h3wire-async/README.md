# h3wire-async

Runtime-neutral async HTTP/3 over the sans-I/O [h3wire](https://crates.io/crates/h3wire)
core: a hyper-shaped client and server, streaming bodies with trailers, Extended
CONNECT tunnels (RFC 9220) and HTTP datagrams (RFC 9297).

The QUIC transport plugs in through the poll-based traits in `h3wire_async::quic`;
[h3wire-quinn](https://crates.io/crates/h3wire-quinn) implements them for quinn. The
application supplies the executor (`rt::Executor`); the `tokio` feature adds
`rt::TokioExecutor`.

> **Note:** h3wire-async is a stable candidate; 1.0 waits for a downstream user outside this workspace.

## Usage

```rust,ignore
use h3wire_async::{Builder, rt::TokioExecutor};

// Server: a future that drives `quic_conn` and dispatches requests to a tower `Service`.
let conn = Builder::new().serve_connection(quic_conn, service, TokioExecutor);
conn.await?;

// Client: spawn the driver, then send requests. Dropping the last `SendRequest`
// shuts the connection down gracefully.
let (mut send, driver) = Builder::new().handshake(quic_conn, TokioExecutor).await?;
tokio::spawn(driver);
let resp = send.send_request(request).await?;
```

See the [API documentation](https://docs.rs/h3wire-async).

## Changelog

### 0.2.0

Breaking:

- `datagram_queue` is replaced by the fallible `datagram_recv_queue` and
  `datagram_send_queue`; a size of 0 is rejected.

Added:

- `OnUpgrade::abort` aborts a CONNECT before the response arrives.
- `Datagrams::split` yields a `Clone` `DatagramSender` and a `DatagramReceiver`.
- Datagram receive has its own slice of the per-poll work budget.

Changed:

- Requests that were never sent when GOAWAY arrives are retryable.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
