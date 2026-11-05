# Using eider-tls from eider-http (plan, not implemented)

Status: nothing in eider-http uses this package yet. Issue 29 asks for it; it is split off on purpose, because it
touches the transport of the server, client and websocket code that other work is changing. This is the plan.

## Shape

`conn.Conn[S]` implements `stream.Reader` and `stream.Writer` for any `S`, so a `Conn[stream.Fd]` is a drop-in for
an `Fd` wherever eider-http only reads and writes bytes. What differs is how eider-http *waits*: it polls the file
descriptor (`fd.wait_ready`, `net.try_recv`, `sock.send_by`). TLS buffers: the socket can be readable while the
connection has nothing to return (half a record), and not readable while the connection still holds decrypted
bytes. So the plan is a small transport type in eider-http:

```eider
enum Transport { Plain(stream.Fd), Secure(conn.Conn[stream.Fd]) }
```

with these operations, each a `match` over the two forms:

- `ready_to_read(t)`: Plain: false (ask the poller); Secure: `c.ready_to_read()` (decrypted bytes are buffered), so
  the event loop tests it before waiting on the descriptor.
- `try_recv(t, max)`: Plain: `net.try_recv`; Secure: `c.try_recv(max)` (returns nothing when no whole record has
  arrived; reads the socket without blocking).
- `send_by(t, bytes, deadline)`: Plain: `sock.send_by`; Secure: `c.send_by`.
- `close_by(t, deadline)`: Secure: `c.close_by` (close_notify), then the existing shutdown-and-drain; a peer that
  never answers is covered by the deadline.

## Server

1. `Config` (server.ei, the type near line 69) gains `tls: Option[config.ServerConfig]`; with it set the listener
   serves https.
2. After `net.accept`, the per-connection task runs `server.accept(fd, cfg, deadline)` (the handshake blocks the
   task, not the acceptor; the deadline is the existing header timeout) and carries a `Transport.Secure` from then
   on. A failed handshake closes the descriptor and counts as a rejected connection.
3. Call sites: the roughly 22 uses of `sock.send_by`, `net.try_recv` and `fd.wait_ready`/`wait_conn` in server.ei
   (about lines 287, 291, 312-322, 337, 393, 397, 452, 455-487, 503, 552-570, 681, 688-689) become the `Transport`
   operations. The wait step becomes: if `ready_to_read(t)` skip the wait, else wait on the fd.
4. `negotiated_alpn()` selects HTTP/1.1 now; the same hook is where "h2" would go later.
5. Keep-alive and the lingering close keep their logic; only the I/O calls change.

## Client

client.ei has four transport calls. The `https` scheme dials, runs `client.connect` with
`client_config(host, roots)` (roots: `x509.system_store()` or a configured store; ALPN `http/1.1`), and holds a
`Transport.Secure`. Note the RSA gap: most public sites cannot be reached until the crypto package has RSA.

## WebSocket

ws.ei has two transport calls (about lines 621-626), the frame writer and the poll; both go through `Transport`,
which makes `wss` fall out of the above.

## Build and dependencies

eider-http's `eider.toml` gains `[deps.tls]` (a git dependency on eider-tls) and the `crypto` package it needs,
with the grants (`net`, `io`, `fs` for key files, `clock`); the program links the crypto backend the way the
driver already does for crypto users. Until the crypto package lives in its own repository, eider-http would need
an eider-lang checkout as toolchain, as eider-tls does today. That is the main blocker for a published dependency
and should be solved first.

## Tests to add there

An https round trip against the package's own client; `curl` and `openssl s_client` against an eider-http server;
a slow client that sends one record in two writes (readiness versus buffered bytes); a connection closed without
close_notify (Truncated, not a clean end).
