# Proposal: Web Transport for freeq

## Summary

Add WebSocket and HTTP access to freeq. The WebSocket carries raw IRC
lines — not a new JSON protocol. The HTTP layer provides read-only REST
endpoints backed by the persistence layer. No web UI ships with the server.

This proposal assumes persistence (SQLite) is already implemented.

## Design Principles

freeq is infrastructure, not a product. The web layer follows from that:

- **One protocol.** IRC is the wire protocol. WebSocket is a transport, not
  a new protocol. Web clients speak IRC over WebSocket, the same way they
  speak IRC over TCP. This is how KiwiIRC, The Lounge, and IRCCloud work.
  No JSON wire format, no tagged unions, no second parser.

- **REST is read-only.** The HTTP API exposes data that's already persisted:
  channel history, user identity, server health. It does not accept commands.
  If you want to send a message, open a WebSocket and send `PRIVMSG`. This
  keeps the API surface minimal and the command path singular.

- **No web UI in this repo.** A web frontend is a product. Anyone can build
  one against the WebSocket + REST endpoints. Shipping one here would create
  maintenance obligations and feature pressure that don't belong in an
  infrastructure project. If we want a reference web client later, it gets
  its own repo.

- **No new auth system.** Web clients authenticate the same way IRC clients
  do: CAP negotiation → SASL `ATPROTO-CHALLENGE` → done. The messages
  happen to travel over WebSocket instead of TCP. No session tokens, no
  cookies, no parallel auth flow.

## What This Gets Us

- **Browser access** without a bouncer. Any WebSocket-capable IRC library
  works. A thin JS wrapper around `new WebSocket()` + IRC line parsing is
  all a web client needs.

- **Bot and integration ecosystem** via REST. Fetching history, looking up
  DIDs, checking health — these are the HTTP-shaped operations that tools
  actually need. They read from the database; they don't need a persistent
  connection.

- **Cross-protocol messaging for free.** IRC-over-TCP and IRC-over-WebSocket
  clients share the same server state. A message sent from a TCP client
  appears in a WebSocket client's channel, and vice versa. No translation
  layer, no event mapping, no dual-protocol bugs.

## Architecture

```
IRC clients ──TCP──▸ ┌────────────────────┐ ◂──WS── Browsers
                     │   Connection Mux   │
                     │   (TCP + WS both   │
                     │    feed into the    │
                     │    same handler)    │
                     ├────────────────────┤
                     │   Server State     │  ← SharedState (unchanged)
                     ├────────────────────┤
                     │   SQLite           │  ← persistence layer
                     └────────────────────┘
                            ▲
                     HTTP ──┘  (read-only REST)
```

The WebSocket handler upgrades the HTTP connection, then hands the resulting
bidirectional byte stream to the same `connection::handle_generic()` that
TLS connections already use. From the server's perspective, a WebSocket
client is just another `AsyncRead + AsyncWrite` stream. No new connection
type, no adapter pattern, no engine extraction.

### File Changes

```
freeq-server/
  src/
    connection.rs   Add WebSocket stream adapter (AsyncRead/AsyncWrite over WS frames)
    web.rs          NEW — axum router: WS upgrade endpoint + REST endpoints
    db.rs           Already exists (persistence layer)
    config.rs       Add --web-addr flag
    main.rs         Start HTTP listener alongside TCP
    server.rs       SharedState gets a Db handle (already done by persistence)
```

No new crates. No new workspace members. No engine extraction.

### WebSocket Transport

The WebSocket endpoint (`/irc`) upgrades to a WebSocket connection, then
wraps it in an adapter that implements `AsyncRead + AsyncWrite` by mapping
between WebSocket text frames and IRC line bytes:

- **Inbound:** Each WebSocket text frame contains one IRC line (without
  `\r\n`). The adapter appends `\r\n` and yields the bytes to the reader.
- **Outbound:** The adapter splits on `\r\n` and sends each IRC line as a
  WebSocket text frame.

This adapter is ~50 lines of code. Once it exists, `handle_generic()` works
unchanged. CAP negotiation, SASL, PRIVMSG, JOIN — everything works because
the server sees IRC lines, not WebSocket frames.

### REST API

Read-only endpoints backed by SQLite queries. No authentication required for
public data; DID-gated endpoints can come later if needed.

| Endpoint | Description |
|---|---|
| `GET /api/health` | Server uptime, connection count, channel count |
| `GET /api/channels` | List active channels (name, member count, topic) |
| `GET /api/channels/{name}/history?limit=N&before=T` | Message history (paginated by timestamp) |
| `GET /api/channels/{name}/topic` | Current topic with metadata |
| `GET /api/users/{nick}` | User info: DID, handle, online status |
| `GET /api/users/{nick}/whois` | Same data as IRC WHOIS, as JSON |

All responses are JSON. All timestamps are Unix seconds. Pagination uses
`before` (timestamp) and `limit` (default 50, max 200).

No `POST`, `PUT`, `DELETE`, or `PATCH` endpoints. If you want to act on the
server, speak IRC.

### New Dependencies

| Crate | Purpose |
|---|---|
| `axum` | HTTP framework + WebSocket upgrade |
| `tower-http` | CORS middleware |

Both are tokio-native. axum's WebSocket support is built on `tokio-tungstenite`
which is already battle-tested. No heavyweight additions.

### Configuration

```
--web-addr <ADDR>    HTTP/WebSocket listener address [default: none]
```

If `--web-addr` is not set, no HTTP listener starts. The server behaves
exactly as it does today. WebSocket and REST are opt-in, zero-cost when
unused.

## Implementation Plan

### Phase 1: WebSocket transport

1. Add axum dependency with `ws` feature
2. Implement `WsStream` adapter (AsyncRead + AsyncWrite over WebSocket)
3. Add `/irc` WebSocket upgrade route
4. Wire up `connection::handle_generic()` for WebSocket streams
5. Add `--web-addr` to config
6. Start HTTP listener in `main.rs` when configured
7. Test: connect via WebSocket, complete SASL auth, join channel, exchange
   messages with a TCP client

### Phase 2: REST endpoints

1. Add read-only routes backed by `Db` queries
2. Add CORS middleware (permissive by default for API consumers)
3. Test: fetch channel history, verify it matches what was sent over IRC

### Phase 3: (future, not this proposal) Access control

If needed later: API keys, DID-based bearer tokens for accessing private
channel history, rate limiting per IP. Not building this until there's a
concrete need.

## What This Does NOT Do

- **No JSON wire protocol.** Web clients speak IRC. One protocol to test,
  document, and debug.
- **No engine extraction.** The server's internal structure stays as-is.
  WebSocket connections enter through the same code path as TLS connections.
  Refactoring `connection.rs` is a separate concern, done when warranted by
  code quality, not by transport requirements.
- **No web UI.** No static file serving, no `--web-static` flag, no
  frontend framework. Build a web client in a separate repo if you want one.
- **No write API.** REST is for reading. IRC is for writing. One command
  path means one place to enforce permissions, rate limits, and audit.
- **No new auth mechanism.** SASL `ATPROTO-CHALLENGE` over WebSocket. Same
  flow, same code, same security properties. Session tokens are a different
  auth system with different security properties — we don't need two.

## Open Questions

1. **Should REST endpoints require authentication?** Channel list and public
   channel history probably don't need it. Private channel history (if we
   add +s/+p modes) would. Start open, add auth when channel privacy modes
   exist.

2. **Binary frames or text frames for WebSocket?** Text frames are
   debuggable (you can see IRC lines in browser devtools). Binary frames
   are marginally more efficient. Leaning text — debuggability matters more
   than bandwidth for a chat protocol.

3. **Should the REST API version its URLs?** (`/api/v1/...`) Probably yes,
   costs nothing, prevents future pain. But don't over-engineer — v1 is the
   only version until it isn't.
