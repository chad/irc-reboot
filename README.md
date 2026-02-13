# freeq

IRC server and client with AT Protocol (Bluesky) identity authentication,
end-to-end encrypted channels, iroh QUIC transport, peer-to-peer DMs,
and federated server-to-server clustering.

Users authenticate with their Bluesky identity via a custom SASL mechanism
(`ATPROTO-CHALLENGE`). Standard IRC clients connect as guests. Authenticated
users get their DID bound to their connection — visible via WHOIS, enforced
for nick ownership, and usable for DID-based bans, invites, and persistent ops.

## Architecture

```
freeq-server/     IRC server with SASL, WebSocket, iroh, S2S federation
freeq-sdk/     Reusable client SDK (connect, auth, events, E2EE, P2P)
freeq-tui/     Terminal UI client built on the SDK
```

The SDK exposes a `(ClientHandle, Receiver<Event>)` pattern — any UI or bot
can consume events and send commands.

### Transport Stack

```
┌──────────────────────────────────────────┐
│            IRC Wire Protocol             │
├──────────┬──────────┬──────────┬─────────┤
│   TCP    │   TLS    │WebSocket │  iroh   │
│  :6667   │  :6697   │  :8080   │  QUIC   │
└──────────┴──────────┴──────────┴─────────┘
```

All transports feed into the same `handle_generic()` handler — the IRC
protocol is transport-agnostic. Each transport is zero-cost when not enabled.

## Quick Start

### Build

```sh
cargo build --release
```

### Run the Server

```sh
# Minimal: plain TCP only, in-memory
cargo run --release --bin freeq-server

# With persistence
cargo run --release --bin freeq-server -- --db-path data/irc.db

# With TLS
cargo run --release --bin freeq-server -- \
  --tls-cert certs/cert.pem --tls-key certs/key.pem

# With WebSocket + REST API
cargo run --release --bin freeq-server -- --web-addr 0.0.0.0:8080

# With iroh transport (QUIC, NAT-traversing)
cargo run --release --bin freeq-server -- --iroh

# Full production setup
cargo run --release --bin freeq-server -- \
  --listen-addr 0.0.0.0:6667 \
  --tls-listen-addr 0.0.0.0:6697 \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
  --db-path ./irc.db \
  --web-addr 0.0.0.0:8080 \
  --iroh
```

Generate a self-signed cert for local development:

```sh
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### Connect with the TUI Client

```sh
# Guest (no auth)
cargo run --release --bin freeq-tui -- 127.0.0.1:6667 mynick

# Bluesky OAuth (opens browser)
cargo run --release --bin freeq-tui -- 127.0.0.1:6697 mynick \
  --handle alice.bsky.social

# App password fallback
cargo run --release --bin freeq-tui -- 127.0.0.1:6667 mynick \
  --handle alice.bsky.social --app-password xxxx-xxxx-xxxx-xxxx

# Auto-join channels
cargo run --release --bin freeq-tui -- 127.0.0.1:6667 mynick \
  -c '#general,#random'

# Explicit iroh transport
cargo run --release --bin freeq-tui -- 127.0.0.1:6667 mynick \
  --iroh-addr <endpoint-id>

# Vi keybindings
cargo run --release --bin freeq-tui -- 127.0.0.1:6667 mynick --vi
```

**Iroh auto-discovery**: When connecting to a server that has `--iroh`
enabled, the TUI probes `CAP LS` for the `iroh=<endpoint-id>` capability
and auto-upgrades to iroh QUIC transport. No manual endpoint ID needed.

OAuth sessions are cached to `~/.config/freeq-tui/<handle>.session.json`
so you don't need to re-authenticate on every launch.

### Connect with a Standard IRC Client

Any IRC client works as a guest — irssi, WeeChat, HexChat, LimeChat, etc.
Connect to `127.0.0.1:6667` (plain) or `127.0.0.1:6697` (TLS). No special
configuration needed.

### Connect via WebSocket

When `--web-addr` is set, the server accepts WebSocket connections at
`ws://<addr>/irc`. A test HTML client is included at `freeq-server/test-client.html`.

## Authentication

### SASL ATPROTO-CHALLENGE

The server implements a custom SASL mechanism for AT Protocol identity:

1. Client requests `CAP sasl`, then `AUTHENTICATE ATPROTO-CHALLENGE`
2. Server sends a challenge: `base64url(json { session_id, nonce, timestamp })`
3. Client responds with one of:
   - **Crypto signature** (`method: "crypto"`): Signs challenge bytes with a
     private key listed in the DID document
   - **PDS session** (`method: "pds-session"`): Sends an app-password JWT;
     server verifies against the PDS
   - **PDS OAuth** (`method: "pds-oauth"`): Sends a DPoP-bound access token
     with proof; server verifies against the PDS
4. Server verifies, emits `903` (success) or `904` (failure)
5. Client sends `CAP END`, registration completes

### Security Properties

- Each challenge contains a cryptographically random nonce
- Challenges are invalidated after use (no replay)
- Challenge validity window: configurable, default 60 seconds
- Private keys never leave the client
- PDS URL is verified against the DID document before accepting session tokens
- Supported key types: secp256k1 (MUST), ed25519 (SHOULD)

### What Authentication Gets You

- Nick is bound to your DID — no one else can use it
- WHOIS shows your DID and Bluesky handle
- You can be banned or invited by DID (survives reconnect/nick changes)
- Persistent channel ops tied to your DID (survive reconnects and work across federated servers)
- Your identity is cryptographically verifiable

## Transports

### TCP / TLS (Standard)

Standard IRC on port 6667 (plain) and 6697 (TLS). TLS auto-detected by port
in the client. Always available.

### WebSocket

Enabled with `--web-addr`. Accepts WebSocket IRC at `/irc`. Uses the same
IRC wire protocol — WebSocket is a transport, not a new protocol. Includes
a read-only REST API at `/api/v1/` (channels, members, topics, messages).

### iroh (QUIC)

Enabled with `--iroh`. Provides NAT-traversing encrypted QUIC connections
via [iroh](https://iroh.computer). The server generates a persistent secret
key (`iroh-key.secret`) on first run — endpoint ID is stable across restarts.

The server advertises its iroh endpoint ID in `CAP LS`:
```
CAP * LS :sasl message-tags iroh=44f1415c9db30989...
```

Clients auto-discover and upgrade to iroh when available.

## End-to-End Encryption (E2EE)

Client-side channel encryption using AES-256-GCM with HKDF-SHA256 key
derivation from a shared passphrase. The server relays ciphertext unchanged.

```
/encrypt <passphrase>    Enable E2EE for current channel
/decrypt                 Disable E2EE for current channel
```

Wire format: `ENC1:<nonce-b64>:<ciphertext-b64>` — version-tagged, uses the
message body for robustness. All channel members must use the same passphrase.

## Peer-to-Peer Encrypted DMs

Direct encrypted messaging between clients via iroh QUIC, bypassing the
server entirely.

```
/p2p start               Start your P2P endpoint
/p2p id                  Show your P2P endpoint ID
/p2p connect <id>        Connect to a peer
/p2p msg <id> <message>  Send a direct message
```

P2P conversations appear in dedicated `p2p:<short-id>` buffers. Wire format
is newline-delimited JSON (not IRC protocol). ALPN: `freeq/p2p-dm/1`.

P2P endpoint IDs are visible in WHOIS (numeric `672`).

## Server-to-Server Federation (S2S)

Servers cluster over iroh QUIC connections. Each server maintains its own
local state and syncs channel membership, messages, topics, and DID-based
ops across the federation.

### Setup

```sh
# Server A: just enable iroh (accepts incoming S2S connections)
cargo run --release --bin freeq-server -- --iroh

# Server B: enable iroh + connect to Server A
cargo run --release --bin freeq-server -- --iroh \
  --s2s-peers <server-a-endpoint-id>
```

Server A doesn't need `--s2s-peers` — it accepts incoming S2S connections
automatically when `--iroh` is enabled.

### What Syncs

| Feature | Sync behavior |
|---------|---------------|
| JOIN/PART/QUIT | Membership tracked per origin server |
| PRIVMSG | Channel messages relayed to all peers |
| TOPIC | Topic changes propagate |
| DID-based ops | Persistent ops sync via CRDT |
| Founder | First-write-wins CRDT resolution |
| NAMES | Includes both local and remote members |
| WHOIS | Shows DID, handle, and origin for remote users |

### CRDT-Based State Convergence

Channel authority (founder, DID-based ops) uses Automerge CRDTs for
conflict-free convergence:

- **Founder resolution**: First-write-wins — concurrent claims converge
  deterministically, late entrants cannot overwrite after sync
- **DID ops**: Union merge — grants propagate, revocations propagate
- No timestamps in authority decisions (spoofable by rogue servers)

### S2S Acceptance Tests

```sh
# Run against two live servers
LOCAL_SERVER=localhost:6667 REMOTE_SERVER=irc.freeq.at:6667 \
  cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1
```

9 tests verify: connectivity, bidirectional message relay, NAMES sync,
topic sync, PART/QUIT cleanup, and late-joiner state.

## IRC Features

### Standard IRC

Full compatibility with RFC 1459/2812 basics:

- NICK, USER, JOIN, PART, PRIVMSG, NOTICE, QUIT
- NAMES (query channel membership on demand)
- PING/PONG (client and server keepalive)
- WHOIS (shows DID, handle, iroh ID for authenticated users)
- CTCP ACTION (`/me`)
- Multiple channels, private messages

### Channel Modes

| Mode | Description |
|------|-------------|
| `+o nick` | Channel operator |
| `+v nick` | Voice |
| `+b mask` | Ban (hostmask `*!*@host` or DID `did:plc:xyz`) |
| `+i` | Invite-only |
| `+t` | Topic lock (ops only) |
| `+k key` | Channel key (password) |

### DID-Aware Features

- **DID bans** (`MODE #chan +b did:plc:xyz`): Bans by identity, not just
  hostmask. Survives nick changes and reconnects.
- **DID invites** (`INVITE nick #chan`): If the user is authenticated, the
  invite is stored by DID and survives reconnect.
- **Nick ownership**: Once an authenticated user claims a nick, guests and
  other DIDs cannot use it. If an unauthenticated user tries to take a
  registered nick during SASL negotiation, they're renamed to `GuestXXXX`
  at registration time.
- **Persistent DID-based ops**: When an authenticated user is opped, their DID
  is recorded. They're auto-opped on rejoin — even on a different server in
  the federation. Channel founders (first authenticated user to create a channel)
  can never be de-opped.

### Message History

The server stores the last 100 messages per channel. When you join, recent
history is replayed as standard PRIVMSG — works with any IRC client, no
special protocol extension needed.

### Rich Media (IRCv3 Message Tags)

Rich media is supported through IRCv3 message tags, giving **multipart/alternative
semantics** — the same content in two representations:

- **Tags**: Structured metadata (content-type, URL, dimensions, alt text)
- **Body**: Plain text fallback (description + URL)

```
@content-type=image/jpeg;media-url=https://cdn.bsky.app/img/...;media-alt=Sunset;media-w=1200;media-h=800 :alice!a@host PRIVMSG #photos :Sunset https://cdn.bsky.app/img/...
```

| Client | What they see |
|--------|--------------|
| irssi, WeeChat | `Sunset https://cdn.bsky.app/img/...` (clickable link) |
| freeq-tui | `🖼 [image/jpeg] Sunset 1200×800 https://cdn.bsky.app/img/...` |

Media is hosted externally (AT Protocol PDS blob storage). The IRC server
never handles media bytes — it just relays tagged messages.

**Supported tag keys:**

| Tag | Description |
|-----|-------------|
| `content-type` | MIME type (e.g. `image/jpeg`, `video/mp4`) |
| `media-url` | URL where the media can be fetched |
| `media-alt` | Alt text / description |
| `media-w` | Width in pixels |
| `media-h` | Height in pixels |
| `media-blurhash` | Blurhash placeholder |
| `media-size` | File size in bytes |
| `media-filename` | Original filename |

### Rate Limiting

Token bucket rate limiter (10 commands/second) kicks in after registration.
The initial connection burst is not rate-limited, so clients that send many
commands on connect (like LimeChat) work correctly.

## TUI Client

### Status Bar

The status bar shows:
- **Transport badge**: Colored indicator (red=TCP, green=TLS, cyan=WS, magenta=Iroh)
- **Nick**: Your current nick
- **Auth**: Authenticated DID or "guest"
- **Uptime**: Connection duration

### Keybindings

**Emacs mode** (default):

| Key | Action |
|-----|--------|
| Ctrl-A / Home | Beginning of line |
| Ctrl-E / End | End of line |
| Ctrl-F / Right | Forward char |
| Ctrl-B / Left | Back char |
| Alt-F | Forward word |
| Alt-B | Back word |
| Ctrl-D | Delete char |
| Ctrl-H / Backspace | Delete back |
| Ctrl-K | Kill to end of line |
| Ctrl-U | Kill to beginning |
| Ctrl-W | Kill word back |
| Alt-D | Kill word forward |
| Ctrl-Y | Yank (paste kill ring) |
| Ctrl-T | Transpose chars |
| Alt-U | Uppercase word |
| Alt-L | Lowercase word |
| Alt-C | Capitalize word |
| Tab | Nick completion |
| Up / Down | Input history |
| Ctrl-N / Alt-N | Next buffer |
| Ctrl-P / Alt-P | Previous buffer |
| BackTab (Shift-Tab) | Previous buffer |
| PageUp / PageDown | Scroll messages |
| Ctrl-C / Ctrl-Q | Quit |

**Vi mode** (`--vi`):

Normal mode: `h/l` move, `w/b/e` word motion, `0/$` line edges,
`i/a/I/A` enter insert, `x/X/D/C/S/s` delete/change, `p/P` paste,
`k/j` history, `dd` clear line. Insert mode: standard typing, Esc to
exit to normal mode.

### Commands

```
/join #channel          Join a channel
/part [#channel]        Leave current or named channel
/msg nick message       Private message
/me action              CTCP ACTION
/topic [text]           View or set channel topic
/mode +o/-o nick        Op/deop
/mode +v/-v nick        Voice/devoice
/mode +b [mask]         Ban (or list bans)
/mode +i/-i             Invite-only
/mode +t/-t             Topic lock
/mode +k/-k [key]       Channel key
/op nick                Shortcut for /mode +o
/deop nick              Shortcut for /mode -o
/voice nick             Shortcut for /mode +v
/kick nick [reason]     Kick from channel
/ban mask               Ban user
/unban mask             Remove ban
/invite nick            Invite to current channel
/whois nick             Query user info
/names [#channel]       List channel members
/raw <line>             Send raw IRC line
/encrypt <passphrase>   Enable E2EE for current channel
/decrypt                Disable E2EE for current channel
/p2p start              Start P2P endpoint
/p2p id                 Show your P2P endpoint ID
/p2p connect <id>       Connect to a peer
/p2p msg <id> <text>    Send P2P direct message
/net                    Show/hide network info popup
/debug                  Toggle raw IRC line display
/quit [message]         Disconnect
/help                   Show commands
```

### Network Info Popup (`/net`)

Shows: transport type, server address, connection state, uptime, nick,
authenticated DID, iroh endpoint ID, E2EE channels, P2P DM status.
Close with Esc or `q`.

### Debug Mode (`/debug`)

Toggles raw IRC line display in the status buffer (prefixed with `←`).
Useful for diagnosing protocol issues.

## REST API

When `--web-addr` is set, a read-only REST API is available:

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/channels` | List all channels |
| `GET /api/v1/channels/{name}` | Channel info (topic, modes, member count) |
| `GET /api/v1/channels/{name}/members` | Channel member list |
| `GET /api/v1/channels/{name}/topic` | Channel topic |
| `GET /api/v1/channels/{name}/messages` | Recent messages (with pagination) |
| `GET /api/v1/stats` | Server stats |

All writes go through IRC — the REST API is strictly read-only.

## Server Configuration

```
freeq-server [OPTIONS]

Options:
  --listen-addr <ADDR>            Plain TCP address [default: 127.0.0.1:6667]
  --tls-listen-addr <ADDR>        TLS address [default: 127.0.0.1:6697]
  --tls-cert <PATH>               TLS certificate PEM file
  --tls-key <PATH>                TLS private key PEM file
  --server-name <NAME>            Server name [default: freeq]
  --challenge-timeout-secs <N>    SASL challenge validity [default: 60]
  --db-path <PATH>                SQLite database path (omit for in-memory)
  --web-addr <ADDR>               HTTP/WebSocket listener address
  --iroh                          Enable iroh QUIC transport
  --iroh-port <PORT>              UDP port for iroh (default: random)
  --s2s-peers <ID,ID,...>         S2S peer iroh endpoint IDs
```

### Persistence

When `--db-path` is set, the server persists:

- **Message history** — all channel messages, queryable with pagination
- **Channel state** — topics, modes (+t, +i, +k), channel keys
- **Bans** — hostmask and DID bans survive restarts
- **DID-nick bindings** — nick ownership persists across server restarts

Without `--db-path`, the server runs entirely in-memory.
The database uses SQLite with WAL mode for good concurrent read performance.
Persistence failures are logged but do not crash the server.

## Tests

```sh
# Unit + integration tests (104 tests)
cargo test

# S2S federation acceptance tests (9 tests, requires two live servers)
LOCAL_SERVER=localhost:6667 REMOTE_SERVER=irc.freeq.at:6667 \
  cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1
```

**104 tests** covering:

- **SDK (35)**: IRC parsing (with tag support), tag escaping roundtrip, DID
  document parsing, key generation/signing/verification, multibase/multicodec,
  challenge response encoding, SASL signer variants, media attachment roundtrip,
  link preview roundtrip, media type detection
- **Server unit (33)**: Message parsing (with tags), tag escaping, SASL challenge
  store (create, take, replay, expiry, forged nonce), channel state, database
  roundtrips (channels, bans, messages, identities), CRDT tests (founder
  first-write-wins, founder not overwritten after sync, DID ops sync)
- **Integration (27)**: Guest connection, secp256k1 auth, ed25519 auth, wrong key
  rejection, unknown DID rejection, expired challenge rejection, replayed nonce
  rejection, channel messaging, mixed auth/guest, nick collision, channel topic,
  topic lock, channel ops/kick, hostmask bans, DID bans, invite-only, message
  history replay, nick ownership, quit broadcast, channel key (+k), TLS
  connection, rich media tag passthrough, persistence (messages, topics, bans,
  nick ownership survive restart)
- **S2S acceptance (9)**: Connectivity, bidirectional message relay, NAMES sync,
  topic sync, PART/QUIT cleanup, late-joiner state

## Protocol Notes

### Deviations from the Spec

- Challenge uses JSON encoding (not a binary format) for debuggability
- PDS session verification is an additional auth method beyond the spec's
  crypto-only approach — it enables OAuth login without requiring users to
  manage raw signing keys
- History replay uses standard PRIVMSG (no custom extension or batch)

### IRCv3 Compatibility

- CAP negotiation follows IRCv3 `CAP LS 302` / `CAP REQ` / `CAP END`
- SASL flow follows IRCv3 SASL specification with a custom mechanism name
- `message-tags` capability follows the IRCv3 message tags specification
- Media tags use vendor-prefixed names (`content-type`, `media-url`, etc.)
- Server advertises `iroh=<endpoint-id>` in `CAP LS` for transport discovery
- `ATPROTO-CHALLENGE` could be proposed as an IRCv3 WG mechanism

## Known Limitations

- No message pruning/rotation (database grows unbounded when `--db-path` is set)
- No MOTD, LIST, WHO, AWAY, or OPER commands
- No flood protection beyond basic rate limiting
- No hostname cloaking or reverse DNS
- OAuth token refresh is not implemented — when the cached token expires,
  you re-authenticate via browser
- History replay doesn't indicate timestamps (messages appear as if just sent)
- Channel keys are visible in MODE query output (standard IRC behavior)
- No SASL `AUTHENTICATE *` (abort) handling
- Only tested against Bluesky PDS infrastructure (not generic AT Protocol)
- E2EE uses passphrase-based key derivation (no DID-based key exchange yet)
- P2P DMs require manual endpoint ID exchange (auto-discovery via WHOIS planned)
- S2S: rogue server can add itself to `did_ops` (authorization-on-write planned)
- S2S: no partition healing or conflict notification

## License

MIT
