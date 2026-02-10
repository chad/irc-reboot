# irc-reboot

IRC server and client with AT Protocol (Bluesky) identity authentication.

Users authenticate with their Bluesky identity via a custom SASL mechanism
(`ATPROTO-CHALLENGE`). Standard IRC clients connect as guests. Authenticated
users get their DID bound to their connection — visible via WHOIS, enforced
for nick ownership, and usable for DID-based bans and invites.

## Architecture

```
irc-server/     IRC server with SASL ATPROTO-CHALLENGE
irc-at-sdk/     Reusable client SDK (connect, auth, events)
irc-at-tui/     Terminal UI client built on the SDK
```

The SDK exposes a `(ClientHandle, Receiver<Event>)` pattern — any UI or bot
can consume events and send commands.

## Quick Start

### Build

```sh
cargo build --release
```

### Run the Server

```sh
# Plain text only (port 6667)
cargo run --release --bin irc-server

# With TLS (port 6667 + 6697)
cargo run --release --bin irc-server -- \
  --tls-cert certs/cert.pem --tls-key certs/key.pem
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
cargo run --release --bin irc-at-tui -- 127.0.0.1:6667 mynick

# Bluesky OAuth (opens browser, no password needed)
cargo run --release --bin irc-at-tui -- 127.0.0.1:6667 mynick \
  --handle alice.bsky.social

# With TLS
cargo run --release --bin irc-at-tui -- 127.0.0.1:6697 mynick \
  --tls --tls-insecure --handle alice.bsky.social

# App password fallback
cargo run --release --bin irc-at-tui -- 127.0.0.1:6667 mynick \
  --handle alice.bsky.social --app-password xxxx-xxxx-xxxx-xxxx

# Vi keybindings
cargo run --release --bin irc-at-tui -- 127.0.0.1:6667 mynick --vi
```

OAuth sessions are cached to `~/.config/irc-at-tui/<handle>.session.json`
so you don't need to re-authenticate on every launch.

### Connect with a Standard IRC Client

Any IRC client works as a guest — irssi, WeeChat, HexChat, LimeChat, etc.
Connect to `127.0.0.1:6667` (plain) or `127.0.0.1:6697` (TLS). No special
configuration needed.

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
- Your identity is cryptographically verifiable

## IRC Features

### Standard IRC

Full compatibility with RFC 1459/2812 basics:

- NICK, USER, JOIN, PART, PRIVMSG, NOTICE, QUIT
- PING/PONG (client and server keepalive)
- WHOIS (shows DID + handle for authenticated users)
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

### Message History

The server stores the last 100 messages per channel. When you join, recent
history is replayed as standard PRIVMSG — works with any IRC client, no
special protocol extension needed.

### Rate Limiting

Token bucket rate limiter (10 commands/second) kicks in after registration.
The initial connection burst is not rate-limited, so clients that send many
commands on connect (like LimeChat) work correctly.

## TUI Client

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
/raw <line>             Send raw IRC line
/quit [message]         Disconnect
/help                   Show commands
```

## Server Configuration

```
irc-server [OPTIONS]

Options:
  --listen-addr <ADDR>            Plain TCP address [default: 127.0.0.1:6667]
  --tls-listen-addr <ADDR>        TLS address [default: 127.0.0.1:6697]
  --tls-cert <PATH>               TLS certificate PEM file
  --tls-key <PATH>                TLS private key PEM file
  --server-name <NAME>            Server name [default: irc-reboot]
  --challenge-timeout-secs <N>    SASL challenge validity [default: 60]
```

## Tests

```sh
cargo test
```

**47 tests** covering:

- SDK: IRC parsing, DID document parsing, key generation/signing/verification,
  multibase/multicodec, challenge response encoding, SASL signer variants
- Server: message parsing, SASL challenge store (create, take, replay, expiry,
  forged nonce), channel state
- Integration: guest connection, secp256k1 auth, ed25519 auth, wrong key
  rejection, unknown DID rejection, expired challenge rejection, replayed nonce
  rejection, channel messaging, mixed auth/guest, nick collision, channel topic,
  topic lock, channel ops/kick, hostmask bans, DID bans, invite-only, message
  history replay, nick ownership, quit broadcast, channel key (+k), TLS
  connection

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
- `ATPROTO-CHALLENGE` could be proposed as an IRCv3 WG mechanism

## Known Limitations

- No server-to-server federation (single server only)
- No channel persistence across server restarts
- No MOTD, LIST, WHO, AWAY, or OPER commands
- No flood protection beyond basic rate limiting
- No hostname cloaking or reverse DNS
- OAuth token refresh is not implemented — when the cached token expires,
  you re-authenticate via browser
- History replay doesn't indicate timestamps (messages appear as if just sent)
- Channel keys are visible in MODE query output (standard IRC behavior)
- No SASL `AUTHENTICATE *` (abort) handling
- Only tested against Bluesky PDS infrastructure (not generic AT Protocol)

## License

MIT
