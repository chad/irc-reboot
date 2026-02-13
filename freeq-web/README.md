# freeq-web

Browser-based IRC client for freeq servers.

## Features

- **WebSocket transport** — connects to the server's `/irc` WebSocket endpoint
- **AT Protocol authentication** — login with Bluesky handle + app password via SASL
- **IRCv3 capabilities** — server-time, batch, multi-prefix, echo-message, chathistory, account-notify, extended-join
- **Channel management** — join, part, topic, modes, kick, ban, invite
- **Chat history** — `/history [N]` fetches previous messages via CHATHISTORY
- **Nick completion** — Tab to complete nicknames
- **Input history** — Up/Down arrows to recall previous input
- **Mobile responsive** — sidebar and nicklist collapse on narrow screens
- **Zero dependencies** — single HTML file, no build step, no framework

## Running

### Served by freeq-server

Start the server with `--web-addr` and `--web-static-dir`:

```bash
cargo run -p freeq-server --release -- \
  --web-addr 0.0.0.0:8080 \
  --web-static-dir freeq-web \
  --db-path freeq.db
```

Then open `http://localhost:8080` in your browser.

### Standalone

Open `index.html` directly in a browser and enter the WebSocket URL manually (e.g., `ws://localhost:8080/irc`).

## AT Protocol Authentication

1. Enter your Bluesky handle (e.g., `you.bsky.social`)
2. Enter an [app password](https://bsky.app/settings/app-passwords) (NOT your main password)
3. Click Connect

The client will:
- Resolve your handle → DID → PDS
- Create a session with your PDS using the app password
- Authenticate via SASL ATPROTO-CHALLENGE using the `pds-session` method

After authentication, your DID is bound to the connection. You get:
- Persistent nick ownership
- DID-based channel ops
- Identity visible in WHOIS

## Commands

| Command | Description |
|---------|-------------|
| `/join #channel` | Join a channel |
| `/part [#channel]` | Leave current or named channel |
| `/nick newnick` | Change nickname |
| `/topic [text]` | View or set topic |
| `/msg nick text` | Private message |
| `/me action` | Action message |
| `/kick nick [reason]` | Kick user |
| `/mode [modes]` | View or set channel modes |
| `/ban mask` | Ban user |
| `/unban mask` | Remove ban |
| `/op nick` | Give operator status |
| `/deop nick` | Remove operator status |
| `/voice nick` | Give voice |
| `/invite nick` | Invite to channel |
| `/whois nick` | Query user info |
| `/list` | List channels |
| `/names` | List users in channel |
| `/who` | WHO query |
| `/history [N]` | Fetch N messages of history (default 50) |
| `/clear` | Clear current buffer |
| `/close` | Close current buffer |
| `/raw text` | Send raw IRC line |
| `/quit` | Disconnect |
