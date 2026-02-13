//! Server state and TCP listener.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use freeq_sdk::did::DidResolver;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig;
use crate::connection;
use crate::db::Db;
use crate::sasl::ChallengeStore;

/// State for a single channel.
#[derive(Debug, Clone, Default)]
pub struct ChannelState {
    /// Session IDs of local members currently in the channel.
    pub members: HashSet<String>,
    /// Remote members from S2S peers: nick → RemoteMember info.
    pub remote_members: HashMap<String, RemoteMember>,
    /// Session IDs of channel operators (ephemeral, per-session).
    pub ops: HashSet<String>,
    /// Session IDs of voiced users.
    pub voiced: HashSet<String>,

    // ── DID-based persistent authority ──────────────────────────
    /// Channel founder's DID. Set once on channel creation.
    /// Founder always has ops and can't be de-opped.
    /// In S2S: resolved by CRDT (first-write-wins in Automerge causal order),
    /// NOT by timestamps — timestamps can be spoofed by rogue servers.
    pub founder_did: Option<String>,
    /// DIDs with persistent operator status.
    /// Survives reconnects, works across servers.
    /// Granted by founder or other DID-ops.
    pub did_ops: HashSet<String>,
    /// Timestamp (unix secs) when the channel was created (informational only).
    /// NOT used for authority resolution — the CRDT handles that.
    pub created_at: u64,

    /// Ban list: hostmasks (nick!user@host patterns) and/or DIDs.
    pub bans: Vec<BanEntry>,
    /// Invite-only mode (+i).
    pub invite_only: bool,
    /// Invite list (session IDs or DIDs that have been invited).
    pub invites: HashSet<String>,
    /// Recent message history for replay on join.
    pub history: std::collections::VecDeque<HistoryMessage>,
    /// Channel topic, if set.
    pub topic: Option<TopicInfo>,
    /// Channel modes: +t = only ops can set topic.
    pub topic_locked: bool,
    /// Channel mode: +n = no external messages (only members can send).
    pub no_ext_msg: bool,
    /// Channel mode: +m = moderated (only voiced/ops can send).
    pub moderated: bool,
    /// Channel key (+k) — password required to join.
    pub key: Option<String>,
}

/// Info about a remote user connected via S2S federation.
#[derive(Debug, Clone, Default)]
pub struct RemoteMember {
    /// Iroh endpoint ID of the origin server.
    pub origin: String,
    /// Authenticated DID (if any).
    pub did: Option<String>,
    /// Resolved AT Protocol handle (e.g. "chadfowler.com").
    pub handle: Option<String>,
}

/// A stored message for channel history replay.
#[derive(Debug, Clone)]
pub struct HistoryMessage {
    pub from: String,
    pub text: String,
    pub timestamp: u64,
    /// IRCv3 tags from the original message (for rich media replay).
    pub tags: HashMap<String, String>,
}

/// Maximum number of history messages to keep per channel.
pub const MAX_HISTORY: usize = 100;

/// A ban entry — can be a traditional hostmask or a DID.
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub mask: String,
    pub set_by: String,
    pub set_at: u64,
}

impl BanEntry {
    pub fn new(mask: String, set_by: String) -> Self {
        let set_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { mask, set_by, set_at }
    }

    /// Check if this ban matches a user.
    ///
    /// Supports:
    /// - DID bans: mask starts with "did:" — matches against authenticated DID
    /// - Hostmask bans: simple wildcard matching against nick!user@host
    pub fn matches(&self, hostmask: &str, did: Option<&str>) -> bool {
        if self.mask.starts_with("did:") {
            // DID-based ban: exact match
            did.is_some_and(|d| d == self.mask)
        } else {
            // Hostmask ban: simple wildcard match
            wildcard_match(&self.mask, hostmask)
        }
    }
}

/// Simple wildcard matching (* and ?).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    wildcard_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn wildcard_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            // * matches zero or more characters
            wildcard_match_inner(&pattern[1..], text)
                || (!text.is_empty() && wildcard_match_inner(pattern, &text[1..]))
        }
        (Some(b'?'), Some(_)) => wildcard_match_inner(&pattern[1..], &text[1..]),
        (Some(a), Some(b)) if a == b => wildcard_match_inner(&pattern[1..], &text[1..]),
        _ => false,
    }
}

impl ChannelState {
    /// Check if a user is banned from this channel.
    pub fn is_banned(&self, hostmask: &str, did: Option<&str>) -> bool {
        self.bans.iter().any(|b| b.matches(hostmask, did))
    }
}

/// Channel topic with metadata.
#[derive(Debug, Clone)]
pub struct TopicInfo {
    pub text: String,
    pub set_by: String,
    pub set_at: u64,
}

impl TopicInfo {
    pub fn new(text: String, set_by: String) -> Self {
        let set_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            text,
            set_by,
            set_at,
        }
    }
}

/// Shared state accessible by all connection handlers.
pub struct SharedState {
    pub server_name: String,
    pub challenge_store: ChallengeStore,
    pub did_resolver: DidResolver,
    /// session_id -> sender for writing lines to that client
    pub connections: Mutex<HashMap<String, mpsc::Sender<String>>>,
    /// nick -> session_id
    pub nick_to_session: Mutex<HashMap<String, String>>,
    /// session_id -> authenticated DID (for WHOIS lookups by other connections)
    pub session_dids: Mutex<HashMap<String, String>>,
    /// DID -> owned nick (persistent identity-nick binding).
    /// When a user authenticates, they claim their nick. No one else can use it.
    pub did_nicks: Mutex<HashMap<String, String>>,
    /// nick -> DID (reverse lookup for nick enforcement).
    pub nick_owners: Mutex<HashMap<String, String>>,
    /// session_id -> resolved Bluesky handle (for WHOIS display).
    pub session_handles: Mutex<HashMap<String, String>>,
    /// channel name -> channel state (keys are always lowercase)
    pub channels: Mutex<HashMap<String, ChannelState>>,
    /// Sessions that have negotiated message-tags capability.
    pub cap_message_tags: Mutex<HashSet<String>>,
    /// Sessions that have negotiated multi-prefix capability.
    pub cap_multi_prefix: Mutex<HashSet<String>>,
    /// Sessions that have negotiated echo-message capability.
    pub cap_echo_message: Mutex<HashSet<String>>,
    /// Sessions that have negotiated server-time capability.
    pub cap_server_time: Mutex<HashSet<String>>,
    /// Sessions that have negotiated batch capability.
    pub cap_batch: Mutex<HashSet<String>>,
    /// session_id -> iroh endpoint ID (for connections via iroh transport).
    pub session_iroh_ids: Mutex<HashMap<String, String>>,
    /// session_id -> away message (None = not away).
    pub session_away: Mutex<HashMap<String, String>>,
    /// This server's own iroh endpoint ID (advertised in CAP LS).
    pub server_iroh_id: Mutex<Option<String>>,
    /// Iroh endpoint handle (kept alive for the server's lifetime).
    pub iroh_endpoint: Mutex<Option<iroh::Endpoint>>,
    /// S2S manager (if clustering is active).
    pub s2s_manager: Mutex<Option<Arc<crate::s2s::S2sManager>>>,
    /// Database handle for persistence (None = in-memory only).
    pub db: Option<Mutex<Db>>,
    /// Server configuration (for MOTD, max messages, etc.).
    pub config: ServerConfig,
}

impl SharedState {
    /// Run a closure with the database, if persistence is enabled.
    /// Logs errors but does not propagate them — persistence failures
    /// should not break the IRC server.
    pub fn with_db<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Db) -> rusqlite::Result<R>,
    {
        self.db.as_ref().and_then(|db| {
            let db = db.lock().unwrap();
            match f(&db) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::error!("Database error: {e}");
                    None
                }
            }
        })
    }
}

pub struct Server {
    config: ServerConfig,
    resolver: DidResolver,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            resolver: DidResolver::http(),
            config,
        }
    }

    /// Create a server with a custom DID resolver (for testing).
    pub fn with_resolver(config: ServerConfig, resolver: DidResolver) -> Self {
        Self { config, resolver }
    }

    /// Build SharedState, opening the database and loading persisted data.
    fn build_state(&self) -> Result<Arc<SharedState>> {
        let db = match &self.config.db_path {
            Some(path) => {
                tracing::info!("Opening database: {path}");
                Some(Db::open(path).map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?)
            }
            None => None,
        };

        // Load persisted state from DB
        let mut channels = HashMap::new();
        let mut did_nicks = HashMap::new();
        let mut nick_owners = HashMap::new();

        if let Some(ref db) = db {
            // Load channels (metadata + bans)
            channels = db.load_channels()
                .map_err(|e| anyhow::anyhow!("Failed to load channels: {e}"))?;
            tracing::info!("Loaded {} channels from database", channels.len());

            // Load message history into each channel
            for (name, ch) in channels.iter_mut() {
                let messages = db.get_messages(name, crate::server::MAX_HISTORY, None)
                    .map_err(|e| anyhow::anyhow!("Failed to load messages for {name}: {e}"))?;
                for msg in messages {
                    ch.history.push_back(HistoryMessage {
                        from: msg.sender,
                        text: msg.text,
                        timestamp: msg.timestamp,
                        tags: msg.tags,
                    });
                }
            }

            // Load DID-nick bindings
            let identities = db.load_identities()
                .map_err(|e| anyhow::anyhow!("Failed to load identities: {e}"))?;
            tracing::info!("Loaded {} identity bindings from database", identities.len());
            for id in identities {
                nick_owners.insert(id.nick.clone(), id.did.clone());
                did_nicks.insert(id.did, id.nick);
            }
        }

        Ok(Arc::new(SharedState {
            server_name: self.config.server_name.clone(),
            challenge_store: ChallengeStore::new(self.config.challenge_timeout_secs),
            did_resolver: self.resolver.clone(),
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(HashMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            channels: Mutex::new(channels),
            did_nicks: Mutex::new(did_nicks),
            nick_owners: Mutex::new(nick_owners),
            session_handles: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
            cap_multi_prefix: Mutex::new(HashSet::new()),
            cap_echo_message: Mutex::new(HashSet::new()),
            cap_server_time: Mutex::new(HashSet::new()),
            cap_batch: Mutex::new(HashSet::new()),
            session_iroh_ids: Mutex::new(HashMap::new()),
            session_away: Mutex::new(HashMap::new()),
            server_iroh_id: Mutex::new(None),
            iroh_endpoint: Mutex::new(None),
            s2s_manager: Mutex::new(None),
            db: db.map(Mutex::new),
            config: self.config.clone(),
        }))
    }

    /// Run the server, blocking forever.
    pub async fn run(self) -> Result<()> {
        let tls_acceptor = self.build_tls_acceptor()?;
        let web_addr = self.config.web_addr.clone();
        let state = self.build_state()?;

        // Start plain listener
        let plain_listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!("Plain listener on {}", self.config.listen_addr);

        // Start TLS listener if configured
        if let Some(ref acceptor) = tls_acceptor {
            let tls_listener = TcpListener::bind(&self.config.tls_listen_addr).await?;
            tracing::info!("TLS listener on {}", self.config.tls_listen_addr);

            let tls_state = Arc::clone(&state);
            let tls_acc = acceptor.clone();
            tokio::spawn(async move {
                loop {
                    match tls_listener.accept().await {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&tls_state);
                            let acceptor = tls_acc.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) =
                                            connection::handle_generic(tls_stream, state).await
                                        {
                                            tracing::error!("TLS connection error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("TLS handshake failed: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => tracing::error!("TLS accept error: {e}"),
                    }
                }
            });
        }

        // Start iroh transport if configured
        let iroh_endpoint = if self.config.iroh || !self.config.s2s_peers.is_empty() {
            let iroh_state = Arc::clone(&state);
            let iroh_port = self.config.iroh_port;
            match crate::iroh::start(iroh_state, iroh_port).await {
                Ok(endpoint) => {
                    // Wait for the endpoint to be online and print connection info
                    endpoint.online().await;
                    let id = endpoint.id();
                    tracing::info!("Iroh ready. Connect with: --iroh-addr {id}");
                    *state.server_iroh_id.lock().unwrap() = Some(id.to_string());
                    Some(endpoint)
                }
                Err(e) => {
                    tracing::error!("Failed to start iroh endpoint: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Start S2S manager whenever iroh is enabled (not just when peers are configured).
        // This allows the server to accept incoming S2S connections from other servers.
        if let Some(ref endpoint) = iroh_endpoint {
            let s2s_state = Arc::clone(&state);
            match crate::s2s::start(s2s_state, endpoint.clone()).await {
                Ok((manager, mut s2s_rx)) => {
                    // Store manager in shared state so iroh accept loop can route S2S
                    *state.s2s_manager.lock().unwrap() = Some(Arc::clone(&manager));

                    // Connect to configured peers with auto-reconnection
                    for peer_id in &self.config.s2s_peers {
                        let event_tx = manager.event_tx.clone();
                        crate::s2s::connect_peer_with_retry(
                            endpoint.clone(),
                            peer_id.clone(),
                            Arc::clone(&manager),
                            event_tx,
                        );
                    }

                    // Spawn S2S event processor
                    let s2s_state = Arc::clone(&state);
                    let s2s_manager = Arc::clone(&manager);
                    tokio::spawn(async move {
                        while let Some(msg) = s2s_rx.recv().await {
                            process_s2s_message(&s2s_state, &s2s_manager, msg).await;
                        }
                    });

                    if self.config.s2s_peers.is_empty() {
                        tracing::info!("S2S ready (accepting incoming peer connections)");
                    } else {
                        tracing::info!(
                            "S2S clustering active with {} peer(s)",
                            self.config.s2s_peers.len()
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to start S2S: {e}");
                }
            }
        } else if !self.config.s2s_peers.is_empty() {
            tracing::error!("S2S requires iroh transport (--iroh)");
        }

        // Store iroh endpoint in shared state to keep it alive
        if let Some(endpoint) = iroh_endpoint {
            *state.iroh_endpoint.lock().unwrap() = Some(endpoint);
        }

        // Start HTTP/WebSocket listener if configured
        if let Some(ref addr) = web_addr {
            let web_state = Arc::clone(&state);
            let router = crate::web::router(web_state);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("HTTP/WebSocket listener on {addr}");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    tracing::error!("HTTP server error: {e}");
                }
            });
        }

        // Accept plain connections
        loop {
            let (stream, _addr) = plain_listener.accept().await?;
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(e) = connection::handle(stream, state).await {
                    tracing::error!("Connection error: {e}");
                }
            });
        }
    }

    /// Start the server and return the bound address + task handle (for testing).
    pub async fn start(self) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let addr = listener.local_addr()?;
        tracing::info!("Listening on {addr}");

        let state = self.build_state()?;

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _addr) = listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, state).await {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
        });

        Ok((addr, handle))
    }

    /// Start the server with both plain and TLS listeners for testing.
    /// Returns (plain_addr, tls_addr, handle).
    pub async fn start_tls(self) -> Result<(SocketAddr, SocketAddr, JoinHandle<Result<()>>)> {
        let tls_acceptor = self.build_tls_acceptor()?
            .expect("TLS must be configured for start_tls()");

        let plain_listener = TcpListener::bind(&self.config.listen_addr).await?;
        let plain_addr = plain_listener.local_addr()?;

        let tls_listener = TcpListener::bind(&self.config.tls_listen_addr).await?;
        let tls_addr = tls_listener.local_addr()?;

        tracing::info!("Plain on {plain_addr}, TLS on {tls_addr}");

        let state = self.build_state()?;

        let handle = tokio::spawn(async move {
            let tls_state = Arc::clone(&state);
            let tls_acc = tls_acceptor.clone();
            tokio::spawn(async move {
                loop {
                    match tls_listener.accept().await {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&tls_state);
                            let acceptor = tls_acc.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = connection::handle_generic(tls_stream, state).await {
                                            tracing::error!("TLS connection error: {e}");
                                        }
                                    }
                                    Err(e) => tracing::warn!("TLS handshake failed: {e}"),
                                }
                            });
                        }
                        Err(e) => tracing::error!("TLS accept error: {e}"),
                    }
                }
            });

            loop {
                let (stream, _) = plain_listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = connection::handle(stream, state).await {
                        tracing::error!("Connection error: {e}");
                    }
                });
            }
        });

        Ok((plain_addr, tls_addr, handle))
    }

    fn build_tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        if !self.config.tls_enabled() {
            return Ok(None);
        }

        let cert_path = self.config.tls_cert.as_deref().unwrap();
        let key_path = self.config.tls_key.as_deref().unwrap();

        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read TLS cert: {cert_path}"))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read TLS key: {key_path}"))?;

        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse TLS certificates")?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .context("Failed to parse TLS private key")?
            .context("No private key found in PEM file")?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Invalid TLS configuration")?;

        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }
}

/// Process an S2S message received from a peer server.
///
/// Delivers relayed messages to local clients. Currently handles
/// PRIVMSG, JOIN, PART, QUIT, NICK, TOPIC, and sync.
///
/// Remote users are identified by nick (not session ID). We deliver
/// to local sessions that are members of the target channel.
async fn process_s2s_message(
    state: &Arc<SharedState>,
    manager: &Arc<crate::s2s::S2sManager>,
    msg: crate::s2s::S2sMessage,
) {
    use crate::s2s::S2sMessage;

    /// Deliver a raw IRC line to all local members of a channel.
    fn deliver_to_channel(state: &SharedState, channel: &str, line: &str) {
        let channel_key = channel.to_lowercase();
        let channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get(&channel_key) {
            let conns = state.connections.lock().unwrap();
            for session_id in &ch.members {
                if let Some(tx) = conns.get(session_id) {
                    let _ = tx.try_send(line.to_string());
                }
            }
        }
    }

    /// Send NAMES update to all local members of a channel (for nick list refresh).
    fn send_names_update(state: &SharedState, channel: &str) {
        let channels = state.channels.lock().unwrap();
        let ch = match channels.get(channel) {
            Some(ch) => ch,
            None => return,
        };

        // Build nick list (local + remote)
        let n2s = state.nick_to_session.lock().unwrap();
        let reverse: HashMap<&String, &String> = n2s.iter().map(|(n, s)| (s, n)).collect();
        let mut nick_list: Vec<String> = ch.members.iter()
            .filter_map(|s| {
                reverse.get(s).map(|n| {
                    let prefix = if ch.ops.contains(s) { "@" }
                        else if ch.voiced.contains(s) { "+" }
                        else { "" };
                    format!("{prefix}{n}")
                })
            })
            .collect();
        for (nick, rm) in &ch.remote_members {
            let is_op = rm.did.as_ref().is_some_and(|d| {
                ch.founder_did.as_deref() == Some(d) || ch.did_ops.contains(d)
            });
            let prefix = if is_op { "@" } else { "" };
            nick_list.push(format!("{prefix}{nick}"));
        }
        let nick_str = nick_list.join(" ");

        // Send to each local member
        let local_members: Vec<String> = ch.members.iter().cloned().collect();
        drop(channels);

        let conns = state.connections.lock().unwrap();
        for session_id in &local_members {
            // Look up this member's nick for the reply prefix
            let member_nick = reverse.get(session_id).map(|n| n.as_str()).unwrap_or("*");
            let names_line = format!(
                ":{} 353 {} = {} :{}\r\n:{} 366 {} {} :End of /NAMES list\r\n",
                state.server_name, member_nick, channel, nick_str,
                state.server_name, member_nick, channel,
            );
            if let Some(tx) = conns.get(session_id) {
                let _ = tx.try_send(names_line);
            }
        }
    }

    match msg {
        S2sMessage::Privmsg { from, target, text, origin } => {
            if origin == manager.server_id { return; }

            let line = format!(":{from} PRIVMSG {target} :{text}\r\n");

            if target.starts_with('#') || target.starts_with('&') {
                deliver_to_channel(state, &target, &line);
            } else {
                // PM — find target nick's session
                let n2s = state.nick_to_session.lock().unwrap();
                if let Some(sid) = n2s.get(&target) {
                    let conns = state.connections.lock().unwrap();
                    if let Some(tx) = conns.get(sid) {
                        let _ = tx.try_send(line);
                    }
                }
            }
        }

        S2sMessage::Join { nick, channel, did, handle, origin } => {
            if origin == manager.server_id { return; }

            // Ensure channel exists locally (create if needed, no ops granted)
            {
                let mut channels = state.channels.lock().unwrap();
                channels.entry(channel.clone()).or_default();
            }

            // Track remote member with their identity info
            {
                let mut channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get_mut(&channel) {
                    ch.remote_members.insert(nick.clone(), RemoteMember {
                        origin: origin.clone(),
                        did: did.clone(),
                        handle: handle.clone(),
                    });
                }
            }

            let line = format!(":{nick}!{nick}@s2s JOIN {channel}\r\n");
            deliver_to_channel(state, &channel, &line);

            // Send updated NAMES to local members so nick lists refresh
            send_names_update(state, &channel);
        }

        S2sMessage::Part { nick, channel, origin } => {
            if origin == manager.server_id { return; }

            // Remove remote member
            {
                let mut channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get_mut(&channel) {
                    ch.remote_members.remove(&nick);
                }
            }

            let line = format!(":{nick}!{nick}@s2s PART {channel}\r\n");
            deliver_to_channel(state, &channel, &line);
            send_names_update(state, &channel);
        }

        S2sMessage::Quit { nick, reason, origin } => {
            if origin == manager.server_id { return; }

            // Remove remote member from all channels
            let mut affected_channels = Vec::new();
            {
                let mut channels = state.channels.lock().unwrap();
                for (name, ch) in channels.iter_mut() {
                    if ch.remote_members.remove(&nick).is_some() {
                        affected_channels.push(name.clone());
                    }
                }
            }

            let line = format!(":{nick}!{nick}@s2s QUIT :{reason}\r\n");
            for ch_name in &affected_channels {
                deliver_to_channel(state, ch_name, &line);
                send_names_update(state, ch_name);
            }
        }

        S2sMessage::Topic { channel, topic, set_by, origin } => {
            if origin == manager.server_id { return; }
            // Respect +t: the remote server should have enforced it,
            // but if not (old code), we enforce it here too.
            // We allow the topic change if:
            //   - Channel doesn't exist yet (will be created)
            //   - Channel is not +t
            //   - The set_by user is a known DID-op or founder
            // Since we can't easily verify remote ops, we trust the
            // originating server's enforcement and always accept.
            {
                let mut channels = state.channels.lock().unwrap();
                let ch = channels.entry(channel.clone()).or_default();
                ch.topic = Some(TopicInfo::new(topic.clone(), set_by.clone()));
            }
            let line = format!(":{set_by}!remote@s2s TOPIC {channel} :{topic}\r\n");
            deliver_to_channel(state, &channel, &line);
        }

        S2sMessage::ChannelCreated { channel, founder_did, did_ops, created_at: _, origin } => {
            if origin == manager.server_id { return; }

            let mut channels = state.channels.lock().unwrap();
            let ch = channels.entry(channel.clone()).or_default();

            // Founder resolution: first-write-wins.
            // We don't trust timestamps (spoofable). Instead:
            // - If we have no founder, adopt the remote one
            // - If we have a founder, keep ours (first-write-wins locally)
            // - The CRDT (ClusterDoc) handles global convergence:
            //   both servers write "founder:{channel}" only if absent,
            //   and Automerge's deterministic conflict resolution
            //   ensures they converge after sync.
            if ch.founder_did.is_none() {
                if let Some(ref did) = founder_did {
                    tracing::info!(
                        channel = %channel,
                        "Adopting remote founder {did} (no local founder)"
                    );
                    ch.founder_did = Some(did.clone());
                }
            } else {
                tracing::debug!(
                    channel = %channel,
                    "Keeping local founder {:?} (ignoring remote {:?})",
                    ch.founder_did, founder_did
                );
            }

            // Merge DID ops — union of both sets (additive, safe)
            for did in did_ops {
                ch.did_ops.insert(did);
            }

            // Re-op any local members whose DID now has persistent ops
            let has_local_members = !ch.members.is_empty();
            let members: Vec<String> = ch.members.iter().cloned().collect();
            let dids = state.session_dids.lock().unwrap();
            for session_id in &members {
                if let Some(did) = dids.get(session_id) {
                    if ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did) {
                        ch.ops.insert(session_id.clone());
                    }
                }
            }
            drop(dids);
            drop(channels);

            // Notify local members of op changes
            if has_local_members {
                send_names_update(state, &channel);
            }
        }

        S2sMessage::SyncRequest => {
            // Build channel list and respond
            let response = {
                let channels = state.channels.lock().unwrap();
                let n2s = state.nick_to_session.lock().unwrap();
                let s2n: HashMap<&String, &String> = n2s.iter().map(|(n, s)| (s, n)).collect();

                let channel_info: Vec<crate::s2s::ChannelInfo> = channels.iter().map(|(name, ch)| {
                    let nicks: Vec<String> = ch.members.iter()
                        .filter_map(|sid| s2n.get(sid).map(|n| (*n).clone()))
                        .collect();
                    crate::s2s::ChannelInfo {
                        name: name.clone(),
                        topic: ch.topic.as_ref().map(|t| t.text.clone()),
                        nicks,
                        founder_did: ch.founder_did.clone(),
                        did_ops: ch.did_ops.iter().cloned().collect(),
                        created_at: ch.created_at,
                        topic_locked: ch.topic_locked,
                        invite_only: ch.invite_only,
                        no_ext_msg: ch.no_ext_msg,
                        moderated: ch.moderated,
                        key: ch.key.clone(),
                    }
                }).collect();

                S2sMessage::SyncResponse {
                    server_id: manager.server_id.clone(),
                    channels: channel_info,
                }
            };
            manager.broadcast(response).await;
        }

        S2sMessage::SyncResponse { server_id: peer_id, channels: remote_channels } => {
            tracing::info!(
                "Received sync: {} channel(s) from peer {peer_id}",
                remote_channels.len()
            );
            let mut updated_channels = Vec::new();
            {
                let mut channels = state.channels.lock().unwrap();
                for info in remote_channels {
                    let ch = channels.entry(info.name.clone()).or_default();

                    // Merge founder: first-write-wins (no timestamp comparison)
                    if ch.founder_did.is_none() && info.founder_did.is_some() {
                        ch.founder_did = info.founder_did.clone();
                    }

                    // Merge DID ops (union)
                    for did in &info.did_ops {
                        ch.did_ops.insert(did.clone());
                    }

                    // Add remote nicks
                    for nick in &info.nicks {
                        // SyncResponse doesn't include per-user DIDs/handles yet
                        ch.remote_members.entry(nick.clone()).or_insert_with(|| RemoteMember {
                            origin: peer_id.clone(),
                            did: None,
                            handle: None,
                        });
                    }

                    // Merge topic if we don't have one
                    if ch.topic.is_none() {
                        if let Some(ref topic) = info.topic {
                            ch.topic = Some(TopicInfo::new(
                                topic.clone(),
                                info.founder_did.as_deref().unwrap_or("unknown").to_string(),
                            ));
                        }
                    }

                    // Merge modes: if the remote has a restrictive mode set, adopt it.
                    // This ensures +t/+i/+n/+m propagate across the federation.
                    if info.topic_locked { ch.topic_locked = true; }
                    if info.invite_only { ch.invite_only = true; }
                    if info.no_ext_msg { ch.no_ext_msg = true; }
                    if info.moderated { ch.moderated = true; }
                    if ch.key.is_none() && info.key.is_some() {
                        ch.key = info.key.clone();
                    }

                    // Re-op any local members whose DID now has persistent ops
                    let dids = state.session_dids.lock().unwrap();
                    let members: Vec<String> = ch.members.iter().cloned().collect();
                    for session_id in &members {
                        if let Some(did) = dids.get(session_id) {
                            if ch.founder_did.as_deref() == Some(did) || ch.did_ops.contains(did) {
                                ch.ops.insert(session_id.clone());
                            }
                        }
                    }

                    // Track channels that have local members (need NAMES refresh)
                    if !ch.members.is_empty() {
                        updated_channels.push(info.name.clone());
                    }

                    tracing::info!(
                        "  Channel {}: {} remote user(s), founder: {:?}, {} DID ops, topic: {:?}",
                        info.name, ch.remote_members.len(), ch.founder_did, ch.did_ops.len(),
                        ch.topic.as_ref().map(|t| &t.text),
                    );
                }
            }

            // Send NAMES + topic updates to local members of affected channels
            for channel in &updated_channels {
                send_names_update(state, channel);
                // Also push topic to local members
                let topic_info = state.channels.lock().unwrap()
                    .get(channel)
                    .and_then(|ch| ch.topic.as_ref().map(|t| (t.text.clone(), t.set_by.clone())));
                if let Some((topic, _set_by)) = topic_info {
                    let line = format!(
                        ":{} 332 * {} :{}\r\n",
                        state.server_name, channel, topic,
                    );
                    // Send to all local members
                    let members: Vec<String> = state.channels.lock().unwrap()
                        .get(channel)
                        .map(|ch| ch.members.iter().cloned().collect())
                        .unwrap_or_default();
                    let conns = state.connections.lock().unwrap();
                    for session_id in &members {
                        if let Some(tx) = conns.get(session_id) {
                            let _ = tx.try_send(line.clone());
                        }
                    }
                }
            }
        }

        S2sMessage::Mode { channel, mode, arg, set_by, origin } => {
            if origin == manager.server_id { return; }
            // Apply mode change to local channel state
            {
                let mut channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get_mut(&channel) {
                    let adding = mode.starts_with('+');
                    let mode_char = mode.chars().last().unwrap_or(' ');
                    match mode_char {
                        't' => ch.topic_locked = adding,
                        'i' => ch.invite_only = adding,
                        'n' => ch.no_ext_msg = adding,
                        'm' => ch.moderated = adding,
                        'k' => {
                            if adding {
                                ch.key = arg.clone();
                            } else {
                                ch.key = None;
                            }
                        }
                        _ => {} // o, v, b handled differently
                    }
                }
            }
            // Notify local members
            let mode_line = if let Some(ref a) = arg {
                format!(":{set_by}!remote@s2s MODE {channel} {mode} {a}\r\n")
            } else {
                format!(":{set_by}!remote@s2s MODE {channel} {mode}\r\n")
            };
            deliver_to_channel(state, &channel, &mode_line);
        }

        S2sMessage::NickChange { old, new, origin } => {
            if origin == manager.server_id { return; }
            let line = format!(":{old}!remote@s2s NICK :{new}\r\n");

            // Update remote_members: rename old → new in all channels
            let mut channels = state.channels.lock().unwrap();
            let mut affected_sessions = std::collections::HashSet::new();
            for ch in channels.values_mut() {
                if let Some(rm) = ch.remote_members.remove(&old) {
                    ch.remote_members.insert(new.clone(), rm);
                    // Collect local members to notify
                    for s in &ch.members {
                        affected_sessions.insert(s.clone());
                    }
                }
            }
            drop(channels);

            // Notify affected local clients and send updated NAMES
            let conns = state.connections.lock().unwrap();
            for session_id in &affected_sessions {
                if let Some(tx) = conns.get(session_id) {
                    let _ = tx.try_send(line.clone());
                }
            }
        }
    }
}
