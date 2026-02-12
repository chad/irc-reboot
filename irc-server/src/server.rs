//! Server state and TCP listener.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use irc_at_sdk::did::DidResolver;
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
    /// Session IDs of members currently in the channel.
    pub members: HashSet<String>,
    /// Session IDs of channel operators.
    pub ops: HashSet<String>,
    /// Session IDs of voiced users.
    pub voiced: HashSet<String>,
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
    /// Channel key (+k) — password required to join.
    pub key: Option<String>,
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
    /// channel name -> channel state
    pub channels: Mutex<HashMap<String, ChannelState>>,
    /// Sessions that have negotiated message-tags capability.
    pub cap_message_tags: Mutex<HashSet<String>>,
    /// session_id -> iroh endpoint ID (for connections via iroh transport).
    pub session_iroh_ids: Mutex<HashMap<String, String>>,
    /// This server's own iroh endpoint ID (advertised in CAP LS).
    pub server_iroh_id: Mutex<Option<String>>,
    /// Database handle for persistence (None = in-memory only).
    pub db: Option<Mutex<Db>>,
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
            session_iroh_ids: Mutex::new(HashMap::new()),
            server_iroh_id: Mutex::new(None),
            db: db.map(Mutex::new),
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

        // Start S2S clustering if peers are configured
        if !self.config.s2s_peers.is_empty() {
            if let Some(ref endpoint) = iroh_endpoint {
                let s2s_state = Arc::clone(&state);
                match crate::s2s::start(s2s_state, endpoint.clone()).await {
                    Ok((manager, mut s2s_rx)) => {
                        // Connect to configured peers
                        for peer_id in &self.config.s2s_peers {
                            let event_tx = manager.event_tx.clone();
                            if let Err(e) = crate::s2s::connect_peer(
                                endpoint, peer_id, &manager, event_tx,
                            ).await {
                                tracing::error!("Failed to connect to S2S peer {peer_id}: {e}");
                            }
                        }

                        // Spawn S2S event processor
                        let s2s_state = Arc::clone(&state);
                        let s2s_manager = Arc::clone(&manager);
                        tokio::spawn(async move {
                            while let Some(msg) = s2s_rx.recv().await {
                                process_s2s_message(&s2s_state, &s2s_manager, msg).await;
                            }
                        });

                        tracing::info!(
                            "S2S clustering active with {} peer(s)",
                            self.config.s2s_peers.len()
                        );
                    }
                    Err(e) => {
                        tracing::error!("Failed to start S2S: {e}");
                    }
                }
            } else {
                tracing::error!("S2S requires iroh transport (--iroh)");
            }
        }

        // Keep iroh endpoint alive
        if let Some(endpoint) = iroh_endpoint {
            std::mem::forget(endpoint);
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

        S2sMessage::Join { nick, channel, origin } => {
            if origin == manager.server_id { return; }
            let line = format!(":{nick}!remote@s2s JOIN {channel}\r\n");
            deliver_to_channel(state, &channel, &line);
        }

        S2sMessage::Part { nick, channel, origin } => {
            if origin == manager.server_id { return; }
            let line = format!(":{nick}!remote@s2s PART {channel}\r\n");
            deliver_to_channel(state, &channel, &line);
        }

        S2sMessage::Quit { nick, reason, origin } => {
            if origin == manager.server_id { return; }
            // Notify all channels
            let line = format!(":{nick}!remote@s2s QUIT :{reason}\r\n");
            let channels = state.channels.lock().unwrap();
            let conns = state.connections.lock().unwrap();
            for (_name, ch) in channels.iter() {
                for session_id in &ch.members {
                    if let Some(tx) = conns.get(session_id) {
                        let _ = tx.try_send(line.clone());
                    }
                }
            }
        }

        S2sMessage::Topic { channel, topic, set_by, origin } => {
            if origin == manager.server_id { return; }
            let channel_key = channel.to_lowercase();
            // Update our topic state
            {
                let mut channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get_mut(&channel_key) {
                    ch.topic = Some(TopicInfo::new(topic.clone(), set_by.clone()));
                }
            }
            let line = format!(":{set_by}!remote@s2s TOPIC {channel} :{topic}\r\n");
            deliver_to_channel(state, &channel, &line);
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
                    }
                }).collect();

                S2sMessage::SyncResponse {
                    server_id: manager.server_id.clone(),
                    channels: channel_info,
                }
            };
            manager.broadcast(response).await;
        }

        S2sMessage::SyncResponse { server_id: _, channels: remote_channels } => {
            tracing::info!(
                "Received sync: {} channel(s) from peer",
                remote_channels.len()
            );
            // For now, just log. Full state merging (remote user tracking)
            // requires a more sophisticated model with virtual sessions.
            for info in &remote_channels {
                tracing::info!(
                    "  Channel {}: {} user(s), topic: {:?}",
                    info.name, info.nicks.len(), info.topic
                );
            }
        }

        S2sMessage::NickChange { old, new, origin } => {
            if origin == manager.server_id { return; }
            let line = format!(":{old}!remote@s2s NICK {new}\r\n");
            // Notify all channels (broadcast to all local clients for simplicity)
            let channels = state.channels.lock().unwrap();
            let conns = state.connections.lock().unwrap();
            for (_name, ch) in channels.iter() {
                for session_id in &ch.members {
                    if let Some(tx) = conns.get(session_id) {
                        let _ = tx.try_send(line.clone());
                    }
                }
            }
        }
    }
}
