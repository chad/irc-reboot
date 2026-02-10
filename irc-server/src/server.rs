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

    /// Run the server, blocking forever.
    pub async fn run(self) -> Result<()> {
        let tls_acceptor = self.build_tls_acceptor()?;

        let state = Arc::new(SharedState {
            server_name: self.config.server_name.clone(),
            challenge_store: ChallengeStore::new(self.config.challenge_timeout_secs),
            did_resolver: self.resolver,
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(HashMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            did_nicks: Mutex::new(HashMap::new()),
            nick_owners: Mutex::new(HashMap::new()),
            session_handles: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
        });

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

        let state = Arc::new(SharedState {
            server_name: self.config.server_name.clone(),
            challenge_store: ChallengeStore::new(self.config.challenge_timeout_secs),
            did_resolver: self.resolver,
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(HashMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            did_nicks: Mutex::new(HashMap::new()),
            nick_owners: Mutex::new(HashMap::new()),
            session_handles: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
        });

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

        let state = Arc::new(SharedState {
            server_name: self.config.server_name.clone(),
            challenge_store: ChallengeStore::new(self.config.challenge_timeout_secs),
            did_resolver: self.resolver,
            connections: Mutex::new(HashMap::new()),
            nick_to_session: Mutex::new(HashMap::new()),
            session_dids: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            did_nicks: Mutex::new(HashMap::new()),
            nick_owners: Mutex::new(HashMap::new()),
            session_handles: Mutex::new(HashMap::new()),
            cap_message_tags: Mutex::new(HashSet::new()),
        });

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
