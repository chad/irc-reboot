//! Server-to-server (S2S) clustering via iroh.
//!
//! Servers connect to each other using iroh's QUIC transport, forming
//! a mesh network. State is propagated via a simple message protocol
//! on bidirectional streams.
//!
//! # Protocol
//!
//! Each S2S link uses a single bidirectional QUIC stream carrying
//! newline-delimited JSON messages. Messages are typed:
//!
//! ```json
//! {"type":"privmsg","from":"nick!user@host","target":"#channel","text":"hello"}
//! {"type":"join","nick":"alice","channel":"#test"}
//! {"type":"part","nick":"alice","channel":"#test"}
//! {"type":"quit","nick":"alice","reason":"bye"}
//! {"type":"nick_change","old":"alice","new":"alicex"}
//! {"type":"topic","channel":"#test","topic":"new topic","set_by":"alice"}
//! {"type":"sync_request"}
//! {"type":"sync_response","channels":[...],"nicks":[...]}
//! ```
//!
//! # Topology
//!
//! The current implementation uses a simple mesh: each server connects
//! to all configured peers. Messages are forwarded with origin tracking
//! to prevent loops.
//!
//! Future: gossip-based propagation, partial mesh, CRDTs for membership.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::server::SharedState;

/// ALPN for server-to-server links.
pub const S2S_ALPN: &[u8] = b"irc-reboot/s2s/1";

/// Messages exchanged between servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum S2sMessage {
    /// A PRIVMSG or NOTICE relayed between servers.
    #[serde(rename = "privmsg")]
    Privmsg {
        from: String,
        target: String,
        text: String,
        /// Origin server ID (to prevent relay loops).
        origin: String,
    },

    /// A user joined a channel.
    #[serde(rename = "join")]
    Join {
        nick: String,
        channel: String,
        /// Authenticated DID (if any) — used for DID-based ops.
        did: Option<String>,
        origin: String,
    },

    /// A channel was created (carries founder info for authority resolution).
    #[serde(rename = "channel_created")]
    ChannelCreated {
        channel: String,
        /// DID of the channel founder.
        founder_did: Option<String>,
        /// DIDs with operator status.
        did_ops: Vec<String>,
        /// Unix timestamp of channel creation (earliest wins in conflicts).
        created_at: u64,
        origin: String,
    },

    /// A user left a channel.
    #[serde(rename = "part")]
    Part {
        nick: String,
        channel: String,
        origin: String,
    },

    /// A user quit.
    #[serde(rename = "quit")]
    Quit {
        nick: String,
        reason: String,
        origin: String,
    },

    /// A user changed nick.
    #[serde(rename = "nick_change")]
    NickChange {
        old: String,
        new: String,
        origin: String,
    },

    /// Channel topic changed.
    #[serde(rename = "topic")]
    Topic {
        channel: String,
        topic: String,
        set_by: String,
        origin: String,
    },

    /// Request full state sync (sent on initial link).
    #[serde(rename = "sync_request")]
    SyncRequest,

    /// Response with current server state.
    #[serde(rename = "sync_response")]
    SyncResponse {
        /// Server's iroh endpoint ID.
        server_id: String,
        /// Active channels and their topics.
        channels: Vec<ChannelInfo>,
    },
}

/// Channel info for sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub topic: Option<String>,
    pub nicks: Vec<String>,
    /// Channel founder DID.
    pub founder_did: Option<String>,
    /// DIDs with persistent operator status.
    pub did_ops: Vec<String>,
    /// Channel creation timestamp.
    pub created_at: u64,
}

/// State for managing S2S links.
pub struct S2sManager {
    /// Our server's iroh endpoint ID.
    pub server_id: String,
    /// Connected peer servers: peer_id → sender for writing messages.
    peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<S2sMessage>>>>,
    /// Channel for S2S events that need to be applied to server state.
    pub event_tx: mpsc::Sender<S2sMessage>,
}

impl S2sManager {
    /// Broadcast a message to all peer servers.
    pub async fn broadcast(&self, msg: S2sMessage) {
        let peers = self.peers.lock().await;
        for (peer_id, tx) in peers.iter() {
            if tx.send(msg.clone()).await.is_err() {
                tracing::warn!(peer = %peer_id, "Failed to send S2S message");
            }
        }
    }
}

/// Start the S2S subsystem.
///
/// Returns the manager + event receiver. Incoming S2S connections are
/// handled by the iroh accept loop in iroh.rs (routed by ALPN), which
/// calls `handle_incoming_s2s()`.
pub async fn start(
    _state: Arc<SharedState>,
    endpoint: iroh::Endpoint,
) -> Result<(Arc<S2sManager>, mpsc::Receiver<S2sMessage>)> {
    let (event_tx, event_rx) = mpsc::channel(1024);
    let server_id = endpoint.id().to_string();

    let manager = Arc::new(S2sManager {
        server_id: server_id.clone(),
        peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        event_tx: event_tx.clone(),
    });

    Ok((manager, event_rx))
}

/// Handle an incoming S2S connection (called from iroh accept loop).
pub async fn handle_incoming_s2s(
    conn: iroh::endpoint::Connection,
    state: Arc<SharedState>,
) {
    let manager = state.s2s_manager.lock().unwrap().clone();
    let manager = match manager {
        Some(m) => m,
        None => {
            tracing::warn!("Incoming S2S connection but no S2S manager active");
            return;
        }
    };
    let peer_id = conn.remote_id().to_string();
    tracing::info!(peer = %peer_id, "S2S incoming connection (routed by ALPN)");
    let peers = Arc::clone(&manager.peers);
    let event_tx = manager.event_tx.clone();
    let server_id = manager.server_id.clone();
    handle_s2s_connection(conn, peers, event_tx, server_id, true).await;
}

/// Connect to a peer server by iroh endpoint ID.
pub async fn connect_peer(
    endpoint: &iroh::Endpoint,
    peer_id: &str,
    manager: &Arc<S2sManager>,
    event_tx: mpsc::Sender<S2sMessage>,
) -> Result<()> {
    let endpoint_id: iroh::EndpointId = peer_id.parse()
        .map_err(|e| anyhow::anyhow!("Invalid peer endpoint ID: {e}"))?;
    let addr = iroh::EndpointAddr::new(endpoint_id);

    tracing::info!(peer = %peer_id, "Connecting to S2S peer");
    let conn = endpoint.connect(addr, S2S_ALPN).await?;
    let _peer_id = conn.remote_id().to_string();

    let peers = Arc::clone(&manager.peers);
    let server_id = manager.server_id.clone();

    tokio::spawn(async move {
        handle_s2s_connection(conn, peers, event_tx, server_id, false).await;
    });

    Ok(())
}

/// Handle an S2S connection (both incoming and outgoing).
async fn handle_s2s_connection(
    conn: iroh::endpoint::Connection,
    peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<S2sMessage>>>>,
    event_tx: mpsc::Sender<S2sMessage>,
    _server_id: String,
    incoming: bool,
) {
    let peer_id = conn.remote_id().to_string();

    // For incoming: accept_bi, for outgoing: open_bi
    let (send, recv) = if incoming {
        match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %peer_id, "S2S accept_bi failed: {e}");
                return;
            }
        }
    } else {
        match conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %peer_id, "S2S open_bi failed: {e}");
                return;
            }
        }
    };

    // Write channel
    let (write_tx, mut write_rx) = mpsc::channel::<S2sMessage>(256);
    peers.lock().await.insert(peer_id.clone(), write_tx);

    tracing::info!(peer = %peer_id, "S2S link established");

    // Bridge QUIC recv → DuplexStream for BufReader line reading
    let (bridge_side, irc_side) = tokio::io::duplex(16384);
    let (_bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    let recv_peer = peer_id.clone();
    tokio::spawn(async move {
        let mut recv = recv;
        let mut buf = vec![0u8; 4096];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if bridge_write.write_all(&buf[..n]).await.is_err() { break; }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = bridge_write.shutdown().await;
        tracing::debug!(peer = %recv_peer, "S2S recv ended");
    });

    // Read JSON lines from the peer
    let read_peer = peer_id.clone();
    let read_event_tx = event_tx.clone();
    let read_handle = tokio::spawn(async move {
        let reader = BufReader::new(irc_side);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match serde_json::from_str::<S2sMessage>(&line) {
                Ok(msg) => {
                    if read_event_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %read_peer, "S2S invalid message: {e}");
                }
            }
        }
    });

    // Write JSON lines to the peer
    let write_handle = tokio::spawn(async move {
        let mut send = send;
        while let Some(msg) = write_rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    let line = format!("{json}\n");
                    if send.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                    // Flush immediately — QUIC streams buffer aggressively
                    if send.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!("S2S serialize error: {e}");
                }
            }
        }
        let _ = send.finish();
    });

    // Send sync request on new link
    if !incoming {
        let sync_req = S2sMessage::SyncRequest;
        if let Some(tx) = peers.lock().await.get(&peer_id) {
            let _ = tx.send(sync_req).await;
        }
    }

    // Wait for either direction to end
    tokio::select! {
        _ = read_handle => {}
        _ = write_handle => {}
    }

    peers.lock().await.remove(&peer_id);
    tracing::info!(peer = %peer_id, "S2S link closed");
}
