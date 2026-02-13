//! Peer-to-peer encrypted direct messaging via iroh.
//!
//! Each client can create a local iroh endpoint for receiving direct
//! connections from other peers. Messages sent via P2P bypass the IRC
//! server entirely — they go client-to-client over encrypted QUIC.
//!
//! # Architecture
//!
//! ```text
//! Client A (iroh endpoint)  ←─ encrypted QUIC ─→  Client B (iroh endpoint)
//! ```
//!
//! The IRC server is used only for endpoint discovery (via WHOIS or
//! CTCP queries). Actual message content never touches the server.
//!
//! # Wire Format
//!
//! Messages on the P2P stream are newline-delimited JSON:
//! ```json
//! {"type":"msg","text":"hello"}
//! {"type":"action","text":"waves"}
//! ```
//!
//! This is intentionally simple. It's not IRC — it's a private channel
//! between two endpoints.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// ALPN for peer-to-peer IRC DMs.
pub const P2P_ALPN: &[u8] = b"freeq/p2p-dm/1";

/// Events from the P2P subsystem.
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// Our endpoint is ready. Share this ID with peers.
    EndpointReady { endpoint_id: String },

    /// A peer connected to us.
    PeerConnected { peer_id: String },

    /// A peer disconnected.
    PeerDisconnected { peer_id: String },

    /// Received a direct message from a peer.
    DirectMessage { peer_id: String, text: String },

    /// Error from the P2P subsystem.
    Error { message: String },
}

/// Commands to the P2P subsystem.
#[derive(Debug)]
pub enum P2pCommand {
    /// Send a direct message to a peer.
    SendMessage { peer_id: String, text: String },

    /// Connect to a peer by endpoint ID.
    ConnectPeer { endpoint_id: String },

    /// Shutdown the P2P subsystem.
    Shutdown,
}

/// Handle for sending commands to the P2P subsystem.
#[derive(Clone)]
pub struct P2pHandle {
    cmd_tx: mpsc::Sender<P2pCommand>,
    /// Our endpoint ID (available after startup).
    pub endpoint_id: String,
}

impl P2pHandle {
    /// Send a direct message to a peer.
    pub async fn send_message(&self, peer_id: &str, text: &str) -> Result<()> {
        self.cmd_tx
            .send(P2pCommand::SendMessage {
                peer_id: peer_id.to_string(),
                text: text.to_string(),
            })
            .await
            .map_err(|_| anyhow::anyhow!("P2P subsystem closed"))
    }

    /// Connect to a peer by endpoint ID.
    pub async fn connect_peer(&self, endpoint_id: &str) -> Result<()> {
        self.cmd_tx
            .send(P2pCommand::ConnectPeer {
                endpoint_id: endpoint_id.to_string(),
            })
            .await
            .map_err(|_| anyhow::anyhow!("P2P subsystem closed"))
    }
}

/// Simple JSON message for P2P wire format.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct P2pMessage {
    #[serde(rename = "type")]
    msg_type: String,
    text: String,
}

/// Start the P2P subsystem.
///
/// Creates an iroh endpoint, listens for incoming peer connections,
/// and processes commands for outgoing connections/messages.
///
/// Returns a handle for sending commands and a receiver for events.
pub async fn start() -> Result<(P2pHandle, mpsc::Receiver<P2pEvent>)> {
    let (event_tx, event_rx) = mpsc::channel(256);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(64);

    let endpoint = iroh::Endpoint::builder()
        .alpns(vec![P2P_ALPN.to_vec()])
        .bind()
        .await?;

    // Wait for the endpoint to be online
    endpoint.online().await;
    let endpoint_id = endpoint.id().to_string();

    let _ = event_tx
        .send(P2pEvent::EndpointReady {
            endpoint_id: endpoint_id.clone(),
        })
        .await;

    let handle = P2pHandle {
        cmd_tx,
        endpoint_id: endpoint_id.clone(),
    };

    // Active peer connections: peer_id → sender for writing messages
    let peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<String>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Spawn accept loop for incoming connections
    let accept_ep = endpoint.clone();
    let accept_peers = Arc::clone(&peers);
    let accept_event_tx = event_tx.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let peers = Arc::clone(&accept_peers);
            let event_tx = accept_event_tx.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        handle_peer_connection(conn, peers, event_tx).await;
                    }
                    Err(e) => {
                        let _ = event_tx
                            .send(P2pEvent::Error {
                                message: format!("Incoming P2P connection failed: {e}"),
                            })
                            .await;
                    }
                }
            });
        }
    });

    // Spawn command processing loop
    let cmd_ep = endpoint.clone();
    let cmd_peers = Arc::clone(&peers);
    let cmd_event_tx = event_tx.clone();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                P2pCommand::SendMessage { peer_id, text } => {
                    let peers = cmd_peers.lock().await;
                    if let Some(tx) = peers.get(&peer_id) {
                        let msg = P2pMessage {
                            msg_type: "msg".to_string(),
                            text,
                        };
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = tx.send(json).await;
                        }
                    } else {
                        let _ = cmd_event_tx
                            .send(P2pEvent::Error {
                                message: format!("Not connected to peer {peer_id}"),
                            })
                            .await;
                    }
                }
                P2pCommand::ConnectPeer { endpoint_id } => {
                    let peer_id: iroh::EndpointId = match endpoint_id.parse() {
                        Ok(id) => id,
                        Err(e) => {
                            let _ = cmd_event_tx
                                .send(P2pEvent::Error {
                                    message: format!("Invalid peer ID: {e}"),
                                })
                                .await;
                            continue;
                        }
                    };
                    let addr = iroh::EndpointAddr::new(peer_id);
                    match cmd_ep.connect(addr, P2P_ALPN).await {
                        Ok(conn) => {
                            let peers = Arc::clone(&cmd_peers);
                            let event_tx = cmd_event_tx.clone();
                            tokio::spawn(async move {
                                handle_peer_connection_outgoing(conn, peers, event_tx).await;
                            });
                        }
                        Err(e) => {
                            let _ = cmd_event_tx
                                .send(P2pEvent::Error {
                                    message: format!("Failed to connect to peer: {e}"),
                                })
                                .await;
                        }
                    }
                }
                P2pCommand::Shutdown => break,
            }
        }
        // Clean shutdown
        endpoint.close().await;
    });

    Ok((handle, event_rx))
}

/// Handle an incoming peer connection (they opened a stream to us).
async fn handle_peer_connection(
    conn: iroh::endpoint::Connection,
    peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<String>>>>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let peer_id = conn.remote_id().to_string();

    let (send, recv) = match conn.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            let _ = event_tx
                .send(P2pEvent::Error {
                    message: format!("Failed to accept bi stream from {peer_id}: {e}"),
                })
                .await;
            return;
        }
    };

    run_peer_session(peer_id, send, recv, peers, event_tx).await;
}

/// Handle an outgoing peer connection (we opened a stream to them).
async fn handle_peer_connection_outgoing(
    conn: iroh::endpoint::Connection,
    peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<String>>>>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let peer_id = conn.remote_id().to_string();

    let (send, recv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            let _ = event_tx
                .send(P2pEvent::Error {
                    message: format!("Failed to open bi stream to {peer_id}: {e}"),
                })
                .await;
            return;
        }
    };

    run_peer_session(peer_id, send, recv, peers, event_tx).await;
}

/// Run a bidirectional message session with a peer.
async fn run_peer_session(
    peer_id: String,
    mut send: iroh_quinn::SendStream,
    recv: iroh_quinn::RecvStream,
    peers: Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<String>>>>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let _ = event_tx
        .send(P2pEvent::PeerConnected {
            peer_id: peer_id.clone(),
        })
        .await;

    // Channel for sending messages to this peer
    let (write_tx, mut write_rx) = mpsc::channel::<String>(64);

    // Register peer
    peers.lock().await.insert(peer_id.clone(), write_tx);

    // Bridge: read from QUIC recv stream → parse JSON → emit events
    let read_peer_id = peer_id.clone();
    let read_event_tx = event_tx.clone();

    // Use a DuplexStream bridge since Quinn RecvStream doesn't impl tokio AsyncRead directly
    let (bridge_side, irc_side) = tokio::io::duplex(8192);
    let (_bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // QUIC recv → bridge
    let quic_peer_id = peer_id.clone();
    tokio::spawn(async move {
        let mut recv = recv;
        let mut buf = vec![0u8; 4096];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if bridge_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = bridge_write.shutdown().await;
        tracing::debug!(peer = %quic_peer_id, "P2P QUIC recv ended");
    });

    // Read JSON lines from bridge
    let read_handle = tokio::spawn(async move {
        let reader = BufReader::new(irc_side);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(msg) = serde_json::from_str::<P2pMessage>(&line) {
                let _ = read_event_tx
                    .send(P2pEvent::DirectMessage {
                        peer_id: read_peer_id.clone(),
                        text: msg.text,
                    })
                    .await;
            }
        }
    });

    // Write loop: receive from channel → write JSON lines to QUIC send stream
    let write_handle = tokio::spawn(async move {
        while let Some(json) = write_rx.recv().await {
            let line = format!("{json}\n");
            if send.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    // Wait for either side to finish
    tokio::select! {
        _ = read_handle => {}
        _ = write_handle => {}
    }

    // Cleanup
    peers.lock().await.remove(&peer_id);
    let _ = event_tx
        .send(P2pEvent::PeerDisconnected {
            peer_id: peer_id.clone(),
        })
        .await;
}
