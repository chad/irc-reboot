//! Iroh transport for the IRC server.
//!
//! Accepts IRC connections over iroh's QUIC-based encrypted transport.
//! Each iroh connection opens a single bidirectional stream that carries
//! IRC lines, exactly like a TCP connection. The server treats it as
//! just another `AsyncRead + AsyncWrite` stream via `handle_generic()`.
//!
//! This gives us:
//! - Encrypted transport by default (no separate TLS setup)
//! - NAT hole-punching + relay fallback
//! - Public-key identity per endpoint
//! - Path toward P2P and mesh topologies

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::server::SharedState;

/// ALPN protocol identifier for IRC-over-iroh.
pub const ALPN: &[u8] = b"freeq/iroh/1";

/// Handle an accepted iroh connection.
///
/// Waits for the client to open a bidirectional stream, bridges it via
/// a DuplexStream (same pattern as WebSocket), and passes it to the
/// generic IRC connection handler.
pub async fn handle_connection(conn: Connection, state: Arc<SharedState>) {
    let remote_id = conn.remote_id();
    tracing::info!(%remote_id, "Iroh connection accepted");

    let (send, recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::warn!(%remote_id, "Failed to accept bi stream: {e}");
            return;
        }
    };

    // Bridge QUIC streams to a DuplexStream that handle_generic() can use.
    // Same pattern as the WebSocket bridge in web.rs.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (irc_read, irc_write) = tokio::io::split(irc_side);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // Task: QUIC recv → bridge_write → IRC handler reads
    let rx_remote = remote_id;
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
                Ok(None) => break, // Stream finished
                Err(e) => {
                    tracing::debug!(remote = %rx_remote, "QUIC recv error: {e}");
                    break;
                }
            }
        }
        let _ = bridge_write.shutdown().await;
    });

    // Task: IRC handler writes → bridge_read → QUIC send
    let tx_remote = remote_id;
    tokio::spawn(async move {
        let mut send = send;
        let mut buf = vec![0u8; 4096];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(remote = %tx_remote, "Bridge read error: {e}");
                    break;
                }
            }
        }
        let _ = send.finish();
    });

    // Now the IRC handler sees a normal AsyncRead + AsyncWrite stream,
    // with the iroh endpoint ID passed through for identity binding.
    let stream = crate::web::WsBridge { reader: irc_read, writer: irc_write };
    let iroh_id = remote_id.to_string();
    if let Err(e) = crate::connection::handle_generic_with_meta(stream, state, Some(iroh_id)).await {
        tracing::error!(%remote_id, "Iroh connection error: {e}");
    }
}

/// Load or generate a persistent secret key for stable endpoint identity.
fn load_or_create_secret_key(path: &std::path::Path) -> Result<iroh::SecretKey> {
    if path.exists() {
        let hex = std::fs::read_to_string(path)?;
        let key: iroh::SecretKey = hex.trim().parse()
            .map_err(|e| anyhow::anyhow!("Invalid iroh secret key in {}: {e}", path.display()))?;
        Ok(key)
    } else {
        // Generate a random 32-byte secret key
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let key = iroh::SecretKey::from_bytes(&bytes);
        // Serialize as hex bytes
        let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(path, &hex)?;
        tracing::info!("Generated new iroh secret key at {}", path.display());
        Ok(key)
    }
}

/// Start the iroh endpoint and accept connections.
///
/// Returns the endpoint (for getting the address/node ID to share with clients).
pub async fn start(
    state: Arc<SharedState>,
    bind_port: Option<u16>,
) -> Result<iroh::Endpoint> {
    // Use a persistent secret key so the endpoint ID is stable across restarts
    let key_path = std::path::PathBuf::from("iroh-key.secret");
    let secret_key = load_or_create_secret_key(&key_path)?;

    let mut builder = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec(), crate::s2s::S2S_ALPN.to_vec()]);

    if let Some(port) = bind_port {
        builder = builder
            .bind_addr(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                port,
            ))?;
    }

    let endpoint = builder.bind().await?;

    tracing::info!("Iroh endpoint ID: {}", endpoint.id());

    // Spawn accept loop
    let ep = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        // Route by ALPN: client connections vs S2S links
                        let alpn = conn.alpn();
                        if alpn == crate::s2s::S2S_ALPN {
                            tracing::info!("Incoming S2S connection from {}", conn.remote_id());
                            crate::s2s::handle_incoming_s2s(conn, state).await;
                        } else {
                            handle_connection(conn, state).await;
                        }
                    }
                    Err(e) => tracing::warn!("Iroh incoming connection failed: {e}"),
                }
            });
        }
        tracing::info!("Iroh accept loop ended");
    });

    Ok(endpoint)
}
