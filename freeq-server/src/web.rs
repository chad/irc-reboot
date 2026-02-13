//! WebSocket IRC transport and read-only REST API.
//!
//! The WebSocket endpoint (`/irc`) upgrades to a WebSocket connection, then
//! bridges it to the IRC connection handler via a `DuplexStream`. From the
//! server's perspective, a WebSocket client is just another async stream.
//!
//! The REST API exposes read-only data backed by the persistence layer.
//! No write endpoints — if you want to act on the server, speak IRC.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tower_http::cors::CorsLayer;

use crate::server::SharedState;

// ── WebSocket ↔ IRC bridge ─────────────────────────────────────────────

/// A WebSocket bridged as `AsyncRead + AsyncWrite` for the IRC handler.
///
/// Uses a `tokio::io::DuplexStream` pair with two background tasks:
/// - **rx task:** reads WebSocket frames → appends `\r\n` → writes to bridge
/// - **tx task:** reads from bridge → splits on `\r\n` → sends as WS text frames
pub struct WsBridge {
    pub reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    pub writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

/// Create a bridged stream from a WebSocket.
///
/// Spawns two async tasks that shuttle data between the WebSocket and a
/// DuplexStream. The returned `WsBridge` implements `AsyncRead + AsyncWrite`
/// and can be passed directly to `handle_generic()`.
fn bridge_ws(socket: WebSocket) -> WsBridge {
    // Split WebSocket into two halves via a channel so each task owns one.
    let (ws_tx, ws_rx) = tokio::sync::mpsc::channel::<WsMessage>(64);

    // DuplexStream: irc_side is what the IRC handler reads/writes.
    // bridge_side is what our background tasks read/write.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (irc_read, irc_write) = tokio::io::split(irc_side);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // We need the WebSocket as a single owner. Use an Arc<Mutex> for sends,
    // and move the socket into the rx task which also handles sends.
    // Actually simpler: move socket into one task, use channel for the other direction.

    // Task 1: owns the WebSocket, reads frames → bridge_write, reads ws_rx → sends frames
    tokio::spawn(async move {
        let mut socket = socket;
        let mut ws_rx = ws_rx;
        loop {
            tokio::select! {
                // Read from WebSocket → write to bridge (→ IRC handler reads)
                frame = socket.recv() => {
                    match frame {
                        Some(Ok(WsMessage::Text(text))) => {
                            let mut bytes = text.as_bytes().to_vec();
                            bytes.extend_from_slice(b"\r\n");
                            if bridge_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Binary(data))) => {
                            let mut bytes = data.to_vec();
                            if !bytes.ends_with(b"\r\n") {
                                bytes.extend_from_slice(b"\r\n");
                            }
                            if bridge_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Close(_))) | None => break,
                        Some(Ok(_)) => {} // Ping/Pong handled by axum
                        Some(Err(_)) => break,
                    }
                }
                // Read from channel → send as WebSocket frame
                msg = ws_rx.recv() => {
                    match msg {
                        Some(ws_msg) => {
                            if socket.send(ws_msg).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        let _ = bridge_write.shutdown().await;
        let _ = socket.send(WsMessage::Close(None)).await;
    });

    // Task 2: reads from bridge (← IRC handler writes) → sends as WS text frames via channel
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut line_buf = Vec::new();
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    line_buf.extend_from_slice(&buf[..n]);
                    // Send complete lines as text frames
                    while let Some(pos) = line_buf.windows(2).position(|w| w == b"\r\n") {
                        let line = String::from_utf8_lossy(&line_buf[..pos]).to_string();
                        line_buf.drain(..pos + 2);
                        if ws_tx.send(WsMessage::Text(line.into())).await.is_err() {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    WsBridge {
        reader: irc_read,
        writer: irc_write,
    }
}

impl AsyncRead for WsBridge {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsBridge {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

// ── Axum router ────────────────────────────────────────────────────────

/// Build the axum router with WebSocket and REST endpoints.
pub fn router(state: Arc<SharedState>) -> Router {
    let mut app = Router::new()
        // WebSocket IRC transport
        .route("/irc", get(ws_upgrade))
        // REST API (read-only, v1)
        .route("/api/v1/health", get(api_health))
        .route("/api/v1/channels", get(api_channels))
        .route("/api/v1/channels/{name}/history", get(api_channel_history))
        .route("/api/v1/channels/{name}/topic", get(api_channel_topic))
        .route("/api/v1/users/{nick}", get(api_user))
        .route("/api/v1/users/{nick}/whois", get(api_user_whois))
        .layer(CorsLayer::permissive());

    // Serve static web client files if the directory exists
    if let Some(ref web_dir) = state.config.web_static_dir {
        let dir = std::path::PathBuf::from(web_dir);
        if dir.exists() {
            tracing::info!("Serving web client from {}", dir.display());
            app = app.fallback_service(
                tower_http::services::ServeDir::new(dir)
                    .append_index_html_on_directories(true)
            );
        } else {
            tracing::warn!("Web static dir not found: {}", dir.display());
        }
    }

    app.with_state(state)
}

// ── WebSocket handler ──────────────────────────────────────────────────

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<SharedState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<SharedState>) {
    let stream = bridge_ws(socket);
    if let Err(e) = crate::connection::handle_generic(stream, state).await {
        tracing::error!("WebSocket connection error: {e}");
    }
}

// ── REST types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    server_name: String,
    connections: usize,
    channels: usize,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct ChannelInfo {
    name: String,
    members: usize,
    topic: Option<String>,
}

#[derive(Serialize)]
struct ChannelTopicResponse {
    channel: String,
    topic: Option<String>,
    set_by: Option<String>,
    set_at: Option<u64>,
}

#[derive(Serialize)]
struct MessageResponse {
    id: i64,
    sender: String,
    text: String,
    timestamp: u64,
    tags: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
    before: Option<u64>,
}

#[derive(Serialize)]
struct UserResponse {
    nick: String,
    online: bool,
    did: Option<String>,
    handle: Option<String>,
}

#[derive(Serialize)]
struct WhoisResponse {
    nick: String,
    online: bool,
    did: Option<String>,
    handle: Option<String>,
    channels: Vec<String>,
}

// ── REST handlers ──────────────────────────────────────────────────────

/// Server start time (set once on first call).
static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

async fn api_health(State(state): State<Arc<SharedState>>) -> Json<HealthResponse> {
    let start = START_TIME.get_or_init(SystemTime::now);
    let uptime = start.elapsed().unwrap_or_default().as_secs();
    let connections = state.connections.lock().unwrap().len();
    let channels = state.channels.lock().unwrap().len();
    Json(HealthResponse {
        server_name: state.server_name.clone(),
        connections,
        channels,
        uptime_secs: uptime,
    })
}

async fn api_channels(State(state): State<Arc<SharedState>>) -> Json<Vec<ChannelInfo>> {
    let channels = state.channels.lock().unwrap();
    let list: Vec<ChannelInfo> = channels
        .iter()
        .map(|(name, ch)| ChannelInfo {
            name: name.clone(),
            members: ch.members.len(),
            topic: ch.topic.as_ref().map(|t| t.text.clone()),
        })
        .collect();
    Json(list)
}

async fn api_channel_history(
    Path(name): Path<String>,
    Query(params): Query<HistoryQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<Vec<MessageResponse>>, StatusCode> {
    let channel = if name.starts_with('#') {
        name
    } else {
        format!("#{name}")
    };

    let limit = params.limit.unwrap_or(50).min(200);

    // Try database first for full history
    let messages = state.with_db(|db| db.get_messages(&channel, limit, params.before));

    match messages {
        Some(rows) => {
            let resp: Vec<MessageResponse> = rows
                .into_iter()
                .map(|r| MessageResponse {
                    id: r.id,
                    sender: r.sender,
                    text: r.text,
                    timestamp: r.timestamp,
                    tags: r.tags,
                })
                .collect();
            Ok(Json(resp))
        }
        None => {
            // No database — fall back to in-memory history
            let channels = state.channels.lock().unwrap();
            match channels.get(&channel) {
                Some(ch) => {
                    let resp: Vec<MessageResponse> = ch
                        .history
                        .iter()
                        .filter(|m| params.before.is_none_or(|b| m.timestamp < b))
                        .rev()
                        .take(limit)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .enumerate()
                        .map(|(i, m)| MessageResponse {
                            id: i as i64,
                            sender: m.from.clone(),
                            text: m.text.clone(),
                            timestamp: m.timestamp,
                            tags: m.tags.clone(),
                        })
                        .collect();
                    Ok(Json(resp))
                }
                None => Err(StatusCode::NOT_FOUND),
            }
        }
    }
}

async fn api_channel_topic(
    Path(name): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<ChannelTopicResponse>, StatusCode> {
    let channel = if name.starts_with('#') {
        name
    } else {
        format!("#{name}")
    };

    let channels = state.channels.lock().unwrap();
    match channels.get(&channel) {
        Some(ch) => Ok(Json(ChannelTopicResponse {
            channel,
            topic: ch.topic.as_ref().map(|t| t.text.clone()),
            set_by: ch.topic.as_ref().map(|t| t.set_by.clone()),
            set_at: ch.topic.as_ref().map(|t| t.set_at),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn api_user(
    Path(nick): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<UserResponse>, StatusCode> {
    let session = state.nick_to_session.lock().unwrap().get(&nick).cloned();
    let online = session.is_some();

    let (did, handle) = if let Some(ref session_id) = session {
        let did = state.session_dids.lock().unwrap().get(session_id).cloned();
        let handle = state
            .session_handles
            .lock()
            .unwrap()
            .get(session_id)
            .cloned();
        (did, handle)
    } else {
        let did = state
            .nick_owners
            .lock()
            .unwrap()
            .get(&nick.to_lowercase())
            .cloned();
        (did, None)
    };

    if !online && did.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(UserResponse {
        nick,
        online,
        did,
        handle,
    }))
}

async fn api_user_whois(
    Path(nick): Path<String>,
    State(state): State<Arc<SharedState>>,
) -> Result<Json<WhoisResponse>, StatusCode> {
    let session = state.nick_to_session.lock().unwrap().get(&nick).cloned();
    let online = session.is_some();

    let (did, handle) = if let Some(ref session_id) = session {
        let did = state.session_dids.lock().unwrap().get(session_id).cloned();
        let handle = state
            .session_handles
            .lock()
            .unwrap()
            .get(session_id)
            .cloned();
        (did, handle)
    } else {
        let did = state
            .nick_owners
            .lock()
            .unwrap()
            .get(&nick.to_lowercase())
            .cloned();
        (did, None)
    };

    if !online && did.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    let channels = if let Some(ref session_id) = session {
        let chans = state.channels.lock().unwrap();
        chans
            .iter()
            .filter(|(_, ch)| ch.members.contains(session_id))
            .map(|(name, _)| name.clone())
            .collect()
    } else {
        vec![]
    };

    Ok(Json(WhoisResponse {
        nick,
        online,
        did,
        handle,
        channels,
    }))
}
