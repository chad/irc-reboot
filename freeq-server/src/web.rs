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
use axum::response::{Html, IntoResponse, Json, Redirect};
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
        // OAuth endpoints for web client
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
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

// ── OAuth endpoints for web client ─────────────────────────────────────

#[derive(Deserialize)]
struct AuthLoginQuery {
    handle: String,
}

/// GET /auth/login?handle=user.bsky.social
///
/// Initiates the AT Protocol OAuth flow. Resolves the handle, does PAR,
/// and redirects the browser to the authorization server.
async fn auth_login(
    Query(q): Query<AuthLoginQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<Redirect, (StatusCode, String)> {
    let handle = q.handle.trim().to_string();

    // Resolve handle → DID → PDS
    let resolver = freeq_sdk::did::DidResolver::http();
    let did = resolver.resolve_handle(&handle).await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cannot resolve handle: {e}")))?;
    let did_doc = resolver.resolve(&did).await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cannot resolve DID: {e}")))?;
    let pds_url = freeq_sdk::pds::pds_endpoint(&did_doc)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "No PDS in DID document".to_string()))?;

    // Discover authorization server
    let client = reqwest::Client::new();
    let pr_url = format!("{}/.well-known/oauth-protected-resource", pds_url.trim_end_matches('/'));
    let pr_meta: serde_json::Value = client.get(&pr_url).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PDS metadata fetch failed: {e}")))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PDS metadata parse failed: {e}")))?;

    let auth_server = pr_meta["authorization_servers"][0].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No authorization server".to_string()))?;

    let as_url = format!("{}/.well-known/oauth-authorization-server", auth_server.trim_end_matches('/'));
    let auth_meta: serde_json::Value = client.get(&as_url).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Auth server metadata failed: {e}")))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Auth server metadata parse failed: {e}")))?;

    let authorization_endpoint = auth_meta["authorization_endpoint"].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No authorization_endpoint".to_string()))?;
    let token_endpoint = auth_meta["token_endpoint"].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No token_endpoint".to_string()))?;
    let par_endpoint = auth_meta["pushed_authorization_request_endpoint"].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No PAR endpoint".to_string()))?;

    // Build redirect URI and client_id
    // We use the server's own web address as the callback
    let web_origin = format!("http://{}", state.config.web_addr.as_deref().unwrap_or("localhost:8080"));
    let redirect_uri = format!("{web_origin}/auth/callback");
    let scope = "atproto transition:generic";
    let client_id = format!(
        "http://localhost?redirect_uri={}&scope={}",
        urlencod(&redirect_uri), urlencod(scope),
    );

    // Generate PKCE + DPoP key + state
    let dpop_key = freeq_sdk::oauth::DpopKey::generate();
    let (code_verifier, code_challenge) = generate_pkce();
    let oauth_state = generate_random_string(16);

    // PAR request
    let params = [
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", &redirect_uri),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("scope", scope),
        ("state", &oauth_state),
        ("login_hint", &handle),
    ];

    // Try without nonce first
    let dpop_proof = dpop_key.proof("POST", par_endpoint, None, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP proof failed: {e}")))?;
    let resp = client.post(par_endpoint).header("DPoP", &dpop_proof).form(&params).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR failed: {e}")))?;

    let status = resp.status();
    let dpop_nonce = resp.headers().get("dpop-nonce")
        .and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let par_resp: serde_json::Value = if status.as_u16() == 400 && dpop_nonce.is_some() {
        // Retry with nonce
        let nonce = dpop_nonce.as_deref().unwrap();
        let dpop_proof2 = dpop_key.proof("POST", par_endpoint, Some(nonce), None)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP retry failed: {e}")))?;
        let resp2 = client.post(par_endpoint).header("DPoP", &dpop_proof2).form(&params).send().await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR retry failed: {e}")))?;
        if !resp2.status().is_success() {
            let text = resp2.text().await.unwrap_or_default();
            return Err((StatusCode::BAD_GATEWAY, format!("PAR failed: {text}")));
        }
        resp2.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR parse failed: {e}")))?
    } else if status.is_success() {
        resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("PAR parse failed: {e}")))?
    } else {
        let text = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("PAR failed ({status}): {text}")));
    };

    let request_uri = par_resp["request_uri"].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No request_uri in PAR response".to_string()))?;

    // Store pending session
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    state.oauth_pending.lock().unwrap().insert(oauth_state.clone(), crate::server::OAuthPending {
        handle: handle.clone(),
        did: did.clone(),
        pds_url: pds_url.clone(),
        code_verifier,
        redirect_uri: redirect_uri.clone(),
        client_id: client_id.clone(),
        token_endpoint: token_endpoint.to_string(),
        dpop_key_b64: dpop_key.to_base64url(),
        created_at: now,
    });

    // Redirect to authorization server
    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_endpoint, urlencod(&client_id), urlencod(request_uri),
    );

    tracing::info!(handle = %handle, did = %did, "OAuth login started, redirecting to auth server");
    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
struct AuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// GET /auth/callback?code=...&state=...
///
/// OAuth callback from the authorization server. Exchanges the code for
/// tokens and returns an HTML page that posts the result to the parent window.
async fn auth_callback(
    Query(q): Query<AuthCallbackQuery>,
    State(state): State<Arc<SharedState>>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Check for error
    if let Some(error) = &q.error {
        let desc = q.error_description.as_deref().unwrap_or("Unknown error");
        return Ok(Html(oauth_result_page(&format!("Error: {error}: {desc}"), None)));
    }

    let code = q.code.as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing code".to_string()))?;
    let oauth_state = q.state.as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing state".to_string()))?;

    // Look up pending session
    let pending = state.oauth_pending.lock().unwrap().remove(oauth_state)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Unknown or expired OAuth state".to_string()))?;

    // Check expiry (5 minutes)
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    if now - pending.created_at > 300 {
        return Err((StatusCode::BAD_REQUEST, "OAuth session expired".to_string()));
    }

    // Exchange code for token
    let dpop_key = freeq_sdk::oauth::DpopKey::from_base64url(&pending.dpop_key_b64)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP key error: {e}")))?;

    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", pending.redirect_uri.as_str()),
        ("client_id", pending.client_id.as_str()),
        ("code_verifier", pending.code_verifier.as_str()),
    ];

    // Try without nonce
    let dpop_proof = dpop_key.proof("POST", &pending.token_endpoint, None, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP proof failed: {e}")))?;
    let resp = client.post(&pending.token_endpoint).header("DPoP", &dpop_proof).form(&params).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token exchange failed: {e}")))?;

    let status = resp.status();
    let dpop_nonce = resp.headers().get("dpop-nonce")
        .and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let token_resp: serde_json::Value = if (status.as_u16() == 400 || status.as_u16() == 401) && dpop_nonce.is_some() {
        let nonce = dpop_nonce.as_deref().unwrap();
        let dpop_proof2 = dpop_key.proof("POST", &pending.token_endpoint, Some(nonce), None)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DPoP retry failed: {e}")))?;
        let resp2 = client.post(&pending.token_endpoint).header("DPoP", &dpop_proof2).form(&params).send().await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token retry failed: {e}")))?;
        if !resp2.status().is_success() {
            let text = resp2.text().await.unwrap_or_default();
            return Ok(Html(oauth_result_page(&format!("Token exchange failed: {text}"), None)));
        }
        resp2.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {e}")))?
    } else if status.is_success() {
        resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, format!("Token parse failed: {e}")))?
    } else {
        let text = resp.text().await.unwrap_or_default();
        return Ok(Html(oauth_result_page(&format!("Token exchange failed ({status}): {text}"), None)));
    };

    let access_token = token_resp["access_token"].as_str()
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "No access_token".to_string()))?;

    let result = crate::server::OAuthResult {
        did: pending.did.clone(),
        handle: pending.handle.clone(),
        access_jwt: access_token.to_string(),
        pds_url: pending.pds_url.clone(),
    };

    tracing::info!(did = %pending.did, handle = %pending.handle, "OAuth callback: token obtained");

    // Return HTML page that posts result to parent window
    Ok(Html(oauth_result_page("Authentication successful!", Some(&result))))
}

/// Generate the HTML page returned by the OAuth callback.
/// If result is Some, it posts the credentials to the parent window via postMessage.
fn oauth_result_page(message: &str, result: Option<&crate::server::OAuthResult>) -> String {
    let script = if let Some(r) = result {
        let json = serde_json::to_string(r).unwrap_or_default();
        format!(
            r#"<script>
            if (window.opener) {{
                window.opener.postMessage({{ type: 'freeq-oauth', result: {json} }}, '*');
                setTimeout(() => window.close(), 2000);
            }}
            </script>"#
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>freeq auth</title>
<style>
body {{ font-family: system-ui; background: #1e1e2e; color: #cdd6f4; display: flex; align-items: center; justify-content: center; height: 100vh; }}
.box {{ text-align: center; }}
h1 {{ color: #89b4fa; font-size: 20px; }}
p {{ color: #a6adc8; }}
</style></head>
<body><div class="box"><h1>freeq</h1><p>{message}</p><p style="color:#6c7086">You can close this window.</p></div>
{script}
</body></html>"#
    )
}

fn generate_pkce() -> (String, String) {
    use base64::Engine;
    use sha2::{Sha256, Digest};
    let verifier = generate_random_string(32);
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn generate_random_string(len: usize) -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

fn urlencod(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}
