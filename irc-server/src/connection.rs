#![allow(clippy::too_many_arguments)]
//! Per-client connection handler.
//!
//! Each TCP connection gets a Connection that manages:
//! - IRC registration (NICK/USER)
//! - CAP capability negotiation
//! - SASL authentication flow
//! - Message routing post-registration
//! - WHOIS with DID information

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::irc::{self, Message};
use crate::sasl;
use crate::server::SharedState;

/// State of a single client connection.
pub struct Connection {
    pub id: String,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub authenticated_did: Option<String>,
    pub registered: bool,

    /// Iroh endpoint ID of the remote peer (if connected via iroh).
    /// This is a cryptographic public key, giving us verified identity.
    pub iroh_endpoint_id: Option<String>,

    // CAP negotiation state
    cap_negotiating: bool,
    cap_sasl_requested: bool,
    cap_message_tags: bool,
    /// Client understands E2EE messages (won't get synthetic notices instead).
    cap_e2ee: bool,

    // SASL state
    sasl_in_progress: bool,
}

impl Connection {
    fn new(id: String) -> Self {
        Self {
            id,
            nick: None,
            user: None,
            realname: None,
            authenticated_did: None,
            registered: false,
            iroh_endpoint_id: None,
            cap_negotiating: false,
            cap_sasl_requested: false,
            cap_message_tags: false,
            cap_e2ee: false,
            sasl_in_progress: false,
        }
    }

    fn nick_or_star(&self) -> &str {
        self.nick.as_deref().unwrap_or("*")
    }

    fn hostmask(&self) -> String {
        let nick = self.nick.as_deref().unwrap_or("*");
        let user = self.user.as_deref().unwrap_or("~u");
        format!("{nick}!{user}@host")
    }
}

/// Handle a plain TCP connection.
pub async fn handle(stream: TcpStream, state: Arc<SharedState>) -> Result<()> {
    let peer = stream.peer_addr()?;
    let session_id = format!("{peer}");
    tracing::info!(%session_id, "New connection (plain)");
    let (reader, writer) = tokio::io::split(stream);
    handle_io(BufReader::new(reader), writer, session_id, state).await
}

/// Handle a generic async stream (for TLS, WebSocket, or other wrappers).
pub async fn handle_generic<S>(stream: S, state: Arc<SharedState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_generic_with_meta(stream, state, None).await
}

/// Handle a generic async stream with optional connection metadata.
///
/// `iroh_endpoint_id` is set when the connection comes via iroh transport,
/// providing cryptographic identity for the remote peer.
pub async fn handle_generic_with_meta<S>(
    stream: S,
    state: Arc<SharedState>,
    iroh_endpoint_id: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session_id = format!("stream-{id}");
    tracing::info!(%session_id, iroh_id = ?iroh_endpoint_id, "New connection (generic stream)");
    let (reader, writer) = tokio::io::split(stream);
    handle_io_with_meta(BufReader::new(reader), writer, session_id, state, iroh_endpoint_id).await
}

async fn handle_io<R, W>(
    reader: BufReader<R>,
    writer: W,
    session_id: String,
    state: Arc<SharedState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_io_with_meta(reader, writer, session_id, state, None).await
}

async fn handle_io_with_meta<R, W>(
    mut reader: BufReader<R>,
    writer: W,
    session_id: String,
    state: Arc<SharedState>,
    iroh_endpoint_id: Option<String>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = Connection::new(session_id.clone());
    conn.iroh_endpoint_id = iroh_endpoint_id;

    // Channel for sending messages TO this client
    let (tx, mut rx) = mpsc::channel::<String>(64);
    state
        .connections
        .lock()
        .unwrap()
        .insert(session_id.clone(), tx);

    let server_name = state.server_name.clone();

    // Spawn writer task
    let write_session_id = session_id.clone();
    let mut write_half = writer;
    let write_handle = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if let Err(e) = write_half.write_all(line.as_bytes()).await {
                tracing::warn!(session_id = %write_session_id, "Write error: {e}");
                break;
            }
        }
    });

    let send = |state: &Arc<SharedState>, session_id: &str, msg: String| {
        if let Some(tx) = state.connections.lock().unwrap().get(session_id) {
            let _ = tx.try_send(msg);
        }
    };

    let mut line_buf = String::new();
    let mut last_activity = tokio::time::Instant::now();
    let ping_interval = tokio::time::Duration::from_secs(90);
    let ping_timeout = tokio::time::Duration::from_secs(180);
    let mut awaiting_pong = false;

    // Rate limiting: max 10 commands per second, token bucket
    let mut rate_tokens: f64 = 10.0;
    let mut rate_last = tokio::time::Instant::now();
    let rate_max: f64 = 10.0;
    let rate_refill: f64 = 10.0; // tokens per second

    loop {
        line_buf.clear();
        let read_result = tokio::time::timeout(
            ping_interval,
            reader.read_line(&mut line_buf),
        ).await;

        match read_result {
            Ok(Ok(0)) | Ok(Err(_)) => break, // EOF or error
            Err(_) => {
                // Timeout — no data received, send PING or check PONG
                if awaiting_pong {
                    if last_activity.elapsed() > ping_timeout {
                        tracing::info!(%session_id, "Ping timeout");
                        break;
                    }
                } else {
                    let ping = Message::from_server(&server_name, "PING", vec![&server_name]);
                    send(&state, &session_id, format!("{ping}\r\n"));
                    awaiting_pong = true;
                }
                continue;
            }
            Ok(Ok(_)) => {}
        }

        last_activity = tokio::time::Instant::now();

        let Some(msg) = Message::parse(&line_buf) else {
            continue;
        };

        // Rate limiting (skip during registration — clients burst on connect)
        if conn.registered {
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(rate_last).as_secs_f64();
            rate_tokens = (rate_tokens + elapsed * rate_refill).min(rate_max);
            rate_last = now;
            if rate_tokens < 1.0 {
                tracing::debug!(%session_id, "Rate limited");
                continue;
            }
            rate_tokens -= 1.0;
        }

        tracing::debug!(%session_id, "<- {}", line_buf.trim());

        match msg.command.as_str() {
            "CAP" => {
                handle_cap(&mut conn, &msg, &state, &server_name, &session_id, &send);
            }
            "AUTHENTICATE" => {
                handle_authenticate(
                    &mut conn,
                    &msg,
                    &state,
                    &server_name,
                    &session_id,
                    &send,
                )
                .await;
            }
            "NICK" => {
                if let Some(nick) = msg.params.first() {
                    let nick_lower = nick.to_lowercase();
                    let in_use = state.nick_to_session.lock().unwrap().contains_key(nick);

                    // Check if nick is owned by another DID.
                    // During CAP negotiation (pre-auth), allow provisionally —
                    // the user might be about to authenticate as the owner.
                    // Enforce ownership only for post-registration nick changes
                    // or when not doing SASL.
                    let owner_did = state.nick_owners.lock().unwrap().get(&nick_lower).cloned();
                    let my_did = conn.authenticated_did.as_deref();
                    let nick_stolen = if conn.cap_negotiating || conn.sasl_in_progress {
                        // Allow provisionally during auth — will be verified at registration
                        false
                    } else {
                        owner_did.as_ref().is_some_and(|owner| {
                            my_did.is_none_or(|my| my != owner)
                        })
                    };

                    if in_use {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NICKNAMEINUSE,
                            vec![conn.nick_or_star(), nick, "Nickname is already in use"],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    } else if nick_stolen {
                        let reply = Message::from_server(
                            &server_name,
                            irc::ERR_NICKNAMEINUSE,
                            vec![conn.nick_or_star(), nick, "Nickname is registered to another identity"],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    } else {
                        if let Some(ref old) = conn.nick {
                            state.nick_to_session.lock().unwrap().remove(old);
                        }
                        state
                            .nick_to_session
                            .lock()
                            .unwrap()
                            .insert(nick.clone(), session_id.clone());
                        conn.nick = Some(nick.clone());
                        try_complete_registration(
                            &mut conn,
                            &state,
                            &server_name,
                            &session_id,
                            &send,
                        );
                    }
                }
            }
            "USER" => {
                if msg.params.len() >= 4 {
                    conn.user = Some(msg.params[0].clone());
                    conn.realname = Some(msg.params[3].clone());
                    try_complete_registration(
                        &mut conn,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "PING" => {
                let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let reply =
                    Message::from_server(&server_name, "PONG", vec![&server_name, token]);
                send(&state, &session_id, format!("{reply}\r\n"));
            }
            "PONG" => {
                awaiting_pong = false;
            }
            "JOIN" => {
                if !conn.registered {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_NOTREGISTERED,
                        vec![conn.nick_or_star(), "You have not registered"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                    continue;
                }
                if let Some(channels) = msg.params.first() {
                    let keys: Vec<&str> = msg.params.get(1)
                        .map(|k| k.split(',').collect())
                        .unwrap_or_default();
                    for (i, channel) in channels.split(',').enumerate() {
                        let key = keys.get(i).copied();
                        handle_join(
                            &conn,
                            channel,
                            key,
                            &state,
                            &server_name,
                            &session_id,
                            &send,
                        );
                    }
                }
            }
            "PART" => {
                if !conn.registered {
                    continue;
                }
                if let Some(channels) = msg.params.first() {
                    for channel in channels.split(',') {
                        handle_part(
                            &conn,
                            channel,
                            &state,
                            &session_id,
                        );
                    }
                }
            }
            "MODE" => {
                if !conn.registered {
                    continue;
                }
                if let Some(target) = msg.params.first() {
                    if target.starts_with('#') || target.starts_with('&') {
                        let mode_str = msg.params.get(1).map(|s| s.as_str());
                        let mode_arg = msg.params.get(2).map(|s| s.as_str());
                        handle_mode(
                            &conn,
                            target,
                            mode_str,
                            mode_arg,
                            &state,
                            &server_name,
                            &session_id,
                            &send,
                        );
                    } else {
                        // User mode query — just reply with empty modes
                        let reply = Message::from_server(
                            &server_name,
                            "221",
                            vec![conn.nick_or_star(), "+"],
                        );
                        send(&state, &session_id, format!("{reply}\r\n"));
                    }
                }
            }
            "INVITE" => {
                if !conn.registered {
                    continue;
                }
                if msg.params.len() >= 2 {
                    let target_nick = &msg.params[0];
                    let channel = &msg.params[1];
                    handle_invite(
                        &conn,
                        target_nick,
                        channel,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "KICK" => {
                if !conn.registered {
                    continue;
                }
                if msg.params.len() >= 2 {
                    let channel = &msg.params[0];
                    let target_nick = &msg.params[1];
                    let reason = msg.params.get(2).map(|s| s.as_str()).unwrap_or(conn.nick_or_star());
                    handle_kick(
                        &conn,
                        channel,
                        target_nick,
                        reason,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "TOPIC" => {
                if !conn.registered {
                    continue;
                }
                if let Some(channel) = msg.params.first() {
                    let new_topic = msg.params.get(1).map(|s| s.as_str());
                    handle_topic(
                        &conn,
                        channel,
                        new_topic,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "WHOIS" => {
                if !conn.registered {
                    continue;
                }
                if let Some(target_nick) = msg.params.first() {
                    handle_whois(
                        &conn,
                        target_nick,
                        &state,
                        &server_name,
                        &session_id,
                        &send,
                    );
                }
            }
            "PRIVMSG" | "NOTICE" => {
                if !conn.registered {
                    continue;
                }
                if let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) {
                    handle_privmsg(&conn, &msg.command, target, text, &msg.tags, &state);
                }
            }
            "TAGMSG" => {
                // IRCv3 TAGMSG: relay tags with no body, only to message-tags capable clients
                if !conn.registered {
                    continue;
                }
                if let Some(target) = msg.params.first() {
                    handle_tagmsg(&conn, target, &msg.tags, &state);
                }
            }
            "QUIT" => {
                break;
            }
            _ => {
                if conn.registered {
                    let reply = Message::from_server(
                        &server_name,
                        irc::ERR_UNKNOWNCOMMAND,
                        vec![conn.nick_or_star(), &msg.command, "Unknown command"],
                    );
                    send(&state, &session_id, format!("{reply}\r\n"));
                }
            }
        }
    }

    // Cleanup — broadcast QUIT to all channels user was in
    if let Some(ref nick) = conn.nick {
        let hostmask = conn.hostmask();
        let quit_msg = format!(":{hostmask} QUIT :Connection closed\r\n");
        let channels = state.channels.lock().unwrap();
        let conns = state.connections.lock().unwrap();
        for ch in channels.values() {
            if ch.members.contains(&session_id) {
                for member in &ch.members {
                    if member != &session_id
                        && let Some(tx) = conns.get(member) {
                            let _ = tx.try_send(quit_msg.clone());
                        }
                }
            }
        }
        drop(conns);
        drop(channels);
        state.nick_to_session.lock().unwrap().remove(nick);
    }

    tracing::info!(%session_id, "Connection closed");
    state.connections.lock().unwrap().remove(&session_id);
    state.session_dids.lock().unwrap().remove(&session_id);
    state.session_handles.lock().unwrap().remove(&session_id);
    state.session_iroh_ids.lock().unwrap().remove(&session_id);
    state.cap_message_tags.lock().unwrap().remove(&session_id);
    {
        let mut channels = state.channels.lock().unwrap();
        for ch in channels.values_mut() {
            ch.members.remove(&session_id);
            ch.ops.remove(&session_id);
            ch.voiced.remove(&session_id);
        }
        channels.retain(|_, ch| !ch.members.is_empty());
    }

    write_handle.abort();
    Ok(())
}

fn handle_cap(
    conn: &mut Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let subcmd = msg.params.first().map(|s| s.to_ascii_uppercase());
    match subcmd.as_deref() {
        Some("LS") => {
            conn.cap_negotiating = true;
            // Build capability list, including iroh endpoint ID if available
            let mut caps = String::from("sasl message-tags");
            if let Some(ref iroh_id) = *state.server_iroh_id.lock().unwrap() {
                caps.push_str(&format!(" iroh={iroh_id}"));
            }
            let reply = Message::from_server(
                server_name,
                "CAP",
                vec![conn.nick_or_star(), "LS", &caps],
            );
            send(state, session_id, format!("{reply}\r\n"));
        }
        Some("REQ") => {
            if let Some(caps) = msg.params.get(1) {
                let requested: Vec<&str> = caps.split_whitespace().collect();
                let mut acked = Vec::new();
                let mut all_ok = true;

                for cap in &requested {
                    match cap.to_ascii_lowercase().as_str() {
                        "sasl" => {
                            conn.cap_sasl_requested = true;
                            acked.push("sasl");
                        }
                        "message-tags" => {
                            conn.cap_message_tags = true;
                            state.cap_message_tags.lock().unwrap().insert(session_id.to_string());
                            acked.push("message-tags");
                        }
                        _ => { all_ok = false; }
                    }
                }

                if all_ok && !acked.is_empty() {
                    let ack_str = acked.join(" ");
                    let reply = Message::from_server(
                        server_name,
                        "CAP",
                        vec![conn.nick_or_star(), "ACK", &ack_str],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                } else {
                    let reply = Message::from_server(
                        server_name,
                        "CAP",
                        vec![conn.nick_or_star(), "NAK", caps],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                }
            }
        }
        Some("END") => {
            conn.cap_negotiating = false;
            try_complete_registration(conn, state, server_name, session_id, send);
        }
        _ => {}
    }
}

async fn handle_authenticate(
    conn: &mut Connection,
    msg: &Message,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let param = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    if param.eq_ignore_ascii_case("ATPROTO-CHALLENGE") {
        conn.sasl_in_progress = true;
        let encoded = state.challenge_store.create(session_id);
        let reply = Message::new("AUTHENTICATE", vec![&encoded]);
        send(state, session_id, format!("{reply}\r\n"));
    } else if conn.sasl_in_progress {
        if let Some(response) = sasl::decode_response(param) {
            let taken = state.challenge_store.take(session_id);
            match taken {
                Some((challenge, challenge_bytes)) => {
                    match sasl::verify_response(
                        &challenge,
                        &challenge_bytes,
                        &response,
                        &state.did_resolver,
                    )
                    .await
                    {
                        Ok(did) => {
                            conn.authenticated_did = Some(did.clone());
                            conn.sasl_in_progress = false;
                            state
                                .session_dids
                                .lock()
                                .unwrap()
                                .insert(session_id.to_string(), did.clone());

                            // Bind nick to DID (persistent identity-nick)
                            if let Some(ref nick) = conn.nick {
                                let nick_lower = nick.to_lowercase();
                                state.did_nicks.lock().unwrap().insert(did.clone(), nick_lower.clone());
                                state.nick_owners.lock().unwrap().insert(nick_lower, did.clone());
                                state.with_db(|db| db.save_identity(&did, &nick.to_lowercase()));
                            }

                            // Resolve handle from DID document for WHOIS display
                            {
                                let did_clone = did.clone();
                                let state_clone = Arc::clone(state);
                                let sid = session_id.to_string();
                                tokio::spawn(async move {
                                    if let Ok(doc) = state_clone.did_resolver.resolve(&did_clone).await {
                                        for aka in &doc.also_known_as {
                                            if let Some(handle) = aka.strip_prefix("at://") {
                                                state_clone.session_handles.lock().unwrap()
                                                    .insert(sid, handle.to_string());
                                                break;
                                            }
                                        }
                                    }
                                });
                            }

                            let nick = conn.nick_or_star();
                            let hostmask = conn.hostmask();
                            let logged_in = Message::from_server(
                                server_name,
                                irc::RPL_LOGGEDIN,
                                vec![
                                    nick,
                                    &hostmask,
                                    &did,
                                    &format!("You are now logged in as {did}"),
                                ],
                            );
                            send(state, session_id, format!("{logged_in}\r\n"));

                            let success = Message::from_server(
                                server_name,
                                irc::RPL_SASLSUCCESS,
                                vec![nick, "SASL authentication successful"],
                            );
                            send(state, session_id, format!("{success}\r\n"));
                        }
                        Err(reason) => {
                            tracing::warn!(%session_id, "SASL auth failed: {reason}");
                            conn.sasl_in_progress = false;
                            let fail = Message::from_server(
                                server_name,
                                irc::ERR_SASLFAIL,
                                vec![conn.nick_or_star(), "SASL authentication failed"],
                            );
                            send(state, session_id, format!("{fail}\r\n"));
                        }
                    }
                }
                None => {
                    conn.sasl_in_progress = false;
                    let fail = Message::from_server(
                        server_name,
                        irc::ERR_SASLFAIL,
                        vec![
                            conn.nick_or_star(),
                            "SASL authentication failed (no challenge)",
                        ],
                    );
                    send(state, session_id, format!("{fail}\r\n"));
                }
            }
        } else {
            conn.sasl_in_progress = false;
            let fail = Message::from_server(
                server_name,
                irc::ERR_SASLFAIL,
                vec![
                    conn.nick_or_star(),
                    "SASL authentication failed (bad response)",
                ],
            );
            send(state, session_id, format!("{fail}\r\n"));
        }
    } else {
        let fail = Message::from_server(
            server_name,
            irc::ERR_SASLFAIL,
            vec![conn.nick_or_star(), "Unsupported SASL mechanism"],
        );
        send(state, session_id, format!("{fail}\r\n"));
    }
}

fn try_complete_registration(
    conn: &mut Connection,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    if conn.registered || conn.cap_negotiating || conn.sasl_in_progress {
        return;
    }
    if conn.nick.is_none() || conn.user.is_none() {
        return;
    }

    // Enforce nick ownership at registration time.
    // If the user claimed a registered nick during CAP negotiation
    // but didn't authenticate as the owner, force-rename them.
    if let Some(ref nick) = conn.nick {
        let nick_lower = nick.to_lowercase();
        let owner_did = state.nick_owners.lock().unwrap().get(&nick_lower).cloned();
        if let Some(owner) = owner_did {
            let is_owner = conn.authenticated_did.as_ref().is_some_and(|d| d == &owner);
            if !is_owner {
                // Generate a guest nick
                let guest_nick = format!("Guest{}", &session_id[session_id.len().saturating_sub(4)..]);
                let notice = Message::from_server(
                    server_name,
                    "NOTICE",
                    vec!["*", &format!("Nick {nick} is registered. You have been renamed to {guest_nick}")],
                );
                send(state, session_id, format!("{notice}\r\n"));
                state.nick_to_session.lock().unwrap().remove(nick);
                state.nick_to_session.lock().unwrap().insert(guest_nick.clone(), session_id.to_string());
                conn.nick = Some(guest_nick);
            }
        }
    }

    conn.registered = true;
    let nick = conn.nick.as_deref().unwrap();

    // Store iroh endpoint ID in shared state for WHOIS lookups
    if let Some(ref iroh_id) = conn.iroh_endpoint_id {
        state.session_iroh_ids.lock().unwrap()
            .insert(session_id.to_string(), iroh_id.clone());
    }

    let auth_info = match &conn.authenticated_did {
        Some(did) => format!(" (authenticated as {did})"),
        None => " (guest)".to_string(),
    };

    let welcome = Message::from_server(
        server_name,
        irc::RPL_WELCOME,
        vec![
            nick,
            &format!("Welcome to {server_name}, {nick}{auth_info}"),
        ],
    );
    let yourhost = Message::from_server(
        server_name,
        irc::RPL_YOURHOST,
        vec![
            nick,
            &format!("Your host is {server_name}, running irc-reboot 0.1"),
        ],
    );
    let created = Message::from_server(
        server_name,
        irc::RPL_CREATED,
        vec![nick, "This server was created just now"],
    );
    let myinfo = Message::from_server(
        server_name,
        irc::RPL_MYINFO,
        vec![nick, server_name, "irc-reboot-0.1", "o", "o"],
    );

    for msg in [welcome, yourhost, created, myinfo] {
        send(state, session_id, format!("{msg}\r\n"));
    }
}

fn handle_join(
    conn: &Connection,
    channel: &str,
    supplied_key: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick.as_deref().unwrap();
    let hostmask = conn.hostmask();
    let did = conn.authenticated_did.as_deref();

    let is_new_channel = {
        let channels = state.channels.lock().unwrap();
        !channels.contains_key(channel)
    };

    if !is_new_channel {
        let channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get(channel) {
            // Check channel key (+k)
            if let Some(ref key) = ch.key
                && supplied_key != Some(key.as_str()) {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_BADCHANNELKEY,
                        vec![nick, channel, "Cannot join channel (+k)"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                }
            // Check bans
            if ch.is_banned(&hostmask, did) {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_BANNEDFROMCHAN,
                    vec![nick, channel, "Cannot join channel (+b)"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }
            // Check invite-only
            if ch.invite_only {
                let has_invite = ch.invites.contains(session_id)
                    || did.is_some_and(|d| ch.invites.contains(d));
                if !has_invite {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_INVITEONLYCHAN,
                        vec![nick, channel, "Cannot join channel (+i)"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                }
                // Consume the invite
                drop(channels);
                let mut channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get_mut(channel) {
                    ch.invites.remove(session_id);
                    if let Some(d) = did {
                        ch.invites.remove(d);
                    }
                }
            }
        }
    }

    {
        let mut channels = state.channels.lock().unwrap();
        let ch = channels.entry(channel.to_string()).or_default();
        ch.members.insert(session_id.to_string());
        if is_new_channel {
            ch.ops.insert(session_id.to_string());
            let ch_clone = ch.clone();
            drop(channels);
            state.with_db(|db| db.save_channel(channel, &ch_clone));
        }
    }

    let join_msg = format!(":{hostmask} JOIN {channel}\r\n");
    let members: Vec<String> = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();

    let conns = state.connections.lock().unwrap();
    for member_session in &members {
        if let Some(tx) = conns.get(member_session) {
            let _ = tx.try_send(join_msg.clone());
        }
    }
    drop(conns);

    // Send topic if set (332 + 333)
    {
        let channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get(channel)
            && let Some(ref topic) = ch.topic {
                let rpl_topic = Message::from_server(
                    server_name,
                    irc::RPL_TOPIC,
                    vec![nick, channel, &topic.text],
                );
                send(state, session_id, format!("{rpl_topic}\r\n"));

                let rpl_topicwhotime = Message::from_server(
                    server_name,
                    irc::RPL_TOPICWHOTIME,
                    vec![nick, channel, &topic.set_by, &topic.set_at.to_string()],
                );
                send(state, session_id, format!("{rpl_topicwhotime}\r\n"));
            }
    }

    // Replay recent message history (with tags for capable clients)
    {
        let has_tags_cap = state.cap_message_tags.lock().unwrap().contains(session_id);
        let channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get(channel) {
            for hist in &ch.history {
                if has_tags_cap && !hist.tags.is_empty() {
                    let tag_msg = irc::Message {
                        tags: hist.tags.clone(),
                        prefix: Some(hist.from.clone()),
                        command: "PRIVMSG".to_string(),
                        params: vec![channel.to_string(), hist.text.clone()],
                    };
                    send(state, session_id, format!("{tag_msg}\r\n"));
                } else {
                    let line = format!(":{} PRIVMSG {} :{}\r\n", hist.from, channel, hist.text);
                    send(state, session_id, line);
                }
            }
        }
    }

    let nick_list: Vec<String> = {
        let channels = state.channels.lock().unwrap();
        let (member_sessions, ops, voiced) = match channels.get(channel) {
            Some(ch) => (ch.members.clone(), ch.ops.clone(), ch.voiced.clone()),
            None => Default::default(),
        };
        drop(channels);
        let nicks = state.nick_to_session.lock().unwrap();
        let reverse: std::collections::HashMap<&String, &String> =
            nicks.iter().map(|(n, s)| (s, n)).collect();
        member_sessions
            .iter()
            .filter_map(|s| {
                reverse.get(s).map(|n| {
                    let prefix = if ops.contains(s) {
                        "@"
                    } else if voiced.contains(s) {
                        "+"
                    } else {
                        ""
                    };
                    format!("{prefix}{n}")
                })
            })
            .collect()
    };

    let names = Message::from_server(
        server_name,
        irc::RPL_NAMREPLY,
        vec![nick, "=", channel, &nick_list.join(" ")],
    );
    let end_names = Message::from_server(
        server_name,
        irc::RPL_ENDOFNAMES,
        vec![nick, channel, "End of /NAMES list"],
    );
    send(state, session_id, format!("{names}\r\n"));
    send(state, session_id, format!("{end_names}\r\n"));
}

fn handle_mode(
    conn: &Connection,
    channel: &str,
    mode_str: Option<&str>,
    mode_arg: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify user is in the channel
    let in_channel = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.contains(session_id))
        .unwrap_or(false);

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    let Some(mode_str) = mode_str else {
        // Query channel modes
        let channels = state.channels.lock().unwrap();
        let modes = if let Some(ch) = channels.get(channel) {
            let mut m = String::from("+");
            if ch.topic_locked { m.push('t'); }
            if ch.invite_only { m.push('i'); }
            if ch.key.is_some() { m.push('k'); }
            m
        } else {
            "+".to_string()
        };
        let reply = Message::from_server(
            server_name,
            irc::RPL_CHANNELMODEIS,
            vec![nick, channel, &modes],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    };

    // Only ops can change modes
    let is_op = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.ops.contains(session_id))
        .unwrap_or(false);

    if !is_op {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Parse mode string: +o, -o, +v, -v, +t, -t
    let mut adding = true;
    for ch in mode_str.chars() {
        match ch {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'v' => {
                let Some(target_nick) = mode_arg else {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_NEEDMOREPARAMS,
                        vec![nick, "MODE", "Not enough parameters"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                };

                // Resolve target nick to session
                let target_session = state
                    .nick_to_session
                    .lock()
                    .unwrap()
                    .get(target_nick)
                    .cloned();

                let Some(target_session) = target_session else {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_NOSUCHNICK,
                        vec![nick, target_nick, "No such nick"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                };

                // Verify target is in the channel
                let target_in_channel = state
                    .channels
                    .lock()
                    .unwrap()
                    .get(channel)
                    .map(|c| c.members.contains(&target_session))
                    .unwrap_or(false);

                if !target_in_channel {
                    let reply = Message::from_server(
                        server_name,
                        irc::ERR_USERNOTINCHANNEL,
                        vec![nick, target_nick, channel, "They aren't on that channel"],
                    );
                    send(state, session_id, format!("{reply}\r\n"));
                    return;
                }

                // Apply the mode
                {
                    let mut channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get_mut(channel) {
                        let set = if ch == 'o' { &mut chan.ops } else { &mut chan.voiced };
                        if adding {
                            set.insert(target_session);
                        } else {
                            set.remove(&target_session);
                        }
                    }
                }

                // Broadcast mode change
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}{ch} {target_nick}\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
            }
            'b' => {
                use crate::server::BanEntry;

                if !adding && mode_arg.is_none() {
                    // -b with no arg is invalid, ignore
                    return;
                }

                if adding && mode_arg.is_none() {
                    // +b with no arg: list bans
                    let channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get(channel) {
                        for ban in &chan.bans {
                            let reply = Message::from_server(
                                server_name,
                                irc::RPL_BANLIST,
                                vec![nick, channel, &ban.mask, &ban.set_by, &ban.set_at.to_string()],
                            );
                            send(state, session_id, format!("{reply}\r\n"));
                        }
                    }
                    let end = Message::from_server(
                        server_name,
                        irc::RPL_ENDOFBANLIST,
                        vec![nick, channel, "End of channel ban list"],
                    );
                    send(state, session_id, format!("{end}\r\n"));
                    return;
                }

                let mask = mode_arg.unwrap();
                if adding {
                    let entry = BanEntry::new(mask.to_string(), conn.hostmask());
                    let mut channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get_mut(channel) {
                        // Don't duplicate
                        if !chan.bans.iter().any(|b| b.mask == mask) {
                            chan.bans.push(entry.clone());
                            drop(channels);
                            state.with_db(|db| db.add_ban(channel, &entry));
                        }
                    }
                } else {
                    let mut channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.bans.retain(|b| b.mask != mask);
                    }
                    drop(channels);
                    state.with_db(|db| db.remove_ban(channel, mask));
                }

                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}b {mask}\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
            }
            'i' => {
                {
                    let mut channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.invite_only = adding;
                        if !adding {
                            chan.invites.clear();
                        }
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}i\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
            }
            't' => {
                {
                    let mut channels = state.channels.lock().unwrap();
                    if let Some(chan) = channels.get_mut(channel) {
                        chan.topic_locked = adding;
                        let ch_clone = chan.clone();
                        drop(channels);
                        state.with_db(|db| db.save_channel(channel, &ch_clone));
                    }
                }
                let sign = if adding { "+" } else { "-" };
                let hostmask = conn.hostmask();
                let mode_msg = format!(":{hostmask} MODE {channel} {sign}t\r\n");
                broadcast_to_channel(state, channel, &mode_msg);
            }
            'k' => {
                if adding {
                    let Some(key) = mode_arg else {
                        let reply = Message::from_server(
                            server_name,
                            irc::ERR_NEEDMOREPARAMS,
                            vec![nick, "MODE", "Not enough parameters"],
                        );
                        send(state, session_id, format!("{reply}\r\n"));
                        return;
                    };
                    {
                        let mut channels = state.channels.lock().unwrap();
                        if let Some(chan) = channels.get_mut(channel) {
                            chan.key = Some(key.to_string());
                            let ch_clone = chan.clone();
                            drop(channels);
                            state.with_db(|db| db.save_channel(channel, &ch_clone));
                        }
                    }
                    let hostmask = conn.hostmask();
                    let mode_msg = format!(":{hostmask} MODE {channel} +k {key}\r\n");
                    broadcast_to_channel(state, channel, &mode_msg);
                } else {
                    let old_key = {
                        let mut channels = state.channels.lock().unwrap();
                        if let Some(chan) = channels.get_mut(channel) {
                            let k = chan.key.take();
                            let ch_clone = chan.clone();
                            drop(channels);
                            state.with_db(|db| db.save_channel(channel, &ch_clone));
                            k
                        } else {
                            None
                        }
                    };
                    if let Some(key) = old_key {
                        let hostmask = conn.hostmask();
                        let mode_msg = format!(":{hostmask} MODE {channel} -k {key}\r\n");
                        broadcast_to_channel(state, channel, &mode_msg);
                    }
                }
            }
            _ => {
                let mode_char = ch.to_string();
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_UNKNOWNMODE,
                    vec![nick, &mode_char, "is unknown mode char to me"],
                );
                send(state, session_id, format!("{reply}\r\n"));
            }
        }
    }
}

fn handle_kick(
    conn: &Connection,
    channel: &str,
    target_nick: &str,
    reason: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify kicker is in the channel and is an op
    let (in_channel, is_op) = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| (ch.members.contains(session_id), ch.ops.contains(session_id)))
        .unwrap_or((false, false));

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    if !is_op {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Resolve target
    let target_session = state
        .nick_to_session
        .lock()
        .unwrap()
        .get(target_nick)
        .cloned();

    let Some(target_session) = target_session else {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOSUCHNICK,
            vec![nick, target_nick, "No such nick"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    };

    let target_in_channel = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.contains(&target_session))
        .unwrap_or(false);

    if !target_in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_USERNOTINCHANNEL,
            vec![nick, target_nick, channel, "They aren't on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Broadcast KICK, then remove from channel
    let hostmask = conn.hostmask();
    let kick_msg = format!(":{hostmask} KICK {channel} {target_nick} :{reason}\r\n");
    broadcast_to_channel(state, channel, &kick_msg);

    // Remove target from channel
    {
        let mut channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get_mut(channel) {
            ch.members.remove(&target_session);
            ch.ops.remove(&target_session);
            ch.voiced.remove(&target_session);
        }
    }
}

/// Broadcast a raw message to all members of a channel.
fn handle_invite(
    conn: &Connection,
    target_nick: &str,
    channel: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let nick = conn.nick_or_star();

    // Verify inviter is in the channel and is an op
    let (in_channel, is_op, is_invite_only) = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| (
            ch.members.contains(session_id),
            ch.ops.contains(session_id),
            ch.invite_only,
        ))
        .unwrap_or((false, false, false));

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // If channel is +i, only ops can invite
    if is_invite_only && !is_op {
        let reply = Message::from_server(
            server_name,
            irc::ERR_CHANOPRIVSNEEDED,
            vec![nick, channel, "You're not channel operator"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    // Resolve target
    let target_session = state
        .nick_to_session
        .lock()
        .unwrap()
        .get(target_nick)
        .cloned();

    let Some(target_session) = target_session else {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOSUCHNICK,
            vec![nick, target_nick, "No such nick"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    };

    // Add invite — by session ID and DID if available
    {
        let mut channels = state.channels.lock().unwrap();
        if let Some(ch) = channels.get_mut(channel) {
            ch.invites.insert(target_session.clone());
            // Also invite by DID so it survives reconnect
            if let Some(did) = state.session_dids.lock().unwrap().get(&target_session) {
                ch.invites.insert(did.clone());
            }
        }
    }

    // Notify the inviter (341 RPL_INVITING)
    let reply = Message::from_server(
        server_name,
        "341",
        vec![nick, target_nick, channel],
    );
    send(state, session_id, format!("{reply}\r\n"));

    // Notify the target
    let hostmask = conn.hostmask();
    let invite_msg = format!(":{hostmask} INVITE {target_nick} {channel}\r\n");
    if let Some(tx) = state.connections.lock().unwrap().get(&target_session) {
        let _ = tx.try_send(invite_msg);
    }
}

fn broadcast_to_channel(state: &Arc<SharedState>, channel: &str, msg: &str) {
    let members: Vec<String> = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();

    let conns = state.connections.lock().unwrap();
    for member_session in &members {
        if let Some(tx) = conns.get(member_session) {
            let _ = tx.try_send(msg.to_string());
        }
    }
}

fn handle_topic(
    conn: &Connection,
    channel: &str,
    new_topic: Option<&str>,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    use crate::server::TopicInfo;

    let nick = conn.nick_or_star();

    // Verify user is in the channel
    let in_channel = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.contains(session_id))
        .unwrap_or(false);

    if !in_channel {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOTONCHANNEL,
            vec![nick, channel, "You're not on that channel"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        return;
    }

    match new_topic {
        Some(text) => {
            // Check +t: if topic_locked, only ops can set topic
            let (is_op, is_locked) = {
                let channels = state.channels.lock().unwrap();
                channels.get(channel).map(|ch| {
                    (ch.ops.contains(session_id), ch.topic_locked)
                }).unwrap_or((false, false))
            };
            if is_locked && !is_op {
                let reply = Message::from_server(
                    server_name,
                    irc::ERR_CHANOPRIVSNEEDED,
                    vec![nick, channel, "You're not channel operator"],
                );
                send(state, session_id, format!("{reply}\r\n"));
                return;
            }

            // Set the topic
            let topic = TopicInfo::new(text.to_string(), conn.hostmask());

            // Store it
            state
                .channels
                .lock()
                .unwrap()
                .entry(channel.to_string())
                .and_modify(|ch| {
                    ch.topic = Some(topic);
                });

            // Persist channel state
            {
                let channels = state.channels.lock().unwrap();
                if let Some(ch) = channels.get(channel) {
                    let ch_clone = ch.clone();
                    drop(channels);
                    state.with_db(|db| db.save_channel(channel, &ch_clone));
                }
            }

            // Broadcast TOPIC change to all channel members
            let hostmask = conn.hostmask();
            let topic_msg = format!(":{hostmask} TOPIC {channel} :{text}\r\n");

            let members: Vec<String> = state
                .channels
                .lock()
                .unwrap()
                .get(channel)
                .map(|ch| ch.members.iter().cloned().collect())
                .unwrap_or_default();

            let conns = state.connections.lock().unwrap();
            for member_session in &members {
                if let Some(tx) = conns.get(member_session) {
                    let _ = tx.try_send(topic_msg.clone());
                }
            }
        }
        None => {
            // Query the topic
            let channels = state.channels.lock().unwrap();
            if let Some(ch) = channels.get(channel) {
                if let Some(ref topic) = ch.topic {
                    let rpl = Message::from_server(
                        server_name,
                        irc::RPL_TOPIC,
                        vec![nick, channel, &topic.text],
                    );
                    send(state, session_id, format!("{rpl}\r\n"));

                    let rpl_who = Message::from_server(
                        server_name,
                        irc::RPL_TOPICWHOTIME,
                        vec![nick, channel, &topic.set_by, &topic.set_at.to_string()],
                    );
                    send(state, session_id, format!("{rpl_who}\r\n"));
                } else {
                    let rpl = Message::from_server(
                        server_name,
                        irc::RPL_NOTOPIC,
                        vec![nick, channel, "No topic is set"],
                    );
                    send(state, session_id, format!("{rpl}\r\n"));
                }
            }
        }
    }
}

fn handle_part(
    conn: &Connection,
    channel: &str,
    state: &Arc<SharedState>,
    session_id: &str,
) {
    let hostmask = conn.hostmask();
    let part_msg = format!(":{hostmask} PART {channel}\r\n");

    let members: Vec<String> = state
        .channels
        .lock()
        .unwrap()
        .get(channel)
        .map(|ch| ch.members.iter().cloned().collect())
        .unwrap_or_default();

    let conns = state.connections.lock().unwrap();
    for member_session in &members {
        if let Some(tx) = conns.get(member_session) {
            let _ = tx.try_send(part_msg.clone());
        }
    }
    drop(conns);

    state
        .channels
        .lock()
        .unwrap()
        .entry(channel.to_string())
        .and_modify(|ch| {
            ch.members.remove(session_id);
        });
}

fn handle_whois(
    conn: &Connection,
    target_nick: &str,
    state: &Arc<SharedState>,
    server_name: &str,
    session_id: &str,
    send: &impl Fn(&Arc<SharedState>, &str, String),
) {
    let my_nick = conn.nick_or_star();

    // Find target's session
    let target_session = state
        .nick_to_session
        .lock()
        .unwrap()
        .get(target_nick)
        .cloned();

    let Some(target_session) = target_session else {
        let reply = Message::from_server(
            server_name,
            irc::ERR_NOSUCHNICK,
            vec![my_nick, target_nick, "No such nick"],
        );
        send(state, session_id, format!("{reply}\r\n"));
        let end = Message::from_server(
            server_name,
            irc::RPL_ENDOFWHOIS,
            vec![my_nick, target_nick, "End of /WHOIS list"],
        );
        send(state, session_id, format!("{end}\r\n"));
        return;
    };

    // 311 RPL_WHOISUSER
    let whoisuser = Message::from_server(
        server_name,
        irc::RPL_WHOISUSER,
        vec![my_nick, target_nick, "~u", "host", "*", "IRC User"],
    );
    send(state, session_id, format!("{whoisuser}\r\n"));

    // 312 RPL_WHOISSERVER
    let whoisserver = Message::from_server(
        server_name,
        irc::RPL_WHOISSERVER,
        vec![my_nick, target_nick, server_name, "IRC Reboot"],
    );
    send(state, session_id, format!("{whoisserver}\r\n"));

    // 330 RPL_WHOISACCOUNT — show DID if authenticated
    let did = state
        .session_dids
        .lock()
        .unwrap()
        .get(&target_session)
        .cloned();

    if let Some(ref did) = did {
        let whoisaccount = Message::from_server(
            server_name,
            irc::RPL_WHOISACCOUNT,
            vec![my_nick, target_nick, did, "is authenticated as"],
        );
        send(state, session_id, format!("{whoisaccount}\r\n"));
    }

    // Show Bluesky handle if resolved
    if did.is_some() {
        let handle = state
            .session_handles
            .lock()
            .unwrap()
            .get(&target_session)
            .cloned();
        if let Some(handle) = handle {
            // Use a server notice (not a standard numeric, but informational)
            let notice = Message::from_server(
                server_name,
                "671",  // RPL_WHOISSECURE (repurposed for extra info)
                vec![my_nick, target_nick, &format!("AT Protocol handle: {handle}")],
            );
            send(state, session_id, format!("{notice}\r\n"));
        }
    }

    // Show iroh endpoint ID if connected via iroh
    let iroh_id = state
        .session_iroh_ids
        .lock()
        .unwrap()
        .get(&target_session)
        .cloned();
    if let Some(iroh_id) = iroh_id {
        let iroh_notice = Message::from_server(
            server_name,
            "672",  // Custom numeric for iroh info
            vec![my_nick, target_nick, &format!("iroh endpoint: {iroh_id}")],
        );
        send(state, session_id, format!("{iroh_notice}\r\n"));
    }

    // 318 RPL_ENDOFWHOIS
    let end = Message::from_server(
        server_name,
        irc::RPL_ENDOFWHOIS,
        vec![my_nick, target_nick, "End of /WHOIS list"],
    );
    send(state, session_id, format!("{end}\r\n"));
}

fn handle_tagmsg(
    conn: &Connection,
    target: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
) {
    if tags.is_empty() {
        return; // TAGMSG with no tags is meaningless
    }

    let hostmask = conn.hostmask();
    let tag_msg = irc::Message {
        tags: tags.clone(),
        prefix: Some(hostmask.clone()),
        command: "TAGMSG".to_string(),
        params: vec![target.to_string()],
    };
    let tagged_line = format!("{tag_msg}\r\n");

    // Generate a PRIVMSG fallback for plain clients (server-side downgrade).
    // Only for known tag types — unknown TAGMSGs are silently dropped for plain clients.
    let plain_fallback = tags.get("+react").map(|emoji| {
        format!(":{hostmask} PRIVMSG {target} :\x01ACTION reacted with {emoji}\x01\r\n")
    });

    // Rich clients get TAGMSG, plain clients get fallback PRIVMSG (if any)
    if target.starts_with('#') || target.starts_with('&') {
        let members: Vec<String> = state
            .channels.lock().unwrap()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock().unwrap();
        let conns = state.connections.lock().unwrap();
        for member_session in &members {
            if member_session != &conn.id
                && let Some(tx) = conns.get(member_session)
            {
                if tag_caps.contains(member_session) {
                    let _ = tx.try_send(tagged_line.clone());
                } else if let Some(ref fallback) = plain_fallback {
                    let _ = tx.try_send(fallback.clone());
                }
            }
        }
    } else {
        let target_session = state.nick_to_session.lock().unwrap().get(target).cloned();
        if let Some(ref session) = target_session
            && let Some(tx) = state.connections.lock().unwrap().get(session)
        {
            if state.cap_message_tags.lock().unwrap().contains(session) {
                let _ = tx.try_send(tagged_line.clone());
            } else if let Some(ref fallback) = plain_fallback {
                let _ = tx.try_send(fallback.clone());
            }
        }
    }
}

fn handle_privmsg(
    conn: &Connection,
    command: &str,
    target: &str,
    text: &str,
    tags: &std::collections::HashMap<String, String>,
    state: &Arc<SharedState>,
) {
    let hostmask = conn.hostmask();
    // Plain line (no tags) for clients that don't support message-tags
    let plain_line = format!(":{hostmask} {command} {target} :{text}\r\n");
    // Tagged line for clients that negotiated message-tags
    let tagged_line = if tags.is_empty() {
        None
    } else {
        let tag_msg = irc::Message {
            tags: tags.clone(),
            prefix: Some(hostmask.clone()),
            command: command.to_string(),
            params: vec![target.to_string(), text.to_string()],
        };
        Some(format!("{tag_msg}\r\n"))
    };

    if target.starts_with('#') || target.starts_with('&') {
        // Store in channel history
        if command == "PRIVMSG" {
            use crate::server::{HistoryMessage, MAX_HISTORY};
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut channels = state.channels.lock().unwrap();
            if let Some(ch) = channels.get_mut(target) {
                ch.history.push_back(HistoryMessage {
                    from: hostmask.clone(),
                    text: text.to_string(),
                    timestamp,
                    tags: tags.clone(),
                });
                while ch.history.len() > MAX_HISTORY {
                    ch.history.pop_front();
                }
            }
            drop(channels);
            state.with_db(|db| db.insert_message(target, &hostmask, text, timestamp, tags));
        }

        let members: Vec<String> = state
            .channels
            .lock()
            .unwrap()
            .get(target)
            .map(|ch| ch.members.iter().cloned().collect())
            .unwrap_or_default();

        let tag_caps = state.cap_message_tags.lock().unwrap();
        let conns = state.connections.lock().unwrap();
        for member_session in &members {
            if member_session != &conn.id
                && let Some(tx) = conns.get(member_session)
            {
                let line = match (&tagged_line, tag_caps.contains(member_session)) {
                    (Some(tagged), true) => tagged,
                    _ => &plain_line,
                };
                let _ = tx.try_send(line.clone());
            }
        }
    } else {
        let target_session = state.nick_to_session.lock().unwrap().get(target).cloned();
        if let Some(ref session) = target_session {
            let has_tags = state.cap_message_tags.lock().unwrap().contains(session);
            let line = match (&tagged_line, has_tags) {
                (Some(tagged), true) => tagged,
                _ => &plain_line,
            };
            if let Some(tx) = state.connections.lock().unwrap().get(session) {
                let _ = tx.try_send(line.clone());
            }
        }
    }
}
