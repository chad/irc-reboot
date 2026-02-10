mod app;
mod editor;
mod ui;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event as CrosstermEvent};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::ExecutableCommand;
use editor::EditAction;
use irc_at_sdk::auth::{ChallengeSigner, KeySigner, PdsSessionSigner};
use irc_at_sdk::client::{self, ConnectConfig};
use irc_at_sdk::crypto::PrivateKey;
use irc_at_sdk::did::DidResolver;
use irc_at_sdk::event::Event;
use irc_at_sdk::oauth;
use irc_at_sdk::pds;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::app::App;

/// Minimal TUI client for IRC with AT Protocol authentication.
#[derive(Parser, Debug)]
#[command(name = "irc-at-tui", version, about)]
struct Cli {
    /// Server address (host:port).
    server: String,

    /// IRC nickname.
    nick: String,

    /// Connect with TLS.
    #[arg(long)]
    tls: bool,

    /// Skip TLS certificate verification (for self-signed certs).
    #[arg(long)]
    tls_insecure: bool,

    /// Bluesky handle (e.g. alice.bsky.social).
    /// Opens browser for OAuth authorization (no password needed).
    /// If --app-password is also given, uses app-password auth instead.
    #[arg(long)]
    handle: Option<String>,

    /// App password for Bluesky authentication (legacy, skips OAuth).
    /// Can also be set via ATP_APP_PASSWORD env var.
    #[arg(long, env = "ATP_APP_PASSWORD")]
    app_password: Option<String>,

    /// DID to authenticate as (alternative to --handle, for crypto auth).
    #[arg(long)]
    did: Option<String>,

    /// Path to hex-encoded private key file (for crypto auth).
    #[arg(long)]
    key_file: Option<String>,

    /// Key type: secp256k1 (default) or ed25519.
    #[arg(long, default_value = "secp256k1")]
    key_type: String,

    /// Generate a new keypair for testing (crypto auth).
    #[arg(long)]
    gen_key: bool,

    /// Use vi keybindings for input editing (default: emacs).
    #[arg(long)]
    vi: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Build signer before entering the TUI
    let signer = build_signer(&cli).await?;

    let auth_status = if signer.is_some() {
        "authenticating"
    } else {
        "guest"
    };
    eprintln!("Connecting to {} as {} ({auth_status})...", cli.server, cli.nick);

    let config = ConnectConfig {
        server_addr: cli.server.clone(),
        nick: cli.nick.clone(),
        user: cli.nick.clone(),
        realname: "IRC AT TUI Client".to_string(),
        tls: cli.tls,
        tls_insecure: cli.tls_insecure,
    };

    let (handle, mut events) = client::connect(config, signer);

    // Setup terminal
    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(&cli.nick, cli.vi);

    let result = run_app(&mut terminal, &mut app, &handle, &mut events).await;

    // Restore terminal
    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;

    result
}

async fn build_signer(cli: &Cli) -> Result<Option<Arc<dyn ChallengeSigner>>> {
    // Option 1: Bluesky login via handle
    if let Some(ref handle) = cli.handle {
        if let Some(ref password) = cli.app_password {
            // Legacy: app-password auth
            eprintln!("Authenticating to Bluesky as {handle} (app password)...");
            let resolver = DidResolver::http();
            let (session, pds_url) = pds::create_session(handle, password, &resolver).await?;
            eprintln!("  DID: {}", session.did);
            eprintln!("  Handle: {}", session.handle);
            eprintln!("  PDS: {pds_url}");
            return Ok(Some(Arc::new(PdsSessionSigner::new(
                session.did,
                session.access_jwt,
                pds_url,
            ))));
        } else {
            // Try cached session first
            let cache_path = oauth::default_session_path(handle);
            if cache_path.exists() {
                eprintln!("Found cached session, validating...");
                match oauth::OAuthSession::load(&cache_path) {
                    Ok(cached) => match cached.validate().await {
                        Ok(session) => {
                            eprintln!("  Cached session valid for {}", session.did);
                            // Re-save with fresh nonce
                            let _ = session.save(&cache_path);
                            return Ok(Some(Arc::new(PdsSessionSigner::new_oauth(
                                session.did,
                                session.access_token,
                                session.pds_url,
                                session.dpop_key,
                                session.dpop_nonce,
                            ))));
                        }
                        Err(e) => {
                            eprintln!("  Cached session expired: {e}");
                            let _ = std::fs::remove_file(&cache_path);
                        }
                    },
                    Err(e) => {
                        eprintln!("  Failed to load cache: {e}");
                        let _ = std::fs::remove_file(&cache_path);
                    }
                }
            }

            // OAuth flow — opens browser, no password needed
            eprintln!("Logging in as {handle} via OAuth...");
            let session = oauth::login(handle).await?;
            eprintln!("  DID: {}", session.did);
            eprintln!("  Handle: {}", session.handle);
            eprintln!("  PDS: {}", session.pds_url);

            // Cache the session
            if let Err(e) = session.save(&cache_path) {
                eprintln!("  Warning: failed to cache session: {e}");
            } else {
                eprintln!("  Session cached to {}", cache_path.display());
            }

            return Ok(Some(Arc::new(PdsSessionSigner::new_oauth(
                session.did,
                session.access_token,
                session.pds_url,
                session.dpop_key,
                session.dpop_nonce,
            ))));
        }
    }

    // Option 2: Crypto auth with generated key
    if cli.gen_key {
        let private_key = match cli.key_type.as_str() {
            "ed25519" => PrivateKey::generate_ed25519(),
            _ => PrivateKey::generate_secp256k1(),
        };
        let multibase = private_key.public_key_multibase();
        let did = cli
            .did
            .clone()
            .unwrap_or_else(|| "did:plc:generated-test-key".to_string());
        eprintln!("Generated {} keypair:", cli.key_type);
        eprintln!("  DID: {did}");
        eprintln!("  Public key (multibase): {multibase}");
        return Ok(Some(Arc::new(KeySigner::new(did, private_key))));
    }

    // Option 3: Crypto auth with DID + key file
    if let Some(ref did) = cli.did {
        let private_key = if let Some(ref path) = cli.key_file {
            let hex_str = std::fs::read_to_string(path)?.trim().to_string();
            let bytes =
                hex::decode(&hex_str).map_err(|e| anyhow::anyhow!("Bad hex in key file: {e}"))?;
            match cli.key_type.as_str() {
                "ed25519" => PrivateKey::ed25519_from_bytes(&bytes)?,
                _ => PrivateKey::secp256k1_from_bytes(&bytes)?,
            }
        } else {
            eprintln!("Warning: --did without --key-file. Generating ephemeral key.");
            match cli.key_type.as_str() {
                "ed25519" => PrivateKey::generate_ed25519(),
                _ => PrivateKey::generate_secp256k1(),
            }
        };
        return Ok(Some(Arc::new(KeySigner::new(did.clone(), private_key))));
    }

    // No auth — guest mode
    Ok(None)
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    handle: &client::ClientHandle,
    events: &mut tokio::sync::mpsc::Receiver<Event>,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        let has_crossterm_event =
            tokio::task::block_in_place(|| event::poll(Duration::from_millis(16)))?;

        if has_crossterm_event {
            let evt = tokio::task::block_in_place(event::read)?;
            if let CrosstermEvent::Key(key) = evt {
                let action = app.editor.handle_key(key);
                match action {
                    EditAction::Submit => {
                        let input = app.input_take();
                        if !input.is_empty() {
                            process_input(app, handle, &input).await?;
                        }
                    }
                    EditAction::HistoryUp => app.history_up(),
                    EditAction::HistoryDown => app.history_down(),
                    EditAction::Complete => try_nick_complete(app),
                    EditAction::NextBuffer => app.next_buffer(),
                    EditAction::PrevBuffer => app.prev_buffer(),
                    EditAction::ScrollUp(n) => {
                        if let Some(buf) = app.buffers.get_mut(&app.active_buffer) {
                            buf.scroll = buf.scroll.saturating_add(n);
                        }
                    }
                    EditAction::ScrollDown(n) => {
                        if let Some(buf) = app.buffers.get_mut(&app.active_buffer) {
                            buf.scroll = buf.scroll.saturating_sub(n);
                        }
                    }
                    EditAction::Quit => {
                        let _ = handle.quit(Some("bye")).await;
                        app.should_quit = true;
                    }
                    EditAction::None => {}
                }
            }
        }

        // Drain IRC events
        while let Ok(evt) = events.try_recv() {
            process_irc_event(app, evt);
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn process_irc_event(app: &mut App, event: Event) {
    match event {
        Event::Connected => {
            app.connection_state = "connected".to_string();
            app.status_msg("Connected to server");
        }
        Event::Registered { nick } => {
            app.connection_state = "registered".to_string();
            app.nick = nick.clone();
            app.status_msg(&format!("Registered as {nick}"));
        }
        Event::Authenticated { did } => {
            app.authenticated_did = Some(did.clone());
            app.status_msg(&format!("Authenticated as {did}"));
        }
        Event::AuthFailed { reason } => {
            app.status_msg(&format!("Authentication failed: {reason}"));
        }
        Event::Joined { channel, nick } => {
            let buf = app.buffer_mut(&channel);
            if !buf.nicks.iter().any(|n| {
                let bare = n.trim_start_matches(['@', '+']);
                bare == nick
            }) {
                buf.nicks.push(nick.clone());
            }
            buf.push_system(&format!("{nick} has joined"));
            if nick == app.nick {
                app.active_buffer = channel.to_lowercase();
            }
        }
        Event::Parted { channel, nick } => {
            let buf = app.buffer_mut(&channel);
            buf.nicks.retain(|n| {
                let bare = n.trim_start_matches(['@', '+']);
                bare != nick
            });
            buf.push_system(&format!("{nick} has left"));
        }
        Event::Message { from, target, text, tags } => {
            // Check for media attachment in tags
            let media = irc_at_sdk::media::MediaAttachment::from_tags(&tags);

            // Detect CTCP ACTION (/me)
            if text.starts_with('\x01') && text.ends_with('\x01') {
                let inner = &text[1..text.len()-1];
                if let Some(action) = inner.strip_prefix("ACTION ") {
                    let buf_name = if !target.starts_with('#') && !target.starts_with('&') {
                        if from == app.nick { target.clone() } else { from.clone() }
                    } else {
                        target.clone()
                    };
                    app.buffer_mut(&buf_name).push(crate::app::BufferLine {
                        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                        from: String::new(),
                        text: format!("* {from} {action}"),
                        is_system: true,
                    });
                }
            } else if let Some(ref media) = media {
                // Rich media message
                let buf_name = if !target.starts_with('#') && !target.starts_with('&') {
                    if from == app.nick { target.clone() } else { from.clone() }
                } else {
                    target.clone()
                };
                let display = format_media_display(media);
                app.buffer_mut(&buf_name).push(crate::app::BufferLine {
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                    from: from.clone(),
                    text: display,
                    is_system: false,
                });
            } else {
                app.chat_msg(&target, &from, &text);
            }
        }
        Event::ModeChanged { channel, mode, arg, set_by } => {
            let msg = match &arg {
                Some(a) => format!("{set_by} sets mode {mode} {a}"),
                None => format!("{set_by} sets mode {mode}"),
            };
            app.buffer_mut(&channel).push_system(&msg);

            // Update nick prefixes for +o/-o/+v/-v
            if let Some(ref target_nick) = arg {
                let buf = app.buffer_mut(&channel);
                let bare = target_nick.trim_start_matches(['@', '+']);
                match mode.as_str() {
                    "+o" => {
                        // Remove any existing entry, add with @
                        buf.nicks.retain(|n| n.trim_start_matches(['@', '+']) != bare);
                        buf.nicks.push(format!("@{bare}"));
                    }
                    "-o" => {
                        buf.nicks.retain(|n| n.trim_start_matches(['@', '+']) != bare);
                        buf.nicks.push(bare.to_string());
                    }
                    "+v" => {
                        // Only add + if not already an op
                        let was_op = buf.nicks.iter().any(|n| n == &format!("@{bare}"));
                        if !was_op {
                            buf.nicks.retain(|n| n.trim_start_matches(['@', '+']) != bare);
                            buf.nicks.push(format!("+{bare}"));
                        }
                    }
                    "-v" => {
                        let was_op = buf.nicks.iter().any(|n| n == &format!("@{bare}"));
                        if !was_op {
                            buf.nicks.retain(|n| n.trim_start_matches(['@', '+']) != bare);
                            buf.nicks.push(bare.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        Event::Kicked { channel, nick, by, reason } => {
            let msg = format!("{nick} was kicked by {by} ({reason})");
            app.buffer_mut(&channel).push_system(&msg);
            // If we were kicked, note it
            if nick == app.nick {
                app.status_msg(&format!("You were kicked from {channel} by {by} ({reason})"));
            }
        }
        Event::Invited { channel, by } => {
            app.status_msg(&format!("{by} invited you to {channel}. Type /join {channel}"));
        }
        Event::TopicChanged {
            channel,
            topic,
            set_by,
        } => {
            let buf = app.buffer_mut(&channel);
            buf.topic = Some(topic.clone());
            match set_by {
                Some(who) => buf.push_system(&format!("{who} set topic: {topic}")),
                None => buf.push_system(&format!("Topic: {topic}")),
            }
        }
        Event::Names { channel, nicks } => {
            let buf = app.buffer_mut(&channel);
            buf.nicks = nicks.clone();
            buf.push_system(&format!("Users: {}", nicks.join(", ")));
        }
        Event::UserQuit { nick, reason } => {
            // Remove from all channel nick lists and show quit message
            let buffers: Vec<String> = app.buffers.keys().cloned().collect();
            for buf_name in buffers {
                let buf = app.buffer_mut(&buf_name);
                let was_in = buf.nicks.iter().any(|n| {
                    let bare = n.trim_start_matches(['@', '+']);
                    bare == nick
                });
                if was_in {
                    buf.nicks.retain(|n| {
                        let bare = n.trim_start_matches(['@', '+']);
                        bare != nick
                    });
                    buf.push_system(&format!("{nick} has quit ({reason})"));
                }
            }
        }
        Event::ServerNotice { text } => {
            app.status_msg(&text);
        }
        Event::Disconnected { reason } => {
            app.connection_state = "disconnected".to_string();
            app.status_msg(&format!("Disconnected: {reason}"));
            app.should_quit = true;
        }
        Event::WhoisReply { nick: _, info } => {
            let buf = app.active_buffer.clone();
            app.buffer_mut(&buf).push_system(&format!("*** {info}"));
        }
        Event::RawLine(_) => {}
    }
}

async fn process_input(
    app: &mut App,
    handle: &client::ClientHandle,
    input: &str,
) -> Result<()> {
    if input.starts_with('/') {
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0].to_lowercase();
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd.as_str() {
            "/join" | "/j" => {
                if !arg.is_empty() {
                    handle.join(arg).await?;
                } else {
                    app.status_msg("Usage: /join #channel");
                }
            }
            "/part" | "/leave" => {
                let channel = if arg.is_empty() {
                    app.active_buffer.clone()
                } else {
                    arg.to_string()
                };
                if channel.starts_with('#') || channel.starts_with('&') {
                    handle.raw(&format!("PART {channel}")).await?;
                } else {
                    app.status_msg("Not in a channel");
                }
            }
            "/me" => {
                if !arg.is_empty() {
                    let target = app.active_buffer.clone();
                    if target != "status" {
                        let action = format!("\x01ACTION {arg}\x01");
                        handle.privmsg(&target, &action).await?;
                        let nick = app.nick.clone();
                        app.buffer_mut(&target).push(crate::app::BufferLine {
                            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                            from: String::new(),
                            text: format!("* {nick} {arg}"),
                            is_system: true,
                        });
                    }
                }
            }
            "/msg" => {
                let msg_parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if msg_parts.len() == 2 {
                    handle.privmsg(msg_parts[0], msg_parts[1]).await?;
                    app.chat_msg(msg_parts[0], &app.nick.clone(), msg_parts[1]);
                } else {
                    app.status_msg("Usage: /msg <target> <message>");
                }
            }
            "/mode" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} {arg}")).await?;
                    } else {
                        app.status_msg("Usage: /mode <mode> [nick] (in a channel)");
                    }
                } else {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel}")).await?;
                    } else {
                        app.status_msg("Usage: /mode [+o|-o|+v|-v|+t|-t] [nick]");
                    }
                }
            }
            "/op" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} +o {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /op <nick>");
                }
            }
            "/deop" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} -o {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /deop <nick>");
                }
            }
            "/voice" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} +v {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /voice <nick>");
                }
            }
            "/ban" => {
                let channel = app.active_buffer.clone();
                if channel == "status" {
                    app.status_msg("Usage: /ban <mask|did> (in a channel)");
                } else if arg.is_empty() {
                    // List bans
                    handle.raw(&format!("MODE {channel} +b")).await?;
                } else {
                    handle.raw(&format!("MODE {channel} +b {arg}")).await?;
                }
            }
            "/unban" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("MODE {channel} -b {arg}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /unban <mask|did>");
                }
            }
            "/invite" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("INVITE {arg} {channel}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /invite <nick>");
                }
            }
            "/kick" | "/k" => {
                if !arg.is_empty() {
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        // /kick nick [reason]
                        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                        let target = parts[0];
                        let reason = parts.get(1).unwrap_or(&"Kicked");
                        handle.raw(&format!("KICK {channel} {target} :{reason}")).await?;
                    }
                } else {
                    app.status_msg("Usage: /kick <nick> [reason]");
                }
            }
            "/topic" | "/t" => {
                if arg.is_empty() {
                    // Query topic
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("TOPIC {channel}")).await?;
                    } else {
                        app.status_msg("Usage: /topic [text] (in a channel)");
                    }
                } else {
                    // Set topic
                    let channel = app.active_buffer.clone();
                    if channel != "status" {
                        handle.raw(&format!("TOPIC {channel} :{arg}")).await?;
                    } else {
                        app.status_msg("Usage: /topic [text] (in a channel)");
                    }
                }
            }
            "/whois" => {
                if !arg.is_empty() {
                    handle.raw(&format!("WHOIS {arg}")).await?;
                } else {
                    app.status_msg("Usage: /whois <nick>");
                }
            }
            "/quit" | "/q" => {
                handle
                    .quit(Some(if arg.is_empty() { "bye" } else { arg }))
                    .await?;
                app.should_quit = true;
            }
            "/raw" => {
                if !arg.is_empty() {
                    handle.raw(arg).await?;
                }
            }
            "/help" | "/h" => {
                app.status_msg("Commands:");
                app.status_msg("  /join #channel    - Join a channel");
                app.status_msg("  /part [#channel]  - Leave a channel");
                app.status_msg("  /msg target text  - Send a message");
                app.status_msg("  /topic [text]     - View or set channel topic");
                app.status_msg("  /mode +o nick     - Give channel operator");
                app.status_msg("  /op nick          - Give channel operator (shortcut)");
                app.status_msg("  /deop nick        - Remove channel operator");
                app.status_msg("  /voice nick       - Give voice (+v)");
                app.status_msg("  /kick nick [why]  - Kick user from channel");
                app.status_msg("  /ban [mask|did]   - Ban a user (or list bans)");
                app.status_msg("  /unban mask|did   - Remove a ban");
                app.status_msg("  /invite nick      - Invite user to +i channel");
                app.status_msg("  /mode +t / -t     - Lock/unlock topic to ops");
                app.status_msg("  /mode +i / -i     - Set/unset invite-only");
                app.status_msg("  /me <action>      - Send action message");
                app.status_msg("  /whois nick       - Show user info + DID");
                app.status_msg("  /quit [message]   - Disconnect");
                app.status_msg("  /raw <line>       - Send raw IRC");
                app.status_msg("  Tab               - Nick completion (or switch buffers if empty)");
                app.status_msg("  Shift-Tab         - Previous buffer");
                app.status_msg("  Ctrl-N / Ctrl-P   - Switch buffers");
                app.status_msg("  PageUp / PageDown - Scroll");
                app.status_msg("  Ctrl-C / Ctrl-Q   - Quit");
            }
            _ => {
                app.status_msg(&format!("Unknown command: {cmd}. Type /help for help."));
            }
        }
    } else {
        let target = app.active_buffer.clone();
        if target == "status" {
            app.status_msg(
                "Cannot send messages to the status buffer. Use /msg or switch to a channel.",
            );
        } else {
            handle.privmsg(&target, input).await?;
            app.chat_msg(&target, &app.nick.clone(), input);
        }
    }

    Ok(())
}

/// Format a media attachment for display in the TUI.
fn format_media_display(media: &irc_at_sdk::media::MediaAttachment) -> String {
    let type_icon = if media.is_image() {
        "🖼"
    } else if media.is_video() {
        "🎬"
    } else if media.is_audio() {
        "🎵"
    } else {
        "📎"
    };

    let mut parts = vec![format!("{type_icon} [{ct}]", ct = media.content_type)];

    if let Some(ref alt) = media.alt {
        parts.push(alt.clone());
    }

    if let (Some(w), Some(h)) = (media.width, media.height) {
        parts.push(format!("{w}×{h}"));
    }

    if let Some(size) = media.size {
        parts.push(format_file_size(size));
    }

    parts.push(media.url.clone());
    parts.join(" ")
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn try_nick_complete(app: &mut App) {
    let cursor = app.editor.cursor;
    let text = &app.editor.text;

    // Find the word fragment before the cursor
    let before_cursor = &text[..cursor];
    let word_start = before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
    let fragment = &before_cursor[word_start..];
    if fragment.is_empty() {
        return;
    }

    let fragment_lower = fragment.to_lowercase();

    // Get nicks from the current buffer
    let nicks = match app.buffers.get(&app.active_buffer) {
        Some(buf) => &buf.nicks,
        None => return,
    };

    // Find first matching nick (strip @ and + prefixes for comparison)
    let matching = nicks.iter().find_map(|n| {
        let bare = n.trim_start_matches(['@', '+']);
        if bare.to_lowercase().starts_with(&fragment_lower) {
            Some(bare.to_string())
        } else {
            None
        }
    });

    if let Some(completion) = matching {
        let suffix = if word_start == 0 { ": " } else { " " };
        let after = &text[cursor..];
        let new_text = format!(
            "{}{}{}{}",
            &text[..word_start],
            completion,
            suffix,
            after,
        );
        let new_cursor = word_start + completion.len() + suffix.len();
        app.editor.text = new_text;
        app.editor.cursor = new_cursor;
    }
}
