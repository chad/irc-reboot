//! IRC client with ATPROTO-CHALLENGE SASL support.
//!
//! This is the main entry point for SDK consumers. It manages the TCP
//! connection, IRC registration, CAP/SASL negotiation, and emits events.
//! Supports both plaintext and TLS connections.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

use crate::auth::{self, ChallengeSigner};
use crate::event::Event;
use crate::irc::Message;

/// Configuration for connecting to an IRC server.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Server address (host:port).
    pub server_addr: String,
    /// Desired nickname.
    pub nick: String,
    /// Username (ident).
    pub user: String,
    /// Real name.
    pub realname: String,
    /// Use TLS.
    pub tls: bool,
    /// Skip TLS certificate verification (for self-signed certs).
    pub tls_insecure: bool,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:6667".to_string(),
            nick: "user".to_string(),
            user: "user".to_string(),
            realname: "IRC AT SDK User".to_string(),
            tls: false,
            tls_insecure: false,
        }
    }
}

/// Commands the consumer can send to the client.
#[derive(Debug)]
pub enum Command {
    Join(String),
    Privmsg { target: String, text: String },
    Raw(String),
    Quit(Option<String>),
}

/// A handle to a running IRC client connection.
#[derive(Clone)]
pub struct ClientHandle {
    cmd_tx: mpsc::Sender<Command>,
}

impl ClientHandle {
    pub async fn join(&self, channel: &str) -> Result<()> {
        self.cmd_tx.send(Command::Join(channel.to_string())).await?;
        Ok(())
    }

    pub async fn privmsg(&self, target: &str, text: &str) -> Result<()> {
        self.cmd_tx
            .send(Command::Privmsg {
                target: target.to_string(),
                text: text.to_string(),
            })
            .await?;
        Ok(())
    }

    pub async fn quit(&self, message: Option<&str>) -> Result<()> {
        self.cmd_tx
            .send(Command::Quit(message.map(|s| s.to_string())))
            .await?;
        Ok(())
    }

    pub async fn raw(&self, line: &str) -> Result<()> {
        self.cmd_tx.send(Command::Raw(line.to_string())).await?;
        Ok(())
    }

    /// Send a message with IRCv3 tags (for rich media).
    pub async fn send_tagged(
        &self,
        target: &str,
        text: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let msg = crate::irc::Message {
            tags,
            prefix: None,
            command: "PRIVMSG".to_string(),
            params: vec![target.to_string(), text.to_string()],
        };
        self.cmd_tx.send(Command::Raw(msg.to_string())).await?;
        Ok(())
    }

    /// Send a media attachment to a target (channel or user).
    pub async fn send_media(
        &self,
        target: &str,
        media: &crate::media::MediaAttachment,
    ) -> Result<()> {
        self.send_tagged(target, &media.fallback_text(), media.to_tags()).await
    }

    /// Send a TAGMSG (tags-only, no body) to a target.
    pub async fn send_tagmsg(
        &self,
        target: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let msg = crate::irc::Message {
            tags,
            prefix: None,
            command: "TAGMSG".to_string(),
            params: vec![target.to_string()],
        };
        self.cmd_tx.send(Command::Raw(msg.to_string())).await?;
        Ok(())
    }

    /// Send a reaction to a target (channel or user).
    /// Falls back to PRIVMSG for plain clients.
    pub async fn send_reaction(
        &self,
        target: &str,
        reaction: &crate::media::Reaction,
    ) -> Result<()> {
        self.send_tagmsg(target, reaction.to_tags()).await
    }

    /// Send a link preview as a tagged message.
    pub async fn send_link_preview(
        &self,
        target: &str,
        preview: &crate::media::LinkPreview,
    ) -> Result<()> {
        let fallback = match (&preview.title, &preview.description) {
            (Some(t), Some(d)) => format!("🔗 {} — {} ({})", t, d, preview.url),
            (Some(t), None) => format!("🔗 {} ({})", t, preview.url),
            _ => format!("🔗 {}", preview.url),
        };
        self.send_tagged(target, &fallback, preview.to_tags()).await
    }
}

/// Connect to an IRC server and run the client.
///
/// Returns a handle for sending commands and a receiver for events.
/// The connection runs in a spawned task.
pub fn connect(
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let (event_tx, event_rx) = mpsc::channel(256);
    let (cmd_tx, cmd_rx) = mpsc::channel(64);

    let handle = ClientHandle {
        cmd_tx: cmd_tx.clone(),
    };

    tokio::spawn(async move {
        if let Err(e) = run_client(config, signer, event_tx.clone(), cmd_rx).await {
            let _ = event_tx
                .send(Event::Disconnected {
                    reason: e.to_string(),
                })
                .await;
        }
    });

    (handle, event_rx)
}

async fn run_client(
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    event_tx: mpsc::Sender<Event>,
    cmd_rx: mpsc::Receiver<Command>,
) -> Result<()> {
    // Auto-detect TLS from port if not explicitly set
    let use_tls = config.tls || config.server_addr.ends_with(":6697");
    let mode = if use_tls { "TLS" } else { "plain" };

    eprintln!("  Resolving {}...", config.server_addr);
    let tcp = TcpStream::connect(&config.server_addr).await
        .map_err(|e| anyhow::anyhow!("TCP connect to {} failed: {e}", config.server_addr))?;
    eprintln!("  TCP connected to {} ({mode})", config.server_addr);

    if use_tls {
        let tls_config = if config.tls_insecure {
            eprintln!("  TLS: insecure mode (skipping cert verification)");
            rustls_insecure_config()
        } else {
            eprintln!("  TLS: verifying server certificate...");
            rustls_default_config()
        };
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = config
            .server_addr
            .split(':')
            .next()
            .unwrap_or("localhost");
        let dns_name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
        let tls_stream = connector.connect(dns_name, tcp).await
            .map_err(|e| anyhow::anyhow!("TLS handshake with {} failed: {e}", config.server_addr))?;
        eprintln!("  TLS handshake complete");
        let _ = event_tx.send(Event::Connected).await;
        let (reader, writer) = tokio::io::split(tls_stream);
        run_irc(BufReader::new(reader), writer, &config, signer, event_tx, cmd_rx).await
    } else {
        let _ = event_tx.send(Event::Connected).await;
        let (reader, writer) = tokio::io::split(tcp);
        run_irc(BufReader::new(reader), writer, &config, signer, event_tx, cmd_rx).await
    }
}

fn rustls_default_config() -> rustls::ClientConfig {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn rustls_insecure_config() -> rustls::ClientConfig {
    
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth()
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn run_irc<R, W>(
    mut reader: R,
    mut writer: W,
    config: &ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
    event_tx: mpsc::Sender<Event>,
    mut cmd_rx: mpsc::Receiver<Command>,
) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Always negotiate capabilities (message-tags, and optionally sasl)
    eprintln!("  Sending CAP LS, NICK, USER...");
    writer.write_all(b"CAP LS 302\r\n").await?;

    writer
        .write_all(format!("NICK {}\r\n", config.nick).as_bytes())
        .await?;
    writer
        .write_all(format!("USER {} 0 * :{}\r\n", config.user, config.realname).as_bytes())
        .await?;

    let mut sasl_in_progress = false;
    let mut line_buf = String::new();
    let mut last_activity = tokio::time::Instant::now();
    let ping_interval = tokio::time::Duration::from_secs(60);
    let ping_timeout = tokio::time::Duration::from_secs(120);

    loop {
        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                let n = result?;
                if n == 0 {
                    let _ = event_tx.send(Event::Disconnected { reason: "EOF".to_string() }).await;
                    break;
                }

                last_activity = tokio::time::Instant::now();
                let raw = line_buf.trim_end().to_string();
                let _ = event_tx.send(Event::RawLine(raw.clone())).await;

                if let Some(msg) = Message::parse(&line_buf) {
                    match msg.command.as_str() {
                        "CAP" => {
                            handle_cap_response(&msg, &signer, &mut writer, &mut sasl_in_progress).await?;
                        }
                        "AUTHENTICATE" => {
                            if let Some(ref signer) = signer {
                                handle_authenticate_challenge(&msg, signer.as_ref(), &mut writer).await?;
                            }
                        }
                        "903" => {
                            sasl_in_progress = false;
                            eprintln!("  SASL authentication successful!");
                            if let Some(ref signer) = signer {
                                let _ = event_tx.send(Event::Authenticated { did: signer.did().to_string() }).await;
                            }
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "904" => {
                            sasl_in_progress = false;
                            let reason = msg.params.get(1).cloned().unwrap_or_else(|| "Unknown".to_string());
                            eprintln!("  SASL authentication FAILED: {reason}");
                            let _ = event_tx.send(Event::AuthFailed { reason }).await;
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "001" => {
                            let nick = msg.params.first().cloned().unwrap_or_default();
                            eprintln!("  Registered as {nick}");
                            let _ = event_tx.send(Event::Registered { nick }).await;
                        }
                        "353" => {
                            if msg.params.len() >= 4 {
                                let channel = msg.params[2].clone();
                                let nicks: Vec<String> = msg.params[3].split_whitespace().map(|s| s.to_string()).collect();
                                let _ = event_tx.send(Event::Names { channel, nicks }).await;
                            }
                        }
                        "PING" => {
                            let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                            writer.write_all(format!("PONG :{token}\r\n").as_bytes()).await?;
                        }
                        "JOIN" => {
                            let channel = msg.params.first().cloned().unwrap_or_default();
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let _ = event_tx.send(Event::Joined { channel, nick }).await;
                        }
                        "PART" => {
                            let channel = msg.params.first().cloned().unwrap_or_default();
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let _ = event_tx.send(Event::Parted { channel, nick }).await;
                        }
                        // MODE change
                        "MODE" => {
                            if msg.params.len() >= 2 {
                                let target = &msg.params[0];
                                if target.starts_with('#') || target.starts_with('&') {
                                    let mode = msg.params[1].clone();
                                    let arg = msg.params.get(2).cloned();
                                    let set_by = msg.prefix.as_deref()
                                        .and_then(|p| p.split('!').next())
                                        .unwrap_or("server")
                                        .to_string();
                                    let _ = event_tx.send(Event::ModeChanged {
                                        channel: target.clone(),
                                        mode,
                                        arg,
                                        set_by,
                                    }).await;
                                }
                            }
                        }
                        // KICK
                        "KICK" => {
                            if msg.params.len() >= 2 {
                                let channel = msg.params[0].clone();
                                let kicked_nick = msg.params[1].clone();
                                let reason = msg.params.get(2).cloned().unwrap_or_default();
                                let by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("server")
                                    .to_string();
                                let _ = event_tx.send(Event::Kicked {
                                    channel,
                                    nick: kicked_nick,
                                    by,
                                    reason,
                                }).await;
                            }
                        }
                        // INVITE
                        "INVITE" => {
                            if msg.params.len() >= 2 {
                                let channel = msg.params[1].clone();
                                let by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("someone")
                                    .to_string();
                                let _ = event_tx.send(Event::Invited { channel, by }).await;
                            }
                        }
                        // TOPIC (live change from another user)
                        "TOPIC" => {
                            if let Some(channel) = msg.params.first() {
                                let topic = msg.params.get(1).cloned().unwrap_or_default();
                                let set_by = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .map(|s| s.to_string());
                                let _ = event_tx.send(Event::TopicChanged {
                                    channel: channel.clone(),
                                    topic,
                                    set_by,
                                }).await;
                            }
                        }
                        // RPL_TOPIC (on join or TOPIC query)
                        "332" => {
                            if msg.params.len() >= 3 {
                                let channel = msg.params[1].clone();
                                let topic = msg.params[2].clone();
                                let _ = event_tx.send(Event::TopicChanged {
                                    channel,
                                    topic,
                                    set_by: None,
                                }).await;
                            }
                        }
                        "331" => {
                            // RPL_NOTOPIC — no topic set, ignore or clear
                        }
                        "333" => {
                            // RPL_TOPICWHOTIME — ignore for now (info only)
                        }
                        // WHOIS numerics
                        "311" => {
                            // RPL_WHOISUSER: <nick> <user> <host> * :<realname>
                            if msg.params.len() >= 5 {
                                let nick = msg.params[1].clone();
                                let user = &msg.params[2];
                                let host = &msg.params[3];
                                let realname = &msg.params[4]; // skip the "*" at [3] — it's actually nick user host * :realname
                                let info = format!("{nick} is {user}@{host} ({realname})");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "312" => {
                            // RPL_WHOISSERVER: <nick> <server> :<server info>
                            if msg.params.len() >= 4 {
                                let nick = msg.params[1].clone();
                                let server = &msg.params[2];
                                let info_text = &msg.params[3];
                                let info = format!("{nick} using {server} ({info_text})");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "319" => {
                            // RPL_WHOISCHANNELS: <nick> :<channels>
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let info = format!("{nick} on {}", msg.params[2]);
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "330" => {
                            // RPL_WHOISACCOUNT: <nick> <account> :is logged in as
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let account = &msg.params[2];
                                let label = msg.params.get(3).map(|s| s.as_str()).unwrap_or("is authenticated as");
                                let info = format!("{nick} {label} {account}");
                                let _ = event_tx.send(Event::WhoisReply { nick, info }).await;
                            }
                        }
                        "318" => {
                            // RPL_ENDOFWHOIS — ignore silently
                        }
                        "401" => {
                            // ERR_NOSUCHNICK
                            if msg.params.len() >= 3 {
                                let nick = msg.params[1].clone();
                                let _ = event_tx.send(Event::WhoisReply {
                                    nick: nick.clone(),
                                    info: format!("{nick}: No such nick"),
                                }).await;
                            }
                        }
                        "QUIT" => {
                            let nick = msg.prefix.as_deref()
                                .and_then(|p| p.split('!').next())
                                .unwrap_or("")
                                .to_string();
                            let reason = msg.params.first().cloned().unwrap_or_default();
                            let _ = event_tx.send(Event::UserQuit { nick, reason }).await;
                        }
                        "PRIVMSG" | "NOTICE" => {
                            if msg.params.len() >= 2 {
                                let from = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("")
                                    .to_string();
                                let target = msg.params[0].clone();
                                let text = msg.params[1].clone();
                                let tags = msg.tags.clone();
                                let _ = event_tx.send(Event::Message { from, target, text, tags }).await;
                            }
                        }
                        "TAGMSG" => {
                            if !msg.params.is_empty() {
                                let from = msg.prefix.as_deref()
                                    .and_then(|p| p.split('!').next())
                                    .unwrap_or("")
                                    .to_string();
                                let target = msg.params[0].clone();
                                let _ = event_tx.send(Event::TagMsg { from, target, tags: msg.tags.clone() }).await;
                            }
                        }
                        _ => {}
                    }
                }

                line_buf.clear();
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    Command::Join(channel) => {
                        writer.write_all(format!("JOIN {channel}\r\n").as_bytes()).await?;
                    }
                    Command::Privmsg { target, text } => {
                        writer.write_all(format!("PRIVMSG {target} :{text}\r\n").as_bytes()).await?;
                    }
                    Command::Raw(line) => {
                        writer.write_all(format!("{line}\r\n").as_bytes()).await?;
                    }
                    Command::Quit(msg) => {
                        let quit_line = match msg {
                            Some(m) => format!("QUIT :{m}\r\n"),
                            None => "QUIT\r\n".to_string(),
                        };
                        writer.write_all(quit_line.as_bytes()).await?;
                        break;
                    }
                }
            }
            // Periodic client-to-server PING and timeout detection
            _ = tokio::time::sleep_until(last_activity + ping_interval) => {
                if last_activity.elapsed() > ping_timeout {
                    let _ = event_tx.send(Event::Disconnected { reason: "Ping timeout".to_string() }).await;
                    break;
                }
                writer.write_all(b"PING :keepalive\r\n").await?;
            }
        }
    }

    Ok(())
}

async fn handle_cap_response<W: AsyncWrite + Unpin>(
    msg: &Message,
    signer: &Option<Arc<dyn ChallengeSigner>>,
    writer: &mut W,
    sasl_in_progress: &mut bool,
) -> Result<()> {
    let subcmd = msg.params.get(1).map(|s| s.to_ascii_uppercase());
    match subcmd.as_deref() {
        Some("LS") => {
            let caps_str = msg.params.last().map(|s| s.as_str()).unwrap_or("");
            eprintln!("  Server capabilities: {caps_str}");
            let mut req_caps = Vec::new();
            if caps_str.contains("message-tags") {
                req_caps.push("message-tags");
            }
            if caps_str.contains("sasl") && signer.is_some() {
                req_caps.push("sasl");
            }
            if req_caps.is_empty() {
                eprintln!("  No caps to request, sending CAP END");
                writer.write_all(b"CAP END\r\n").await?;
            } else {
                eprintln!("  Requesting: {}", req_caps.join(" "));
                let req = format!("CAP REQ :{}\r\n", req_caps.join(" "));
                writer.write_all(req.as_bytes()).await?;
            }
        }
        Some("ACK") => {
            let caps = msg.params.last().map(|s| s.as_str()).unwrap_or("");
            eprintln!("  Capabilities acknowledged: {caps}");
            if caps.contains("sasl") {
                *sasl_in_progress = true;
                eprintln!("  Starting SASL ATPROTO-CHALLENGE...");
                writer
                    .write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
                    .await?;
            } else {
                // Got message-tags but no sasl (or no signer) — done with CAP
                eprintln!("  No SASL needed, sending CAP END");
                writer.write_all(b"CAP END\r\n").await?;
            }
        }
        Some("NAK") => {
            eprintln!("  Capabilities rejected, sending CAP END");
            writer.write_all(b"CAP END\r\n").await?;
        }
        _ => {}
    }
    Ok(())
}

async fn handle_authenticate_challenge<W: AsyncWrite + Unpin>(
    msg: &Message,
    signer: &dyn ChallengeSigner,
    writer: &mut W,
) -> Result<()> {
    let encoded_challenge = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    eprintln!("  Received SASL challenge ({} bytes encoded)", encoded_challenge.len());

    // Decode the challenge to raw bytes — these are what we sign
    let challenge_bytes = auth::decode_challenge_bytes(encoded_challenge)?;
    eprintln!("  Challenge decoded ({} bytes), signing with {}...", challenge_bytes.len(), signer.did());

    // Produce the response using the signer
    let response = signer.respond(&challenge_bytes)?;
    let encoded = auth::encode_response(&response);
    eprintln!("  Sending AUTHENTICATE response ({} bytes)", encoded.len());

    writer
        .write_all(format!("AUTHENTICATE {encoded}\r\n").as_bytes())
        .await?;

    Ok(())
}
