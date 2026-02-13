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

/// Establish TCP (and optionally TLS) connection to the server.
///
/// This is done **before** the TUI starts so that connection errors
/// are visible on stderr. Returns the established connection for
/// `connect_with_stream` to use.
pub async fn establish_connection(
    config: &ConnectConfig,
) -> Result<EstablishedConnection> {
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
        Ok(EstablishedConnection::Tls(tls_stream))
    } else {
        Ok(EstablishedConnection::Plain(tcp))
    }
}

/// A connection that has completed TCP (and optionally TLS) but hasn't
/// started IRC registration yet.
pub enum EstablishedConnection {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    /// Iroh QUIC connection (already encrypted, NAT-traversing).
    Iroh(tokio::io::DuplexStream),
}

/// ALPN for IRC-over-iroh (must match server).
pub const IROH_ALPN: &[u8] = b"freeq/iroh/1";

/// Establish a connection to an IRC server via iroh.
///
/// `addr` is the iroh endpoint address string (EndpointAddr format).
pub async fn establish_iroh_connection(addr: &str) -> Result<EstablishedConnection> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    eprintln!("  Creating iroh endpoint...");
    let endpoint = iroh::Endpoint::bind().await?;

    eprintln!("  Connecting to iroh peer {addr}...");
    // Parse the endpoint ID (public key) and create an address.
    // Iroh's relay/discovery system handles finding the actual network path.
    let endpoint_id: iroh::EndpointId = addr.parse()
        .map_err(|e| anyhow::anyhow!("Invalid iroh endpoint ID '{addr}': {e}"))?;
    let endpoint_addr = iroh::EndpointAddr::new(endpoint_id);
    let conn = endpoint.connect(endpoint_addr, IROH_ALPN).await?;
    eprintln!("  Iroh QUIC connection established (encrypted)");

    let (send, recv) = conn.open_bi().await
        .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {e}"))?;
    eprintln!("  Bidirectional stream open, ready for IRC");

    // Bridge QUIC send/recv to a DuplexStream that the IRC handler can use.
    // irc_side goes to the IRC protocol handler.
    // bridge_side is shuttled to/from QUIC by two background tasks.
    let (irc_side, bridge_side) = tokio::io::duplex(16384);
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);

    // QUIC recv → bridge_write → IRC handler reads from irc_side
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
    });

    // IRC handler writes to irc_side → bridge_read → QUIC send
    tokio::spawn(async move {
        let mut send = send;
        let mut buf = vec![0u8; 4096];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
        let _ = send.finish();
    });

    // Keep endpoint + connection alive for the lifetime of the session
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let _conn = conn;
        loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; }
    });

    Ok(EstablishedConnection::Iroh(irc_side))
}

/// Probe an IRC server for iroh endpoint ID via CAP LS.
///
/// Connects via TCP (or TLS for port 6697), sends CAP LS, reads the response,
/// extracts `iroh=<endpoint-id>` if present, and disconnects cleanly.
/// Returns `None` if the server doesn't advertise iroh.
///
/// This enables automatic iroh transport upgrade: connect cheap (TCP),
/// discover capabilities, reconnect optimal (iroh QUIC).
pub async fn discover_iroh_id(server_addr: &str, tls: bool, tls_insecure: bool) -> Option<String> {
    use tokio::time::timeout;
    use std::time::Duration;

    let use_tls = tls || server_addr.ends_with(":6697");

    // Give the probe 5 seconds max
    let result = timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect(server_addr).await.ok()?;

        if use_tls {
            let tls_config = if tls_insecure {
                rustls_insecure_config()
            } else {
                rustls_default_config()
            };
            let connector = TlsConnector::from(Arc::new(tls_config));
            let host = server_addr.split(':').next().unwrap_or("localhost");
            let dns_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
            let tls_stream = connector.connect(dns_name, tcp).await.ok()?;
            probe_cap_ls(tls_stream).await
        } else {
            probe_cap_ls(tcp).await
        }
    }).await;

    result.ok().flatten()
}

/// Send CAP LS and parse iroh endpoint ID from response.
async fn probe_cap_ls<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: S) -> Option<String> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Send CAP LS and a throwaway NICK/USER so the server doesn't time us out
    writer.write_all(b"CAP LS 302\r\nNICK _probe\r\nUSER _probe 0 * :probe\r\n").await.ok()?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.ok()?;
        if n == 0 { return None; }

        // Look for CAP * LS :...
        if line.contains("CAP") && line.contains("LS") {
            // Find iroh=<id> in the caps string
            for token in line.split_whitespace() {
                if let Some(id) = token.strip_prefix("iroh=") {
                    // Clean up: send QUIT
                    let _ = writer.write_all(b"QUIT\r\n").await;
                    let _ = writer.shutdown().await;
                    return Some(id.trim().to_string());
                }
            }
            // Server responded to CAP LS but no iroh — done
            let _ = writer.write_all(b"QUIT\r\n").await;
            let _ = writer.shutdown().await;
            return None;
        }
    }
}

/// Connect using an already-established connection.
///
/// Returns a handle for sending commands and a receiver for events.
/// The IRC protocol runs in a spawned task.
pub fn connect_with_stream(
    conn: EstablishedConnection,
    config: ConnectConfig,
    signer: Option<Arc<dyn ChallengeSigner>>,
) -> (ClientHandle, mpsc::Receiver<Event>) {
    let (event_tx, event_rx) = mpsc::channel(256);
    let (cmd_tx, cmd_rx) = mpsc::channel(64);

    let handle = ClientHandle {
        cmd_tx: cmd_tx.clone(),
    };

    tokio::spawn(async move {
        let _ = event_tx.send(Event::Connected).await;
        let result = match conn {
            EstablishedConnection::Plain(tcp) => {
                let (reader, writer) = tokio::io::split(tcp);
                run_irc(BufReader::new(reader), writer, &config, signer, event_tx.clone(), cmd_rx).await
            }
            EstablishedConnection::Tls(tls) => {
                let (reader, writer) = tokio::io::split(tls);
                run_irc(BufReader::new(reader), writer, &config, signer, event_tx.clone(), cmd_rx).await
            }
            EstablishedConnection::Iroh(duplex) => {
                let (reader, writer) = tokio::io::split(duplex);
                run_irc(BufReader::new(reader), writer, &config, signer, event_tx.clone(), cmd_rx).await
            }
        };
        if let Err(e) = result {
            let _ = event_tx
                .send(Event::Disconnected {
                    reason: e.to_string(),
                })
                .await;
        }
    });

    (handle, event_rx)
}

/// Connect to an IRC server and run the client.
///
/// Returns a handle for sending commands and a receiver for events.
/// The connection runs in a spawned task.
///
/// Note: prefer `establish_connection` + `connect_with_stream` for better
/// error reporting (connection errors happen before the TUI starts).
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
    let conn = establish_connection(&config).await?;
    let _ = event_tx.send(Event::Connected).await;
    match conn {
        EstablishedConnection::Plain(tcp) => {
            let (reader, writer) = tokio::io::split(tcp);
            run_irc(BufReader::new(reader), writer, &config, signer, event_tx, cmd_rx).await
        }
        EstablishedConnection::Tls(tls) => {
            let (reader, writer) = tokio::io::split(tls);
            run_irc(BufReader::new(reader), writer, &config, signer, event_tx, cmd_rx).await
        }
        EstablishedConnection::Iroh(duplex) => {
            let (reader, writer) = tokio::io::split(duplex);
            run_irc(BufReader::new(reader), writer, &config, signer, event_tx, cmd_rx).await
        }
    }
}

fn rustls_default_config() -> rustls::ClientConfig {
    // Ensure ring crypto provider is installed (iroh brings in ring,
    // which can conflict with rustls auto-detection).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn rustls_insecure_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
    writer.write_all(b"CAP LS 302\r\n").await?;

    writer
        .write_all(format!("NICK {}\r\n", config.nick).as_bytes())
        .await?;
    writer
        .write_all(format!("USER {} 0 * :{}\r\n", config.user, config.realname).as_bytes())
        .await?;

    let mut sasl_in_progress = false;
    let mut registered = false;
    let mut pending_commands: Vec<Command> = Vec::new();
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
                            // eprintln!("  SASL authentication successful!");
                            if let Some(ref signer) = signer {
                                let _ = event_tx.send(Event::Authenticated { did: signer.did().to_string() }).await;
                            }
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "904" => {
                            sasl_in_progress = false;
                            let reason = msg.params.get(1).cloned().unwrap_or_else(|| "Unknown".to_string());
                            // eprintln!("  SASL authentication FAILED: {reason}");
                            let _ = event_tx.send(Event::AuthFailed { reason }).await;
                            writer.write_all(b"CAP END\r\n").await?;
                        }
                        "001" => {
                            let nick = msg.params.first().cloned().unwrap_or_default();
                            let _ = event_tx.send(Event::Registered { nick }).await;
                            registered = true;
                            // Flush any commands that were queued before registration
                            for cmd in pending_commands.drain(..) {
                                execute_command(&mut writer, cmd).await?;
                            }
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
                if registered || matches!(cmd, Command::Quit(_)) {
                    execute_command(&mut writer, cmd).await?;
                    if !registered {
                        break; // Quit before registration
                    }
                } else {
                    // Queue until registered — commands silently wait
                    pending_commands.push(cmd);
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

/// Execute a single IRC command on the wire.
async fn execute_command<W: AsyncWrite + Unpin>(writer: &mut W, cmd: Command) -> Result<()> {
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
            // eprintln!("  Server capabilities: {caps_str}");
            let mut req_caps = Vec::new();
            if caps_str.contains("message-tags") {
                req_caps.push("message-tags");
            }
            if caps_str.contains("sasl") && signer.is_some() {
                req_caps.push("sasl");
            }
            if req_caps.is_empty() {
                // eprintln!("  No caps to request, sending CAP END");
                writer.write_all(b"CAP END\r\n").await?;
            } else {
                // eprintln!("  Requesting: {}", req_caps.join(" "));
                let req = format!("CAP REQ :{}\r\n", req_caps.join(" "));
                writer.write_all(req.as_bytes()).await?;
            }
        }
        Some("ACK") => {
            let caps = msg.params.last().map(|s| s.as_str()).unwrap_or("");
            // eprintln!("  Capabilities acknowledged: {caps}");
            if caps.contains("sasl") {
                *sasl_in_progress = true;
                // eprintln!("  Starting SASL ATPROTO-CHALLENGE...");
                writer
                    .write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n")
                    .await?;
            } else {
                // Got message-tags but no sasl (or no signer) — done with CAP
                // eprintln!("  No SASL needed, sending CAP END");
                writer.write_all(b"CAP END\r\n").await?;
            }
        }
        Some("NAK") => {
            // eprintln!("  Capabilities rejected, sending CAP END");
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
    // eprintln!("  Received SASL challenge ({} bytes encoded)", encoded_challenge.len());

    // Decode the challenge to raw bytes — these are what we sign
    let challenge_bytes = auth::decode_challenge_bytes(encoded_challenge)?;
    // eprintln!("  Challenge decoded ({} bytes), signing with {}...", challenge_bytes.len(), signer.did());

    // Produce the response using the signer
    let response = signer.respond(&challenge_bytes)?;
    let encoded = auth::encode_response(&response);
    // eprintln!("  Sending AUTHENTICATE response ({} bytes)", encoded.len());

    writer
        .write_all(format!("AUTHENTICATE {encoded}\r\n").as_bytes())
        .await?;

    Ok(())
}
