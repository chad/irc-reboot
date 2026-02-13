use clap::Parser;

/// freeq IRC server with AT Protocol SASL authentication.
#[derive(Parser, Debug, Clone)]
#[command(name = "freeq-server", version, about)]
pub struct ServerConfig {
    /// Plain TCP listener address.
    #[arg(long, default_value = "127.0.0.1:6667")]
    pub listen_addr: String,

    /// TLS listener address. Only active if --tls-cert and --tls-key are set.
    #[arg(long, default_value = "127.0.0.1:6697")]
    pub tls_listen_addr: String,

    /// Path to TLS certificate PEM file.
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// Path to TLS private key PEM file.
    #[arg(long)]
    pub tls_key: Option<String>,

    /// Server name used in IRC messages.
    #[arg(long, default_value = "freeq")]
    pub server_name: String,

    /// Challenge validity window in seconds.
    #[arg(long, default_value = "60")]
    pub challenge_timeout_secs: u64,

    /// Path to SQLite database file. If not set, uses in-memory storage (no persistence).
    #[arg(long)]
    pub db_path: Option<String>,

    /// HTTP/WebSocket listener address. Enables WebSocket IRC transport and REST API.
    /// If not set, no HTTP listener starts.
    #[arg(long)]
    pub web_addr: Option<String>,

    /// Enable iroh transport (QUIC-based, encrypted, NAT-traversing).
    /// The server's iroh endpoint address will be printed on startup.
    #[arg(long)]
    pub iroh: bool,

    /// UDP port for iroh transport. If not set, a random port is used.
    #[arg(long)]
    pub iroh_port: Option<u16>,

    /// S2S peer iroh endpoint IDs to connect to on startup.
    /// Comma-separated list of hex endpoint IDs.
    #[arg(long, value_delimiter = ',')]
    pub s2s_peers: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:6667".to_string(),
            tls_listen_addr: "127.0.0.1:6697".to_string(),
            tls_cert: None,
            tls_key: None,
            server_name: "freeq".to_string(),
            challenge_timeout_secs: 60,
            db_path: None,
            web_addr: None,
            iroh: false,
            iroh_port: None,
            s2s_peers: vec![],
        }
    }
}

impl ServerConfig {
    /// Returns true if TLS is configured.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}
