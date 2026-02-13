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

    /// Allowed S2S peer endpoint IDs. If set, only these peers can connect.
    /// If empty (default), any peer can connect (open federation).
    /// Comma-separated list of hex endpoint IDs.
    #[arg(long, value_delimiter = ',')]
    pub s2s_allowed_peers: Vec<String>,

    /// Data directory for server state files (iroh key, etc.).
    /// Defaults to the directory containing --db-path, or current directory.
    #[arg(long)]
    pub data_dir: Option<String>,

    /// Maximum messages to retain per channel in the database.
    /// When exceeded, oldest messages are pruned. 0 = unlimited.
    #[arg(long, default_value = "10000")]
    pub max_messages_per_channel: usize,

    /// Message of the Day text. If not set, no MOTD is sent.
    #[arg(long)]
    pub motd: Option<String>,

    /// Directory containing web client static files (index.html, etc.).
    /// If set, files are served at the root path (/) of the web listener.
    /// Typically points to the freeq-web/ directory.
    #[arg(long)]
    pub web_static_dir: Option<String>,

    /// Plugins to load. Format: "name" or "name:key=val,key2=val2".
    /// Can be specified multiple times.
    #[arg(long = "plugin")]
    pub plugins: Vec<String>,

    /// Directory containing plugin config files (*.toml).
    /// Each TOML file defines one plugin and its configuration.
    #[arg(long)]
    pub plugin_dir: Option<String>,
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
            s2s_allowed_peers: vec![],
            data_dir: None,
            max_messages_per_channel: 10000,
            motd: None,
            web_static_dir: None,
            plugins: vec![],
            plugin_dir: None,
        }
    }
}

impl ServerConfig {
    /// Returns true if TLS is configured.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// Resolve the data directory for state files.
    /// Priority: --data-dir > parent of --db-path > current directory.
    pub fn data_dir(&self) -> std::path::PathBuf {
        if let Some(ref dir) = self.data_dir {
            std::path::PathBuf::from(dir)
        } else if let Some(ref db_path) = self.db_path {
            std::path::Path::new(db_path)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        } else {
            std::path::PathBuf::from(".")
        }
    }
}
