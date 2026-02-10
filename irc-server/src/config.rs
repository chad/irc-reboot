use clap::Parser;

/// IRC server with AT Protocol SASL authentication.
#[derive(Parser, Debug, Clone)]
#[command(name = "irc-server", version, about)]
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
    #[arg(long, default_value = "irc-reboot")]
    pub server_name: String,

    /// Challenge validity window in seconds.
    #[arg(long, default_value = "60")]
    pub challenge_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:6667".to_string(),
            tls_listen_addr: "127.0.0.1:6697".to_string(),
            tls_cert: None,
            tls_key: None,
            server_name: "irc-reboot".to_string(),
            challenge_timeout_secs: 60,
        }
    }
}

impl ServerConfig {
    /// Returns true if TLS is configured.
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}
