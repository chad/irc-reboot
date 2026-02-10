use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("irc_server=info".parse()?))
        .init();

    let config = irc_server::config::ServerConfig::parse();
    tracing::info!("Starting IRC server on {}", config.listen_addr);
    if config.tls_enabled() {
        tracing::info!("TLS enabled on {}", config.tls_listen_addr);
    }

    let server = irc_server::server::Server::new(config);
    server.run().await
}
