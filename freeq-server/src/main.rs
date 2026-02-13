use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider before any TLS usage.
    // Iroh brings in ring, but rustls needs an explicit provider selection.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("freeq_server=info".parse()?))
        .init();

    let config = freeq_server::config::ServerConfig::parse();
    tracing::info!("Starting IRC server on {}", config.listen_addr);
    if config.tls_enabled() {
        tracing::info!("TLS enabled on {}", config.tls_listen_addr);
    }
    if let Some(ref web_addr) = config.web_addr {
        tracing::info!("HTTP/WebSocket enabled on {web_addr}");
    }
    if config.iroh {
        tracing::info!("Iroh transport enabled");
    }

    let server = freeq_server::server::Server::new(config);
    server.run().await
}
