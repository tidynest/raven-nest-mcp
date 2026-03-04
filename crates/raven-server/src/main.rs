use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{self, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Raven Nest MCP server starting");

    let config = raven_core::config::RavenConfig::load_with_fallback();

    let service = raven_server::server::RavenServer::new(config);

    service.serve(stdio()).await?.waiting().await?;

    Ok(())
}
