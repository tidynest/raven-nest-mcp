use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{self, EnvFilter};

mod tools;

pub mod server;
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Raven Nest MCP server starting");

    let config = raven_core::config::RavenConfig::load("config/default.toml")
        .unwrap_or_else(|e| {
            tracing::warn!("config load failed: ({e}), using defaults");
            raven_core::config::RavenConfig::default()
        });

    let service = server::RavenServer::new(config);

    service.serve(stdio()).await?.waiting().await?;

    Ok(())
}