//! Entry point for the Raven Nest MCP server.
//!
//! Initialises the tracing subscriber (logs to stderr, no ANSI — safe for
//! stdio-based MCP transport), loads config via the fallback chain in
//! [`RavenConfig::load_with_fallback`](raven_core::config::RavenConfig::load_with_fallback),
//! and starts the MCP server over stdio.

use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{self, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so they don't interfere with the stdio MCP transport
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Raven Nest MCP server starting");

    let config = raven_core::config::RavenConfig::load_with_fallback();

    let service = raven_server::server::RavenServer::new(config);

    // Serve MCP over stdin/stdout and block until the client disconnects
    service.serve(stdio()).await?.waiting().await?;

    Ok(())
}
