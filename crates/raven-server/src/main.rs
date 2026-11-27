//! Entry point for the Raven Nest MCP server.
//!
//! Initialises the tracing subscriber (logs to stderr, no ANSI - safe for
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
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Raven Nest MCP server starting");

    // A config file that exists but does not load stops the server: starting on
    // other settings than the operator wrote could run with the scope off.
    let config = match raven_core::config::RavenConfig::load_with_fallback() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        tracing::error!("invalid configuration: {e}");
        std::process::exit(1);
    }

    let service = raven_server::server::RavenServer::new(config);

    // Serve MCP over stdin/stdout and block until the client disconnects
    service.serve(stdio()).await?.waiting().await?;

    Ok(())
}
