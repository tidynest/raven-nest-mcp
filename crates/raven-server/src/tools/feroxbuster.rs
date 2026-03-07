//! Feroxbuster directory and content discovery handler.
//!
//! Feroxbuster brute-forces directories and files using a wordlist. Supports
//! file extension probing, thread count control, and HTTP status code filtering.
//!
//! Thread count defaults to 50 for remote targets but drops to 10 for localhost
//! (via [`is_localhost`](super::is_localhost)) to prevent self-DoS during local testing.
//! Maximum is capped at 200 regardless of input.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// Default wordlist path (SecLists raft-medium-directories).
const DEFAULT_WORDLIST: &str =
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt";

/// MCP request schema for `run_feroxbuster`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FeroxbusterRequest {
    #[schemars(description = "Target URL (e.g. 'http://example.com')")]
    pub target: String,
    #[schemars(description = "Path to wordlist file (default: raft-medium-directories.txt)")]
    pub wordlist: Option<String>,
    #[schemars(description = "File extensions to check (e.g. 'php,html,txt')")]
    pub extensions: Option<String>,
    #[schemars(description = "Number of concurrent threads (default 50)")]
    pub threads: Option<u16>,
    #[schemars(description = "HTTP status codes to include (e.g. '200,301,302')")]
    pub status_codes: Option<String>,
}

/// Execute feroxbuster for directory discovery.
pub async fn run(
    config: &RavenConfig,
    req: FeroxbusterRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "feroxbuster".into(), req.target.clone())
    });

    // Reduce threads for localhost to prevent self-DoS
    let default_threads: u16 = if super::is_localhost(&req.target) { 10 } else { 50 };
    let threads = req.threads.unwrap_or(default_threads).min(200);

    let wordlist = req.wordlist.as_deref().unwrap_or(DEFAULT_WORDLIST);
    let mut args = vec![
        "-u".to_string(),
        req.target,
        "-w".into(),
        wordlist.into(),
        "--no-state".into(),
        "-q".into(),
    ];

    if let Some(ref ext) = req.extensions {
        args.extend(["-x".into(), ext.clone()]);
    }
    args.extend(["-t".into(), threads.to_string()]);

    if let Some(ref codes) = req.status_codes {
        args.extend(["-s".into(), codes.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "feroxbuster", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("feroxbuster", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
