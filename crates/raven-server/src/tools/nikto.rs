//! Nikto web server scanner handler.
//!
//! Nikto performs comprehensive tests against web servers for dangerous files,
//! outdated software, and configuration issues. Supports four tuning presets:
//! `quick` (default), `thorough`, `injection`, and `fileupload`.
//!
//! Special handling: nikto v2.6+ rejects `-p` (port flag) when given a full URL,
//! so the port argument is only added for bare hostnames.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{Peer, RoleServer};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_nikto`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NiktoRequest {
    #[schemars(description = "Target hostname or URL")]
    pub target: String,
    #[schemars(description = "Port to scan (default 80)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub port: Option<u16>,
    #[schemars(description = "Tuning: 'quick', 'thorough', 'injection', 'fileupload'")]
    pub tuning: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
    #[schemars(description = "Scan timeout in seconds (default 600)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute a nikto scan with tuning presets and version-aware argument building.
pub async fn run(
    config: &RavenConfig,
    req: NiktoRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "nikto".into(), req.target.clone())
    });

    let is_url = req.target.starts_with("http://") || req.target.starts_with("https://");
    let mut args = vec!["-h".to_string(), req.target, "-nocheck".into()];

    // nikto v2.6+ rejects -p alongside a full URI — only add it for bare hostnames
    if !is_url {
        let port = req.port.unwrap_or(80);
        args.extend(["-p".into(), port.to_string()]);
        // Auto-enable SSL for port 443
        if port == 443 {
            args.push("-ssl".into());
        }
    }

    if let Some(ref cookie) = req.cookie {
        args.extend(["-cookie".into(), cookie.clone()]);
    }

    // Tuning presets map to nikto's -T flag (test type bitmask)
    match req.tuning.as_deref() {
        Some("thorough") => args.extend(["-T".into(), "123456789abc".into()]),
        Some("injection") => args.extend(["-T".into(), "9".into()]),
        Some("fileupload") => args.extend(["-T".into(), "0".into()]),
        _ => args.extend(["-T".into(), "1234".into()]), // quick
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "nikto", &arg_refs, req.timeout_secs)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("nikto", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
