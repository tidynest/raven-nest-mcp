//! WhatWeb technology identification handler.
//!
//! WhatWeb identifies web technologies (CMS, frameworks, servers, JS libraries)
//! from HTTP responses. Three aggression levels control how much probing is done:
//! - `stealthy` (default, level 1) — single request, passive analysis.
//! - `passive` (level 2) — follows redirects, parses additional pages.
//! - `aggressive` (level 4) — actively probes with extra requests.
//!
//! This is a fast tool (1-5s) and doesn't require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_whatweb`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WhatwebRequest {
    #[schemars(description = "Target URL or hostname")]
    pub target: String,
    #[schemars(description = "Aggression: 'stealthy', 'passive', 'aggressive'")]
    pub aggression: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
}

/// Execute whatweb with the specified aggression level.
pub async fn run(
    config: &RavenConfig,
    req: WhatwebRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // Map aggression names to whatweb's numeric -a levels
    let level = match req.aggression.as_deref() {
        Some("passive") => "2",
        Some("aggressive") => "4",
        _ => "1", // stealthy (default)
    };

    let mut args = vec!["-a".to_string(), level.into(), "--color=never".into(), req.target];
    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "whatweb", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("whatweb", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
