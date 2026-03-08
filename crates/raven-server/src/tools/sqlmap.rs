//! Sqlmap SQL injection detection and exploitation handler.
//!
//! Sqlmap tests URLs for SQL injection vulnerabilities. Runs in `--batch` mode
//! (no interactive prompts) with level/risk capped by [`SafetyConfig`](raven_core::config::SafetyConfig)
//! to prevent the LLM from escalating to destructive payloads.
//!
//! Supports POST data, cookies for authenticated testing, and technique selection
//! (`BEUSTQ` — Boolean, Error, Union, Stacked, Time-based, Query-based).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_sqlmap`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SqlmapRequest {
    #[schemars(description = "Target URL with injectable parameter")]
    pub url: String,
    #[schemars(description = "POST body data (e.g. 'user=test&pass=test')")]
    pub data: Option<String>,
    #[schemars(description = "Cookie string for authenticated testing")]
    pub cookie: Option<String>,
    #[schemars(description = "Test level 1-5 (default 1, capped by config)")]
    pub level: Option<u8>,
    #[schemars(description = "Risk level 1-3 (default 1, capped by config)")]
    pub risk: Option<u8>,
    #[schemars(description = "SQL injection techniques (e.g. 'BEUSTQ')")]
    pub technique: Option<String>,
}

/// Execute sqlmap with safety-capped level and risk parameters.
pub async fn run(
    config: &RavenConfig,
    req: SqlmapRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.url).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "sqlmap".into(), req.url.clone())
    });

    // Enforce config safety limits — prevents LLM from requesting dangerous levels
    let level = req
        .level
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_level);
    let risk = req
        .risk
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_risk);

    let mut args = vec![
        "-u".to_string(),
        req.url,
        "--batch".into(), // non-interactive mode
        "--level".into(),
        level.to_string(),
        "--risk".into(),
        risk.to_string(),
    ];

    if let Some(ref data) = req.data {
        args.extend(["--data".into(), data.clone()]);
    }

    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }

    if let Some(ref technique) = req.technique {
        args.extend(["--technique".into(), technique.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "sqlmap", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("sqlmap", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
