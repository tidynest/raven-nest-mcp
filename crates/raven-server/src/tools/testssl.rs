//! testssl.sh SSL/TLS configuration auditing handler.
//!
//! Tests a server's TLS configuration for vulnerabilities, weak ciphers,
//! certificate issues, and protocol support. Supports quick mode (fewer checks)
//! and severity-based filtering.
//!
//! Note: `--fast` is deprecated in testssl.sh 3.2+, so quick mode uses
//! `--quiet --sneaky` instead.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_testssl`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestsslRequest {
    #[schemars(description = "Target hostname, host:port, or URL")]
    pub target: String,
    #[schemars(description = "Run in fast mode (fewer checks)")]
    pub quick: Option<bool>,
    #[schemars(description = "Severity filter: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")]
    pub severity: Option<String>,
}

/// Execute testssl.sh with optional quick mode and severity filtering.
pub async fn run(
    config: &RavenConfig,
    req: TestsslRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "testssl".into(), req.target.clone())
    });

    let mut args = Vec::new();

    if req.quick.unwrap_or(false) {
        // --fast is deprecated in testssl.sh 3.2+; use individual flags instead
        args.extend([
            "--quiet".to_string(),
            "--sneaky".into(),
        ]);
    }

    // Validate and apply severity filter (case-insensitive input)
    if let Some(ref sev) = req.severity {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        if valid.contains(&sev.to_uppercase().as_str()) {
            args.extend(["--severity".into(), sev.to_uppercase()]);
        }
    }

    args.push(req.target);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "testssl.sh", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("testssl.sh", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
