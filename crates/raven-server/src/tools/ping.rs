//! ICMP ping handler — verifies target connectivity and measures latency.
//!
//! This is typically the first tool invoked in a pentest session. Unlike other
//! tools, ping bypasses [`executor::run`](raven_core::executor::run) and
//! spawns the process directly, since it only needs basic timeout containment
//! and output truncation (no quality assessment or proxy injection needed).
//!
//! Safety layers: allowlist check → target validation → argument clamping →
//! timeout containment → output truncation.

use raven_core::{config::RavenConfig, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use tokio::process::Command;

/// MCP request schema for `ping_target`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PingRequest {
    #[schemars(description = "Target IP address or hostname")]
    pub target: String,
    #[schemars(description = "Number of ping packets (1-10), default 4)")]
    pub count: Option<u8>,
}

/// Run ping against the target and return the output.
pub async fn run(
    config: &RavenConfig,
    req: PingRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::check_allowlist("ping", &config.safety).map_err(crate::error::to_mcp)?;
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // Clamp packet count to prevent abuse (1-10 range)
    let count = req.count.unwrap_or(4).clamp(1, 10);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(config.execution.default_timeout_secs),
        Command::new("ping")
            .args(["-c", &count.to_string(), &req.target])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        rmcp::ErrorData::new(
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "ping timed out",
            None,
        )
    })?
    .map_err(|e| {
        rmcp::ErrorData::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e.to_string(), None)
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let result = if output.status.success() {
        safety::truncate_output(&stdout, config.safety.max_output_chars)
    } else {
        format!("ping failed (exit {}):\n{stderr}", output.status)
    };

    Ok(CallToolResult::success(vec![Content::text(result)]))
}
