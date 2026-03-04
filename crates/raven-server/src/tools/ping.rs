use raven_core::{config::RavenConfig, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use tokio::process::Command;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PingRequest {
    #[schemars(description = "Target IP address or hostname")]
    pub target: String,
    #[schemars(description = "Number of ping packets (1-10), default 4)")]
    pub count: Option<u8>,
}

pub async fn run(
    config: &RavenConfig,
    req: PingRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Layer 1: allowlist
    safety::check_allowlist("ping", &config.safety).map_err(crate::error::to_mcp)?;

    // Layer 2: input validation
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let count = req.count.unwrap_or(4).clamp(1, 10);

    // Layer 3+4: argument building + execution containment
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
        // Layer 5: output sanitisation
        safety::truncate_output(&stdout, config.safety.max_output_chars)
    } else {
        format!("ping failed (exit {}):\n{stderr}", output.status)
    };

    Ok(CallToolResult::success(vec![Content::text(result)]))
}
