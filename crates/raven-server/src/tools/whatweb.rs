use raven_core::{config::RavenConfig, executor, safety};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WhatwebRequest {
    #[schemars(description = "Target URL or hostname")]
    pub target: String,
    #[schemars(description = "Aggression: 'stealthy', 'passive', 'aggressive'")]
    pub aggression: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: WhatwebRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let level = match req.aggression.as_deref() {
        Some("passive") => "2",
        Some("aggressive") => "4",
        _ => "1", // stealthy (default)
    };

    let args = ["-a", level, "--color=never", &req.target];
    let result = executor::run(config, "whatweb", &args, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("whatweb", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
