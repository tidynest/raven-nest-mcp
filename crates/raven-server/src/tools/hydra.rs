use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HydraRequest {
    #[schemars(description = "Target IP or hostname")]
    pub target: String,
    #[schemars(description = "Service to attack (e.g. 'ssh', 'ftp', 'http-post-form')")]
    pub service: String,
    #[schemars(description = "Path to username list file")]
    pub userlist: String,
    #[schemars(description = "Path to password list file")]
    pub passlist: String,
    #[schemars(description = "Number of parallel tasks (capped by config)")]
    pub tasks: Option<u16>,
}

pub async fn run(
    config: &RavenConfig,
    req: HydraRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let tasks = req
        .tasks
        .unwrap_or(4)
        .clamp(1, config.safety.hydra_max_tasks);

    let args = vec![
        "-L".to_string(),
        req.userlist,
        "-P".into(),
        req.passlist,
        "-t".into(),
        tasks.to_string(),
        "-f".into(), // stop on first valid pair
        req.target,
        req.service,
    ];

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "hydra", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("hydra", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
