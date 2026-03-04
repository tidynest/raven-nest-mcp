use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MasscanRequest {
    #[schemars(description = "Target CIDR range (e.g. '10.0.0.0/24')")]
    pub target: String,
    #[schemars(description = "Port spec (e.g. '80,443' or '0-65535')")]
    pub ports: String,
    #[schemars(description = "Packets per second (capped by config, default 100)")]
    pub rate: Option<u32>,
}

pub async fn run(
    config: &RavenConfig,
    req: MasscanRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // masscan requires root for raw sockets
    // SAFETY: geteuid is a trivial read-only syscall with no invariants
    if unsafe { libc::geteuid() } != 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "masscan requires root privileges (raw socket access)",
            None,
        ));
    }

    let rate = req
        .rate
        .unwrap_or(100)
        .clamp(1, config.safety.masscan_max_rate);

    let args = [
        req.target,
        "-p".to_string(),
        req.ports,
        "--rate".into(),
        rate.to_string(),
        "--open".into(), // only show open ports
    ];

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "masscan", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("masscan", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
