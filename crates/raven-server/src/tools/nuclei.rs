use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NucleiRequest {
    #[schemars(description = "Target URL or hostname")]
    pub target: String,
    #[schemars(description = "Severity filter: 'info', 'low', 'medium', 'high', 'critical'")]
    pub severity: Option<String>,
    #[schemars(description = "Template tags to include (e.g. 'cve,oast)")]
    pub tags: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: NucleiRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "nuclei".into(), req.target.clone())
    });

    let mut args = vec!["-u".to_string(), req.target, "-jsonl".to_string()];

    if let Some(sev) = &req.severity {
        let valid = ["info", "low", "medium", "high", "critical"];
        if valid.contains(&sev.as_str()) {
            args.extend(["-severity".into(), sev.clone()])
        }
    }

    if let Some(tags) = &req.tags {
        args.extend(["-tags".to_string(), tags.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "nuclei", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("nuclei", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
