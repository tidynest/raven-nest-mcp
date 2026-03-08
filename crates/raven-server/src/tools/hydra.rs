//! Hydra network authentication brute-force handler.
//!
//! Hydra tests login credentials against network services (SSH, FTP, HTTP forms,
//! etc.). Parallel task count is capped by [`SafetyConfig::hydra_max_tasks`](raven_core::config::SafetyConfig::hydra_max_tasks)
//! to limit brute-force throughput.
//!
//! The `-f` flag is always set (stop on first valid credential pair), and
//! `http-*-form` services require the `form_params` field to specify the
//! login path, form fields, and failure condition.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_hydra`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub tasks: Option<u16>,
    #[schemars(description = "Form attack string for http-post-form/http-get-form (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')")]
    pub form_params: Option<String>,
}

/// Execute hydra with safety-capped parallelism and form-service validation.
pub async fn run(
    config: &RavenConfig,
    req: HydraRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "hydra".into(), req.target.clone())
    });

    // Cap parallel tasks to prevent excessive brute-force throughput
    let tasks = req
        .tasks
        .unwrap_or(4)
        .clamp(1, config.safety.hydra_max_tasks);

    // http-*-form services need form_params to know the login path and fields
    let is_form_service = req.service.starts_with("http-") && req.service.contains("form");
    if is_form_service && req.form_params.is_none() {
        return Err(rmcp::ErrorData::invalid_params(
            "form_params is required for http-post-form/http-get-form \
             (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')",
            None,
        ));
    }

    let mut args = vec![
        "-L".to_string(),
        req.userlist,
        "-P".into(),
        req.passlist,
        "-t".into(),
        tasks.to_string(),
        "-f".into(), // stop on first valid credential pair
        req.target,
        req.service,
    ];

    // form_params is passed as a positional arg after the service name
    if let Some(form_params) = req.form_params {
        args.push(form_params);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "hydra", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("hydra", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
