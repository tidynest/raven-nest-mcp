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
    #[schemars(
        description = "Form attack string for http-post-form/http-get-form (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')"
    )]
    pub form_params: Option<String>,
}

/// Execute hydra with safety-capped parallelism and form-service validation.
pub async fn run(
    config: &RavenConfig,
    req: HydraRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "hydra".into(), req.target.clone()));

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

    let output = if result.success {
        let mut out = parse_hydra_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("hydra", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse hydra output, extracting found credentials and the summary line.
///
/// Credential lines contain both `login:` and `password:` keywords.
/// The summary line matches "valid password found" or "successfully completed".
/// All other lines (status updates, data info) are discarded.
pub fn parse_hydra_output(raw: &str) -> Option<String> {
    let mut creds = Vec::new();
    let mut summary = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.contains("login:") && trimmed.contains("password:") {
            creds.push(trimmed);
        } else if trimmed.contains("valid password") || trimmed.contains("successfully completed") {
            summary = Some(trimmed);
        }
    }

    if creds.is_empty() && summary.is_none() {
        return None;
    }

    let mut out = String::new();
    if !creds.is_empty() {
        out.push_str(&format!("{} credential(s) found:\n", creds.len()));
        for c in &creds {
            out.push_str(c);
            out.push('\n');
        }
    }
    if let Some(s) = summary {
        out.push_str(s);
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hydra_extracts_credentials() {
        let raw = r#"Hydra v9.5 (c) 2023 by van Hauser/THC
[DATA] max 4 tasks per 1 server, overall 4 tasks, 100 login tries
[DATA] attacking ssh://10.0.0.1:22/
[22][ssh] host: 10.0.0.1   login: admin   password: password123
[22][ssh] host: 10.0.0.1   login: root   password: toor
[STATUS] 100.00 tries/min, 100 tries in 00:01h, 0 to do in 00:00h, 4 active
1 of 1 target successfully completed, 2 valid passwords found"#;
        let result = parse_hydra_output(raw).unwrap();
        assert!(result.contains("2 credential(s) found:"));
        assert!(result.contains("login: admin"));
        assert!(result.contains("password: password123"));
        assert!(result.contains("login: root"));
        assert!(result.contains("2 valid passwords found"));
        assert!(!result.contains("[DATA]"));
        assert!(!result.contains("[STATUS]"));
    }

    #[test]
    fn parse_hydra_no_creds_returns_summary() {
        let raw = r#"[DATA] attacking ssh://10.0.0.1:22/
[STATUS] 50.00 tries/min, 50 tries in 00:01h, 50 to do
1 of 1 target successfully completed, 0 valid passwords found"#;
        let result = parse_hydra_output(raw).unwrap();
        assert!(result.contains("0 valid passwords found"));
        assert!(!result.contains("[DATA]"));
    }

    #[test]
    fn parse_hydra_empty_returns_none() {
        assert!(parse_hydra_output("").is_none());
        assert!(parse_hydra_output("some random text\nno credentials here").is_none());
    }
}
