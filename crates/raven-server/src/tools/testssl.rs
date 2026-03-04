use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TestsslRequest {
    #[schemars(description = "Target hostname, host:port, or URL")]
    pub target: String,
    #[schemars(description = "Run in fast mode (fewer checks)")]
    pub quick: Option<bool>,
    #[schemars(description = "Severity filter: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")]
    pub severity: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: TestsslRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = Vec::new();

    if req.quick.unwrap_or(false) {
        // --fast is deprecated in testssl.sh 3.2+; use individual skips instead
        args.extend([
            "--quiet".to_string(),
            "--sneaky".into(),
        ]);
    }

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
