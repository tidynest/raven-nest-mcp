use raven_core::{config::RavenConfig, executor, safety};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NiktoRequest {
    #[schemars(description = "Target hostname or URL")]
    pub target: String,
    #[schemars(description = "Port to scan (default 80)")]
    pub port: Option<u16>,
    #[schemars(description = "Tuning: 'quick', 'thorough', 'injection', 'fileupload'")]
    pub tuning: Option<String>,
    #[schemars(description = "Scan timeout in seconds (default 600)")]
    pub timeout_secs: Option<u64>,
}

pub async fn run(
    config: &RavenConfig,
    req: NiktoRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = vec!["-h".to_string(), req.target, "-nocheck".into()];

    let port = req.port.unwrap_or(80);
    args.extend(["-p".into(), port.to_string()]);

    if port == 443 {
        args.push("-ssl".into());
    }

    match req.tuning.as_deref() {
        Some("thorough") => args.extend(["-T".into(), "123456789abc".into()]),
        Some("injection") => args.extend(["-T".into(), "9".into()]),
        Some("fileupload") => args.extend(["-T".into(), "0".into()]),
        _ => args.extend(["-T".into(), "1234".into()]), // quick
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "nikto", &arg_refs, req.timeout_secs)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("nikto", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
