use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SqlmapRequest {
    #[schemars(description = "Target URL with injectable parameter")]
    pub url: String,
    #[schemars(description = "POST body data (e.g. 'user=test&pass=test')")]
    pub data: Option<String>,
    #[schemars(description = "Cookie string for authenticated testing")]
    pub cookie: Option<String>,
    #[schemars(description = "Test level 1-5 (default 1, capped by config)")]
    pub level: Option<u8>,
    #[schemars(description = "Risk level 1-3 (default 1, capped by config)")]
    pub risk: Option<u8>,
    #[schemars(description = "SQL injection techniques (e.g. 'BEUSTQ')")]
    pub technique: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: SqlmapRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.url).map_err(crate::error::to_mcp)?;

    // Enforce config safety limits
    let level = req
        .level
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_level);
    let risk = req
        .risk
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_risk);

    let mut args = vec![
        "-u".to_string(),
        req.url,
        "--batch".into(),
        "--level".into(),
        level.to_string(),
        "--risk".into(),
        risk.to_string(),
    ];

    if let Some(ref data) = req.data {
        args.extend(["--data".into(), data.clone()]);
    }

    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }

    if let Some(ref technique) = req.technique {
        args.extend(["--technique".into(), technique.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "sqlmap", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("sqlmap", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
