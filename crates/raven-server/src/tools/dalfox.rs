//! XSS vulnerability scanner via dalfox.
//!
//! Dalfox performs parameter analysis and XSS injection testing, outputting
//! results in JSON format. This is a fast tool (1-5s per URL) and doesn't
//! require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_dalfox`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DalfoxRequest {
    #[schemars(description = "Target URL to test for XSS")]
    pub target: String,
    #[schemars(description = "Comma-separated parameter names to test (e.g. 'q,search')")]
    pub parameters: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning")]
    pub cookie: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute dalfox for XSS vulnerability scanning.
pub async fn run(
    config: &RavenConfig,
    req: DalfoxRequest,
    result_limit: usize,
) -> Result<(CallToolResult, Vec<crate::tools::extract::ExtractedFinding>), rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = vec![
        "url".to_string(),
        req.target,
        "--silence".into(),
        "--format".into(),
        "json".into(),
    ];

    if let Some(ref params) = req.parameters {
        args.extend(["--param".into(), params.clone()]);
    }
    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "dalfox", &arg_refs, req.timeout_secs)
        .await
        .map_err(crate::error::to_mcp)?;

    let mut findings = Vec::new();
    let output = if result.success {
        findings = crate::tools::extract::extract_dalfox(&result.stdout);
        let mut out = parse_dalfox_json(&result.stdout, result_limit)
            .unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("dalfox", &result)
    };
    Ok((
        CallToolResult::success(vec![Content::text(output)]),
        findings,
    ))
}

/// Parse dalfox JSON output into compact XSS finding lines.
///
/// Each JSON object contains `{"type":"...","inject_type":"...","poc_type":"...","data":"...","param":"...","payload":"..."}`.
/// Extracts type, param, and payload; caps at 20 results.
fn parse_dalfox_json(raw: &str, max_results: usize) -> Option<String> {
    let mut entries = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let xss_type = v
                .get("inject_type")
                .or_else(|| v.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("XSS");
            let param = v.get("param").and_then(|v| v.as_str()).unwrap_or("?");
            let payload = v
                .get("payload")
                .or_else(|| v.get("data"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let poc = v.get("poc_type").and_then(|v| v.as_str()).unwrap_or("");

            if !payload.is_empty() {
                let poc_tag = if poc.is_empty() {
                    String::new()
                } else {
                    format!(" [{poc}]")
                };
                entries.push(format!("[{xss_type}] param={param}{poc_tag} | {payload}"));
            }
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} XSS finding(s):\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n+{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dalfox_extracts_findings() {
        let json = concat!(
            r#"{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","data":"http://example.com?q=%3Cscript%3E","param":"q","payload":"<script>alert(1)</script>"}"#,
            "\n",
            r#"{"type":"V","inject_type":"inATTR","poc_type":"plain","data":"http://example.com?search=test","param":"search","payload":"\" onmouseover=alert(1)"}"#,
        );
        let result = parse_dalfox_json(json, 20).unwrap();
        assert!(result.starts_with("2 XSS finding(s):"));
        assert!(result.contains("param=q"));
        assert!(result.contains("<script>alert(1)</script>"));
        assert!(result.contains("param=search"));
    }

    #[test]
    fn parse_dalfox_empty_returns_none() {
        assert!(parse_dalfox_json("", 20).is_none());
        assert!(parse_dalfox_json("no json here", 20).is_none());
    }

    #[test]
    fn parse_dalfox_caps_at_20() {
        let lines: Vec<String> = (0..30)
            .map(|i| {
                format!(
                    r#"{{"type":"V","inject_type":"inHTML","param":"p{i}","payload":"<img src=x onerror=alert({i})>"}}"#
                )
            })
            .collect();
        let json = lines.join("\n");
        let result = parse_dalfox_json(&json, 20).unwrap();
        assert!(result.starts_with("30 XSS finding(s):"));
        assert!(result.contains("+10 more"));
    }
}
