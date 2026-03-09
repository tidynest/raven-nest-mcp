//! Nuclei template-based vulnerability scanner handler.
//!
//! Nuclei runs community-maintained detection templates against a target.
//! Output is requested in JSONL format (`-jsonl`) for structured processing.
//!
//! Supports optional severity filtering (e.g. only `high,critical`) and
//! tag-based template selection (e.g. `cve,oast`).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_nuclei`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NucleiRequest {
    #[schemars(description = "Target URL or hostname")]
    pub target: String,
    #[schemars(description = "Severity filter: 'info', 'low', 'medium', 'high', 'critical'")]
    pub severity: Option<String>,
    #[schemars(description = "Template tags to include (e.g. 'cve,oast)")]
    pub tags: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
}

/// Execute a nuclei scan with optional severity/tag filtering.
pub async fn run(
    config: &RavenConfig,
    req: NucleiRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "nuclei".into(), req.target.clone()));

    let mut args = vec!["-u".to_string(), req.target, "-jsonl".to_string()];

    // Only apply severity filter if it's a valid nuclei severity value
    if let Some(sev) = &req.severity {
        let valid = ["info", "low", "medium", "high", "critical"];
        if valid.contains(&sev.as_str()) {
            args.extend(["-severity".into(), sev.clone()])
        }
    }

    if let Some(tags) = &req.tags {
        args.extend(["-tags".to_string(), tags.clone()]);
    }
    if let Some(cookie) = &req.cookie {
        args.extend(["-H".to_string(), format!("Cookie: {cookie}")]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "nuclei", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_nuclei_jsonl(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("nuclei", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse nuclei JSONL output into a compact findings summary.
///
/// Each JSONL line becomes: `[SEVERITY] template-id — name @ matched-url (type)`
/// Reduces raw JSON noise to an actionable table of findings.
pub fn parse_nuclei_jsonl(raw: &str) -> Option<String> {
    let mut findings = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let template = v
                .get("template-id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let severity = v
                .get("info")
                .and_then(|i| i.get("severity"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let name = v
                .get("info")
                .and_then(|i| i.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let matched = v.get("matched-at").and_then(|v| v.as_str()).unwrap_or("");
            let kind = v.get("type").and_then(|v| v.as_str()).unwrap_or("");

            findings.push(format!(
                "[{severity}] {template} — {name} @ {matched} ({kind})"
            ));
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(format!(
            "{} finding(s):\n{}",
            findings.len(),
            findings.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nuclei_extracts_findings() {
        let jsonl = r#"{"template-id":"tech-detect","info":{"name":"Wappalyzer","severity":"info"},"type":"http","matched-at":"http://example.com/"}
{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"type":"http","matched-at":"http://example.com/api"}"#;
        let result = parse_nuclei_jsonl(jsonl).unwrap();
        assert!(result.starts_with("2 finding(s):"));
        assert!(result.contains("[info] tech-detect"));
        assert!(result.contains("[critical] cve-2021-44228"));
        assert!(result.contains("Log4Shell"));
        assert!(result.contains("http://example.com/api"));
    }

    #[test]
    fn parse_nuclei_skips_non_json_lines() {
        let raw = "some warning text\n{\"template-id\":\"test\",\"info\":{\"name\":\"T\",\"severity\":\"low\"},\"type\":\"http\",\"matched-at\":\"http://x\"}\nmore text";
        let result = parse_nuclei_jsonl(raw).unwrap();
        assert!(result.starts_with("1 finding(s):"));
    }

    #[test]
    fn parse_nuclei_empty_returns_none() {
        assert!(parse_nuclei_jsonl("").is_none());
        assert!(parse_nuclei_jsonl("no json here").is_none());
    }
}
