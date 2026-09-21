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
    model::{CallToolResult, ContentBlock},
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
    progress_token: Option<rmcp::model::ProgressToken>,
    result_limit: usize,
) -> Result<(CallToolResult, Vec<crate::tools::extract::ExtractedFinding>), rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = crate::progress::ProgressTicker::start(
        peer,
        progress_token,
        "nuclei".into(),
        req.target.clone(),
    );

    let mut args = vec!["-u".to_string(), req.target.clone(), "-jsonl".to_string()];

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
    let result = executor::run(config, "nuclei", Some(req.target.as_str()), &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let findings = if result.success {
        crate::tools::extract::extract_nuclei(&result.stdout)
    } else {
        Vec::new()
    };
    let output = super::format_output("nuclei", &result, |s| parse_nuclei_jsonl(s, result_limit));

    // Machine-readable form for MCP clients, exposed as `structured_content`.
    let mut call_result = CallToolResult::success(vec![ContentBlock::text(output)]);
    if let Some(value) = structured_nuclei(&result.stdout, result_limit) {
        call_result.structured_content = Some(value);
    }

    Ok((call_result, findings))
}

/// One nuclei JSONL hit in the fields shared by the text summary and the
/// structured output.
#[derive(Debug, serde::Serialize)]
pub struct NucleiHit {
    pub template: String,
    pub severity: String,
    pub name: String,
    pub matched_at: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// Parse every valid JSONL hit from nuclei output into [`NucleiHit`]s.
///
/// Tolerates non-JSON noise lines and salvages a final line truncated mid-object
/// (output truncation can cut the last hit) by closing the brace.
fn parse_nuclei_hits(raw: &str) -> Vec<NucleiHit> {
    let mut hits = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let v = serde_json::from_str::<serde_json::Value>(trimmed)
            .or_else(|_| {
                // Truncated JSON - try to salvage by closing the object
                let salvaged = format!("{trimmed}}}");
                serde_json::from_str::<serde_json::Value>(&salvaged)
            })
            .ok();
        let Some(v) = v else { continue };

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
        let matched_at = v.get("matched-at").and_then(|v| v.as_str()).unwrap_or("");
        let kind = v.get("type").and_then(|v| v.as_str()).unwrap_or("");

        // Skip if we couldn't extract the essential fields
        if template == "unknown" && name.is_empty() {
            continue;
        }
        hits.push(NucleiHit {
            template: template.to_string(),
            severity: severity.to_string(),
            name: name.to_string(),
            matched_at: matched_at.to_string(),
            kind: kind.to_string(),
        });
    }
    hits
}

/// Parse nuclei JSONL output into a compact findings summary.
///
/// Each JSONL line becomes: `[SEVERITY] template-id - name @ matched-url (type)`
/// Reduces raw JSON noise to an actionable table of findings.
pub fn parse_nuclei_jsonl(raw: &str, max_results: usize) -> Option<String> {
    let hits = parse_nuclei_hits(raw);
    if hits.is_empty() {
        return None;
    }
    let lines: Vec<String> = hits
        .iter()
        .map(|h| {
            format!(
                "[{}] {} - {} @ {} ({})",
                h.severity, h.template, h.name, h.matched_at, h.kind
            )
        })
        .collect();
    let total = lines.len();
    let shown: Vec<_> = lines.into_iter().take(max_results).collect();
    let extra = if total > max_results {
        format!("\n+{} more finding(s)", total - max_results)
    } else {
        String::new()
    };
    Some(format!("{total} finding(s):\n{}{extra}", shown.join("\n")))
}

/// Structured nuclei result for `structured_content`: the full hit list capped
/// at `max_results`, with the true total. `None` when there are no hits.
pub fn structured_nuclei(raw: &str, max_results: usize) -> Option<serde_json::Value> {
    let hits = parse_nuclei_hits(raw);
    if hits.is_empty() {
        return None;
    }
    let total = hits.len();
    let shown: Vec<&NucleiHit> = hits.iter().take(max_results).collect();
    Some(serde_json::json!({
        "total": total,
        "shown": shown.len(),
        "findings": shown,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nuclei_extracts_findings() {
        let jsonl = r#"{"template-id":"tech-detect","info":{"name":"Wappalyzer","severity":"info"},"type":"http","matched-at":"http://example.com/"}
{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"type":"http","matched-at":"http://example.com/api"}"#;
        let result = parse_nuclei_jsonl(jsonl, 25).unwrap();
        assert!(result.starts_with("2 finding(s):"));
        assert!(result.contains("[info] tech-detect"));
        assert!(result.contains("[critical] cve-2021-44228"));
        assert!(result.contains("Log4Shell"));
        assert!(result.contains("http://example.com/api"));
    }

    #[test]
    fn parse_nuclei_skips_non_json_lines() {
        let raw = "some warning text\n{\"template-id\":\"test\",\"info\":{\"name\":\"T\",\"severity\":\"low\"},\"type\":\"http\",\"matched-at\":\"http://x\"}\nmore text";
        let result = parse_nuclei_jsonl(raw, 25).unwrap();
        assert!(result.starts_with("1 finding(s):"));
    }

    #[test]
    fn parse_nuclei_empty_returns_none() {
        assert!(parse_nuclei_jsonl("", 25).is_none());
        assert!(parse_nuclei_jsonl("no json here", 25).is_none());
        assert!(structured_nuclei("", 25).is_none());
    }

    #[test]
    fn structured_nuclei_lists_hits_with_total() {
        let jsonl = r#"{"template-id":"tech-detect","info":{"name":"Wappalyzer","severity":"info"},"type":"http","matched-at":"http://example.com/"}
{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"type":"http","matched-at":"http://example.com/api"}
{"template-id":"cve-2022-22965","info":{"name":"Spring4Shell","severity":"critical"},"type":"http","matched-at":"http://example.com/actuator"}"#;
        let value = structured_nuclei(jsonl, 2).unwrap();
        assert_eq!(value["total"], 3);
        assert_eq!(value["shown"], 2);
        let findings = value["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2); // capped at max_results
        assert_eq!(findings[0]["template"], "tech-detect");
        assert_eq!(findings[0]["type"], "http");
        assert_eq!(findings[1]["severity"], "critical");
        assert_eq!(findings[1]["matched_at"], "http://example.com/api");
    }

    #[test]
    fn structured_nuclei_salvages_truncated_last_line() {
        // Truncated after the last value's closing quote but before the final
        // brace - appending `}` makes the object valid again.
        let raw = "{\"template-id\":\"t\",\"info\":{\"name\":\"N\",\"severity\":\"high\"},\"type\":\"http\",\"matched-at\":\"http://x\"";
        let value = structured_nuclei(raw, 25).unwrap();
        assert_eq!(value["total"], 1);
        assert_eq!(value["findings"][0]["template"], "t");
        assert_eq!(value["findings"][0]["matched_at"], "http://x");
    }
}
