//! Passive subdomain enumeration via subfinder.
//!
//! Queries certificate transparency logs, DNS databases, and search engines
//! to discover subdomains without active probing. Output is requested in JSONL
//! format (`-oJ`) for structured processing.
//!
//! This is a fast tool (1-5s) and doesn't require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, safety};
use rmcp::model::CallToolResult;
use rmcp::schemars;

/// MCP request schema for `run_subfinder`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubfinderRequest {
    #[schemars(description = "Domain to enumerate subdomains for")]
    pub target: String,
    #[schemars(description = "Comma-separated sources (e.g. 'crtsh,hackertarget')")]
    pub sources: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute subfinder for passive subdomain enumeration.
pub async fn run(
    config: &RavenConfig,
    req: SubfinderRequest,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = vec!["-d".to_string(), req.target, "-silent".into(), "-oJ".into()];

    if let Some(ref sources) = req.sources {
        args.extend(["-sources".into(), sources.clone()]);
    }
    if let Some(timeout) = req.timeout_secs {
        args.extend(["-timeout".into(), timeout.to_string()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "subfinder", &arg_refs, req.timeout_secs, |s| {
        parse_subfinder_jsonl(s, result_limit)
    })
    .await
}

/// Parse subfinder JSONL output into a compact subdomain list.
///
/// Each JSONL line contains `{"host":"sub.example.com","source":"crtsh","ip":"..."}`.
/// Extracts host and source, caps at 50 results, and appends a truncation note
/// if more were found.
fn parse_subfinder_jsonl(raw: &str, max_results: usize) -> Option<String> {
    let mut entries = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let host = v.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let source = v
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if !host.is_empty() {
                entries.push(format!("{host} ({source})"));
            }
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} subdomain(s) found:\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n+{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subfinder_extracts_hosts() {
        let jsonl = concat!(
            r#"{"host":"api.example.com","source":"crtsh","ip":"1.2.3.4"}"#,
            "\n",
            r#"{"host":"mail.example.com","source":"hackertarget","ip":"5.6.7.8"}"#,
            "\n",
            r#"{"host":"dev.example.com","source":"dnsdumpster","ip":"9.10.11.12"}"#,
        );
        let result = parse_subfinder_jsonl(jsonl, 50).unwrap();
        assert!(result.starts_with("3 subdomain(s) found:"));
        assert!(result.contains("api.example.com (crtsh)"));
        assert!(result.contains("mail.example.com (hackertarget)"));
        assert!(result.contains("dev.example.com (dnsdumpster)"));
    }

    #[test]
    fn parse_subfinder_empty_returns_none() {
        assert!(parse_subfinder_jsonl("", 50).is_none());
        assert!(parse_subfinder_jsonl("no json here", 50).is_none());
        assert!(parse_subfinder_jsonl("   \n  \n", 50).is_none());
    }

    #[test]
    fn parse_subfinder_caps_at_50() {
        let lines: Vec<String> = (0..75)
            .map(|i| {
                format!(r#"{{"host":"sub{i}.example.com","source":"crtsh","ip":"1.2.3.{i}"}}"#)
            })
            .collect();
        let jsonl = lines.join("\n");
        let result = parse_subfinder_jsonl(&jsonl, 50).unwrap();
        assert!(result.starts_with("75 subdomain(s) found:"));
        assert!(result.contains("+25 more"));
        // Verify only 50 host entries appear (not 75)
        assert!(result.contains("sub49.example.com"));
        assert!(!result.contains("sub50.example.com"));
    }
}
