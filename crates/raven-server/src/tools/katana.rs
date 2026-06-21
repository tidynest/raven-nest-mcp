//! Web crawling and endpoint discovery via katana (ProjectDiscovery).
//!
//! Crawls a target URL to enumerate reachable endpoints, scoped to the root
//! domain. Output is requested in JSONL format (`-jsonl`) for structured
//! processing.
//!
//! Crawling can take a while on large sites, so this tool starts a
//! [`ProgressTicker`](crate::progress::ProgressTicker) to keep the client informed.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_katana`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KatanaRequest {
    #[schemars(description = "Target URL to crawl")]
    pub target: String,
    #[schemars(description = "Scan type: 'passive', 'standard' (default), 'deep'")]
    pub scan_type: Option<String>,
    #[schemars(description = "Crawl depth (1-5, default 3)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub depth: Option<u32>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute katana to crawl a target and enumerate endpoints.
pub async fn run(
    config: &RavenConfig,
    req: KatanaRequest,
    peer: Option<Peer<RoleServer>>,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "katana".into(), req.target.clone()));

    // Clamp crawl depth to a sane maximum to bound runtime.
    let depth = req.depth.unwrap_or(3).min(5);

    let mut args = vec![
        "-u".to_string(),
        req.target.clone(),
        "-jsonl".into(),
        "-silent".into(),
        "-nc".into(),
        "-d".into(),
        depth.to_string(),
        // Scope crawl to the root domain (fully-qualified)
        "-fs".into(),
        "fqdn".into(),
    ];

    // Scan type presets control JavaScript parsing and headless crawling.
    let preset: &[&str] = match req.scan_type.as_deref() {
        Some("passive") => &[],
        Some("deep") => &["-jc", "-hl"],
        // "standard" (default)
        _ => &["-jc"],
    };
    args.extend(preset.iter().map(|s| s.to_string()));

    // Reduce concurrency/rate against localhost to avoid self-DoS.
    if super::is_localhost(&req.target) {
        args.extend(["-c".into(), "5".into(), "-rl".into(), "20".into()]);
    } else {
        args.extend(["-c".into(), "10".into()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "katana", &arg_refs, req.timeout_secs)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_katana_jsonl(&result.stdout, result_limit)
            .unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("katana", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse katana JSONL output into a compact, deduplicated endpoint list.
///
/// Each JSONL line contains `{"request":{"endpoint":"https://x/path",
/// "method":"GET"},"response":{"status_code":200}}`. Emits one line per unique
/// endpoint: `GET https://x/path (200)`. Caps at `max_results` and appends a
/// truncation note if more were found.
///
/// Returns `None` if no valid JSON lines are present.
fn parse_katana_jsonl(raw: &str, max_results: usize) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let request = v.get("request");
            let endpoint = request
                .and_then(|r| r.get("endpoint"))
                .and_then(|e| e.as_str())
                .unwrap_or("");
            if endpoint.is_empty() || !seen.insert(endpoint.to_string()) {
                continue;
            }

            let method = request
                .and_then(|r| r.get("method"))
                .and_then(|m| m.as_str())
                .unwrap_or("GET");

            let mut entry = format!("{method} {endpoint}");
            if let Some(status) = v
                .get("response")
                .and_then(|r| r.get("status_code"))
                .and_then(|s| s.as_u64())
            {
                entry.push_str(&format!(" ({status})"));
            }
            entries.push(entry);
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} endpoint(s):\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n... +{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_katana_extracts_endpoints() {
        let jsonl = concat!(
            r#"{"request":{"endpoint":"https://example.com/","method":"GET"},"response":{"status_code":200}}"#,
            "\n",
            r#"{"request":{"endpoint":"https://example.com/login","method":"POST"},"response":{"status_code":302}}"#,
        );
        let result = parse_katana_jsonl(jsonl, 50).unwrap();
        assert!(result.starts_with("2 endpoint(s):"));
        assert!(result.contains("GET https://example.com/ (200)"));
        assert!(result.contains("POST https://example.com/login (302)"));
    }

    #[test]
    fn parse_katana_dedups_endpoints() {
        let jsonl = concat!(
            r#"{"request":{"endpoint":"https://example.com/dup","method":"GET"},"response":{"status_code":200}}"#,
            "\n",
            r#"{"request":{"endpoint":"https://example.com/dup","method":"GET"},"response":{"status_code":200}}"#,
            "\n",
            r#"{"request":{"endpoint":"https://example.com/other","method":"GET"},"response":{"status_code":200}}"#,
        );
        let result = parse_katana_jsonl(jsonl, 50).unwrap();
        // Only 2 unique endpoints despite 3 lines
        assert!(result.starts_with("2 endpoint(s):"));
        assert_eq!(result.matches("https://example.com/dup").count(), 1);
    }

    #[test]
    fn parse_katana_empty_returns_none() {
        assert!(parse_katana_jsonl("", 50).is_none());
        assert!(parse_katana_jsonl("not json at all", 50).is_none());
        assert!(parse_katana_jsonl("  \n  \n", 50).is_none());
        // Valid JSON but no endpoint -> skipped -> None
        assert!(parse_katana_jsonl(r#"{"request":{"method":"GET"}}"#, 50).is_none());
    }

    #[test]
    fn parse_katana_caps_results() {
        let lines: Vec<String> = (0..70)
            .map(|i| {
                format!(
                    r#"{{"request":{{"endpoint":"https://example.com/p{i}","method":"GET"}},"response":{{"status_code":200}}}}"#
                )
            })
            .collect();
        let jsonl = lines.join("\n");
        let result = parse_katana_jsonl(&jsonl, 50).unwrap();
        assert!(result.starts_with("70 endpoint(s):"));
        assert!(result.contains("... +20 more"));
        assert!(result.contains("/p49"));
        assert!(!result.contains("/p50 "));
    }
}
