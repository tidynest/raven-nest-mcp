//! HTTP probing and fingerprinting via httpx (ProjectDiscovery).
//!
//! Probes a target URL/host for live HTTP services, extracting status codes,
//! titles, technologies, and server headers. Output is requested in JSONL
//! format (`-json`) for structured processing.
//!
//! This is a fast tool and doesn't require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, safety};
use rmcp::model::CallToolResult;
use rmcp::schemars;

/// MCP request schema for `run_httpx`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpxRequest {
    #[schemars(description = "Target URL or host to probe")]
    pub target: String,
    #[schemars(description = "Scan type: 'probe' (default), 'fingerprint', 'full'")]
    pub scan_type: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute httpx to probe and fingerprint an HTTP target.
pub async fn run(
    config: &RavenConfig,
    req: HttpxRequest,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = vec![
        "-u".to_string(),
        req.target,
        "-json".into(),
        "-silent".into(),
        "-no-color".into(),
    ];

    // Scan type presets control which fields httpx extracts.
    let preset: &[&str] = match req.scan_type.as_deref() {
        Some("fingerprint") => &["-sc", "-title", "-td", "-server", "-method"],
        Some("full") => &[
            "-sc", "-title", "-td", "-server", "-method", "-favicon", "-jarm", "-ip", "-cname",
        ],
        // "probe" (default)
        _ => &["-sc", "-title", "-wc", "-cl"],
    };
    args.extend(preset.iter().map(|s| s.to_string()));

    if let Some(timeout) = req.timeout_secs {
        args.extend(["-timeout".into(), timeout.to_string()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "httpx", &arg_refs, req.timeout_secs, |s| {
        parse_httpx_jsonl(s, result_limit)
    })
    .await
}

/// Parse httpx JSONL output into a compact per-URL summary.
///
/// Each JSONL line contains fields like `{"url":"https://x","status_code":200,
/// "title":"Home","webserver":"nginx","tech":["WordPress","PHP"],
/// "content_length":1234}`. Emits one compact line per result:
/// `https://x (200) [nginx] {WordPress,PHP} "Home"`. Caps at `max_results` and
/// appends a truncation note if more were found.
///
/// Returns `None` if no valid JSON lines are present.
fn parse_httpx_jsonl(raw: &str, max_results: usize) -> Option<String> {
    let mut entries = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let url = v.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if url.is_empty() {
                continue;
            }

            let mut line = url.to_string();

            if let Some(status) = v.get("status_code").and_then(|v| v.as_u64()) {
                line.push_str(&format!(" ({status})"));
            }
            if let Some(server) = v.get("webserver").and_then(|v| v.as_str())
                && !server.is_empty()
            {
                line.push_str(&format!(" [{server}]"));
            }
            if let Some(tech) = v.get("tech").and_then(|v| v.as_array()) {
                let techs: Vec<&str> = tech.iter().filter_map(|t| t.as_str()).collect();
                if !techs.is_empty() {
                    line.push_str(&format!(" {{{}}}", techs.join(", ")));
                }
            }
            if let Some(cl) = v.get("content_length").and_then(|v| v.as_u64()) {
                line.push_str(&format!(" {cl}b"));
            }
            if let Some(title) = v.get("title").and_then(|v| v.as_str())
                && !title.is_empty()
            {
                line.push_str(&format!(" \"{title}\""));
            }
            entries.push(line);
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} result(s):\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n... +{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_httpx_extracts_fields() {
        let jsonl = concat!(
            r#"{"url":"https://a.example.com","status_code":200,"title":"Home","webserver":"nginx","tech":["WordPress","PHP"],"content_length":1234}"#,
            "\n",
            r#"{"url":"https://b.example.com","status_code":404,"webserver":"Apache","tech":["jQuery"]}"#,
        );
        let result = parse_httpx_jsonl(jsonl, 50).unwrap();
        assert!(result.starts_with("2 result(s):"));
        assert!(
            result.contains("https://a.example.com (200) [nginx] {WordPress, PHP} 1234b \"Home\"")
        );
        assert!(result.contains("https://b.example.com (404) [Apache] {jQuery}"));
    }

    #[test]
    fn parse_httpx_empty_returns_none() {
        assert!(parse_httpx_jsonl("", 50).is_none());
        assert!(parse_httpx_jsonl("not json output", 50).is_none());
        assert!(parse_httpx_jsonl("   \n  \n", 50).is_none());
        // Valid JSON but no url field -> skipped -> None
        assert!(parse_httpx_jsonl(r#"{"status_code":200}"#, 50).is_none());
    }

    #[test]
    fn parse_httpx_caps_results() {
        let lines: Vec<String> = (0..75)
            .map(|i| format!(r#"{{"url":"https://h{i}.example.com","status_code":200}}"#))
            .collect();
        let jsonl = lines.join("\n");
        let result = parse_httpx_jsonl(&jsonl, 50).unwrap();
        assert!(result.starts_with("75 result(s):"));
        assert!(result.contains("... +25 more"));
        assert!(result.contains("h49.example.com"));
        assert!(!result.contains("h50.example.com"));
    }
}
