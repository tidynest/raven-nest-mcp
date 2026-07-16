//! DNS record resolution and enumeration via dnsx (ProjectDiscovery).
//!
//! Resolves a single domain across multiple record types (A, AAAA, CNAME, MX,
//! NS, TXT, PTR, ASN). Output is requested in JSONL format (`-json`) for
//! structured processing.
//!
//! This is a fast tool and doesn't require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, safety};
use rmcp::model::CallToolResult;
use rmcp::schemars;

/// MCP request schema for `run_dnsx`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsxRequest {
    #[schemars(description = "Domain to resolve")]
    pub target: String,
    #[schemars(description = "Scan type: 'resolve' (default), 'records', 'recon'")]
    pub scan_type: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute dnsx to resolve DNS records for a domain.
pub async fn run(
    config: &RavenConfig,
    req: DnsxRequest,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut args = vec![
        "-d".to_string(),
        req.target,
        "-json".into(),
        "-silent".into(),
    ];

    // Scan type presets control which record types dnsx queries.
    let preset: &[&str] = match req.scan_type.as_deref() {
        Some("records") => &["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp"],
        Some("recon") => &["-a", "-aaaa", "-cname", "-ptr", "-asn", "-resp"],
        // "resolve" (default)
        _ => &["-a", "-aaaa", "-resp"],
    };
    args.extend(preset.iter().map(|s| s.to_string()));

    if let Some(timeout) = req.timeout_secs {
        args.extend(["-timeout".into(), timeout.to_string()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "dnsx", &arg_refs, req.timeout_secs, |s| {
        parse_dnsx_jsonl(s, result_limit)
    })
    .await
}

/// Render a JSON record array as a compact `TYPE:[v1,v2]` fragment.
///
/// Returns an empty string when the field is absent or contains no values.
fn render_records(v: &serde_json::Value, key: &str, label: &str) -> String {
    let Some(arr) = v.get(key).and_then(|v| v.as_array()) else {
        return String::new();
    };
    let vals: Vec<&str> = arr.iter().filter_map(|e| e.as_str()).collect();
    if vals.is_empty() {
        String::new()
    } else {
        format!(" {label}:[{}]", vals.join(","))
    }
}

/// Parse dnsx JSONL output into a compact per-host record summary.
///
/// Each JSONL line contains `{"host":"sub.example.com","a":["1.2.3.4"],
/// "cname":["cdn.x"],...}`. Emits one line per host listing only the record
/// types present: `sub.example.com -> A:[1.2.3.4] CNAME:[cdn.x]`. Caps at
/// `max_results` and appends a truncation note if more were found.
///
/// Returns `None` if no valid JSON lines are present.
fn parse_dnsx_jsonl(raw: &str, max_results: usize) -> Option<String> {
    let mut entries = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let host = v.get("host").and_then(|v| v.as_str()).unwrap_or("");
            if host.is_empty() {
                continue;
            }

            let mut records = String::new();
            records.push_str(&render_records(&v, "a", "A"));
            records.push_str(&render_records(&v, "aaaa", "AAAA"));
            records.push_str(&render_records(&v, "cname", "CNAME"));
            records.push_str(&render_records(&v, "mx", "MX"));
            records.push_str(&render_records(&v, "ns", "NS"));
            records.push_str(&render_records(&v, "txt", "TXT"));

            entries.push(format!("{host} ->{records}"));
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} record set(s):\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n... +{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dnsx_extracts_records() {
        let jsonl = concat!(
            r#"{"host":"www.example.com","a":["1.2.3.4"],"cname":["cdn.example.net"]}"#,
            "\n",
            r#"{"host":"mail.example.com","a":["5.6.7.8"],"mx":["mx1.example.com"]}"#,
        );
        let result = parse_dnsx_jsonl(jsonl, 50).unwrap();
        assert!(result.starts_with("2 record set(s):"));
        assert!(result.contains("www.example.com -> A:[1.2.3.4] CNAME:[cdn.example.net]"));
        assert!(result.contains("mail.example.com -> A:[5.6.7.8] MX:[mx1.example.com]"));
    }

    #[test]
    fn parse_dnsx_empty_returns_none() {
        assert!(parse_dnsx_jsonl("", 50).is_none());
        assert!(parse_dnsx_jsonl("garbage not json", 50).is_none());
        assert!(parse_dnsx_jsonl("  \n \n", 50).is_none());
        // Valid JSON but no host field -> skipped -> None
        assert!(parse_dnsx_jsonl(r#"{"a":["1.2.3.4"]}"#, 50).is_none());
    }

    #[test]
    fn parse_dnsx_caps_results() {
        let lines: Vec<String> = (0..60)
            .map(|i| format!(r#"{{"host":"h{i}.example.com","a":["10.0.0.{i}"]}}"#))
            .collect();
        let jsonl = lines.join("\n");
        let result = parse_dnsx_jsonl(&jsonl, 50).unwrap();
        assert!(result.starts_with("60 record set(s):"));
        assert!(result.contains("... +10 more"));
        assert!(result.contains("h49.example.com"));
        assert!(!result.contains("h50.example.com"));
    }
}
