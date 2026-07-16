//! DNS reconnaissance via dnsrecon.
//!
//! Performs DNS enumeration including standard lookups, zone transfers, and SRV
//! record discovery. Output is requested in JSON format (`-j /dev/stdout`) for
//! structured parsing.
//!
//! This is a medium-duration tool (5-30s) and uses a
//! [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, safety};
use rmcp::model::CallToolResult;
use rmcp::schemars;

/// MCP request schema for `run_dnsrecon`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsreconRequest {
    #[schemars(description = "Target domain to enumerate")]
    pub target: String,
    #[schemars(description = "Scan type: 'standard' (default), 'zone_transfer', 'srv'")]
    pub scan_type: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute dnsrecon for DNS enumeration.
pub async fn run(
    config: &RavenConfig,
    req: DnsreconRequest,
    peer: Option<rmcp::Peer<rmcp::RoleServer>>,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let target_display = req.target.clone();
    let mut args = vec![
        "-d".to_string(),
        req.target,
        "-j".into(),
        "/dev/stdout".into(),
    ];

    if let Some(ref scan_type) = req.scan_type {
        match scan_type.as_str() {
            "zone_transfer" => args.extend(["-t".into(), "axfr".into()]),
            "srv" => args.extend(["-t".into(), "srv".into()]),
            "standard" | "" => {} // default
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid scan_type '{other}' - must be: standard, zone_transfer, srv"),
                    None,
                ));
            }
        }
    }

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "dnsrecon".into(), target_display));

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "dnsrecon", &arg_refs, req.timeout_secs, |s| {
        parse_dnsrecon_json(s, result_limit)
    })
    .await
}

/// Parse dnsrecon JSON output into compact record lines.
///
/// dnsrecon outputs a JSON array of record objects with `type`, `name`, `address`
/// (or `target` for SRV/MX). Extracts `TYPE NAME VALUE`, caps at 30.
fn parse_dnsrecon_json(raw: &str, max_results: usize) -> Option<String> {
    // dnsrecon may emit text before/after JSON - find the array.
    // Use "[{" to avoid matching bracket chars in non-JSON text like "[*]".
    let trimmed = raw.trim();
    let json_start = trimmed.find("[{").or_else(|| trimmed.find("[\n"))?;
    let json_end = trimmed.rfind(']')? + 1;
    let json_str = &trimmed[json_start..json_end];

    let records: Vec<serde_json::Value> = serde_json::from_str(json_str).ok()?;
    let mut entries = Vec::new();

    for rec in &records {
        let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
        // MX/NS/SRV/CNAME use "target"; A/AAAA use "address"; TXT uses "strings"
        let value = rec
            .get("target")
            .or_else(|| rec.get("address"))
            .or_else(|| rec.get("strings"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !name.is_empty() && rtype != "info" {
            entries.push(format!("{rtype}\t{name}\t{value}"));
        }
    }

    if entries.is_empty() {
        return None;
    }

    let total = entries.len();
    let truncated = total > max_results;
    entries.truncate(max_results);

    let mut out = format!("{total} DNS record(s):\n{}", entries.join("\n"));
    if truncated {
        out.push_str(&format!("\n+{} more", total - max_results));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dnsrecon_extracts_records() {
        let json = r#"[
            {"type":"A","name":"example.com","address":"93.184.216.34"},
            {"type":"MX","name":"example.com","target":"mail.example.com","exchange_address":"93.184.216.35","priority":"10"},
            {"type":"NS","name":"example.com","target":"ns1.example.com","address":"198.51.100.1"},
            {"type":"info","name":"dnsrecon version","address":""}
        ]"#;
        let result = parse_dnsrecon_json(json, 30).unwrap();
        assert!(result.starts_with("3 DNS record(s):"));
        assert!(result.contains("A\texample.com\t93.184.216.34"));
        assert!(result.contains("MX\texample.com\tmail.example.com"));
        assert!(result.contains("NS\texample.com\tns1.example.com"));
        // info records should be filtered
        assert!(!result.contains("dnsrecon version"));
    }

    #[test]
    fn parse_dnsrecon_empty_returns_none() {
        assert!(parse_dnsrecon_json("", 30).is_none());
        assert!(parse_dnsrecon_json("[]", 30).is_none());
        assert!(parse_dnsrecon_json("no json", 30).is_none());
    }

    #[test]
    fn parse_dnsrecon_handles_text_prefix() {
        let raw = "[*] Performing General Enumeration...\n[{\"type\":\"A\",\"name\":\"test.com\",\"address\":\"1.2.3.4\"}]";
        let result = parse_dnsrecon_json(raw, 30).unwrap();
        assert!(result.contains("A\ttest.com\t1.2.3.4"));
    }

    #[test]
    fn parse_dnsrecon_caps_at_30() {
        let records: Vec<String> = (0..45)
            .map(|i| {
                format!(r#"{{"type":"A","name":"sub{i}.example.com","address":"10.0.0.{i}"}}"#)
            })
            .collect();
        let json = format!("[{}]", records.join(","));
        let result = parse_dnsrecon_json(&json, 30).unwrap();
        assert!(result.starts_with("45 DNS record(s):"));
        assert!(result.contains("+15 more"));
    }
}
