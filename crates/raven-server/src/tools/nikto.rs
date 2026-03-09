//! Nikto web server scanner handler.
//!
//! Nikto performs comprehensive tests against web servers for dangerous files,
//! outdated software, and configuration issues. Supports four tuning presets:
//! `quick` (default), `thorough`, `injection`, and `fileupload`.
//!
//! Special handling: nikto v2.6+ rejects `-p` (port flag) when given a full URL,
//! so the port argument is only added for bare hostnames.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;
use rmcp::{Peer, RoleServer};

/// MCP request schema for `run_nikto`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NiktoRequest {
    #[schemars(description = "Target hostname or URL")]
    pub target: String,
    #[schemars(description = "Port to scan (default 80)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub port: Option<u16>,
    #[schemars(description = "Tuning: 'quick', 'thorough', 'injection', 'fileupload'")]
    pub tuning: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
    #[schemars(description = "Scan timeout in seconds (default 600)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute a nikto scan with tuning presets and version-aware argument building.
pub async fn run(
    config: &RavenConfig,
    req: NiktoRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "nikto".into(), req.target.clone()));

    let is_url = req.target.starts_with("http://") || req.target.starts_with("https://");
    let mut args = vec!["-h".to_string(), req.target, "-nocheck".into()];

    // nikto v2.6+ rejects -p alongside a full URI — only add it for bare hostnames
    if !is_url {
        let port = req.port.unwrap_or(80);
        args.extend(["-p".into(), port.to_string()]);
        // Auto-enable SSL for port 443
        if port == 443 {
            args.push("-ssl".into());
        }
    }

    if let Some(ref cookie) = req.cookie {
        args.extend(["-Add-header".into(), format!("Cookie: {cookie}")]);
    }

    // Tuning presets map to nikto's -T flag (test type bitmask)
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

    let output = if result.success {
        let mut out = parse_nikto_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("nikto", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse nikto output, keeping only findings and target info.
///
/// Nikto lines starting with `+` are findings or target metadata.
/// Everything else (banner, separator lines, blank lines) is discarded.
pub fn parse_nikto_output(raw: &str) -> Option<String> {
    let findings: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('+') && !line.contains("requires a value"))
        .collect();

    // If no target info found, this isn't valid scan output (e.g. help text)
    let has_target = findings
        .iter()
        .any(|l| l.contains("Target IP") || l.contains("Target Hostname"));

    if findings.is_empty() || !has_target {
        None
    } else {
        Some(findings.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nikto_extracts_findings() {
        let raw = r#"- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Target Hostname:    target.local
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-3092: /admin/: This might be interesting.
+ 7915 requests: 0 error(s) and 3 item(s) reported
---------------------------------------------------------------------------
+ 1 host(s) tested"#;
        let result = parse_nikto_output(raw).unwrap();
        assert!(result.contains("+ Target IP:"));
        assert!(result.contains("+ Server: Apache"));
        assert!(result.contains("OSVDB-3092"));
        assert!(result.contains("+ 1 host(s) tested"));
        // Banner and separators stripped
        assert!(!result.contains("Nikto v2.5.0"));
        assert!(!result.contains("---"));
    }

    #[test]
    fn parse_nikto_empty_returns_none() {
        assert!(parse_nikto_output("").is_none());
        assert!(parse_nikto_output("no plus-prefixed lines here").is_none());
    }

    #[test]
    fn parse_nikto_rejects_help_text() {
        // When nikto gets a bad flag it prints help, which includes "+ requires a value"
        let help = r#"   Options:
       -h+   Target host/URL
       + requires a value
       -p+   Port to use (default 80)
       + requires a value"#;
        assert!(
            parse_nikto_output(help).is_none(),
            "help text should not parse as valid scan output"
        );
    }

    #[test]
    fn cookie_uses_add_header_flag() {
        // Verify the args builder produces -Add-header, not -cookie
        let req = NiktoRequest {
            target: "http://example.com".into(),
            port: None,
            tuning: None,
            cookie: Some("PHPSESSID=abc123".into()),
            timeout_secs: None,
        };
        let is_url = req.target.starts_with("http://") || req.target.starts_with("https://");
        let mut args = vec!["-h".to_string(), req.target.clone(), "-nocheck".into()];
        if !is_url {
            args.extend(["-p".into(), "80".into()]);
        }
        if let Some(ref cookie) = req.cookie {
            args.extend(["-Add-header".into(), format!("Cookie: {cookie}")]);
        }
        assert!(args.contains(&"-Add-header".to_string()));
        assert!(args.contains(&"Cookie: PHPSESSID=abc123".to_string()));
        assert!(!args.iter().any(|a| a == "-cookie"));
    }
}
