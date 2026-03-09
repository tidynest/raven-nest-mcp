//! testssl.sh SSL/TLS configuration auditing handler.
//!
//! Tests a server's TLS configuration for vulnerabilities, weak ciphers,
//! certificate issues, and protocol support. Supports quick mode (fewer checks)
//! and severity-based filtering.
//!
//! Note: `--fast` is deprecated in testssl.sh 3.2+, so quick mode uses
//! `--quiet --sneaky` instead.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_testssl`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestsslRequest {
    #[schemars(description = "Target hostname, host:port, or URL")]
    pub target: String,
    #[schemars(description = "Run in fast mode (fewer checks)")]
    pub quick: Option<bool>,
    #[schemars(description = "Severity filter: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")]
    pub severity: Option<String>,
}

/// Execute testssl.sh with optional quick mode and severity filtering.
pub async fn run(
    config: &RavenConfig,
    req: TestsslRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "testssl".into(), req.target.clone()));

    let mut args = Vec::new();

    if req.quick.unwrap_or(false) {
        // --fast is deprecated in testssl.sh 3.2+; use individual flags instead
        args.extend(["--quiet".to_string(), "--sneaky".into()]);
    }

    // Validate and apply severity filter (case-insensitive input)
    if let Some(ref sev) = req.severity {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        if valid.contains(&sev.to_uppercase().as_str()) {
            args.extend(["--severity".into(), sev.to_uppercase()]);
        }
    }

    args.push(req.target);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "testssl.sh", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_testssl_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("testssl.sh", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse testssl.sh output, extracting vulnerability findings and certificate info.
///
/// Keeps vulnerability assessment lines (VULNERABLE / not vulnerable),
/// certificate subject/issuer/expiry, and overall rating. Discards the
/// verbose cipher enumeration and protocol negotiation details that
/// dominate testssl output.
pub fn parse_testssl_output(raw: &str) -> Option<String> {
    let mut output = String::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Vulnerability assessments
        if trimmed.contains("VULNERABLE") || trimmed.contains("not vulnerable") {
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Certificate details
        if trimmed.starts_with("Common Name")
            || trimmed.starts_with("Subject Alternative Name")
            || trimmed.starts_with("Issuer")
            || trimmed.contains("expires")
            || trimmed.starts_with("Trust")
            || trimmed.starts_with("Certificate Transparency")
        {
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Overall rating
        if trimmed.starts_with("Overall Grade") || trimmed.starts_with("Rating") {
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Section headers for context
        if trimmed.starts_with("Testing vulnerabilities")
            || trimmed.starts_with("Server Certificate")
        {
            output.push('\n');
            output.push_str(trimmed);
            output.push('\n');
        }
    }

    let result = output.trim().to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_testssl_extracts_vulns_and_certs() {
        let raw = r#"
 Start 2026-03-08 10:00:00

 Testing protocols via sockets
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

 Testing cipher categories
 NULL ciphers                      not offered (OK)
 Export ciphers                    not offered (OK)

 Server Certificate #1
   Common Name (CN)       example.com
   Issuer                 Let's Encrypt Authority X3
   Trust (hostname)       Ok via SAN
   Certificate Transparency  yes

 Testing vulnerabilities

   Heartbleed (CVE-2014-0160)            not vulnerable (OK)
   CCS (CVE-2014-0224)                   not vulnerable (OK)
   ROBOT                                 not vulnerable (OK)
   POODLE, TLS (CVE-2014-8730)           not vulnerable (OK)
   DROWN (CVE-2016-0800)                 not vulnerable (OK)

 Rating (experimental) A
"#;
        let result = parse_testssl_output(raw).unwrap();
        assert!(result.contains("Common Name"));
        assert!(result.contains("Heartbleed"));
        assert!(result.contains("not vulnerable"));
        assert!(result.contains("Rating"));
        // Cipher enumeration should be stripped
        assert!(!result.contains("NULL ciphers"));
        assert!(!result.contains("Export ciphers"));
        // Protocol details stripped
        assert!(!result.contains("SSLv2"));
        assert!(!result.contains("TLS 1.2"));
    }

    #[test]
    fn parse_testssl_detects_vulnerable() {
        let raw = "   Heartbleed (CVE-2014-0160)            VULNERABLE (NOT ok)";
        let result = parse_testssl_output(raw).unwrap();
        assert!(result.contains("VULNERABLE"));
    }

    #[test]
    fn parse_testssl_empty_returns_none() {
        assert!(parse_testssl_output("").is_none());
        assert!(parse_testssl_output("Testing protocols\nTLS 1.2 offered").is_none());
    }
}
