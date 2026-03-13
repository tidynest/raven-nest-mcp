//! Masscan high-speed port scanner handler.
//!
//! Masscan can scan the entire internet in under 6 minutes. Because of this
//! power, it has strict safety controls:
//! - Requires root (raw socket access for SYN scanning).
//! - Packet rate is capped by [`SafetyConfig::masscan_max_rate`](raven_core::config::SafetyConfig::masscan_max_rate)
//!   to prevent network saturation.
//! - `--open` flag is always set (only report open ports).
//!
//! This is a fast tool (1-5s for small ranges) and doesn't use a
//! [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_masscan`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MasscanRequest {
    #[schemars(description = "Target CIDR range (e.g. '10.0.0.0/24')")]
    pub target: String,
    #[schemars(description = "Port spec (e.g. '80,443' or '0-65535')")]
    pub ports: String,
    #[schemars(description = "Packets per second (capped by config, default 100)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub rate: Option<u32>,
}

/// Execute masscan with root-privilege check and rate-capped packet transmission.
pub async fn run(
    config: &RavenConfig,
    req: MasscanRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // masscan requires root for raw sockets (SYN scanning)
    // SAFETY: geteuid is a trivial read-only syscall with no invariants
    if unsafe { libc::geteuid() } != 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "masscan requires root privileges (raw socket access)",
            None,
        ));
    }

    // Cap packet rate to configured maximum to prevent network saturation
    let rate = req
        .rate
        .unwrap_or(100)
        .clamp(1, config.safety.masscan_max_rate);

    let args = [
        req.target,
        "-p".to_string(),
        req.ports,
        "--rate".into(),
        rate.to_string(),
        "--open".into(), // only report open ports
    ];

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "masscan", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_masscan_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("masscan", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse masscan output, extracting discovered open ports.
///
/// Result lines start with "Discovered open port" and contain the
/// port/protocol and target IP. Banner, timing, and status lines
/// are discarded.
pub fn parse_masscan_output(raw: &str) -> Option<String> {
    let ports: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Discovered open port"))
        .collect();

    if ports.is_empty() {
        None
    } else {
        Some(format!(
            "{} open port(s) found:\n{}",
            ports.len(),
            ports.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_masscan_extracts_ports() {
        let raw = r#"Starting masscan 1.3.2 (http://bit.ly/14GZzcT)
Initiating SYN Stealth Scan
Scanning 1 hosts [100 ports/host]
Discovered open port 22/tcp on 10.0.0.1
Discovered open port 80/tcp on 10.0.0.1
Discovered open port 443/tcp on 10.0.0.2"#;
        let result = parse_masscan_output(raw).unwrap();
        assert!(result.contains("3 open port(s) found:"));
        assert!(result.contains("22/tcp on 10.0.0.1"));
        assert!(result.contains("80/tcp on 10.0.0.1"));
        assert!(result.contains("443/tcp on 10.0.0.2"));
        assert!(!result.contains("Starting masscan"));
        assert!(!result.contains("Initiating"));
    }

    #[test]
    fn parse_masscan_no_ports_returns_none() {
        let raw = "Starting masscan 1.3.2\nScanning 1 hosts [100 ports/host]\n";
        assert!(parse_masscan_output(raw).is_none());
    }

    #[test]
    fn parse_masscan_empty_returns_none() {
        assert!(parse_masscan_output("").is_none());
    }
}
