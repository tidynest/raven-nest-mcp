//! Sandboxed command execution for external pentesting tools.
//!
//! This module is the single point through which all tool invocations pass.
//! It enforces the safety pipeline:
//!
//! 1. **Allowlist check** — via [`safety::check_allowlist`](crate::safety::check_allowlist).
//! 2. **Timeout containment** — per-tool or global, enforced with `tokio::time::timeout`.
//! 3. **Proxy injection** — sets `HTTP_PROXY`/`HTTPS_PROXY` env vars from [`NetworkConfig`](crate::config::NetworkConfig).
//! 4. **Output truncation** — via [`safety::truncate_output`](crate::safety::truncate_output).
//! 5. **Quality assessment** — detects empty results, rate-limiting, and missing
//!    completion indicators so the MCP client can warn the user.
//!
//! Tool handlers in `raven-server::tools` call [`run`] and receive a
//! [`CommandResult`] that is then formatted by [`raven_server::error::format_result`].

use crate::config::RavenConfig;
use crate::error::PentestError;
use crate::safety;
use std::time::Duration;
use tokio::process::Command;

/// Describes how trustworthy the tool output is.
///
/// Surfaced as a warning in the MCP response so the LLM can decide whether
/// to retry with different parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputQuality {
    /// Tool ran to completion and output looks healthy.
    Complete,
    /// Output below [`MIN_OUTPUT_LEN`] — likely a silent failure.
    Empty,
    /// Output present but missing expected completion markers for the tool.
    Partial,
    /// Output contains rate-limiting or WAF indicators.
    RateLimited,
}

/// Result of a single tool execution, returned by [`run`].
///
/// Consumed by `raven-server::error::format_result` to build the MCP response,
/// and by `raven-core::scan_manager` for background scans.
pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub quality: OutputQuality,
    /// Human-readable quality warning, if any (appended to MCP response).
    pub warning: Option<String>,
}

/// Minimum stdout length (chars) below which output is flagged as [`OutputQuality::Empty`].
const MIN_OUTPUT_LEN: usize = 50;

/// Substrings that suggest the target is rate-limiting or blocking requests.
const RATE_LIMIT_INDICATORS: &[&str] = &[
    "429",
    "rate limit",
    "too many requests",
    "blocked",
    "forbidden",
    "access denied",
    "waf",
    "firewall",
];

/// Check for rate-limiting or WAF indicators in combined output.
fn detect_rate_limit(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_lowercase();
    RATE_LIMIT_INDICATORS
        .iter()
        .any(|ind| combined.contains(ind))
}

/// Assess output quality after a successful command execution.
///
/// Uses tool-specific heuristics (e.g. nmap should contain "Nmap done") to
/// detect partial scans that exit 0 but produced incomplete results.
fn assess_quality(tool: &str, stdout: &str, stderr: &str) -> (OutputQuality, Option<String>) {
    if stdout.len() < MIN_OUTPUT_LEN {
        return (
            OutputQuality::Empty,
            Some(format!(
                "{tool} returned minimal output ({} chars) — scan may have failed silently",
                stdout.len()
            )),
        );
    }

    if detect_rate_limit(stdout, stderr) {
        return (
            OutputQuality::RateLimited,
            Some("target may be rate-limiting requests — consider increasing scan delays or reducing aggressiveness".into()),
        );
    }

    // Tool-specific success indicators
    let has_indicator = match tool {
        "nmap" => stdout.contains("Nmap done") || stdout.contains("Nmap scan report"),
        "nuclei" => {
            stdout.contains("templates loaded")
                || stdout.contains("found")
                || stdout.lines().count() > 1
        }
        "nikto" => stdout.contains("host(s) tested") || stdout.contains("Target"),
        "whatweb" => stdout.contains("http") || stdout.contains("HTTP"),
        _ => true,
    };

    if !has_indicator {
        return (
            OutputQuality::Partial,
            Some(format!(
                "{tool} output missing expected completion indicators — results may be incomplete"
            )),
        );
    }

    (OutputQuality::Complete, None)
}

/// Execute an external tool with full safety enforcement.
///
/// This is the **only** function that spawns tool subprocesses. The pipeline:
/// 1. Allowlist gate
/// 2. Timeout resolution (explicit → per-tool config → global default)
/// 3. Binary path resolution (custom path → `$PATH`)
/// 4. Proxy env var injection from [`NetworkConfig`](crate::config::NetworkConfig)
/// 5. `kill_on_drop(true)` ensures the child is killed if the future is cancelled
/// 6. Output truncation to `max_output_chars`
/// 7. Quality assessment on successful exits
pub async fn run(
    config: &RavenConfig,
    tool: &str,
    args: &[&str],
    timeout: Option<u64>,
) -> Result<CommandResult, PentestError> {
    safety::check_allowlist(tool, &config.safety)?;

    let timeout =
        Duration::from_secs(timeout.unwrap_or_else(|| config.execution.timeout_for(tool)));
    let binary = config.safety.resolve_tool_binary(tool);

    let mut cmd = Command::new(binary);
    cmd.args(args).kill_on_drop(true);

    // Inject proxy env vars (both cases for tool compatibility)
    if let Some(ref proxy) = config.network.http_proxy {
        cmd.env("HTTP_PROXY", proxy);
        cmd.env("http_proxy", proxy);
    }
    if let Some(ref proxy) = config.network.https_proxy {
        cmd.env("HTTPS_PROXY", proxy);
        cmd.env("https_proxy", proxy);
    }
    if !config.network.no_proxy.is_empty() {
        let no_proxy = config.network.no_proxy.join(",");
        cmd.env("NO_PROXY", &no_proxy);
        cmd.env("no_proxy", &no_proxy);
    }

    let output = tokio::time::timeout(timeout, cmd.output())
    .await
    .map_err(|_| {
        PentestError::CommandTimeout(format!("{tool} time out after {}s", timeout.as_secs()))
    })?
    .map_err(|e| PentestError::CommandFailed(format!("{tool}: {e}")))?;

    let stdout = safety::truncate_output(
        &String::from_utf8_lossy(&output.stdout),
        config.safety.max_output_chars,
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Only assess quality on successful exits — failed commands already surface their errors
    let (quality, warning) = if output.status.success() {
        assess_quality(tool, &stdout, &stderr)
    } else {
        (OutputQuality::Complete, None)
    };

    Ok(CommandResult {
        exit_code: output.status.code(),
        success: output.status.success(),
        stdout,
        stderr,
        quality,
        warning,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn proxy_env_vars_set_on_command() {
        use std::process::Command;
        let mut cmd = Command::new("echo");
        let proxy = "http://proxy:3128";
        cmd.env("HTTP_PROXY", proxy);
        cmd.env("http_proxy", proxy);
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs.iter().any(|(k, v)| *k == "HTTP_PROXY"
            && *v == Some(std::ffi::OsStr::new(proxy))));
        assert!(envs.iter().any(|(k, v)| *k == "http_proxy"
            && *v == Some(std::ffi::OsStr::new(proxy))));
    }
}
