use crate::config::RavenConfig;
use crate::error::PentestError;
use crate::safety;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputQuality {
    Complete,
    Empty,
    Partial,
    RateLimited,
}

pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub quality: OutputQuality,
    pub warning: Option<String>,
}

const MIN_OUTPUT_LEN: usize = 50;

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

    let output = tokio::time::timeout(
        timeout,
        Command::new(binary).args(args).kill_on_drop(true).output(),
    )
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
