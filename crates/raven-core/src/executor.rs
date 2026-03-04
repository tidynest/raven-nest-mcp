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

    let timeout = Duration::from_secs(timeout.unwrap_or(config.execution.default_timeout_secs));

    let output = tokio::time::timeout(
        timeout,
        Command::new(tool).args(args).kill_on_drop(true).output(),
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_rate_limit ────────────────────────────────────

    #[test]
    fn detects_429_in_stdout() {
        assert!(detect_rate_limit("HTTP/1.1 429 Too Many Requests", ""));
    }

    #[test]
    fn no_false_positive_on_clean_output() {
        let stdout =
            "Nmap scan report for 192.168.1.1\nPORT STATE SERVICE\n80/tcp open http\nNmap done";
        assert!(!detect_rate_limit(stdout, ""));
    }

    // ── assess_quality ───────────────────────────────────────

    #[test]
    fn empty_output_flagged() {
        let (quality, warning) = assess_quality("nmap", "tiny", "");
        assert_eq!(quality, OutputQuality::Empty);
        assert!(warning.unwrap().contains("minimal output"));
    }

    #[test]
    fn rate_limited_output_flagged() {
        let stdout = "X".repeat(60) + " blocked by WAF";
        let (quality, warning) = assess_quality("nuclei", &stdout, "");
        assert_eq!(quality, OutputQuality::RateLimited);
        assert!(warning.is_some());
    }

    #[test]
    fn complete_nmap_output() {
        let stdout = format!("{}\nNmap done: 1 IP address scanned", "X".repeat(60));
        let (quality, warning) = assess_quality("nmap", &stdout, "");
        assert_eq!(quality, OutputQuality::Complete);
        assert!(warning.is_none());
    }
}
