//! Secret scanning via gitleaks.
//!
//! Scans a directory's working tree (`gitleaks dir`) or a repo's full commit
//! history (`gitleaks git`) for committed secrets — API keys, tokens, private
//! keys. The scan path is confined to the configured output directory (plus
//! `/usr/share`, `/usr/lib`) by [`validate_file_path`](super::validate_file_path),
//! so clone target repos into the engagement workspace before scanning.
//!
//! Secret values are redacted by default and never printed by the parser
//! (location + rule id only); set `show_secrets` to reveal them in the raw
//! report. Slow tool — uses a [`ProgressTicker`](crate::progress::ProgressTicker).
//!
//! ponytail: path confined to output_dir; if operators need arbitrary scan
//! roots, add a config path-allowlist. Report is read from `/dev/stdout`
//! (Linux); a Windows port would need a temp report file instead.

use raven_core::{config::RavenConfig, executor};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_gitleaks`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitleaksRequest {
    #[schemars(description = "Directory or git repo to scan (must be under the output directory)")]
    pub path: String,
    #[schemars(
        description = "Scan full git commit history instead of just the working tree (default false)"
    )]
    pub scan_git_history: Option<bool>,
    #[schemars(description = "Reveal secret values instead of redacting them (default false)")]
    pub show_secrets: Option<bool>,
}

/// Execute gitleaks to detect committed secrets.
pub async fn run(
    config: &RavenConfig,
    req: GitleaksRequest,
    peer: Option<rmcp::Peer<rmcp::RoleServer>>,
) -> Result<(CallToolResult, Vec<crate::tools::extract::ExtractedFinding>), rmcp::ErrorData> {
    // Confine the scan root to the engagement workspace (same gate as john).
    super::validate_file_path(&req.path, &config.execution.output_dir)?;

    // `git` walks commit history; `dir` scans the working tree (and works on
    // non-git directories too). The JSON report is written to stdout; gitleaks'
    // own logs go to stderr, so stdout stays pure JSON.
    let subcmd = if req.scan_git_history.unwrap_or(false) {
        "git"
    } else {
        "dir"
    };
    let mut args = vec![
        subcmd,
        req.path.as_str(),
        "--report-format",
        "json",
        "--report-path",
        "/dev/stdout",
        "--no-banner",
    ];
    // Redact secret values in the report unless explicitly asked to reveal them.
    if !req.show_secrets.unwrap_or(false) {
        args.push("--redact");
    }

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "gitleaks".into(), req.path.clone()));

    let result = executor::run(config, "gitleaks", &args, Some(300))
        .await
        .map_err(crate::error::to_mcp)?;

    // gitleaks exit codes: 0 = no leaks, 1 = leaks found (our success case),
    // anything else = a real error.
    let mut findings = Vec::new();
    let output = match result.exit_code {
        Some(0) => "No secrets detected.".to_string(),
        Some(1) => {
            findings = crate::tools::extract::extract_gitleaks(&result.stdout);
            parse_gitleaks(&result.stdout).unwrap_or_else(|| result.stdout.clone())
        }
        _ => crate::error::format_result("gitleaks", &result),
    };
    Ok((
        CallToolResult::success(vec![Content::text(output)]),
        findings,
    ))
}

/// One entry from a gitleaks JSON report. Only the fields used in the summary
/// are deserialized; the `Secret`/`Match` fields are deliberately ignored so a
/// live secret value can never reach the summary text.
#[derive(serde::Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "StartLine")]
    start_line: i64,
    #[serde(rename = "Commit", default)]
    commit: String,
}

/// Parse a gitleaks JSON report into a compact summary: one line per finding
/// with rule id, file:line, short commit (history mode), and description.
/// Returns `None` on parse failure so the caller falls back to the raw output.
fn parse_gitleaks(json: &str) -> Option<String> {
    let findings: Vec<GitleaksFinding> = serde_json::from_str(json.trim()).ok()?;
    if findings.is_empty() {
        return Some("No secrets detected.".to_string());
    }
    let mut out = format!("{} secret(s) detected:\n", findings.len());
    for f in &findings {
        let loc = if f.commit.is_empty() {
            format!("{}:{}", f.file, f.start_line)
        } else {
            format!(
                "{}:{} (commit {})",
                f.file,
                f.start_line,
                &f.commit[..f.commit.len().min(8)]
            )
        };
        out.push_str(&format!("- [{}] {} — {}\n", f.rule_id, loc, f.description));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gitleaks_summarizes_without_leaking_secrets() {
        let json = r#"[
          {"RuleID":"generic-api-key","Description":"API key","File":"src/config.js","StartLine":12,"Secret":"AKIALEAKEDVALUE","Match":"key=AKIALEAKEDVALUE","Commit":"abcdef1234567890"},
          {"RuleID":"private-key","Description":"Private key","File":"id_rsa","StartLine":1,"Secret":"-----BEGINKEY","Commit":""}
        ]"#;
        let out = parse_gitleaks(json).unwrap();
        assert!(out.contains("2 secret(s)"));
        assert!(out.contains("generic-api-key"));
        assert!(out.contains("src/config.js:12"));
        assert!(out.contains("commit abcdef12")); // short commit in history mode
        assert!(out.contains("id_rsa:1"));
        // The secret value must never appear in the summary.
        assert!(!out.contains("AKIALEAKEDVALUE"));
        assert!(!out.contains("BEGINKEY"));
    }

    #[test]
    fn parse_gitleaks_handles_empty_report() {
        assert_eq!(parse_gitleaks("[]").unwrap(), "No secrets detected.");
    }

    #[test]
    fn parse_gitleaks_rejects_non_json() {
        assert!(parse_gitleaks("gitleaks: command failed").is_none());
    }
}
