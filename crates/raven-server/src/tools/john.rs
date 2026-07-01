//! Password cracking via John the Ripper.
//!
//! Runs john against a hash file with optional wordlist and format specification.
//! Runtime is capped via `--max-run-time` (default 300s, max 600s) to prevent
//! runaway sessions.
//!
//! This is a slow tool (30-300s) and uses a
//! [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, executor};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_john`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JohnRequest {
    #[schemars(description = "Path to hash file")]
    pub hash_file: String,
    #[schemars(description = "Path to wordlist file")]
    pub wordlist: Option<String>,
    #[schemars(description = "Hash format (e.g. 'raw-md5', 'bcrypt', 'sha512crypt')")]
    pub format: Option<String>,
    #[schemars(description = "Max runtime in seconds (default 300, max 600)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub max_run_time: Option<u64>,
}

/// Execute John the Ripper for password cracking.
pub async fn run(
    config: &RavenConfig,
    req: JohnRequest,
    peer: Option<rmcp::Peer<rmcp::RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Validate file paths - prevent reading arbitrary files
    super::validate_file_path(&req.hash_file, &config.execution.output_dir)?;
    if let Some(ref wordlist) = req.wordlist {
        super::validate_file_path(wordlist, &config.execution.output_dir)?;
    }

    let pot_file = format!("{}/john.pot", config.execution.output_dir);
    let max_time = req.max_run_time.unwrap_or(300).min(600);

    let mut args = vec![
        format!("--pot={pot_file}"),
        format!("--max-run-time={max_time}"),
    ];

    if let Some(ref wordlist) = req.wordlist {
        args.push(format!("--wordlist={wordlist}"));
    }
    if let Some(ref format) = req.format {
        args.push(format!("--format={format}"));
    }

    let hash_file_display = req.hash_file.clone();
    args.push(req.hash_file);

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "john".into(), hash_file_display));

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let timeout = Some(max_time + 30); // grace period beyond max-run-time
    let result = executor::run(config, "john", &arg_refs, timeout)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_john_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("john", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse John the Ripper output to extract cracked passwords.
///
/// John outputs cracked passwords as `password (username)` lines. Also looks
/// for status lines like "N passwords cracked" and "guesses: N".
fn parse_john_output(raw: &str) -> Option<String> {
    let mut cracked = Vec::new();
    let mut status_lines = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Cracked password lines contain "(username)" at the end
        if trimmed.contains('(') && trimmed.ends_with(')') {
            cracked.push(trimmed.to_string());
        } else if trimmed.contains("password")
            || trimmed.contains("guesses:")
            || trimmed.contains("cracked")
            || trimmed.contains("Session completed")
            || trimmed.contains("Session aborted")
        {
            status_lines.push(trimmed.to_string());
        }
    }

    if cracked.is_empty() && status_lines.is_empty() {
        return None;
    }

    let mut out = String::new();
    if !cracked.is_empty() {
        out.push_str(&format!("{} password(s) cracked:\n", cracked.len()));
        out.push_str(&cracked.join("\n"));
    } else {
        out.push_str("0 passwords cracked");
    }
    if !status_lines.is_empty() {
        out.push_str(&format!("\n\n{}", status_lines.join("\n")));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_john_extracts_cracked() {
        let output = "Using default input encoding: UTF-8\n\
                      Loaded 3 password hashes\n\
                      password123      (admin)\n\
                      letmein          (user1)\n\
                      2g 0:00:00:05 DONE 0.40g/s 1234p/s\n\
                      Session completed";
        let result = parse_john_output(output).unwrap();
        assert!(result.contains("2 password(s) cracked:"));
        assert!(result.contains("password123      (admin)"));
        assert!(result.contains("letmein          (user1)"));
        assert!(result.contains("Session completed"));
    }

    #[test]
    fn parse_john_no_cracked() {
        let output = "Loaded 5 password hashes\n\
                      0g 0:00:05:00 DONE 0.00g/s 5000p/s\n\
                      Session completed";
        let result = parse_john_output(output).unwrap();
        assert!(result.contains("0 passwords cracked"));
        assert!(result.contains("Session completed"));
    }

    #[test]
    fn parse_john_empty_returns_none() {
        assert!(parse_john_output("").is_none());
        assert!(parse_john_output("   \n  \n").is_none());
    }
}
