//! Feroxbuster directory and content discovery handler.
//!
//! Feroxbuster brute-forces directories and files using a wordlist. Supports
//! file extension probing, thread count control, and HTTP status code filtering.
//!
//! Thread count defaults to 50 for remote targets but drops to 10 for localhost
//! (via [`is_localhost`](super::is_localhost)) to prevent self-DoS during local testing.
//! Maximum is capped at 200 regardless of input.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// Default wordlist path (SecLists raft-medium-directories).
const DEFAULT_WORDLIST: &str =
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt";

/// MCP request schema for `run_feroxbuster`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeroxbusterRequest {
    #[schemars(description = "Target URL (e.g. 'http://example.com')")]
    pub target: String,
    #[schemars(description = "Path to wordlist file (default: raft-medium-directories.txt)")]
    pub wordlist: Option<String>,
    #[schemars(description = "File extensions to check (e.g. 'php,html,txt')")]
    pub extensions: Option<String>,
    #[schemars(description = "Number of concurrent threads (default 50)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub threads: Option<u16>,
    #[schemars(description = "HTTP status codes to include (e.g. '200,301,302')")]
    pub status_codes: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
}

/// Execute feroxbuster for directory discovery.
pub async fn run(
    config: &RavenConfig,
    req: FeroxbusterRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "feroxbuster".into(), req.target.clone())
    });

    // Reduce threads for localhost to prevent self-DoS
    let default_threads: u16 = if super::is_localhost(&req.target) {
        10
    } else {
        50
    };
    let threads = req.threads.unwrap_or(default_threads).min(200);

    let wordlist = req.wordlist.as_deref().unwrap_or(DEFAULT_WORDLIST);
    let mut args = vec![
        "-u".to_string(),
        req.target,
        "-w".into(),
        wordlist.into(),
        "--no-state".into(),
        "-q".into(),
    ];

    if let Some(ref ext) = req.extensions {
        args.extend(["-x".into(), ext.clone()]);
    }
    args.extend(["-t".into(), threads.to_string()]);

    if let Some(ref codes) = req.status_codes {
        args.extend(["-s".into(), codes.clone()]);
    }
    if let Some(ref cookie) = req.cookie {
        args.extend(["-b".into(), cookie.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "feroxbuster", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out =
            parse_feroxbuster_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("feroxbuster", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse feroxbuster quiet-mode output to extract discovered URLs.
///
/// In quiet mode (`-q`), each result line starts with a 3-digit status code
/// followed by method, dimensions, and URL. Extracts status + URL pairs,
/// discarding progress bars and stats.
pub fn parse_feroxbuster_output(raw: &str) -> Option<String> {
    let mut results = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // Quiet-mode lines start with a 3-digit HTTP status code
        let starts_with_status = parts
            .first()
            .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()));
        if starts_with_status {
            let status = parts[0];
            if status == "404" {
                continue;
            }
            // Extract status and URL (token containing "http")
            if let Some(url_pos) = parts.iter().position(|p| p.starts_with("http")) {
                let url_and_rest = parts[url_pos..].join(" ");
                results.push(format!("{status}  {url_and_rest}"));
            }
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(format!(
            "{} URL(s) discovered:\n{}",
            results.len(),
            results.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feroxbuster_extracts_urls() {
        let raw = "200      GET        5l       10w      178c http://example.com/index.html\n301      GET        5l       10w      178c http://example.com/admin => http://example.com/admin/\n403      GET        5l       10w      178c http://example.com/server-status";
        let result = parse_feroxbuster_output(raw).unwrap();
        assert!(result.starts_with("3 URL(s) discovered:"));
        assert!(result.contains("200  http://example.com/index.html"));
        assert!(result.contains("301  http://example.com/admin"));
        assert!(result.contains("403  http://example.com/server-status"));
    }

    #[test]
    fn parse_feroxbuster_filters_404s() {
        let raw = "200      GET        5l       10w      178c http://example.com/index.html\n404      GET        1l        2w       15c http://example.com/missing\n301      GET        5l       10w      178c http://example.com/admin => http://example.com/admin/\n404      GET        1l        2w       15c http://example.com/nope";
        let result = parse_feroxbuster_output(raw).unwrap();
        assert!(result.starts_with("2 URL(s) discovered:"));
        assert!(result.contains("200  http://example.com/index.html"));
        assert!(result.contains("301  http://example.com/admin"));
        assert!(!result.contains("404"));
        assert!(!result.contains("missing"));
        assert!(!result.contains("nope"));
    }

    #[test]
    fn parse_feroxbuster_all_404s_returns_none() {
        let raw = "404      GET        1l        2w       15c http://example.com/a\n404      GET        1l        2w       15c http://example.com/b";
        assert!(parse_feroxbuster_output(raw).is_none());
    }

    #[test]
    fn parse_feroxbuster_empty_returns_none() {
        assert!(parse_feroxbuster_output("").is_none());
        assert!(parse_feroxbuster_output("progress: 50%\nscanning...").is_none());
    }
}
