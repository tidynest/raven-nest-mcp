//! WhatWeb technology identification handler.
//!
//! WhatWeb identifies web technologies (CMS, frameworks, servers, JS libraries)
//! from HTTP responses. Three aggression levels control how much probing is done:
//! - `stealthy` (default, level 1) - single request, passive analysis.
//! - `passive` (level 2) - follows redirects, parses additional pages.
//! - `aggressive` (level 4) - actively probes with extra requests.
//!
//! This is a fast tool (1-5s) and doesn't require a [`ProgressTicker`](crate::progress::ProgressTicker).

use raven_core::{config::RavenConfig, safety};
use rmcp::model::CallToolResult;
use rmcp::schemars;

/// MCP request schema for `run_whatweb`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WhatwebRequest {
    #[schemars(description = "Target URL or hostname")]
    pub target: String,
    #[schemars(description = "Aggression: 'stealthy', 'passive', 'aggressive'")]
    pub aggression: Option<String>,
    #[schemars(description = "Cookie string for authenticated scanning (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
}

/// Execute whatweb with the specified aggression level.
pub async fn run(
    config: &RavenConfig,
    req: WhatwebRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // Map aggression names to whatweb's numeric -a levels
    let level = match req.aggression.as_deref() {
        Some("passive") => "2",
        Some("aggressive") => "4",
        _ => "1", // stealthy (default)
    };

    let mut args = vec![
        "-a".to_string(),
        level.into(),
        "--color=never".into(),
        req.target,
    ];
    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "whatweb", &arg_refs, None, parse_whatweb_output).await
}

/// Parse whatweb output, keeping only technology identification lines.
///
/// Valid result lines start with `http://` or `https://` followed by status
/// and detected technologies in bracket notation. Blank lines, errors, and
/// verbose logging are discarded.
pub fn parse_whatweb_output(raw: &str) -> Option<String> {
    let results: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| {
            (line.starts_with("http://") || line.starts_with("https://")) && line.contains('[')
        })
        .collect();

    if results.is_empty() {
        None
    } else {
        Some(results.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whatweb_extracts_tech_lines() {
        let raw = r#"WhatWeb report for http://10.0.0.1
http://10.0.0.1 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.0.0.1], Title[Welcome]
http://10.0.0.1/admin [403 Forbidden] Apache[2.4.25], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)]"#;
        let result = parse_whatweb_output(raw).unwrap();
        assert!(result.contains("[200 OK]"));
        assert!(result.contains("Apache[2.4.25]"));
        assert!(result.contains("[403 Forbidden]"));
        assert!(!result.contains("WhatWeb report for"));
    }

    #[test]
    fn parse_whatweb_empty_returns_none() {
        assert!(parse_whatweb_output("").is_none());
        assert!(parse_whatweb_output("WhatWeb report for http://10.0.0.1\n").is_none());
        assert!(parse_whatweb_output("ERROR: connection refused").is_none());
    }
}
