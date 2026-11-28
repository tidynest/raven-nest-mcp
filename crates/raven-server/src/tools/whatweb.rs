//! WhatWeb technology identification handler.
//!
//! WhatWeb identifies web technologies (CMS, frameworks, servers, JS libraries)
//! from HTTP responses. Three aggression levels control how much probing is done.
//! They are whatweb's own: it has no level 2.
//! - `stealthy` (default, level 1) - one request per target, follows redirects.
//! - `aggressive` (level 3) - extra requests when a level 1 plugin matches.
//! - `heavy` (level 4) - many requests per target, every plugin URL is tried.
//!
//! `passive` is accepted as an old name for `stealthy`. It used to map to
//! level 2, which whatweb rejects, so the scan returned nothing.
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
    #[schemars(description = "Aggression: 'stealthy' (default), 'aggressive', 'heavy'")]
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

    let level = aggression_level(req.aggression.as_deref());

    let mut args = vec![
        "-a".to_string(),
        level.into(),
        "--color=never".into(),
        req.target.clone(),
    ];
    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(
        config,
        "whatweb",
        Some(req.target.as_str()),
        &arg_refs,
        None,
        parse_whatweb_output,
    )
    .await
}

/// Map an aggression name to whatweb's numeric `-a` level. whatweb accepts
/// 1, 3 and 4 only. Anything else, the old `passive` included, is stealthy.
fn aggression_level(aggression: Option<&str>) -> &'static str {
    match aggression {
        Some("aggressive") => "3",
        Some("heavy") => "4",
        _ => "1",
    }
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
    fn aggression_maps_only_to_levels_whatweb_accepts() {
        assert_eq!(aggression_level(None), "1");
        assert_eq!(aggression_level(Some("stealthy")), "1");
        assert_eq!(aggression_level(Some("aggressive")), "3");
        assert_eq!(aggression_level(Some("heavy")), "4");
        // The old name, and anything unknown, fall back to stealthy. Level 2
        // does not exist in whatweb and must never be produced.
        assert_eq!(aggression_level(Some("passive")), "1");
        assert_eq!(aggression_level(Some("maximum")), "1");
    }

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
