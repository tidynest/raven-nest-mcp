//! Ffuf web fuzzer handler.
//!
//! Ffuf substitutes the `FUZZ` keyword in URLs (and optionally headers/bodies)
//! with wordlist entries. Supports custom HTTP methods, headers, status code
//! matching, and response size filtering.
//!
//! Like [`feroxbuster`](super::feroxbuster), thread count defaults lower for
//! localhost targets (10 vs 40) and is capped at 150.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

/// Default wordlist path (SecLists raft-medium-words).
const DEFAULT_WORDLIST: &str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt";

/// MCP request schema for `run_ffuf`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FfufRequest {
    #[schemars(description = "Target URL with FUZZ keyword (e.g. 'http://example.com/FUZZ')")]
    pub url: String,
    #[schemars(description = "Path to wordlist file")]
    pub wordlist: Option<String>,
    #[schemars(description = "HTTP method (default GET)")]
    pub method: Option<String>,
    #[schemars(description = "Custom headers as 'Name: Value' (repeatable, comma-separated)")]
    pub headers: Option<String>,
    #[schemars(description = "Match HTTP status codes (e.g. '200,301,302')")]
    pub match_codes: Option<String>,
    #[schemars(description = "Filter responses by size (bytes)")]
    pub filter_size: Option<String>,
    #[schemars(
        description = "Number of concurrent threads (default 40, reduced to 10 for localhost)"
    )]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub threads: Option<u16>,
    #[schemars(description = "Cookie string for authenticated fuzzing (e.g. 'PHPSESSID=abc123')")]
    pub cookie: Option<String>,
}

/// Execute ffuf with FUZZ keyword substitution and configurable filtering.
pub async fn run(
    config: &RavenConfig,
    req: FfufRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Validate the base URL (substitute FUZZ keyword for validation only)
    let validation_url = req.url.replace("FUZZ", "test");
    safety::validate_target(&validation_url).map_err(crate::error::to_mcp)?;

    // The FUZZ keyword is required — it's the substitution point for wordlist entries
    if !req.url.contains("FUZZ") {
        return Err(rmcp::ErrorData::invalid_params(
            "URL must contain the FUZZ keyword (e.g. http://example.com/FUZZ)",
            None,
        ));
    }

    // Reduce threads for localhost to prevent self-DoS
    let default_threads: u16 = if super::is_localhost(&req.url) {
        10
    } else {
        40
    };
    let threads = req.threads.unwrap_or(default_threads).min(150);

    let wordlist = req.wordlist.as_deref().unwrap_or(DEFAULT_WORDLIST);
    let mut args = vec![
        "-u".to_string(),
        req.url,
        "-w".into(),
        wordlist.into(),
        "-noninteractive".into(),
        "-t".into(),
        threads.to_string(),
    ];

    if let Some(ref method) = req.method {
        args.extend(["-X".into(), method.to_uppercase()]);
    }

    // Split comma-separated headers into individual -H flags
    if let Some(ref headers) = req.headers {
        for header in headers.split(',') {
            args.extend(["-H".into(), header.trim().to_string()]);
        }
    }

    if let Some(ref codes) = req.match_codes {
        args.extend(["-mc".into(), codes.clone()]);
    }

    if let Some(ref size) = req.filter_size {
        args.extend(["-fs".into(), size.clone()]);
    }
    if let Some(ref cookie) = req.cookie {
        args.extend(["-b".into(), cookie.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "ffuf", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_ffuf_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("ffuf", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Parse ffuf output, extracting fuzzing results.
///
/// Result lines contain `[Status: NNN,` with the matched word, HTTP status,
/// response size, and word/line counts. The ASCII banner, config header,
/// and progress lines are discarded.
pub fn parse_ffuf_output(raw: &str) -> Option<String> {
    let results: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("[Status:"))
        .collect();

    if results.is_empty() {
        None
    } else {
        Some(format!(
            "{} result(s) found:\n{}",
            results.len(),
            results.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ffuf_extracts_results() {
        let raw = r#"        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.0.1/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
________________________________________________

admin                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
index.html              [Status: 200, Size: 1256, Words: 156, Lines: 42, Duration: 15ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 12ms]
:: Progress: [63087/63087] :: Job [1/1] :: 500 req/sec :: Duration: [0:02:06] :: Errors: 0 ::"#;
        let result = parse_ffuf_output(raw).unwrap();
        assert!(result.contains("3 result(s) found:"));
        assert!(result.contains("admin"));
        assert!(result.contains("[Status: 301,"));
        assert!(result.contains("index.html"));
        assert!(result.contains("[Status: 200,"));
        assert!(!result.contains("/'___\\"));
        assert!(!result.contains(":: Progress:"));
        assert!(!result.contains(":: Method"));
    }

    #[test]
    fn parse_ffuf_no_results_returns_none() {
        let raw = r#"       v2.1.0
 :: Method           : GET
 :: URL              : http://10.0.0.1/FUZZ
:: Progress: [63087/63087] :: Job [1/1] :: 500 req/sec :: Duration: [0:02:06] :: Errors: 0 ::"#;
        assert!(parse_ffuf_output(raw).is_none());
    }

    #[test]
    fn parse_ffuf_empty_returns_none() {
        assert!(parse_ffuf_output("").is_none());
    }
}
