//! Sqlmap SQL injection detection and exploitation handler.
//!
//! Sqlmap tests URLs for SQL injection vulnerabilities. Runs in `--batch` mode
//! (no interactive prompts) with level/risk capped by [`SafetyConfig`](raven_core::config::SafetyConfig)
//! to prevent the LLM from escalating to destructive payloads.
//!
//! Supports POST data, cookies for authenticated testing, and technique selection
//! (`BEUSTQ` — Boolean, Error, Union, Stacked, Time-based, Query-based).

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_sqlmap`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SqlmapRequest {
    #[schemars(description = "Target URL with injectable parameter")]
    pub url: String,
    #[schemars(description = "POST body data (e.g. 'user=test&pass=test')")]
    pub data: Option<String>,
    #[schemars(description = "Cookie string for authenticated testing")]
    pub cookie: Option<String>,
    #[schemars(description = "Test level 1-5 (default 1, capped by config)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub level: Option<u8>,
    #[schemars(description = "Risk level 1-3 (default 1, capped by config)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub risk: Option<u8>,
    #[schemars(description = "SQL injection techniques (e.g. 'BEUSTQ')")]
    pub technique: Option<String>,
}

/// Execute sqlmap with safety-capped level and risk parameters.
pub async fn run(
    config: &RavenConfig,
    req: SqlmapRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.url).map_err(crate::error::to_mcp)?;

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "sqlmap".into(), req.url.clone()));

    // Enforce config safety limits — prevents LLM from requesting dangerous levels
    let level = req
        .level
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_level);
    let risk = req
        .risk
        .unwrap_or(1)
        .clamp(1, config.safety.sqlmap_max_risk);

    let mut args = vec![
        "-u".to_string(),
        req.url,
        "--batch".into(), // non-interactive mode
        "--level".into(),
        level.to_string(),
        "--risk".into(),
        risk.to_string(),
    ];

    if let Some(ref data) = req.data {
        args.extend(["--data".into(), data.clone()]);
    }

    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }

    if let Some(ref technique) = req.technique {
        args.extend(["--technique".into(), technique.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "sqlmap", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = parse_sqlmap_output(&result.stdout).unwrap_or_else(|| result.stdout.clone());
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("sqlmap", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Strip ANSI escape sequences from tool output.
///
/// Sqlmap (and other tools) emit terminal control codes even in batch mode.
/// These waste context tokens and confuse text parsing.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // CSI sequence: ESC [ ... final_byte
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c.is_ascii_alphabetic() || c == '~' {
                        break;
                    }
                }
            } else if matches!(chars.peek(), Some(&'(' | &')' | &'*' | &'+')) {
                // Charset designation: ESC ( X — consume designator + charset
                chars.next();
                chars.next();
            } else {
                // Other escape: ESC + one char
                chars.next();
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Extract the log-level tag from a sqlmap line, ignoring the timestamp prefix.
///
/// Sqlmap lines look like `[HH:MM:SS] [CRITICAL] message` — this returns
/// the content after the timestamp so callers can match on `[CRITICAL]` etc.
/// Only strips brackets containing digits and colons (timestamps), not `[CRITICAL]`.
fn sqlmap_log_content(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('[')
        && let Some(close) = trimmed.find(']')
    {
        let bracket = &trimmed[1..close];
        // Only strip if it looks like a timestamp: digits and colons
        if bracket.contains(':') && bracket.chars().all(|c| c.is_ascii_digit() || c == ':') {
            return trimmed[close + 1..].trim_start();
        }
    }
    trimmed
}

/// Parse sqlmap output to extract injection findings, DBMS info, and errors.
///
/// Strips ANSI escape codes and timestamp prefixes, then keeps only actionable
/// results: injection points, backend identification, data retrieval summaries,
/// and critical errors. Discards verbose testing/progress lines.
pub fn parse_sqlmap_output(raw: &str) -> Option<String> {
    let clean = strip_ansi(raw);
    let mut output = String::new();
    let mut in_injection_block = false;
    let mut separator_count = 0;

    for line in clean.lines() {
        let trimmed = line.trim();
        let content = sqlmap_log_content(trimmed);

        // Injection point header
        if trimmed.contains("the following injection point") {
            in_injection_block = true;
            separator_count = 0;
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Separators within injection block
        if in_injection_block && trimmed == "---" {
            separator_count += 1;
            output.push_str("---\n");
            if separator_count >= 2 {
                in_injection_block = false;
            }
            continue;
        }

        // Injection details (Parameter, Type, Title, Payload)
        if in_injection_block {
            output.push_str(line);
            output.push('\n');
            continue;
        }

        // DBMS and technology identification
        if trimmed.starts_with("back-end DBMS:")
            || trimmed.starts_with("web server operating system:")
            || trimmed.starts_with("web application technology:")
            || trimmed.starts_with("database:")
            || trimmed.starts_with("Table:")
        {
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Not-injectable verdict
        if trimmed.contains("do not appear to be injectable") || trimmed.contains("not injectable")
        {
            output.push_str(trimmed);
            output.push('\n');
            continue;
        }

        // Critical errors and warnings (match after stripping timestamp)
        if content.starts_with("[CRITICAL]") || content.starts_with("[ERROR]") {
            output.push_str(content);
            output.push('\n');
        }
    }

    let result = output.trim_end().to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sqlmap_extracts_injection_points() {
        let raw = r#"[INFO] testing connection
[INFO] testing parameter 'id'
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 1=1

    Type: time-based blind
    Title: MySQL >= 5.0 time-based blind
    Payload: id=1 AND SLEEP(5)
---
[INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.6, Apache 2.4
back-end DBMS: MySQL >= 5.0"#;
        let result = parse_sqlmap_output(raw).unwrap();
        assert!(result.contains("Parameter: id (GET)"));
        assert!(result.contains("boolean-based blind"));
        assert!(result.contains("time-based blind"));
        assert!(result.contains("back-end DBMS: MySQL"));
        assert!(result.contains("Apache 2.4"));
        // Progress lines should be stripped
        assert!(!result.contains("[INFO] testing connection"));
        assert!(!result.contains("[INFO] testing parameter"));
    }

    #[test]
    fn parse_sqlmap_not_injectable() {
        let raw = "[INFO] testing\n[WARNING] all tested parameters do not appear to be injectable\n[INFO] done";
        let result = parse_sqlmap_output(raw).unwrap();
        assert!(result.contains("do not appear to be injectable"));
        assert!(!result.contains("[INFO]"));
    }

    #[test]
    fn parse_sqlmap_critical_errors() {
        let raw = "[INFO] testing\n[CRITICAL] connection refused\n[INFO] done";
        let result = parse_sqlmap_output(raw).unwrap();
        assert!(result.contains("[CRITICAL] connection refused"));
    }

    #[test]
    fn parse_sqlmap_timestamped_critical() {
        let raw = "[00:11:29] [INFO] testing\n[00:11:29] [CRITICAL] page not found (404)\n[00:11:29] [INFO] done";
        let result = parse_sqlmap_output(raw).unwrap();
        assert!(result.contains("[CRITICAL] page not found (404)"));
        assert!(!result.contains("[INFO]"));
    }

    #[test]
    fn strip_ansi_removes_escape_sequences() {
        let raw = "\x1b[?1049h\x1b[1;24r\x1b(B\x1b[mhello\x1b[?1049l";
        assert_eq!(strip_ansi(raw), "hello");
    }

    #[test]
    fn parse_sqlmap_empty_returns_none() {
        assert!(parse_sqlmap_output("").is_none());
        assert!(parse_sqlmap_output("[INFO] starting\n[INFO] done").is_none());
    }

    #[test]
    fn parse_sqlmap_resumed_injection_points() {
        let raw = r#"[INFO] resuming back-end DBMS 'MySQL'
[INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 5678=5678

    Type: error-based
    Title: MySQL >= 5.0 error-based
    Payload: id=1 AND (SELECT 1234 FROM(SELECT COUNT(*),CONCAT(0x71,0x71,(SELECT 1),0x71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0 time-based blind
    Payload: id=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL)
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x71,0x71,0x71),NULL-- -
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0"#;
        let result = parse_sqlmap_output(raw).unwrap();
        assert!(result.contains("resumed the following injection point"));
        assert!(result.contains("boolean-based blind"));
        assert!(result.contains("error-based"));
        assert!(result.contains("time-based blind"));
        assert!(result.contains("UNION query"));
        assert!(result.contains("back-end DBMS: MySQL"));
    }
}
