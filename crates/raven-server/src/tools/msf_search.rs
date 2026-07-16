//! Metasploit module search - find exploits, auxiliaries, and post modules.

use raven_core::msf_client::MsfClient;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsfSearchRequest {
    #[schemars(description = "Search query (e.g. 'cve:2021-44228', 'type:exploit smb')")]
    pub query: String,
    #[schemars(description = "Max results (default 20)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub limit: Option<usize>,
}

pub async fn run(
    client: &Arc<MsfClient>,
    req: MsfSearchRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let limit = req.limit.unwrap_or(20);
    let result = client
        .search_modules(&req.query, limit)
        .await
        .map_err(crate::error::to_mcp)?;
    let output = parse_search_results(&result, limit);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

fn parse_search_results(value: &serde_json::Value, limit: usize) -> String {
    // Parse array of module hashes into compact table
    if let serde_json::Value::Array(modules) = value {
        if modules.is_empty() {
            return "No modules found.".into();
        }
        let total = modules.len();
        let mut lines = Vec::new();
        for m in modules.iter().take(limit) {
            let name = m
                .get("fullname")
                .or(m.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let rank = m
                .get("rank_to_s")
                .or(m.get("rank"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let desc = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let desc_short = super::char_prefix(desc, 70);
            lines.push(format!("{rank:<10} {name}\n           {desc_short}"));
        }
        let header = format!("{total} module(s) found (showing {}):\n", lines.len());
        let extra = if total > limit {
            format!("\n+{} more", total - limit)
        } else {
            String::new()
        };
        format!("{header}{}{extra}", lines.join("\n"))
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_results() {
        let val = json!([]);
        assert_eq!(parse_search_results(&val, 20), "No modules found.");
    }

    #[test]
    fn parse_module_results() {
        let val = json!([
            {"fullname": "exploit/multi/http/log4shell", "rank_to_s": "excellent", "name": "Log4Shell RCE"},
            {"fullname": "auxiliary/scanner/http/log4shell_scanner", "rank_to_s": "normal", "name": "Log4Shell Scanner"}
        ]);
        let result = parse_search_results(&val, 20);
        assert!(result.contains("2 module(s) found"));
        assert!(result.contains("log4shell"));
    }
}
