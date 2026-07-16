//! Metasploit module information - details, options, and compatible payloads.

use raven_core::msf_client::MsfClient;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsfModuleInfoRequest {
    #[schemars(description = "Module path (e.g. 'exploit/multi/http/log4shell_header_injection')")]
    pub module: String,
}

pub async fn run(
    client: &Arc<MsfClient>,
    req: MsfModuleInfoRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Infer module type from path prefix
    let module_type = req.module.split('/').next().unwrap_or("exploit");
    let info = client
        .module_info(module_type, &req.module)
        .await
        .map_err(crate::error::to_mcp)?;
    let options = client
        .module_options(module_type, &req.module)
        .await
        .map_err(crate::error::to_mcp)?;

    let mut output = parse_module_info(&info);
    output.push_str("\n\nRequired options:\n");
    output.push_str(&parse_module_options(&options));

    if module_type == "exploit"
        && let Ok(payloads) = client.compatible_payloads(&req.module).await
    {
        output.push_str("\n\nCompatible payloads (top 5):\n");
        output.push_str(&parse_payloads(&payloads));
    }

    Ok(CallToolResult::success(vec![Content::text(output)]))
}

fn parse_module_info(info: &serde_json::Value) -> String {
    let name = info.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let rank = info.get("rank").and_then(|v| v.as_str()).unwrap_or("?");
    let desc = info
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let desc_short = if desc.len() > 300 {
        format!("{}...", super::char_prefix(desc, 300))
    } else {
        desc.to_string()
    };

    let mut refs = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = info.get("references") {
        for r in arr.iter().take(5) {
            if let Some(s) = r.as_str() {
                if s.starts_with("CVE-") || s.starts_with("EDB-") {
                    refs.push(s.to_string());
                }
            } else if let Some(arr2) = r.as_array() {
                // Some formats use ["CVE", "2021-44228"]
                if arr2.len() == 2 {
                    let prefix = arr2[0].as_str().unwrap_or("");
                    let id = arr2[1].as_str().unwrap_or("");
                    if prefix == "CVE" || prefix == "EDB" {
                        refs.push(format!("{prefix}-{id}"));
                    }
                }
            }
        }
    }

    let ref_str = if refs.is_empty() {
        String::new()
    } else {
        format!("\nReferences: {}", refs.join(", "))
    };
    format!("{name} (rank: {rank})\n{desc_short}{ref_str}")
}

fn parse_module_options(options: &serde_json::Value) -> String {
    let mut lines = Vec::new();
    if let serde_json::Value::Object(opts) = options {
        for (name, details) in opts {
            let required = details
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !required {
                continue;
            }
            let default = details
                .get("default")
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.as_str()),
                    serde_json::Value::Null => None,
                    _ => None,
                })
                .unwrap_or("(none)");
            let desc = details.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            let desc_short = super::char_prefix(desc, 60);
            lines.push(format!("  {name}: {desc_short} [default: {default}]"));
        }
    }
    if lines.is_empty() {
        "  (none)".into()
    } else {
        lines.join("\n")
    }
}

fn parse_payloads(payloads: &serde_json::Value) -> String {
    if let Some(serde_json::Value::Array(arr)) = payloads.get("payloads") {
        arr.iter()
            .take(5)
            .filter_map(|v| v.as_str())
            .map(|s| format!("  {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        "  (none)".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_info_basic() {
        let info = json!({"name": "Log4Shell", "rank": "excellent", "description": "Apache Log4j RCE", "references": [["CVE", "2021-44228"]]});
        let result = parse_module_info(&info);
        assert!(result.contains("Log4Shell"));
        assert!(result.contains("CVE-2021-44228"));
    }
}
