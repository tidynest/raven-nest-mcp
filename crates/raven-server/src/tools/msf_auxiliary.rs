//! Metasploit auxiliary module execution (scanners, fuzzers).

use raven_core::msf_client::MsfClient;
use raven_core::safety;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsfAuxiliaryRequest {
    #[schemars(description = "Auxiliary module path")]
    pub module: String,
    #[schemars(description = "Target host, IP, or CIDR")]
    pub target: String,
    #[schemars(description = "Target port")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub port: Option<u16>,
    #[schemars(description = "Additional module options as key=value")]
    pub options: Option<std::collections::HashMap<String, String>>,
}

pub async fn run(
    client: &Arc<MsfClient>,
    req: MsfAuxiliaryRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let mut opts = serde_json::Map::new();
    opts.insert("RHOSTS".into(), serde_json::Value::String(req.target));
    if let Some(port) = req.port {
        opts.insert("RPORT".into(), serde_json::Value::String(port.to_string()));
    }
    if let Some(ref extra) = req.options {
        for (k, v) in extra {
            if k != "RHOSTS" {
                opts.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }
    }

    let result = client
        .execute_module("auxiliary", &req.module, &opts)
        .await
        .map_err(crate::error::to_mcp)?;
    let uuid = result
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Poll for completion
    let mut output = format!("Auxiliary module launched (uuid {uuid})\n");
    let mut delay = 2u64;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        if let Ok(status) = client.module_results(uuid).await {
            let state = status
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if state == "completed" || state == "errored" {
                output.push_str(&format!("Status: {state}\n"));
                if let Some(result_data) = status.get("result") {
                    let s = serde_json::to_string_pretty(result_data).unwrap_or_default();
                    let truncated = if s.len() > 3000 {
                        format!("{}...", &s[..3000])
                    } else {
                        s
                    };
                    output.push_str(&truncated);
                }
                break;
            }
        }
        delay = (delay * 2).min(16);
    }

    Ok(CallToolResult::success(vec![Content::text(output)]))
}
