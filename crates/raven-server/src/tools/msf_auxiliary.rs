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

    // Run via a console so the module's printed findings are captured;
    // module.execute alone only exposes the (usually empty) results hash.
    let output = client
        .run_auxiliary_console(&req.module, &opts)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if output.trim().is_empty() {
        format!("Module '{}' ran but produced no output.", req.module)
    } else {
        // Truncate on a char boundary (console text is UTF-8).
        output.chars().take(4000).collect::<String>()
    };

    Ok(CallToolResult::success(vec![Content::text(output)]))
}
