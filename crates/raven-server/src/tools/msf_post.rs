//! Metasploit post-exploitation module execution.

use raven_core::msf_client::MsfClient;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsfPostRequest {
    #[schemars(description = "Post module path (e.g. 'post/multi/gather/env')")]
    pub module: String,
    #[schemars(description = "Session ID to run on")]
    pub session_id: u32,
    #[schemars(description = "Additional module options as key=value")]
    pub options: Option<std::collections::HashMap<String, String>>,
}

pub async fn run(
    client: &Arc<MsfClient>,
    req: MsfPostRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let mut opts = serde_json::Map::new();
    opts.insert(
        "SESSION".into(),
        serde_json::Value::Number(req.session_id.into()),
    );
    if let Some(ref extra) = req.options {
        for (k, v) in extra {
            opts.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
    }

    let result = client
        .execute_module("post", &req.module, &opts)
        .await
        .map_err(crate::error::to_mcp)?;
    let uuid = result
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let mut output = format!(
        "Post module launched on session {} (uuid {uuid})\n",
        req.session_id
    );
    let mut delay = 2u64;
    for _ in 0..8 {
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
                    let truncated = if s.len() > 2000 {
                        format!("{}...", &s[..2000])
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

#[cfg(test)]
mod tests {
    #[test]
    fn request_struct_compiles() {
        // Struct field check - ensures deny_unknown_fields and deserialize work
        let json = r#"{"module": "post/multi/gather/env", "session_id": 1}"#;
        let req: Result<super::MsfPostRequest, _> = serde_json::from_str(json);
        assert!(req.is_ok());
    }
}
