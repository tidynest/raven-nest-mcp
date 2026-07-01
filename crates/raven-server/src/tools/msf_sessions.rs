//! Metasploit session management - list, interact, stop.

use raven_core::msf_client::MsfClient;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Arc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsfSessionsRequest {
    #[schemars(description = "Action: 'list', 'interact', 'stop', 'compatible_modules'")]
    pub action: String,
    #[schemars(description = "Session ID (required for interact/stop)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub session_id: Option<u32>,
    #[schemars(description = "Command to run in session (for action='interact')")]
    pub command: Option<String>,
}

/// Commands that are always blocked in sessions.
const BLOCKED_COMMANDS: &[&str] = &[
    "rm ", "del ", "format ", "mkfs ", "dd ", "shutdown", "reboot", "halt", "poweroff", "upload ",
];

pub async fn run(
    client: &Arc<MsfClient>,
    req: MsfSessionsRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    match req.action.as_str() {
        "list" => {
            let sessions = client.list_sessions().await.map_err(crate::error::to_mcp)?;
            let output = parse_sessions_list(&sessions);
            Ok(CallToolResult::success(vec![Content::text(output)]))
        }
        "interact" => {
            let sid = req.session_id.ok_or_else(|| {
                rmcp::ErrorData::invalid_params("session_id required for interact", None)
            })?;
            let cmd = req.command.as_deref().ok_or_else(|| {
                rmcp::ErrorData::invalid_params("command required for interact", None)
            })?;

            // Check command against blocklist
            let cmd_lower = cmd.to_lowercase();
            for blocked in BLOCKED_COMMANDS {
                if cmd_lower.starts_with(blocked) {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("command blocked for safety: {blocked}"),
                        None,
                    ));
                }
            }

            client
                .session_write(sid, cmd)
                .await
                .map_err(crate::error::to_mcp)?;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let result = client
                .session_read(sid)
                .await
                .map_err(crate::error::to_mcp)?;
            let data = result
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("(no output)");
            let truncated = if data.len() > 4096 {
                format!("{}--- truncated ---", &data[..4096])
            } else {
                data.to_string()
            };
            Ok(CallToolResult::success(vec![Content::text(truncated)]))
        }
        "stop" => {
            let sid = req.session_id.ok_or_else(|| {
                rmcp::ErrorData::invalid_params("session_id required for stop", None)
            })?;
            client
                .stop_session(sid)
                .await
                .map_err(crate::error::to_mcp)?;
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Session {sid} stopped."
            ))]))
        }
        "compatible_modules" => {
            let sid = req
                .session_id
                .ok_or_else(|| rmcp::ErrorData::invalid_params("session_id required", None))?;
            let modules = client
                .compatible_post_modules(sid)
                .await
                .map_err(crate::error::to_mcp)?;
            let output = if let serde_json::Value::Array(arr) = &modules {
                let names: Vec<&str> = arr.iter().take(20).filter_map(|v| v.as_str()).collect();
                if names.is_empty() {
                    "No compatible modules.".into()
                } else {
                    format!("{} module(s):\n{}", names.len(), names.join("\n"))
                }
            } else {
                format!("{modules}")
            };
            Ok(CallToolResult::success(vec![Content::text(output)]))
        }
        _ => Err(rmcp::ErrorData::invalid_params(
            "action must be: list, interact, stop, compatible_modules",
            None,
        )),
    }
}

fn parse_sessions_list(sessions: &serde_json::Value) -> String {
    if let serde_json::Value::Object(map) = sessions {
        if map.is_empty() {
            return "No active sessions.".into();
        }
        let mut lines = vec![format!("{} active session(s):", map.len())];
        for (id, info) in map {
            let stype = info.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            let tunnel = info
                .get("tunnel_local")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let peer = info
                .get("tunnel_peer")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let platform = info.get("platform").and_then(|v| v.as_str()).unwrap_or("?");
            lines.push(format!("  [{id}] {stype} {peer} -> {tunnel} ({platform})"));
        }
        lines.join("\n")
    } else {
        "No active sessions.".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_sessions() {
        let val = json!({});
        assert_eq!(parse_sessions_list(&val), "No active sessions.");
    }

    #[test]
    fn parse_sessions_with_entries() {
        let val = json!({"1": {"type": "meterpreter", "tunnel_local": "10.0.0.1:4444", "tunnel_peer": "10.0.0.2:54321", "platform": "linux"}});
        let result = parse_sessions_list(&val);
        assert!(result.contains("1 active session"));
        assert!(result.contains("meterpreter"));
    }

    #[test]
    fn blocked_commands() {
        let cmd = "rm -rf /";
        assert!(
            BLOCKED_COMMANDS
                .iter()
                .any(|b| cmd.to_lowercase().starts_with(b))
        );
    }
}
