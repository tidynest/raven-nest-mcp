//! Error mapping and output formatting for MCP responses.
//!
//! Bridges `raven-core`'s [`PentestError`] to MCP's `ErrorData`, and formats
//! [`CommandResult`] into user-facing text with quality warnings.
//!
//! Every tool handler calls [`to_mcp`] via `.map_err(crate::error::to_mcp)` and
//! [`format_result`] to build the final response text.

use raven_core::error::PentestError;
use raven_core::executor::CommandResult;
use rmcp::model::ErrorCode;

/// Map [`PentestError`] variants to semantically correct MCP error codes.
///
/// - `InvalidTarget` → `INVALID_PARAMS` (caller sent bad input)
/// - `ToolNotAllowed` → `INVALID_REQUEST` (tool not in allowlist)
/// - Everything else → `INTERNAL_ERROR` (server-side failure)
pub fn to_mcp(err: PentestError) -> rmcp::ErrorData {
    let (code, msg) = match &err {
        PentestError::InvalidTarget(_) => (ErrorCode::INVALID_PARAMS, err.to_string()),
        PentestError::ToolNotAllowed(_) => (ErrorCode::INVALID_REQUEST, err.to_string()),
        PentestError::CommandTimeout(_)
        | PentestError::CommandFailed(_)
        | PentestError::ConfigError(_)
        | PentestError::Io(_) => (ErrorCode::INTERNAL_ERROR, err.to_string()),
    };
    rmcp::ErrorData::new(code, msg, None)
}

/// Format a [`CommandResult`] into user-facing output, appending quality warnings.
///
/// On success: returns stdout. On failure: includes exit code, stdout, and stderr.
/// If [`CommandResult::warning`] is set (from [`OutputQuality`](raven_core::executor::OutputQuality)
/// assessment), it's appended with a warning marker.
pub fn format_result(tool: &str, result: &CommandResult) -> String {
    let body = if result.success {
        result.stdout.clone()
    } else {
        format!(
            "{tool} failed (exit {:?}):\n{}\n{}",
            result.exit_code, result.stdout, result.stderr,
        )
    };

    match &result.warning {
        Some(warning) => format!("{body}\n\n⚠ Warning: {warning}"),
        None => body,
    }
}
