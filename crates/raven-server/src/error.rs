use raven_core::error::PentestError;
use raven_core::executor::CommandResult;
use rmcp::model::ErrorCode;

/// Map PentestError variants to semantically correct MCP error codes.
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

/// Format a CommandResult into user-facing output, appending quality warnings.
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
