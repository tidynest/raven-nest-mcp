//! Shared error type for the Raven Nest toolkit.
//!
//! [`PentestError`] is the single error enum propagated through `raven-core`
//! and into `raven-server`, where [`raven_server::error::to_mcp`] maps each
//! variant to the appropriate MCP error code.

use thiserror::Error;

/// Top-level error for all pentesting operations.
///
/// Each variant maps to a distinct failure mode:
/// - Safety violations (`ToolNotAllowed`, `InvalidTarget`) — caller error.
/// - Execution failures (`CommandFailed`, `CommandTimeout`) — tool-side error.
/// - Startup issues (`ConfigError`, `Io`) — environment error.
#[derive(Debug, Error)]
pub enum PentestError {
    /// The requested tool is not in [`SafetyConfig::allowed_tools`](crate::config::SafetyConfig::allowed_tools).
    #[error("tool not allowed: {0}")]
    ToolNotAllowed(String),

    /// The target string failed validation (empty, shell metacharacters, bad CIDR, etc.).
    #[error("invalid target: {0}")]
    InvalidTarget(String),

    /// The external tool process exited with an error or could not be spawned.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// The tool exceeded its configured timeout and was killed.
    #[error("command timed out after {0}")]
    CommandTimeout(String),

    /// Configuration file could not be read or parsed.
    #[error("config error: {0}")]
    ConfigError(String),

    /// Low-level I/O error (file system, process pipes, etc.).
    #[error("transparent")]
    Io(#[from] std::io::Error),
}
