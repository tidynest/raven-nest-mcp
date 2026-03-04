use thiserror::Error;

#[derive(Debug, Error)]
pub enum PentestError {
    #[error("tool not allowed: {0}")]
    ToolNotAllowed(String),

    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("command failed: {0}")]
    CommandFailed(String),

    #[error("command timed out after {0}s")]
    CommandTimeout(String),

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("transparent")]
    Io(#[from] std::io::Error),
}
