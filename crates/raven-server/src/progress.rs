//! Periodic progress notifications for long-running synchronous tools.
//!
//! `ProgressTicker` sends MCP logging notifications every `TICK_INTERVAL`
//! seconds while a tool is executing. It uses RAII auto-cancel: when the
//! ticker is dropped (tool handler returns), the background task stops.

use rmcp::{
    Peer, RoleServer,
    model::LoggingMessageNotificationParam,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const TICK_INTERVAL: Duration = Duration::from_secs(15);

/// Sends periodic logging notifications while alive. Cancels on drop.
pub struct ProgressTicker {
    cancel: CancellationToken,
}

impl ProgressTicker {
    /// Starts a background ticker that sends progress every 15s.
    ///
    /// `tool_name` and `target` are included in the notification message.
    /// The ticker runs until this struct is dropped.
    pub fn start(peer: Peer<RoleServer>, tool_name: String, target: String) -> Self {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let started = Instant::now();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TICK_INTERVAL);
            // Skip the immediate first tick
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    _ = interval.tick() => {
                        let elapsed = started.elapsed().as_secs();
                        let msg = format!(
                            "{tool_name} scanning {target}... ({elapsed}s elapsed)"
                        );
                        let param = LoggingMessageNotificationParam::new(
                            rmcp::model::LoggingLevel::Info,
                            serde_json::Value::String(msg),
                        );
                        // Best-effort: client may not support logging
                        let _ = peer.notify_logging_message(param).await;
                    }
                }
            }
        });

        Self { cancel }
    }
}

impl Drop for ProgressTicker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
