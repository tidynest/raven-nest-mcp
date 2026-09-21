//! Periodic progress notifications for long-running synchronous tools.
//!
//! `ProgressTicker` sends MCP progress notifications (`notifications/progress`)
//! every `TICK_INTERVAL` seconds while a tool is executing. It uses RAII
//! auto-cancel: when the ticker is dropped (tool handler returns), the
//! background task stops.
//!
//! The notification carries the `progressToken` the client supplied with the
//! tool call. Without a token the client has not asked for progress updates
//! and the protocol forbids sending them, so `start` returns `None`.
//!
//! Previously this rode on logging notifications, which SEP-2577 deprecates
//! in favor of stderr/OpenTelemetry; server operational logging already goes
//! to stderr via `tracing`.

use rmcp::{
    Peer, RoleServer,
    model::{ProgressNotificationParam, ProgressToken},
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const TICK_INTERVAL: Duration = Duration::from_secs(15);

/// Sends periodic progress notifications while alive. Cancels on drop.
pub struct ProgressTicker {
    cancel: CancellationToken,
}

impl ProgressTicker {
    /// Starts a background ticker that sends progress every 15s.
    ///
    /// `tool_name` and `target` are included in the notification message.
    /// Returns `None` when there is no peer or no client-supplied
    /// `progressToken`, in which case there is nothing to report and no
    /// task is spawned.
    pub fn start(
        peer: Option<Peer<RoleServer>>,
        progress_token: Option<ProgressToken>,
        tool_name: String,
        target: String,
    ) -> Option<Self> {
        let peer = peer?;
        let progress_token = progress_token?;

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
                        let param = ProgressNotificationParam::new(
                            progress_token.clone(),
                            elapsed as f64,
                        )
                        .with_message(msg);
                        // Best-effort: client may have disconnected
                        let _ = peer.notify_progress(param).await;
                    }
                }
            }
        });

        Some(Self { cancel })
    }
}

impl Drop for ProgressTicker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
