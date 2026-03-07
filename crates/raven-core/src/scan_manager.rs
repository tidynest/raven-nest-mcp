//! Background scan orchestration with concurrency control and memory management.
//!
//! [`ScanManager`] lets the MCP client fire off long-running scans without blocking
//! the tool call. Scans are tracked by UUID and can be polled, paginated, or cancelled.
//!
//! Key design decisions:
//! - **Concurrency cap** — `max_concurrent_scans` prevents resource exhaustion.
//! - **Spill-to-disk** — outputs exceeding [`SPILL_THRESHOLD`] (1 MB) are written
//!   to `{output_dir}/scans/{id}.txt` instead of held in memory.
//! - **Auto-inline** — `raven-server::tools::scans::status` embeds small outputs
//!   directly in the status response, saving an extra `get_scan_results` call.
//!
//! This module delegates actual execution to [`executor::run`](crate::executor::run)
//! and is consumed by the `raven-server::tools::scans` handler.

use crate::config::RavenConfig;
use crate::error::PentestError;
use crate::executor;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Lifecycle state of a background scan.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Outputs larger than this are spilled to disk to prevent unbounded memory growth.
const SPILL_THRESHOLD: usize = 1_048_576; // 1 MB

/// Where the scan output lives — either in-process memory or a file on disk.
enum ScanOutput {
    Memory(String),
    Disk(std::path::PathBuf),
}

impl ScanOutput {
    /// Approximate size: char count for memory, byte count for disk.
    fn size(&self) -> usize {
        match self {
            ScanOutput::Memory(s) => s.len(),
            ScanOutput::Disk(path) => {
                std::fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0)
            }
        }
    }
}

/// Enriched status snapshot returned by [`ScanManager::status_enriched`] and [`ScanManager::list`].
///
/// Provides everything the MCP client needs to display scan progress without
/// a separate results call.
#[derive(Debug, Clone)]
pub struct ScanStatusInfo {
    pub id: String,
    pub tool: String,
    pub target: String,
    pub status: ScanStatus,
    pub elapsed_secs: u64,
    /// Character count of the output, if available (scan must be completed/failed).
    pub output_chars: Option<usize>,
}

/// Internal bookkeeping for a single scan.
struct ScanEntry {
    tool: String,
    target: String,
    status: ScanStatus,
    output: Option<ScanOutput>,
    /// Handle to the tokio task running the scan. Taken (consumed) on cancel.
    handle: Option<JoinHandle<()>>,
    started_at: Instant,
}

/// Thread-safe background scan manager.
///
/// Cloned cheaply (all state behind `Arc<Mutex>`) and shared across MCP tool handlers.
/// Created once in [`RavenServer::new`](raven_server::server::RavenServer::new).
#[derive(Clone)]
pub struct ScanManager {
    scans: Arc<Mutex<HashMap<String, ScanEntry>>>,
    config: Arc<RavenConfig>,
    max_concurrent: usize,
}

impl ScanManager {
    /// Acquire the scan state lock, converting a poisoned mutex into a `PentestError`.
    fn lock_scans(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, ScanEntry>>, PentestError> {
        self.scans
            .lock()
            .map_err(|_| PentestError::CommandFailed("scan state lock poisoned".into()))
    }

    pub fn new(config: Arc<RavenConfig>) -> Self {
        let max_concurrent = config.execution.max_concurrent_scans;
        Self {
            scans: Arc::new(Mutex::new(HashMap::new())),
            config,
            max_concurrent,
        }
    }

    /// Build sensible default arguments when the caller provides none.
    ///
    /// Mirrors the defaults used by each dedicated tool handler in `raven-server::tools`,
    /// so that `launch_scan("nmap", target, [])` behaves like `run_nmap(target)`.
    fn default_args(tool: &str, target: &str) -> Vec<String> {
        match tool {
            "nmap" => vec![
                "-T4".into(),
                "-F".into(),
                "-oX".into(),
                "-".into(),
                target.into(),
            ],
            "nuclei" => vec!["-u".into(), target.into(), "-silent".into()],
            "nikto" => vec!["-h".into(), target.into()],
            _ => vec![target.into()],
        }
    }

    /// Launch a new background scan, returning its UUID.
    ///
    /// Validates the tool against the allowlist and the target against injection rules
    /// before spawning. Enforces the concurrency cap — returns an error if already at
    /// `max_concurrent_scans`.
    pub fn launch(
        &self,
        tool: &str,
        args: Vec<String>,
        target: &str,
        timeout_secs: Option<u64>,
    ) -> Result<String, PentestError> {
        crate::safety::check_allowlist(tool, &self.config.safety)?;
        crate::safety::validate_target(target)?;

        // Enforce concurrency limit
        let scans = self.lock_scans()?;
        let running = scans
            .values()
            .filter(|s| s.status == ScanStatus::Running)
            .count();
        if running >= self.max_concurrent {
            return Err(PentestError::CommandFailed(format!(
                "max concurrent scans ({}) reached",
                self.max_concurrent
            )));
        }
        drop(scans);

        let id = Uuid::new_v4().to_string();
        let config = self.config.clone();
        let tool_owned = tool.to_string();
        let scans_for_task = self.scans.clone();
        let scan_id = id.clone();

        let arg_strings = if args.is_empty() {
            Self::default_args(tool, target)
        } else {
            args
        };

        // Spawn the scan as a background tokio task
        let handle = tokio::spawn(async move {
            let arg_refs: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();
            let result = executor::run(&config, &tool_owned, &arg_refs, timeout_secs).await;

            let mut scans = match scans_for_task.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    tracing::error!("scan state lock poisoned — scan {scan_id} result lost");
                    return;
                }
            };
            if let Some(entry) = scans.get_mut(&scan_id) {
                // Don't overwrite a cancellation
                if entry.status == ScanStatus::Cancelled {
                    return;
                }
                match result {
                    Ok(r) => {
                        entry.status = ScanStatus::Completed;
                        let output_str = if r.success {
                            r.stdout
                        } else {
                            format!("{}\n{}", r.stdout, r.stderr)
                        };

                        // Spill large outputs to disk to prevent unbounded memory growth
                        entry.output = Some(if output_str.len() > SPILL_THRESHOLD {
                            let scan_dir = std::path::Path::new(&config.execution.output_dir)
                                .join("scans");
                            let _ = std::fs::create_dir_all(&scan_dir);
                            let path = scan_dir.join(format!("{scan_id}.txt"));
                            match std::fs::write(&path, &output_str) {
                                Ok(()) => {
                                    tracing::info!(
                                        "scan {scan_id}: spilled {}B to disk",
                                        output_str.len()
                                    );
                                    ScanOutput::Disk(path)
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "scan {scan_id}: disk spill failed ({e}), keeping in memory"
                                    );
                                    ScanOutput::Memory(output_str)
                                }
                            }
                        } else {
                            ScanOutput::Memory(output_str)
                        });
                    }
                    Err(e) => {
                        entry.status = ScanStatus::Failed(e.to_string());
                    }
                }
            }
        });

        // Register the scan entry so it can be polled
        let mut scans = self.lock_scans()?;
        scans.insert(
            id.clone(),
            ScanEntry {
                tool: tool.to_string(),
                target: target.to_string(),
                status: ScanStatus::Running,
                output: None,
                handle: Some(handle),
                started_at: Instant::now(),
            },
        );

        Ok(id)
    }

    /// Get the bare status of a scan (no output, no timing).
    pub fn status(&self, id: &str) -> Result<Option<ScanStatus>, PentestError> {
        Ok(self.lock_scans()?.get(id).map(|e| e.status.clone()))
    }

    /// Get enriched status including elapsed time and output size.
    ///
    /// Used by `raven-server::tools::scans::status` for the auto-inline feature.
    pub fn status_enriched(&self, id: &str) -> Result<Option<ScanStatusInfo>, PentestError> {
        let scans = self.lock_scans()?;
        Ok(scans.get(id).map(|e| ScanStatusInfo {
            id: id.to_string(),
            tool: e.tool.clone(),
            target: e.target.clone(),
            status: e.status.clone(),
            elapsed_secs: e.started_at.elapsed().as_secs(),
            output_chars: e.output.as_ref().map(|o| o.size()),
        }))
    }

    /// Get the full output string for a completed scan.
    ///
    /// Reads from memory or disk depending on where the output was stored.
    /// Used by `raven-server::tools::scans::status` for auto-inline.
    pub fn output(&self, id: &str) -> Result<Option<String>, PentestError> {
        let scans = self.lock_scans()?;
        let Some(entry) = scans.get(id) else { return Ok(None) };
        match &entry.output {
            None => Ok(None),
            Some(ScanOutput::Memory(s)) => Ok(Some(s.clone())),
            Some(ScanOutput::Disk(path)) => std::fs::read_to_string(path)
                .map(Some)
                .map_err(|e| PentestError::CommandFailed(format!("read spilled output: {e}"))),
        }
    }

    /// Get a paginated slice of the scan output (character-based offset + limit).
    ///
    /// Used by `get_scan_results` for outputs too large for auto-inline.
    pub fn results(
        &self,
        id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Option<String>, PentestError> {
        let scans = self.lock_scans()?;
        let Some(entry) = scans.get(id) else {
            return Ok(None);
        };

        let content = match &entry.output {
            None => return Ok(None),
            Some(ScanOutput::Memory(s)) => std::borrow::Cow::Borrowed(s.as_str()),
            Some(ScanOutput::Disk(path)) => std::borrow::Cow::Owned(
                std::fs::read_to_string(path)
                    .map_err(|e| PentestError::CommandFailed(format!("read spilled output: {e}")))?,
            ),
        };

        let chars: Vec<char> = content.chars().collect();
        if offset >= chars.len() {
            return Ok(Some(String::new()));
        }
        let end = chars.len().min(offset + limit);
        Ok(Some(chars[offset..end].iter().collect()))
    }

    /// Cancel a running scan by aborting its tokio task.
    pub fn cancel(&self, id: &str) -> Result<(), PentestError> {
        let mut scans = self.lock_scans()?;
        let entry = scans
            .get_mut(id)
            .ok_or_else(|| PentestError::CommandFailed(format!("scan {id} not found")))?;

        if entry.status == ScanStatus::Running {
            entry.status = ScanStatus::Cancelled;
            if let Some(handle) = entry.handle.take() {
                handle.abort();
            }
        }
        Ok(())
    }

    /// List enriched status for all tracked scans (running, completed, failed, cancelled).
    pub fn list(&self) -> Result<Vec<ScanStatusInfo>, PentestError> {
        Ok(self
            .lock_scans()?
            .iter()
            .map(|(id, e)| ScanStatusInfo {
                id: id.clone(),
                tool: e.tool.clone(),
                target: e.target.clone(),
                status: e.status.clone(),
                elapsed_secs: e.started_at.elapsed().as_secs(),
                output_chars: e.output.as_ref().map(|o| o.size()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_status_info_tracks_elapsed_and_output() {
        let info = ScanStatusInfo {
            id: "test-id".into(),
            tool: "nmap".into(),
            target: "10.0.0.1".into(),
            status: ScanStatus::Completed,
            elapsed_secs: 42,
            output_chars: Some(2340),
        };
        assert_eq!(info.elapsed_secs, 42);
        assert_eq!(info.output_chars, Some(2340));
    }

    #[test]
    fn default_args_nmap_builds_quick_scan() {
        let args = ScanManager::default_args("nmap", "example.com");
        assert_eq!(args, vec!["-T4", "-F", "-oX", "-", "example.com"]);
    }

    #[test]
    fn default_args_nuclei_builds_silent_scan() {
        let args = ScanManager::default_args("nuclei", "http://example.com");
        assert_eq!(args, vec!["-u", "http://example.com", "-silent"]);
    }

    #[test]
    fn default_args_unknown_tool_appends_target() {
        let args = ScanManager::default_args("custom", "10.0.0.1");
        assert_eq!(args, vec!["10.0.0.1"]);
    }

    #[test]
    fn scan_output_memory_size() {
        let out = ScanOutput::Memory("hello world".into());
        assert_eq!(out.size(), 11);
    }

    #[test]
    fn scan_output_disk_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let content = "x".repeat(2_000_000);
        std::fs::write(&path, &content).unwrap();
        let out = ScanOutput::Disk(path);
        assert_eq!(out.size(), 2_000_000);
    }

    #[test]
    fn spill_threshold_is_one_megabyte() {
        assert_eq!(SPILL_THRESHOLD, 1_048_576);
    }

    #[test]
    fn scan_status_info_none_output_for_running() {
        let info = ScanStatusInfo {
            id: "test-id".into(),
            tool: "nuclei".into(),
            target: "http://example.com".into(),
            status: ScanStatus::Running,
            elapsed_secs: 10,
            output_chars: None,
        };
        assert!(info.output_chars.is_none());
    }
}
