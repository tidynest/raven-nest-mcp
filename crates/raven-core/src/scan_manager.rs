//! Background scan orchestration with concurrency control and memory management.
//!
//! [`ScanManager`] lets the MCP client fire off long-running scans without blocking
//! the tool call. Scans are tracked by UUID and can be polled, paginated, or cancelled.
//!
//! Key design decisions:
//! - **Concurrency cap** - `max_concurrent_scans` prevents resource exhaustion.
//! - **Spill-to-disk** - outputs exceeding [`SPILL_THRESHOLD`] (1 MB) are written
//!   to `{output_dir}/scans/{id}.txt` instead of held in memory.
//! - **Auto-inline** - `raven-server::tools::scans::status` embeds small outputs
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

/// Where the scan output lives - either in-process memory or a file on disk.
enum ScanOutput {
    Memory(String),
    Disk(std::path::PathBuf),
}

impl ScanOutput {
    /// Approximate size: char count for memory, byte count for disk.
    fn size(&self) -> usize {
        match self {
            ScanOutput::Memory(s) => s.len(),
            ScanOutput::Disk(path) => std::fs::metadata(path)
                .map(|m| m.len() as usize)
                .unwrap_or(0),
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
    /// When the scan reached a terminal state (completed/failed/cancelled).
    /// `None` while running. Drives TTL eviction in [`ScanManager::prune_expired`].
    terminal_at: Option<Instant>,
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

    /// Evict terminal (completed/failed/cancelled) scans older than the retention
    /// TTL, deleting any spilled output file. Runs lazily under the caller's lock
    /// on launch/status/list - no background timer. Running scans are never evicted.
    fn prune_expired(&self, scans: &mut HashMap<String, ScanEntry>) {
        let retention = self.config.execution.scan_retention_secs;
        let expired: Vec<String> = scans
            .iter()
            .filter(|(_, e)| {
                e.status != ScanStatus::Running
                    && e.terminal_at
                        .is_some_and(|t| t.elapsed().as_secs() >= retention)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            if let Some(entry) = scans.remove(id)
                && let Some(ScanOutput::Disk(path)) = entry.output
            {
                let _ = std::fs::remove_file(path);
            }
        }
        if !expired.is_empty() {
            tracing::debug!("pruned {} expired scan(s)", expired.len());
        }
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
            "nikto" => vec!["-h".into(), target.into(), "-nocheck".into()],
            "whatweb" => vec![
                "-a".into(),
                "1".into(),
                "--color=never".into(),
                target.into(),
            ],
            "testssl.sh" => vec!["--quiet".into(), "--sneaky".into(), target.into()],
            "feroxbuster" => vec![
                "-u".into(),
                target.into(),
                "-w".into(),
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt".into(),
                "--no-state".into(),
                "-q".into(),
            ],
            "sqlmap" => vec![
                "-u".into(),
                target.into(),
                "--batch".into(),
                "--level".into(),
                "1".into(),
                "--risk".into(),
                "1".into(),
            ],
            "masscan" => vec![
                target.into(),
                "-p".into(),
                "1-1000".into(),
                "--rate".into(),
                "100".into(),
                "--open".into(),
            ],
            "subfinder" => vec!["-d".into(), target.into(), "-silent".into(), "-oJ".into()],
            "wpscan" => vec![
                "--url".into(),
                target.into(),
                "--format".into(),
                "json".into(),
                "--no-banner".into(),
                "-e".into(),
                "vp,vt,u".into(),
            ],
            "enum4linux-ng" => vec!["-A".into(), target.into()],
            "dalfox" => vec![
                "url".into(),
                target.into(),
                "--silence".into(),
                "--format".into(),
                "json".into(),
            ],
            "dnsrecon" => vec!["-d".into(), target.into()],
            // Tools that require specific files (hydra needs wordlists, john needs
            // hash file, ffuf needs FUZZ URL) - no safe default possible.
            // The executor will report a usage error, which is safe.
            _ => vec![target.into()],
        }
    }

    /// Launch a new background scan, returning its UUID.
    ///
    /// Validates the tool against the allowlist and the target against injection rules
    /// before spawning. Enforces the concurrency cap - returns an error if already at
    /// `max_concurrent_scans`.
    pub fn launch(
        &self,
        tool: &str,
        target: &str,
        timeout_secs: Option<u64>,
    ) -> Result<String, PentestError> {
        crate::safety::check_allowlist(tool, &self.config.safety)?;
        crate::safety::validate_target(target)?;

        // Evict expired scans, then enforce the concurrency limit
        let mut scans = self.lock_scans()?;
        self.prune_expired(&mut scans);
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

        let arg_strings = Self::default_args(tool, target);

        // Spawn the scan as a background tokio task
        let handle = tokio::spawn(async move {
            let arg_refs: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();
            let result =
                executor::run_unmetered(&config, &tool_owned, &arg_refs, timeout_secs).await;

            let mut scans = match scans_for_task.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    tracing::error!("scan state lock poisoned - scan {scan_id} result lost");
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
                        entry.terminal_at = Some(Instant::now());
                        let output_str = if r.success {
                            r.stdout
                        } else {
                            format!("{}\n{}", r.stdout, r.stderr)
                        };

                        // Spill large outputs to disk to prevent unbounded memory growth
                        entry.output = Some(if output_str.len() > SPILL_THRESHOLD {
                            let scan_dir =
                                std::path::Path::new(&config.execution.output_dir).join("scans");
                            let _ = crate::safety::ensure_dir_secure(&scan_dir);
                            let path = scan_dir.join(format!("{scan_id}.txt"));
                            let write_result = {
                                use std::os::unix::fs::OpenOptionsExt;
                                std::fs::OpenOptions::new()
                                    .write(true)
                                    .create(true)
                                    .truncate(true)
                                    .mode(0o600)
                                    .open(&path)
                                    .and_then(|mut f| {
                                        use std::io::Write;
                                        f.write_all(output_str.as_bytes())
                                    })
                            };
                            match write_result {
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
                        entry.terminal_at = Some(Instant::now());
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
                terminal_at: None,
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
        let mut scans = self.lock_scans()?;
        self.prune_expired(&mut scans);
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
        let Some(entry) = scans.get(id) else {
            return Ok(None);
        };
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
            Some(ScanOutput::Disk(path)) => {
                std::borrow::Cow::Owned(std::fs::read_to_string(path).map_err(|e| {
                    PentestError::CommandFailed(format!("read spilled output: {e}"))
                })?)
            }
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
            entry.terminal_at = Some(Instant::now());
            if let Some(handle) = entry.handle.take() {
                handle.abort();
            }
        }
        Ok(())
    }

    /// List enriched status for all tracked scans (running, completed, failed, cancelled).
    pub fn list(&self) -> Result<Vec<ScanStatusInfo>, PentestError> {
        let mut scans = self.lock_scans()?;
        self.prune_expired(&mut scans);
        Ok(scans
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

    fn entry(status: ScanStatus, terminal_at: Option<Instant>) -> ScanEntry {
        ScanEntry {
            tool: "nmap".into(),
            target: "10.0.0.1".into(),
            status,
            output: None,
            handle: None,
            started_at: Instant::now(),
            terminal_at,
        }
    }

    #[test]
    fn prune_evicts_terminal_but_never_running() {
        let mut cfg = RavenConfig::default();
        cfg.execution.scan_retention_secs = 0; // evict terminal scans immediately
        let mgr = ScanManager::new(Arc::new(cfg));
        let mut scans = mgr.scans.lock().unwrap();
        scans.insert(
            "done".into(),
            entry(ScanStatus::Completed, Some(Instant::now())),
        );
        scans.insert(
            "failed".into(),
            entry(ScanStatus::Failed("boom".into()), Some(Instant::now())),
        );
        scans.insert("running".into(), entry(ScanStatus::Running, None));
        mgr.prune_expired(&mut scans);
        assert!(!scans.contains_key("done"));
        assert!(!scans.contains_key("failed"));
        assert!(
            scans.contains_key("running"),
            "running scans must never be pruned"
        );
    }

    #[test]
    fn prune_keeps_fresh_terminal_within_ttl() {
        let mgr = ScanManager::new(Arc::new(RavenConfig::default())); // 3600s TTL
        let mut scans = mgr.scans.lock().unwrap();
        scans.insert(
            "fresh".into(),
            entry(ScanStatus::Completed, Some(Instant::now())),
        );
        mgr.prune_expired(&mut scans);
        assert!(
            scans.contains_key("fresh"),
            "recent terminal scan retained within TTL"
        );
    }

    #[test]
    fn default_args_whatweb_builds_stealthy_scan() {
        let args = ScanManager::default_args("whatweb", "http://example.com");
        assert!(args.contains(&"-a".to_string()));
        assert!(args.contains(&"1".to_string()));
        assert!(args.contains(&"http://example.com".to_string()));
    }

    #[test]
    fn default_args_sqlmap_uses_safe_levels() {
        let args = ScanManager::default_args("sqlmap", "http://example.com/page?id=1");
        assert!(args.contains(&"--batch".to_string()));
        assert!(args.contains(&"--level".to_string()));
        assert!(args.contains(&"1".to_string()));
        assert!(args.contains(&"--risk".to_string()));
    }

    #[test]
    fn default_args_masscan_caps_rate() {
        let args = ScanManager::default_args("masscan", "10.0.0.0/24");
        assert!(args.contains(&"--rate".to_string()));
        assert!(args.contains(&"100".to_string()));
        assert!(args.contains(&"--open".to_string()));
    }

    #[test]
    fn default_args_subfinder_uses_silent() {
        let args = ScanManager::default_args("subfinder", "example.com");
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"-silent".to_string()));
    }

    #[test]
    fn default_args_dnsrecon_targets_domain() {
        let args = ScanManager::default_args("dnsrecon", "example.com");
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"example.com".to_string()));
    }

    #[test]
    fn default_args_wpscan_uses_json_format() {
        let args = ScanManager::default_args("wpscan", "http://example.com");
        assert!(args.contains(&"--format".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    fn default_args_dalfox_uses_json_format() {
        let args = ScanManager::default_args("dalfox", "http://example.com/page?q=test");
        assert!(args.contains(&"url".to_string()));
        assert!(args.contains(&"--format".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    fn default_args_enum4linux_targets_host() {
        let args = ScanManager::default_args("enum4linux-ng", "10.0.0.1");
        assert!(args.contains(&"-A".to_string()));
        assert!(args.contains(&"10.0.0.1".to_string()));
    }

    // --- real spawn/poll/cancel lifecycle ---
    // Drives the full launch → execute → writeback path through `executor` using
    // coreutils `echo`/`sleep` (always present on the Linux-only target) rather
    // than a real scanner, so the tests stay fast, deterministic, and offline.

    fn proc_config(output_dir: &std::path::Path, max_scans: usize) -> RavenConfig {
        let mut cfg = RavenConfig::default();
        cfg.safety.allowed_tools = vec!["echo".into(), "sleep".into()];
        cfg.execution.output_dir = output_dir.to_string_lossy().into_owned();
        cfg.execution.max_concurrent_scans = max_scans;
        cfg
    }

    /// Poll until the scan reaches `want`, up to ~5s. Returns false on timeout.
    async fn wait_status(mgr: &ScanManager, id: &str, want: ScanStatus) -> bool {
        for _ in 0..100 {
            if mgr.status(id).unwrap() == Some(want.clone()) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn lifecycle_echo_completes_and_captures_output() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 3)));
        let id = mgr.launch("echo", "raven-probe", None).unwrap();
        assert!(
            wait_status(&mgr, &id, ScanStatus::Completed).await,
            "echo scan should reach Completed"
        );
        let out = mgr.output(&id).unwrap().expect("completed scan has output");
        assert!(out.contains("raven-probe"), "stdout captured: {out:?}");
    }

    #[tokio::test]
    async fn lifecycle_cancel_while_running_sets_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 3)));
        let id = mgr.launch("sleep", "5", None).unwrap();
        assert_eq!(mgr.status(&id).unwrap(), Some(ScanStatus::Running));
        mgr.cancel(&id).unwrap();
        assert_eq!(mgr.status(&id).unwrap(), Some(ScanStatus::Cancelled));
        assert!(
            mgr.output(&id).unwrap().is_none(),
            "a cancelled scan has no output"
        );
    }

    #[tokio::test]
    async fn lifecycle_cancel_after_complete_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 3)));
        let id = mgr.launch("echo", "done-probe", None).unwrap();
        assert!(wait_status(&mgr, &id, ScanStatus::Completed).await);
        mgr.cancel(&id).unwrap(); // status != Running → must not clobber the result
        assert_eq!(mgr.status(&id).unwrap(), Some(ScanStatus::Completed));
    }

    #[tokio::test]
    async fn lifecycle_concurrency_cap_rejects_excess() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 1)));
        let id = mgr.launch("sleep", "5", None).unwrap();
        let second = mgr.launch("sleep", "5", None);
        assert!(
            matches!(&second, Err(PentestError::CommandFailed(m)) if m.contains("max concurrent")),
            "second launch must hit the cap: {second:?}"
        );
        mgr.cancel(&id).unwrap(); // stop the held sleep
    }
}
