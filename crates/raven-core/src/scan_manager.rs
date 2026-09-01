//! Background scan orchestration with concurrency control and memory management.
//!
//! [`ScanManager`] lets the MCP client fire off long-running scans without blocking
//! the tool call. Scans are tracked by UUID and can be polled, paginated, or cancelled.
//!
//! Key design decisions:
//! - **Concurrency cap** - `max_concurrent_scans` prevents resource exhaustion.
//! - **Persistence** - every terminal scan writes `{output_dir}/scans/{id}.txt`
//!   plus `{id}.json` metadata. After a restart, completed outputs are
//!   recovered as-is (never re-run) and scans interrupted mid-flight surface
//!   as failed; both are still evicted by the retention TTL.
//! - **Auto-inline** - `raven-server::tools::scans::status` embeds small outputs
//!   directly in the status response, saving an extra `get_scan_results` call.
//!
//! This module delegates actual execution to [`executor::run`](crate::executor::run)
//! and is consumed by the `raven-server::tools::scans` handler.

use crate::config::RavenConfig;
use crate::error::PentestError;
use crate::executor;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Lifecycle state of a background scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Where the scan output lives - on disk (`{output_dir}/scans/{id}.txt`, the
/// normal terminal path so results survive a restart) or in-process memory
/// (fallback when the disk write failed).
enum ScanOutput {
    Memory(String),
    Disk(PathBuf),
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

/// On-disk metadata for one scan (`{output_dir}/scans/{id}.json`), enabling
/// recovery after a restart: completed outputs are preserved as-is and scans
/// still running when the process died surface as failed instead of vanishing.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedScan {
    tool: String,
    target: String,
    status: ScanStatus,
    /// Unix epoch seconds when the scan was launched.
    started_epoch: u64,
    /// Unix epoch seconds when the scan reached a terminal state.
    terminal_epoch: Option<u64>,
}

/// Current Unix time in whole seconds (0 if the clock is before the epoch).
fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Rebuild an [`Instant`] from an epoch-seconds timestamp for a recovered
/// entry. Time elapsed before `now` is subtracted; clock skew clamps to `now`.
fn instant_from_epoch(epoch: u64, now_epoch: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(now_epoch.saturating_sub(epoch)))
        .unwrap_or_else(Instant::now)
}

/// Write scan output to `{dir}/{id}.txt` with owner-only permissions.
fn write_scan_output(dir: &Path, id: &str, content: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = crate::safety::ensure_dir_secure(dir);
    let path = dir.join(format!("{id}.txt"));
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(content.as_bytes()))?;
    Ok(path)
}

/// Atomically write scan metadata to `{dir}/{id}.json` (tmp + rename, 0o600).
/// A crash mid-write leaves only the `.tmp` file, which recovery deletes.
fn write_scan_meta(dir: &Path, id: &str, meta: &PersistedScan) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = crate::safety::ensure_dir_secure(dir);
    let tmp = dir.join(format!("{id}.json.tmp"));
    let json = serde_json::to_vec(meta).map_err(std::io::Error::other)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&json))?;
    std::fs::rename(&tmp, dir.join(format!("{id}.json")))
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
    /// Launch time as epoch seconds, kept so terminal transitions can
    /// re-persist metadata without recomputing it.
    started_epoch: u64,
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
    /// TTL, deleting its output and metadata files. Runs lazily under the caller's lock
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
        let scan_dir = self.scan_dir();
        for id in &expired {
            if let Some(entry) = scans.remove(id) {
                if let Some(ScanOutput::Disk(path)) = entry.output {
                    let _ = std::fs::remove_file(path);
                }
                let _ = std::fs::remove_file(scan_dir.join(format!("{id}.json")));
            }
        }
        if !expired.is_empty() {
            tracing::debug!("pruned {} expired scan(s)", expired.len());
        }
    }

    pub fn new(config: Arc<RavenConfig>) -> Self {
        let max_concurrent = config.execution.max_concurrent_scans;
        let manager = Self {
            scans: Arc::new(Mutex::new(HashMap::new())),
            config,
            max_concurrent,
        };
        manager.recover();
        manager
    }

    /// Directory holding scan outputs and metadata: `{output_dir}/scans`.
    fn scan_dir(&self) -> PathBuf {
        Path::new(&self.config.execution.output_dir).join("scans")
    }

    /// Write `{id}.json` metadata so the scan survives a restart. Best effort:
    /// failures are logged, never fatal.
    fn persist_meta(&self, id: &str, meta: &PersistedScan) {
        if let Err(e) = write_scan_meta(&self.scan_dir(), id, meta) {
            tracing::warn!(
                "scan {id}: metadata write failed ({e}) - it will not survive a restart"
            );
        }
    }

    /// Rebuild scan state from `{output_dir}/scans/*.json` left by a previous
    /// process. Terminal scans come back with their output file attached,
    /// `Running` entries (whose process died) are rewritten as failed, and
    /// files past the retention TTL, unreadable metadata, crash leftovers, and
    /// orphaned outputs are removed.
    fn recover(&self) {
        let scan_dir = self.scan_dir();
        let Ok(read_dir) = std::fs::read_dir(&scan_dir) else {
            return; // fresh install - nothing to recover
        };
        let now_epoch = epoch_secs();
        let mut scans = match self.lock_scans() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        for file in read_dir.flatten() {
            let path = file.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Crash leftover from an interrupted atomic rename.
            if name.ends_with(".json.tmp") {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if let Some(id) = name.strip_suffix(".json").map(str::to_owned) {
                let meta = std::fs::read(&path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<PersistedScan>(&b).ok());
                let Some(meta) = meta else {
                    tracing::warn!("scan {id}: unreadable metadata - removing");
                    let _ = std::fs::remove_file(&path);
                    let _ = std::fs::remove_file(scan_dir.join(format!("{id}.txt")));
                    continue;
                };
                // A scan still marked Running died with the previous process;
                // it is never re-run, so surface it as failed.
                let (status, terminal_epoch, interrupted) = match meta.status {
                    ScanStatus::Running => (
                        ScanStatus::Failed("interrupted by server restart".into()),
                        now_epoch,
                        true,
                    ),
                    other => (other, meta.terminal_epoch.unwrap_or(now_epoch), false),
                };
                // Don't resurrect scans already past the retention TTL.
                if now_epoch.saturating_sub(terminal_epoch)
                    >= self.config.execution.scan_retention_secs
                {
                    let _ = std::fs::remove_file(&path);
                    let _ = std::fs::remove_file(scan_dir.join(format!("{id}.txt")));
                    continue;
                }
                let txt = scan_dir.join(format!("{id}.txt"));
                let output = (status == ScanStatus::Completed && txt.is_file())
                    .then_some(ScanOutput::Disk(txt));
                if interrupted {
                    tracing::info!("scan {id}: recovered as failed (was running at shutdown)");
                    self.persist_meta(
                        &id,
                        &PersistedScan {
                            tool: meta.tool.clone(),
                            target: meta.target.clone(),
                            status: status.clone(),
                            started_epoch: meta.started_epoch,
                            terminal_epoch: Some(terminal_epoch),
                        },
                    );
                }
                scans.insert(
                    id,
                    ScanEntry {
                        tool: meta.tool,
                        target: meta.target,
                        status,
                        output,
                        handle: None,
                        started_at: instant_from_epoch(meta.started_epoch, now_epoch),
                        terminal_at: Some(instant_from_epoch(terminal_epoch, now_epoch)),
                        started_epoch: meta.started_epoch,
                    },
                );
            } else if let Some(id) = name.strip_suffix(".txt")
                && !scan_dir.join(format!("{id}.json")).is_file()
            {
                // Output without metadata is unreachable (pre-persistence spill
                // or failed metadata write) - remove it.
                let _ = std::fs::remove_file(&path);
            }
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

    /// Clamp quick-launch default args to the operator's safety caps.
    ///
    /// The dedicated tool handlers enforce caps (e.g. masscan `--rate`); this
    /// mirrors that on the `launch_scan` path so a stricter operator cap can't
    /// be silently bypassed by launching the same tool as a background scan.
    fn clamp_to_caps(tool: &str, args: &mut [String], safety: &crate::config::SafetyConfig) {
        if tool == "masscan"
            && let Some(i) = args.iter().position(|a| a == "--rate")
            && let Some(rate) = args.get_mut(i + 1)
            && rate
                .parse::<u32>()
                .is_ok_and(|r| r > safety.masscan_max_rate)
        {
            *rate = safety.masscan_max_rate.to_string();
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

        let mut arg_strings = Self::default_args(tool, target);
        Self::clamp_to_caps(tool, &mut arg_strings, &self.config.safety);

        let id = Uuid::new_v4().to_string();
        let started_epoch = epoch_secs();

        // Evict expired scans, enforce the concurrency limit, and register the
        // entry under one lock hold - a concurrent launch can't squeeze past
        // the cap, and the spawned task always finds its entry registered.
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
        scans.insert(
            id.clone(),
            ScanEntry {
                tool: tool.to_string(),
                target: target.to_string(),
                status: ScanStatus::Running,
                output: None,
                handle: None,
                started_at: Instant::now(),
                terminal_at: None,
                started_epoch,
            },
        );
        drop(scans);

        // Persist as Running before the task exists: fast tools can complete
        // and write terminal metadata before `launch` returns, and a stale
        // Running copy written after that would lie to recovery.
        self.persist_meta(
            &id,
            &PersistedScan {
                tool: tool.to_string(),
                target: target.to_string(),
                status: ScanStatus::Running,
                started_epoch,
                terminal_epoch: None,
            },
        );

        // Spawn the scan as a background tokio task
        let manager = self.clone();
        let scan_id = id.clone();
        let tool_owned = tool.to_string();
        let handle = tokio::spawn(async move {
            let arg_refs: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();
            let result =
                executor::run_unmetered(&manager.config, &tool_owned, &arg_refs, timeout_secs)
                    .await;

            let (status, output) = match result {
                Ok(r) => {
                    let output_str = if r.success {
                        r.stdout
                    } else {
                        format!("{}\n{}", r.stdout, r.stderr)
                    };
                    // Persist every terminal output to disk (not just large
                    // spills, as before) so results survive a restart.
                    match write_scan_output(&manager.scan_dir(), &scan_id, &output_str) {
                        Ok(path) => (ScanStatus::Completed, Some(ScanOutput::Disk(path))),
                        Err(e) => {
                            tracing::warn!(
                                "scan {scan_id}: output write failed ({e}), keeping in memory"
                            );
                            (ScanStatus::Completed, Some(ScanOutput::Memory(output_str)))
                        }
                    }
                }
                Err(e) => (ScanStatus::Failed(e.to_string()), None),
            };

            let mut scans = match manager.lock_scans() {
                Ok(guard) => guard,
                Err(_) => {
                    tracing::error!("scan state lock poisoned - scan {scan_id} result lost");
                    return;
                }
            };
            // Don't overwrite a cancellation; take the metadata fields while
            // the entry is locked, persist after releasing it.
            let Some(entry) = scans.get_mut(&scan_id) else {
                return;
            };
            if entry.status == ScanStatus::Cancelled {
                return;
            }
            entry.status = status.clone();
            entry.terminal_at = Some(Instant::now());
            entry.output = output;
            let meta = PersistedScan {
                tool: entry.tool.clone(),
                target: entry.target.clone(),
                status,
                started_epoch: entry.started_epoch,
                terminal_epoch: Some(epoch_secs()),
            };
            drop(scans);
            manager.persist_meta(&scan_id, &meta);
        });

        // Attach the handle for cancellation. The task may already have
        // finished; cancelling a terminal entry is a no-op either way.
        if let Some(entry) = self.lock_scans()?.get_mut(&id) {
            entry.handle = Some(handle);
        }

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
                .map_err(|e| PentestError::CommandFailed(format!("read scan output: {e}"))),
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
                    .map_err(|e| PentestError::CommandFailed(format!("read scan output: {e}")))?,
            ),
        };

        // Char-boundary slicing without materialising the whole output as a
        // Vec<char> (a large disk-backed output would double its size in memory
        // otherwise).
        let Some((start, _)) = content.char_indices().nth(offset) else {
            return Ok(Some(String::new())); // offset at/past the end
        };
        let end = content[start..]
            .char_indices()
            .nth(limit)
            .map_or(content.len(), |(i, _)| start + i);
        Ok(Some(content[start..end].to_string()))
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
            let meta = PersistedScan {
                tool: entry.tool.clone(),
                target: entry.target.clone(),
                status: ScanStatus::Cancelled,
                started_epoch: entry.started_epoch,
                terminal_epoch: Some(epoch_secs()),
            };
            if let Some(handle) = entry.handle.take() {
                handle.abort();
            }
            drop(scans);
            self.persist_meta(id, &meta);
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

    #[test]
    fn results_slices_on_char_boundaries_without_panicking() {
        let mgr = ScanManager::new(Arc::new(RavenConfig::default()));
        // 40 chars of mixed-width UTF-8 (1/2/3/4 bytes per char).
        let content = "aé中🔥".repeat(10);
        mgr.scans.lock().unwrap().insert(
            "t".into(),
            ScanEntry {
                tool: "nmap".into(),
                target: "10.0.0.1".into(),
                status: ScanStatus::Completed,
                output: Some(ScanOutput::Memory(content.clone())),
                handle: None,
                started_at: Instant::now(),
                terminal_at: Some(Instant::now()),
                started_epoch: epoch_secs(),
            },
        );

        // Partial page: exactly `limit` chars, cut on char boundaries.
        let page = mgr.results("t", 0, 15).unwrap().unwrap();
        assert_eq!(page.chars().count(), 15);
        assert_eq!(page, content.chars().take(15).collect::<String>());

        // Offset + limit spanning the middle of the output.
        let mid = mgr.results("t", 7, 10).unwrap().unwrap();
        assert_eq!(mid, content.chars().skip(7).take(10).collect::<String>());

        // Offset at/past the end → empty string, not a panic.
        assert_eq!(mgr.results("t", 40, 10).unwrap().unwrap(), "");
        assert_eq!(mgr.results("t", 1_000, 10).unwrap().unwrap(), "");

        // Limit beyond the end → the rest of the output.
        assert_eq!(mgr.results("t", 0, 40).unwrap().unwrap(), content);
        assert_eq!(mgr.results("t", 0, usize::MAX).unwrap().unwrap(), content);

        // Unknown scan → None.
        assert!(mgr.results("missing", 0, 10).unwrap().is_none());
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
            started_epoch: epoch_secs(),
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
    fn prune_removes_metadata_alongside_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = RavenConfig::default();
        cfg.execution.scan_retention_secs = 0; // evict terminal scans immediately
        cfg.execution.output_dir = dir.path().to_string_lossy().into_owned();
        let mgr = ScanManager::new(Arc::new(cfg));
        let scan_dir = dir.path().join("scans");
        std::fs::create_dir_all(&scan_dir).unwrap();
        let txt = scan_dir.join("t.txt");
        std::fs::write(&txt, "out").unwrap();
        std::fs::write(scan_dir.join("t.json"), "{}").unwrap();
        let mut scans = mgr.scans.lock().unwrap();
        scans.insert(
            "t".into(),
            ScanEntry {
                output: Some(ScanOutput::Disk(txt)),
                ..entry(ScanStatus::Completed, Some(Instant::now()))
            },
        );
        mgr.prune_expired(&mut scans);
        assert!(!scans.contains_key("t"));
        assert!(!scan_dir.join("t.txt").exists(), "output file deleted");
        assert!(!scan_dir.join("t.json").exists(), "metadata file deleted");
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
    fn clamp_to_caps_lowers_masscan_rate_below_cap() {
        let mut cfg = RavenConfig::default();
        // Operator cap stricter than the launch default of 100.
        cfg.safety.masscan_max_rate = 50;
        let mut args = ScanManager::default_args("masscan", "10.0.0.0/24");
        ScanManager::clamp_to_caps("masscan", &mut args, &cfg.safety);
        let i = args.iter().position(|a| a == "--rate").unwrap();
        assert_eq!(args[i + 1], "50", "rate must be clamped to the cap");
    }

    #[test]
    fn clamp_to_caps_leaves_rate_below_cap_untouched() {
        let cfg = RavenConfig::default(); // masscan_max_rate default 1000 > 100
        let mut args = ScanManager::default_args("masscan", "10.0.0.0/24");
        ScanManager::clamp_to_caps("masscan", &mut args, &cfg.safety);
        let i = args.iter().position(|a| a == "--rate").unwrap();
        assert_eq!(args[i + 1], "100", "rate under the cap is unchanged");
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
        // Terminal scans persist to disk for restart recovery.
        let scan_dir = dir.path().join("scans");
        assert!(scan_dir.join(format!("{id}.txt")).is_file());
        assert!(scan_dir.join(format!("{id}.json")).is_file());
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

    // --- persistence across restarts ---
    // Dropping the manager (and its tokio task) simulates a hard stop; a fresh
    // manager on the same output dir must rebuild state from disk alone.

    #[tokio::test]
    async fn completed_scan_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Arc::new(proc_config(dir.path(), 3));
        let id = {
            let mgr = ScanManager::new(Arc::clone(&cfg));
            let id = mgr.launch("echo", "restart-probe", None).unwrap();
            assert!(wait_status(&mgr, &id, ScanStatus::Completed).await);
            id
        };
        let revived = ScanManager::new(Arc::clone(&cfg));
        assert_eq!(revived.status(&id).unwrap(), Some(ScanStatus::Completed));
        let out = revived
            .output(&id)
            .unwrap()
            .expect("output recovered from disk");
        assert!(out.contains("restart-probe"));
        assert!(revived.list().unwrap().iter().any(|s| s.id == id));
    }

    #[tokio::test]
    async fn restart_fails_scan_that_was_running() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Arc::new(proc_config(dir.path(), 3));
        let id = {
            let mgr = ScanManager::new(Arc::clone(&cfg));
            mgr.launch("sleep", "60", None).unwrap()
        };
        let revived = ScanManager::new(Arc::clone(&cfg));
        match revived.status(&id).unwrap() {
            Some(ScanStatus::Failed(m)) => assert!(m.contains("restart"), "{m}"),
            other => panic!("expected restart failure, got {other:?}"),
        }
        // The rewrite is persisted: a second restart keeps it failed.
        drop(revived);
        let again = ScanManager::new(cfg);
        assert!(matches!(
            again.status(&id).unwrap(),
            Some(ScanStatus::Failed(_))
        ));
    }

    #[tokio::test]
    async fn cancelled_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Arc::new(proc_config(dir.path(), 3));
        let id = {
            let mgr = ScanManager::new(Arc::clone(&cfg));
            let id = mgr.launch("sleep", "5", None).unwrap();
            mgr.cancel(&id).unwrap();
            id
        };
        let revived = ScanManager::new(cfg);
        assert_eq!(revived.status(&id).unwrap(), Some(ScanStatus::Cancelled));
    }

    #[test]
    fn recovery_cleans_corrupt_and_orphaned_files() {
        let dir = tempfile::tempdir().unwrap();
        let scan_dir = dir.path().join("scans");
        std::fs::create_dir_all(&scan_dir).unwrap();
        std::fs::write(scan_dir.join("bad.json"), "{not json").unwrap();
        std::fs::write(scan_dir.join("bad.txt"), "partial").unwrap();
        std::fs::write(scan_dir.join("crash.json.tmp"), "{}").unwrap();
        std::fs::write(scan_dir.join("orphan.txt"), "no metadata").unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 3)));
        assert!(mgr.list().unwrap().is_empty(), "nothing recoverable");
        assert!(!scan_dir.join("bad.json").exists());
        assert!(!scan_dir.join("bad.txt").exists());
        assert!(!scan_dir.join("crash.json.tmp").exists());
        assert!(!scan_dir.join("orphan.txt").exists());
    }

    #[test]
    fn recovery_skips_scans_past_retention() {
        let dir = tempfile::tempdir().unwrap();
        let scan_dir = dir.path().join("scans");
        std::fs::create_dir_all(&scan_dir).unwrap();
        let now = epoch_secs();
        let stale = serde_json::json!({
            "tool": "nmap", "target": "example.com", "status": "Completed",
            "started_epoch": now - 7200, "terminal_epoch": now - 7200,
        });
        std::fs::write(scan_dir.join("stale.json"), stale.to_string()).unwrap();
        std::fs::write(scan_dir.join("stale.txt"), "old output").unwrap();
        let mgr = ScanManager::new(Arc::new(proc_config(dir.path(), 3)));
        assert!(
            mgr.list().unwrap().is_empty(),
            "scan past TTL not resurrected"
        );
        assert!(!scan_dir.join("stale.json").exists());
        assert!(!scan_dir.join("stale.txt").exists());
    }
}
