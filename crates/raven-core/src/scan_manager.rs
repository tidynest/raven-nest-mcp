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

#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Rich status snapshot returned by `status_enriched()` and `list()`.
#[derive(Debug, Clone)]
pub struct ScanStatusInfo {
    pub id: String,
    pub tool: String,
    pub target: String,
    pub status: ScanStatus,
    pub elapsed_secs: u64,
    pub output_chars: Option<usize>,
}

struct ScanEntry {
    tool: String,
    target: String,
    status: ScanStatus,
    output: Option<String>,
    handle: Option<JoinHandle<()>>,
    started_at: Instant,
}

#[derive(Clone)]
pub struct ScanManager {
    scans: Arc<Mutex<HashMap<String, ScanEntry>>>,
    config: Arc<RavenConfig>,
    max_concurrent: usize,
}

impl ScanManager {
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
    /// Mirrors the defaults used by each dedicated tool handler.
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

    pub fn launch(
        &self,
        tool: &str,
        args: Vec<String>,
        target: &str,
        timeout_secs: Option<u64>,
    ) -> Result<String, PentestError> {
        crate::safety::check_allowlist(tool, &self.config.safety)?;
        crate::safety::validate_target(target)?;

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
                if entry.status == ScanStatus::Cancelled {
                    return;
                }
                match result {
                    Ok(r) => {
                        entry.status = ScanStatus::Completed;
                        entry.output = Some(if r.success {
                            r.stdout
                        } else {
                            format!("{}\n{}", r.stdout, r.stderr)
                        });
                    }
                    Err(e) => {
                        entry.status = ScanStatus::Failed(e.to_string());
                    }
                }
            }
        });

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

    pub fn status(&self, id: &str) -> Result<Option<ScanStatus>, PentestError> {
        Ok(self.lock_scans()?.get(id).map(|e| e.status.clone()))
    }

    /// Returns enriched status including elapsed time and output size.
    pub fn status_enriched(&self, id: &str) -> Result<Option<ScanStatusInfo>, PentestError> {
        let scans = self.lock_scans()?;
        Ok(scans.get(id).map(|e| ScanStatusInfo {
            id: id.to_string(),
            tool: e.tool.clone(),
            target: e.target.clone(),
            status: e.status.clone(),
            elapsed_secs: e.started_at.elapsed().as_secs(),
            output_chars: e.output.as_ref().map(|o| o.len()),
        }))
    }

    /// Returns the raw output string for completed scans (used for auto-inline).
    pub fn output(&self, id: &str) -> Result<Option<String>, PentestError> {
        let scans = self.lock_scans()?;
        Ok(scans.get(id).and_then(|e| e.output.clone()))
    }

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
        let Some(output) = entry.output.as_ref() else {
            return Ok(None);
        };

        let chars: Vec<char> = output.chars().collect();
        if offset >= chars.len() {
            return Ok(Some(String::new()));
        }
        let end = chars.len().min(offset + limit);
        Ok(Some(chars[offset..end].iter().collect()))
    }

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

    /// Returns enriched status for all scans.
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
                output_chars: e.output.as_ref().map(|o| o.len()),
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
