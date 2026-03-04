use crate::config::RavenConfig;
use crate::error::PentestError;
use crate::executor;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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

struct ScanEntry {
    tool: String,
    target: String,
    status: ScanStatus,
    output: Option<String>,
    handle: Option<JoinHandle<()>>,
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

        let arg_strings = args;

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
            },
        );

        Ok(id)
    }

    pub fn status(&self, id: &str) -> Result<Option<ScanStatus>, PentestError> {
        Ok(self.lock_scans()?.get(id).map(|e| e.status.clone()))
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

    pub fn list(&self) -> Result<Vec<(String, String, String, ScanStatus)>, PentestError> {
        Ok(self
            .lock_scans()?
            .iter()
            .map(|(id, e)| {
                (
                    id.clone(),
                    e.tool.clone(),
                    e.target.clone(),
                    e.status.clone(),
                )
            })
            .collect())
    }
}
