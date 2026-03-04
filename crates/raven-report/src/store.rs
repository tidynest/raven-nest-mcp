use crate::finding::Finding;
use std::{collections::HashMap, path::{Path, PathBuf}};

#[derive(Default)]
pub struct FindingStore {
    findings: HashMap<String, Finding>,
    persist_path: Option<PathBuf>,
}

impl FindingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from disk if file exists, and remember the path for auto-saving.
    pub fn with_persistence(path: PathBuf) -> Self {
        if path.exists() {
            match Self::load_from_file(&path) {
                Ok(mut store) => {
                    store.persist_path = Some(path);
                    return store;
                }
                Err(e) => tracing::warn!("failed to load findings from disk: {e}"),
            }
        }
        Self {
            findings: HashMap::new(),
            persist_path: Some(path),
        }
    }

    pub fn insert(&mut self, finding: Finding) -> String {
        let id = finding.id.clone();
        self.findings.insert(id.clone(), finding);
        self.auto_save();
        id
    }

    pub fn get(&self, id: &str) -> Option<&Finding> {
        self.findings.get(id)
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let removed = self.findings.remove(id).is_some();
        if removed {
            self.auto_save();
        }
        removed
    }

    pub fn list(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.values().collect();
        findings.sort_by(|a, b| a.severity.cmp(&b.severity));
        findings
    }

    fn auto_save(&self) {
        if let Some(path) = &self.persist_path
            && let Err(e) = self.save_to_file(path) {
                tracing::warn!("failed to persist findings: {e}");
            }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let findings: Vec<&Finding> = self.findings.values().collect();
        let json = serde_json::to_string_pretty(&findings)
            .map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn load_from_file(path: &Path) -> Result<FindingStore, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let findings: Vec<Finding> = serde_json::from_str(&content)
            .map_err(|e| e.to_string())?;

        let mut store = FindingStore::new();
        for finding in findings {
            store.findings.insert(finding.id.clone(), finding);
        }
        Ok(store)
    }
}
