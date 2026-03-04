use crate::finding::Finding;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct FindingStore {
    findings: HashMap<String, Finding>,
    persist_path: Option<PathBuf>,
}

pub const MAX_FINDINGS: usize = 1000;

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

    pub fn insert(&mut self, finding: Finding) -> Result<String, String> {
        if self.findings.len() >= MAX_FINDINGS {
            return Err(format!(
                "maximum findings limit ({MAX_FINDINGS}) reached — delete old findings first"
            ));
        }
        let id = finding.id.clone();
        self.findings.insert(id.clone(), finding);
        self.auto_save();
        Ok(id)
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
            && let Err(e) = self.save_to_file(path)
        {
            tracing::warn!("failed to persist findings: {e}");
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let findings: Vec<&Finding> = self.findings.values().collect();
        let json = serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn load_from_file(path: &Path) -> Result<FindingStore, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let findings: Vec<Finding> = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let mut store = FindingStore::new();
        for finding in findings {
            store.findings.insert(finding.id.clone(), finding);
        }
        Ok(store)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(
            title.into(),
            severity,
            "test description".into(),
            "10.0.0.1".into(),
            "nmap".into(),
        )
    }

    #[test]
    fn insert_and_get() {
        let mut store = FindingStore::new();
        let finding = make_finding("XSS in login", Severity::High);
        let id = store.insert(finding).unwrap();
        assert!(store.get(&id).is_some());
        assert_eq!(store.get(&id).unwrap().title, "XSS in login");
    }

    #[test]
    fn delete_existing() {
        let mut store = FindingStore::new();
        let id = store
            .insert(make_finding("SQLi", Severity::Critical))
            .unwrap();
        assert!(store.delete(&id));
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn delete_nonexistent() {
        let mut store = FindingStore::new();
        assert!(!store.delete("nonexistent-id"));
    }

    #[test]
    fn list_sorted_by_severity() {
        let mut store = FindingStore::new();
        store
            .insert(make_finding("Info leak", Severity::Info))
            .unwrap();
        store
            .insert(make_finding("RCE", Severity::Critical))
            .unwrap();
        store
            .insert(make_finding("Open redirect", Severity::Low))
            .unwrap();

        let findings = store.list();
        let severities: Vec<&Severity> = findings.iter().map(|f| &f.severity).collect();
        assert_eq!(
            severities,
            vec![&Severity::Critical, &Severity::Low, &Severity::Info]
        );
    }

    #[test]
    fn count_limit_enforced() {
        let mut store = FindingStore::new();
        for i in 0..MAX_FINDINGS {
            store
                .insert(make_finding(&format!("Finding {i}"), Severity::Info))
                .unwrap();
        }
        assert_eq!(store.len(), MAX_FINDINGS);

        // Next insert should fail
        let result = store.insert(make_finding("One too many", Severity::High));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum findings limit"));
    }

    #[test]
    fn count_limit_allows_after_delete() {
        let mut store = FindingStore::new();
        let mut ids = Vec::new();
        for i in 0..MAX_FINDINGS {
            ids.push(
                store
                    .insert(make_finding(&format!("Finding {i}"), Severity::Info))
                    .unwrap(),
            );
        }
        // Delete one, then insert should succeed again
        store.delete(&ids[0]);
        assert!(
            store
                .insert(make_finding("Replacement", Severity::High))
                .is_ok()
        );
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        // Write findings with persistence
        let mut store = FindingStore::with_persistence(path.clone());
        let id = store
            .insert(make_finding("Stored XSS", Severity::Medium))
            .unwrap();

        // Load from disk into a new store
        let loaded = FindingStore::load_from_file(&path).unwrap();
        let finding = loaded.get(&id).unwrap();
        assert_eq!(finding.title, "Stored XSS");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn persistence_survives_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        let mut store = FindingStore::with_persistence(path.clone());
        let id1 = store.insert(make_finding("Keep", Severity::High)).unwrap();
        let id2 = store.insert(make_finding("Remove", Severity::Low)).unwrap();
        store.delete(&id2);

        let loaded = FindingStore::load_from_file(&path).unwrap();
        assert!(loaded.get(&id1).is_some());
        assert!(loaded.get(&id2).is_none());
    }

    #[test]
    fn with_persistence_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        // Create and save
        let mut store = FindingStore::with_persistence(path.clone());
        store
            .insert(make_finding("Persisted", Severity::Critical))
            .unwrap();
        drop(store);

        // Re-open should load existing data
        let store2 = FindingStore::with_persistence(path);
        assert_eq!(store2.len(), 1);
    }
}
