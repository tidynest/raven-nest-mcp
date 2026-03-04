use crate::finding::{Finding, FindingMeta};
use std::{collections::HashMap, fs, path::PathBuf};

pub struct FindingStore {
    index: HashMap<String, FindingMeta>,
    findings_dir: PathBuf,
}

impl FindingStore {
    /// Create or open a file-per-finding store at `findings_dir`.
    ///
    /// On first run, migrates any legacy `findings.json` found in the parent directory.
    pub fn new(findings_dir: PathBuf) -> Self {
        fs::create_dir_all(&findings_dir).unwrap_or_else(|e| {
            panic!(
                "failed to create findings directory {}: {e}",
                findings_dir.display()
            );
        });

        // One-time migration from legacy single-file format
        if let Some(parent) = findings_dir.parent() {
            let legacy_path = parent.join("findings.json");
            if legacy_path.exists() {
                Self::migrate_legacy(&legacy_path, &findings_dir);
            }
        }

        // Rebuild index from individual files on disk
        let mut index = HashMap::new();
        if let Ok(entries) = fs::read_dir(&findings_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    match fs::read_to_string(&path) {
                        Ok(content) => match serde_json::from_str::<Finding>(&content) {
                            Ok(f) => {
                                index.insert(f.id.clone(), FindingMeta::from(&f));
                            }
                            Err(e) => {
                                tracing::warn!("skipping corrupt finding {}: {e}", path.display())
                            }
                        },
                        Err(e) => tracing::warn!("failed to read {}: {e}", path.display()),
                    }
                }
            }
        }

        Self {
            index,
            findings_dir,
        }
    }

    pub fn insert(&mut self, finding: Finding) -> Result<String, String> {
        let id = finding.id.clone();
        let path = self.finding_path(&id);
        let json = serde_json::to_string_pretty(&finding).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| format!("disk write failed: {e}"))?;
        self.index.insert(id.clone(), FindingMeta::from(&finding));
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<Finding> {
        if !self.index.contains_key(id) {
            return None;
        }
        let path = self.finding_path(id);
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn delete(&mut self, id: &str) -> bool {
        if self.index.remove(id).is_none() {
            return false;
        }
        let path = self.finding_path(id);
        if let Err(e) = fs::remove_file(&path) {
            tracing::warn!("failed to delete finding file {}: {e}", path.display());
        }
        true
    }

    /// List metadata for all findings, sorted by severity (critical first).
    /// Zero disk I/O — reads only the in-memory index.
    pub fn list(&self) -> Vec<&FindingMeta> {
        let mut metas: Vec<&FindingMeta> = self.index.values().collect();
        metas.sort_by(|a, b| a.severity.cmp(&b.severity));
        metas
    }

    /// Load full findings from disk in severity order.
    /// Used by report generation — infrequent, O(n) disk reads acceptable.
    pub fn load_all(&self) -> Vec<Finding> {
        let sorted_ids: Vec<&str> = self.list().iter().map(|m| m.id.as_str()).collect();
        sorted_ids
            .into_iter()
            .filter_map(|id| self.get(id))
            .collect()
    }

    fn finding_path(&self, id: &str) -> PathBuf {
        self.findings_dir.join(format!("{id}.json"))
    }

    fn migrate_legacy(legacy_path: &std::path::Path, findings_dir: &std::path::Path) {
        let content = match fs::read_to_string(legacy_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to read legacy findings file: {e}");
                return;
            }
        };
        let findings: Vec<Finding> = match serde_json::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("failed to parse legacy findings file: {e}");
                return;
            }
        };

        let count = findings.len();
        for finding in &findings {
            let path = findings_dir.join(format!("{}.json", finding.id));
            if let Ok(json) = serde_json::to_string_pretty(finding)
                && let Err(e) = fs::write(&path, json)
            {
                tracing::warn!("migration: failed to write {}: {e}", path.display());
            }
        }

        let migrated_path = legacy_path.with_extension("json.migrated");
        if let Err(e) = fs::rename(legacy_path, &migrated_path) {
            tracing::warn!("failed to rename legacy file: {e}");
        }
        tracing::info!("migrated {count} findings from legacy format");
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

    fn test_store() -> (FindingStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = FindingStore::new(dir.path().join("findings"));
        (store, dir)
    }

    #[test]
    fn insert_and_get() {
        let (mut store, _dir) = test_store();
        let f = make_finding("XSS", Severity::High);
        let id = store.insert(f.clone()).unwrap();
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.title, "XSS");
        assert_eq!(retrieved.severity, Severity::High);
    }

    #[test]
    fn delete_existing() {
        let (mut store, _dir) = test_store();
        let f = make_finding("SQLi", Severity::Critical);
        let id = store.insert(f).unwrap();
        assert!(store.delete(&id));
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn delete_nonexistent() {
        let (store, _dir) = test_store();
        // Mutable required for delete — shadow with mut
        let mut store = store;
        assert!(!store.delete("does-not-exist"));
    }

    #[test]
    fn list_sorted_by_severity() {
        let (mut store, _dir) = test_store();
        store.insert(make_finding("low", Severity::Low)).unwrap();
        store
            .insert(make_finding("critical", Severity::Critical))
            .unwrap();
        store.insert(make_finding("high", Severity::High)).unwrap();

        let list = store.list();
        let severities: Vec<&Severity> = list.iter().map(|m| &m.severity).collect();
        assert_eq!(
            severities,
            vec![&Severity::Critical, &Severity::High, &Severity::Low]
        );
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let findings_dir = dir.path().join("findings");

        let id = {
            let mut store = FindingStore::new(findings_dir.clone());
            store
                .insert(make_finding("persisted", Severity::Medium))
                .unwrap()
        };

        // Reopen store from disk
        let store = FindingStore::new(findings_dir);
        let f = store.get(&id).unwrap();
        assert_eq!(f.title, "persisted");
    }

    #[test]
    fn persistence_survives_delete() {
        let dir = tempfile::tempdir().unwrap();
        let findings_dir = dir.path().join("findings");

        let (id1, _id2) = {
            let mut store = FindingStore::new(findings_dir.clone());
            let id1 = store.insert(make_finding("keep", Severity::High)).unwrap();
            let id2 = store.insert(make_finding("remove", Severity::Low)).unwrap();
            store.delete(&id2);
            (id1, id2)
        };

        let store = FindingStore::new(findings_dir);
        assert!(store.get(&id1).is_some());
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn unlimited_findings() {
        let (mut store, _dir) = test_store();
        for i in 0..1500 {
            store
                .insert(make_finding(&format!("finding-{i}"), Severity::Info))
                .unwrap();
        }
        assert_eq!(store.list().len(), 1500);
    }

    #[test]
    fn corrupted_file_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let findings_dir = dir.path().join("findings");
        fs::create_dir_all(&findings_dir).unwrap();

        // Write a valid finding
        let f = make_finding("valid", Severity::High);
        let valid_json = serde_json::to_string_pretty(&f).unwrap();
        fs::write(findings_dir.join(format!("{}.json", f.id)), &valid_json).unwrap();

        // Write corrupt JSON
        fs::write(findings_dir.join("corrupt.json"), "not valid json{{{").unwrap();

        let store = FindingStore::new(findings_dir);
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].title, "valid");
    }

    #[test]
    fn migration_from_legacy_format() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path();

        // Write old-style findings.json
        let f1 = make_finding("legacy-1", Severity::Critical);
        let f2 = make_finding("legacy-2", Severity::Low);
        let legacy_json = serde_json::to_string_pretty(&vec![&f1, &f2]).unwrap();
        fs::write(output_dir.join("findings.json"), &legacy_json).unwrap();

        // Open store — should auto-migrate
        let store = FindingStore::new(output_dir.join("findings"));
        assert_eq!(store.list().len(), 2);

        // Legacy file should be renamed
        assert!(!output_dir.join("findings.json").exists());
        assert!(output_dir.join("findings.json.migrated").exists());

        // Individual files should exist
        assert!(store.get(&f1.id).is_some());
        assert!(store.get(&f2.id).is_some());
    }

    #[test]
    fn load_all_returns_sorted() {
        let (mut store, _dir) = test_store();
        store.insert(make_finding("info", Severity::Info)).unwrap();
        store
            .insert(make_finding("critical", Severity::Critical))
            .unwrap();
        store
            .insert(make_finding("medium", Severity::Medium))
            .unwrap();

        let all = store.load_all();
        let titles: Vec<&str> = all.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["critical", "medium", "info"]);
    }
}
