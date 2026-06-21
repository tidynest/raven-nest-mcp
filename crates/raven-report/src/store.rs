//! File-per-finding persistence layer.
//!
//! Each [`Finding`] is stored as `{id}.json` inside a dedicated directory.
//! An in-memory [`HashMap`] of [`FindingMeta`] entries serves as the index,
//! rebuilt from disk on startup.
//!
//! This design was chosen over a single JSON file because:
//! - Individual writes don't risk corrupting the entire dataset.
//! - The in-memory index avoids O(n) disk reads for listing.
//! - Deletes are a single `fs::remove_file` with no rewrite.
//!
//! On first run, any legacy `findings.json` in the parent directory is
//! automatically migrated to individual files and renamed to `.migrated`.
//!
//! Consumed by `raven-server::tools::findings` via `RwLock<FindingStore>`.

use crate::finding::{Finding, FindingMeta};
use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    path::PathBuf,
};

/// File-per-finding store with an in-memory severity-sorted index.
pub struct FindingStore {
    /// In-memory index: finding ID → lightweight metadata.
    index: HashMap<String, FindingMeta>,
    /// Reverse index: scan ID → finding IDs produced by that scan.
    by_scan: HashMap<String, Vec<String>>,
    /// Dedup index: content fingerprint → the finding IDs sharing it. A set
    /// (not a single ID) so duplicate manual saves don't orphan one another and
    /// eviction stays exact.
    seen: HashMap<u64, HashSet<String>>,
    /// Reverse map: finding ID → its fingerprint, so `delete` can evict from
    /// `seen` using only the in-memory index — never re-reading the (possibly
    /// already-gone) file from disk.
    id_to_fp: HashMap<String, u64>,
    /// Directory where `{id}.json` files are stored.
    findings_dir: PathBuf,
}

/// Compute a content fingerprint for dedup, insensitive to case and surrounding
/// whitespace so `"Nmap"` and `" nmap "` collapse to the same finding.
///
/// Hashes the normalised `(tool, target, title, cve)` tuple — the natural
/// identity of a finding regardless of which scan re-discovered it.
fn fingerprint(tool: &str, target: &str, title: &str, cve: Option<&str>) -> u64 {
    let mut hasher = DefaultHasher::new();
    tool.trim().to_lowercase().hash(&mut hasher);
    target.trim().to_lowercase().hash(&mut hasher);
    title.trim().to_lowercase().hash(&mut hasher);
    cve.map(|c| c.trim().to_lowercase()).hash(&mut hasher);
    hasher.finish()
}

impl FindingStore {
    /// Create or open a file-per-finding store at `findings_dir`.
    ///
    /// On first run, migrates any legacy `findings.json` found in the parent directory.
    /// Rebuilds the in-memory index by scanning all `.json` files in the directory.
    pub fn new(findings_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&findings_dir).map_err(|e| {
            format!(
                "failed to create findings directory {}: {e}",
                findings_dir.display()
            )
        })?;

        // One-time migration from legacy single-file format
        if let Some(parent) = findings_dir.parent() {
            let legacy_path = parent.join("findings.json");
            if legacy_path.exists() {
                Self::migrate_legacy(&legacy_path, &findings_dir);
            }
        }

        // Rebuild index from individual files on disk
        let mut index = HashMap::new();
        let mut by_scan: HashMap<String, Vec<String>> = HashMap::new();
        let mut seen: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut id_to_fp: HashMap<String, u64> = HashMap::new();
        if let Ok(entries) = fs::read_dir(&findings_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    match fs::read_to_string(&path) {
                        Ok(content) => match serde_json::from_str::<Finding>(&content) {
                            Ok(f) => {
                                let fp =
                                    fingerprint(&f.tool, &f.target, &f.title, f.cve.as_deref());
                                seen.entry(fp).or_default().insert(f.id.clone());
                                id_to_fp.insert(f.id.clone(), fp);
                                if let Some(scan_id) = &f.scan_id {
                                    by_scan
                                        .entry(scan_id.clone())
                                        .or_default()
                                        .push(f.id.clone());
                                }
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

        Ok(Self {
            index,
            by_scan,
            seen,
            id_to_fp,
            findings_dir,
        })
    }

    /// Persist a new finding to disk and add it to the in-memory index.
    ///
    /// Always inserts — manual saves are never skipped. The fingerprint and
    /// scan reverse-index are updated so later [`insert_dedup`](Self::insert_dedup)
    /// and [`list_by_scan`](Self::list_by_scan) calls see this finding.
    pub fn insert(&mut self, finding: Finding) -> Result<String, String> {
        let id = finding.id.clone();
        let path = self.finding_path(&id);
        let json = serde_json::to_string_pretty(&finding).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| format!("disk write failed: {e}"))?;
        let fp = fingerprint(
            &finding.tool,
            &finding.target,
            &finding.title,
            finding.cve.as_deref(),
        );
        self.seen.entry(fp).or_default().insert(id.clone());
        self.id_to_fp.insert(id.clone(), fp);
        if let Some(scan_id) = &finding.scan_id {
            self.by_scan
                .entry(scan_id.clone())
                .or_default()
                .push(id.clone());
        }
        self.index.insert(id.clone(), FindingMeta::from(&finding));
        Ok(id)
    }

    /// Insert a finding unless an identical one (same fingerprint) already exists.
    ///
    /// Returns `(id, inserted)`: when a duplicate is found, the existing finding's
    /// ID is returned with `inserted = false` and nothing is written; otherwise the
    /// finding is inserted via [`insert`](Self::insert) and `(new_id, true)` returned.
    /// Intended for auto-extracted findings, where the same vuln may surface across
    /// multiple scans.
    pub fn insert_dedup(&mut self, finding: Finding) -> Result<(String, bool), String> {
        let fp = fingerprint(
            &finding.tool,
            &finding.target,
            &finding.title,
            finding.cve.as_deref(),
        );
        if let Some(existing) = self.seen.get(&fp).and_then(|ids| ids.iter().next()) {
            return Ok((existing.clone(), false));
        }
        let id = self.insert(finding)?;
        Ok((id, true))
    }

    /// Load the full finding from disk by ID. Returns `None` if not found.
    pub fn get(&self, id: &str) -> Option<Finding> {
        // Reject non-UUID IDs to prevent path traversal via finding_path()
        if uuid::Uuid::parse_str(id).is_err() {
            return None;
        }
        if !self.index.contains_key(id) {
            return None;
        }
        let path = self.finding_path(id);
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Delete a finding from disk and the in-memory index. Returns `true` if found.
    ///
    /// Also evicts the finding's dedup fingerprint and its entry in the scan
    /// reverse-index, so a deleted finding can later be re-inserted as new.
    pub fn delete(&mut self, id: &str) -> bool {
        // Reject non-UUID IDs to prevent path traversal via finding_path()
        if uuid::Uuid::parse_str(id).is_err() {
            return false;
        }
        // Pull metadata from the in-memory index BEFORE removing, so eviction of
        // the dedup/scan indices never depends on the on-disk file still being
        // readable — an out-of-band deletion would otherwise leak stale entries
        // and permanently block re-adding an identical finding.
        let Some(meta) = self.index.remove(id) else {
            return false;
        };
        if let Some(fp) = self.id_to_fp.remove(id)
            && let Some(ids) = self.seen.get_mut(&fp)
        {
            ids.remove(id);
            if ids.is_empty() {
                self.seen.remove(&fp);
            }
        }
        if let Some(scan_id) = &meta.scan_id
            && let Some(ids) = self.by_scan.get_mut(scan_id)
        {
            ids.retain(|existing| existing != id);
            if ids.is_empty() {
                self.by_scan.remove(scan_id);
            }
        }
        let path = self.finding_path(id);
        if let Err(e) = fs::remove_file(&path) {
            tracing::warn!("failed to delete finding file {}: {e}", path.display());
        }
        true
    }

    /// List metadata for all findings, sorted by severity (critical first).
    ///
    /// Zero disk I/O — reads only the in-memory index.
    pub fn list(&self) -> Vec<&FindingMeta> {
        let mut metas: Vec<&FindingMeta> = self.index.values().collect();
        metas.sort_by(|a, b| a.severity.cmp(&b.severity));
        metas
    }

    /// List metadata for findings produced by `scan_id`, sorted by severity.
    ///
    /// Mirrors [`list`](Self::list) but filters to the scan's findings via the
    /// `by_scan` reverse-index. Returns an empty vec for an unknown scan.
    pub fn list_by_scan(&self, scan_id: &str) -> Vec<&FindingMeta> {
        let mut metas: Vec<&FindingMeta> = self
            .by_scan
            .get(scan_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.index.get(id))
            .collect();
        metas.sort_by(|a, b| a.severity.cmp(&b.severity));
        metas
    }

    /// Load full findings from disk in severity order.
    ///
    /// Used by [`markdown::generate_report`](crate::markdown::generate_report)
    /// — infrequent, so O(n) disk reads are acceptable.
    pub fn load_all(&self) -> Vec<Finding> {
        let sorted_ids: Vec<&str> = self.list().iter().map(|m| m.id.as_str()).collect();
        sorted_ids
            .into_iter()
            .filter_map(|id| self.get(id))
            .collect()
    }

    /// Build the filesystem path for a finding's JSON file.
    fn finding_path(&self, id: &str) -> PathBuf {
        self.findings_dir.join(format!("{id}.json"))
    }

    /// Migrate from the legacy single-file `findings.json` to individual files.
    ///
    /// Reads the array, writes each finding as `{id}.json`, then renames the
    /// legacy file to `findings.json.migrated` to prevent re-migration.
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
        let store = FindingStore::new(dir.path().join("findings")).unwrap();
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
            let mut store = FindingStore::new(findings_dir.clone()).unwrap();
            store
                .insert(make_finding("persisted", Severity::Medium))
                .unwrap()
        };

        // Reopen store from disk
        let store = FindingStore::new(findings_dir).unwrap();
        let f = store.get(&id).unwrap();
        assert_eq!(f.title, "persisted");
    }

    #[test]
    fn persistence_survives_delete() {
        let dir = tempfile::tempdir().unwrap();
        let findings_dir = dir.path().join("findings");

        let (id1, _id2) = {
            let mut store = FindingStore::new(findings_dir.clone()).unwrap();
            let id1 = store.insert(make_finding("keep", Severity::High)).unwrap();
            let id2 = store.insert(make_finding("remove", Severity::Low)).unwrap();
            store.delete(&id2);
            (id1, id2)
        };

        let store = FindingStore::new(findings_dir).unwrap();
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

        let store = FindingStore::new(findings_dir).unwrap();
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
        let store = FindingStore::new(output_dir.join("findings")).unwrap();
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

    #[test]
    fn get_rejects_path_traversal_id() {
        let (store, _dir) = test_store();
        assert!(store.get("../../etc/passwd").is_none());
    }

    #[test]
    fn delete_rejects_path_traversal_id() {
        let (mut store, _dir) = test_store();
        assert!(!store.delete("../../etc/shadow"));
    }

    #[test]
    fn get_rejects_non_uuid_id() {
        let (store, _dir) = test_store();
        assert!(store.get("not-a-uuid-at-all").is_none());
    }

    #[test]
    fn new_returns_error_on_unwritable_path() {
        // /proc is not writable — FindingStore should return Err, not panic
        let result = FindingStore::new(std::path::PathBuf::from("/proc/nonexistent/findings"));
        assert!(result.is_err());
    }

    #[test]
    fn insert_dedup_skips_duplicate() {
        let (mut store, _dir) = test_store();
        let (id1, inserted1) = store
            .insert_dedup(make_finding("XSS", Severity::High))
            .unwrap();
        assert!(inserted1);

        // Same (tool, target, title, cve) fingerprint — should be skipped.
        let (id2, inserted2) = store
            .insert_dedup(make_finding("XSS", Severity::High))
            .unwrap();
        assert!(!inserted2);
        assert_eq!(id1, id2);
        assert_eq!(store.list().len(), 1);

        // A genuinely different finding inserts.
        let (_id3, inserted3) = store
            .insert_dedup(make_finding("SQLi", Severity::High))
            .unwrap();
        assert!(inserted3);
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn fingerprint_is_case_and_whitespace_insensitive() {
        assert_eq!(
            fingerprint("Nmap", "10.0.0.1", "Open port", None),
            fingerprint(" nmap ", "10.0.0.1", "open PORT", None)
        );
        assert_eq!(
            fingerprint("nuclei", "host", "CVE hit", Some("CVE-2024-1")),
            fingerprint("nuclei", "host", "CVE hit", Some(" cve-2024-1 "))
        );
        // Different cve must differ.
        assert_ne!(
            fingerprint("nuclei", "host", "CVE hit", Some("CVE-2024-1")),
            fingerprint("nuclei", "host", "CVE hit", Some("CVE-2024-2"))
        );
    }

    #[test]
    fn list_by_scan_filters_to_scan() {
        let (mut store, _dir) = test_store();
        let scan_a = uuid::Uuid::new_v4().to_string();
        let scan_b = uuid::Uuid::new_v4().to_string();

        let mut f1 = make_finding("a1", Severity::High);
        f1.scan_id = Some(scan_a.clone());
        let mut f2 = make_finding("a2", Severity::Low);
        f2.scan_id = Some(scan_a.clone());
        let mut f3 = make_finding("b1", Severity::Critical);
        f3.scan_id = Some(scan_b.clone());
        let f4 = make_finding("orphan", Severity::Medium); // no scan_id

        store.insert(f1).unwrap();
        store.insert(f2).unwrap();
        store.insert(f3).unwrap();
        store.insert(f4).unwrap();

        let a = store.list_by_scan(&scan_a);
        let titles: Vec<&str> = a.iter().map(|m| m.title.as_str()).collect();
        // Scoped to scan_a only, sorted by severity (High before Low).
        assert_eq!(titles, vec!["a1", "a2"]);

        let b = store.list_by_scan(&scan_b);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].title, "b1");

        // Unknown scan -> empty.
        assert!(
            store
                .list_by_scan(&uuid::Uuid::new_v4().to_string())
                .is_empty()
        );
    }

    #[test]
    fn legacy_finding_without_source_deserializes() {
        // A pre-existing {id}.json that lacks scan_id/source must still load,
        // defaulting source = Manual and scan_id = None (backward compat).
        let id = uuid::Uuid::new_v4().to_string();
        let legacy = serde_json::json!({
            "id": id,
            "title": "legacy",
            "severity": "High",
            "description": "old finding",
            "target": "10.0.0.1",
            "tool": "nmap",
            "evidence": null,
            "remediation": null,
            "cvss": null,
            "cve": null,
            "owasp_category": null,
            "timestamp": "2024-01-01T00:00:00Z"
        });
        let f: Finding = serde_json::from_value(legacy).unwrap();
        assert_eq!(f.source, crate::finding::FindingSource::Manual);
        assert_eq!(f.scan_id, None);
    }

    #[test]
    fn delete_evicts_fingerprint() {
        let (mut store, _dir) = test_store();
        let (id, inserted) = store
            .insert_dedup(make_finding("XSS", Severity::High))
            .unwrap();
        assert!(inserted);

        assert!(store.delete(&id));

        // After delete, the same finding can be insert_dedup'd as new.
        let (_id2, inserted2) = store
            .insert_dedup(make_finding("XSS", Severity::High))
            .unwrap();
        assert!(inserted2);
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn dedup_index_survives_duplicate_save_then_delete() {
        // Two manual saves of identical content both persist (manual always
        // inserts). Deleting the one the index happens to point at must NOT
        // orphan the fingerprint — the other copy still represents it, so a
        // later insert_dedup of that content is still skipped.
        let (mut store, _dir) = test_store();
        let _id_a = store.insert(make_finding("dup", Severity::High)).unwrap();
        let id_b = store.insert(make_finding("dup", Severity::High)).unwrap();
        assert_eq!(store.list().len(), 2);

        assert!(store.delete(&id_b));
        let (_id, inserted) = store
            .insert_dedup(make_finding("dup", Severity::High))
            .unwrap();
        assert!(
            !inserted,
            "fingerprint must remain live while a duplicate still exists"
        );
        assert_eq!(store.list().len(), 1);
    }
}
