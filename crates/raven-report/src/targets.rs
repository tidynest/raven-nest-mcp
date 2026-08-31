//! Host/service discovery tracking across scans.
//!
//! Persists what the scanners learned about each host - open ports, service
//! names/versions, first/last seen - as one JSON file per host under a
//! `targets/` directory (same file-per-record design as [`FindingStore`](crate::store)).
//! Re-scanning merges into the existing record: new ports are added, changed
//! service versions are updated, and `last_seen` is bumped, so the record
//! accumulates a history of what was observed and when.
//!
//! Hosts come from *parsed scanner output* (e.g. nmap's `addr` attribute),
//! which is target-controlled data - so [`sanitize_host`] strictly validates
//! the value before it is used as a filename.
//!
//! Scoped per engagement: `raven-server` points the store at
//! `{engagement_dir}/targets`, swapping it alongside the findings store.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// One observed service on a host, merged across scans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceRecord {
    pub port: u16,
    pub proto: String,
    /// Port state as reported (`open`, `closed`, `filtered`).
    pub state: String,
    /// Service name (e.g. `ssh`, `http`), empty if unknown.
    pub service: String,
    /// Product/version string (e.g. `OpenSSH 8.9`), empty if unknown.
    #[serde(default)]
    pub version: String,
    /// Tool that last reported this service.
    pub source_tool: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Everything observed about one host, persisted as `{targets_dir}/{host}.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostRecord {
    pub host: String,
    /// Technologies identified on the host (from any scanner).
    #[serde(default)]
    pub technologies: Vec<String>,
    /// Services keyed by `"{proto}/{port}"` for idempotent merging.
    /// BTreeMap so serialisation (and file diffs) are deterministic.
    #[serde(default)]
    pub services: BTreeMap<String, ServiceRecord>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl HostRecord {
    /// Number of services currently reported `open`.
    pub fn open_port_count(&self) -> usize {
        self.services.values().filter(|s| s.state == "open").count()
    }
}

/// Lightweight listing entry - everything `list_targets` needs without loading
/// every full record from disk.
#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub host: String,
    pub open_ports: usize,
    pub total_services: usize,
    pub last_seen: DateTime<Utc>,
}

/// A service observation to merge into a host record. Producers are scanner
/// parsers (e.g. the nmap structured parser in `raven-server`).
#[derive(Debug, Clone)]
pub struct ServiceObservation {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
    pub version: String,
}

/// Validate a host value before it is used as a filename (or looked up).
///
/// Allows exactly the characters that appear in IPs, CIDRs, and DNS names
/// (alphanumerics, `.`, `:`, `-`, `_`), rejects `.`/`..`, path separators, and
/// anything over the 253-char DNS limit. Scan output is target-controlled, so
/// this is a path-traversal guard in the same class as the finding-ID check in
/// [`FindingStore::get`](crate::store::FindingStore::get). Public so the server
/// validates lookups with the same rule the store keys on.
pub fn sanitize_host(host: &str) -> Result<(), String> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host != "."
        && host != ".."
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "host '{host}' is not a valid IP/hostname - refusing to use it as a file name"
        ))
    }
}

/// File-per-host discovery store with an in-memory listing index.
pub struct TargetStore {
    /// In-memory index: host → summary (kept in lockstep with disk).
    index: HashMap<String, HostSummary>,
    /// Directory where `{host}.json` files live.
    targets_dir: PathBuf,
}

impl TargetStore {
    /// Create or open a store at `targets_dir`, rebuilding the listing index
    /// from the files on disk. Corrupt files are skipped with a warning.
    pub fn new(targets_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&targets_dir).map_err(|e| {
            format!(
                "failed to create targets directory {}: {e}",
                targets_dir.display()
            )
        })?;
        let mut index = HashMap::new();
        if let Ok(entries) = fs::read_dir(&targets_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().is_some_and(|ext| ext == "json") {
                    continue;
                }
                match fs::read_to_string(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|c| serde_json::from_str::<HostRecord>(&c).map_err(|e| e.to_string()))
                {
                    Ok(rec) => {
                        index.insert(
                            rec.host.clone(),
                            HostSummary {
                                host: rec.host.clone(),
                                open_ports: rec.open_port_count(),
                                total_services: rec.services.len(),
                                last_seen: rec.last_seen,
                            },
                        );
                    }
                    Err(e) => {
                        tracing::warn!("skipping corrupt target record {}: {e}", path.display())
                    }
                }
            }
        }
        Ok(Self { index, targets_dir })
    }

    /// Directory holding the per-host files (the engagement's dir when scoped).
    pub fn base_dir(&self) -> &Path {
        &self.targets_dir
    }

    fn record_path(&self, host: &str) -> PathBuf {
        self.targets_dir.join(format!("{host}.json"))
    }

    /// Merge one batch of service observations into a host's record.
    ///
    /// Existing entries keep their `first_seen`; changed state/service/version
    /// are overwritten and `last_seen` bumped. New entries are added with both
    /// timestamps set to now. Best-effort for the index; disk write failure is
    /// returned as an error (the caller decides whether to surface it).
    pub fn observe(
        &mut self,
        host: &str,
        source_tool: &str,
        observations: &[ServiceObservation],
        technologies: &[String],
    ) -> Result<(), String> {
        sanitize_host(host)?;
        let now = Utc::now();
        let path = self.record_path(host);

        // Load existing record (or start fresh), merge, write back.
        let mut record: HostRecord = fs::read_to_string(&path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        let fresh = record.host.is_empty();
        record.host = host.to_string();
        record.first_seen = if fresh { now } else { record.first_seen };
        record.last_seen = now;

        for obs in observations {
            let key = format!("{}/{}", obs.proto, obs.port);
            let entry = record.services.entry(key).or_insert_with(|| ServiceRecord {
                port: obs.port,
                proto: obs.proto.clone(),
                state: obs.state.clone(),
                service: obs.service.clone(),
                version: obs.version.clone(),
                source_tool: source_tool.to_string(),
                first_seen: now,
                last_seen: now,
            });
            entry.state = obs.state.clone();
            entry.service = obs.service.clone();
            entry.version = obs.version.clone();
            entry.source_tool = source_tool.to_string();
            entry.last_seen = now;
        }
        for tech in technologies {
            if !record.technologies.iter().any(|t| t == tech) {
                record.technologies.push(tech.clone());
            }
        }

        // Atomic write via temp file + rename (same pattern as FindingStore).
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
        fs::write(&tmp, json).map_err(|e| format!("disk write failed: {e}"))?;
        fs::rename(&tmp, &path).map_err(|e| format!("disk rename failed: {e}"))?;

        self.index.insert(
            host.to_string(),
            HostSummary {
                host: host.to_string(),
                open_ports: record.open_port_count(),
                total_services: record.services.len(),
                last_seen: record.last_seen,
            },
        );
        Ok(())
    }

    /// Load the full record for a host. `None` if unknown (or unreadable).
    pub fn get(&self, host: &str) -> Option<HostRecord> {
        sanitize_host(host).ok()?;
        if !self.index.contains_key(host) {
            return None;
        }
        fs::read_to_string(self.record_path(host))
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
    }

    /// Summaries for every known host, sorted by name (deterministic order).
    pub fn list(&self) -> Vec<HostSummary> {
        let mut out: Vec<HostSummary> = self.index.values().cloned().collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (TargetStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = TargetStore::new(dir.path().to_path_buf()).unwrap();
        (s, dir)
    }

    fn obs(port: u16, service: &str, version: &str) -> ServiceObservation {
        ServiceObservation {
            port,
            proto: "tcp".into(),
            state: "open".into(),
            service: service.into(),
            version: version.into(),
        }
    }

    #[test]
    fn observe_creates_and_reload_survives_restart() {
        let (mut s, dir) = store();
        s.observe(
            "10.0.0.1",
            "nmap",
            &[obs(22, "ssh", "OpenSSH 8.9"), obs(80, "http", "nginx")],
            &[],
        )
        .unwrap();
        assert_eq!(s.list().len(), 1);
        assert_eq!(s.list()[0].open_ports, 2);

        // Reopen from the same dir - the record persists.
        let s2 = TargetStore::new(dir.path().to_path_buf()).unwrap();
        let rec = s2.get("10.0.0.1").unwrap();
        assert_eq!(rec.services.len(), 2);
        assert_eq!(rec.services["tcp/22"].version, "OpenSSH 8.9");
    }

    #[test]
    fn observe_merges_across_scans_keeping_first_seen() {
        let (mut s, _dir) = store();
        s.observe("10.0.0.1", "nmap", &[obs(22, "ssh", "OpenSSH 8.9")], &[])
            .unwrap();
        let first = s.get("10.0.0.1").unwrap().services["tcp/22"].first_seen;

        // Later scan: version changed, one new port.
        s.observe(
            "10.0.0.1",
            "nmap",
            &[obs(22, "ssh", "OpenSSH 9.0"), obs(443, "https", "")],
            &["nginx".into()],
        )
        .unwrap();
        let rec = s.get("10.0.0.1").unwrap();
        assert_eq!(rec.services.len(), 2); // tcp/22 (merged) + tcp/443 (new)
        assert_eq!(rec.services["tcp/22"].version, "OpenSSH 9.0");
        assert_eq!(rec.services["tcp/22"].first_seen, first);
        assert!(rec.services["tcp/22"].last_seen >= first);
        assert_eq!(rec.technologies, vec!["nginx"]);
        assert_eq!(rec.open_port_count(), 2);
    }

    #[test]
    fn sanitize_rejects_traversal_and_odd_chars() {
        for host in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/b",
            "a\\b",
            "host;rm",
            "café.io",
            " ",
        ] {
            assert!(sanitize_host(host).is_err(), "should reject: {host:?}");
        }
        for host in ["10.0.0.1", "fe80::1", "web-01.example.com", "a_b.example"] {
            assert!(sanitize_host(host).is_ok(), "should accept: {host:?}");
        }
        assert!(sanitize_host(&"a".repeat(254)).is_err());
    }

    #[test]
    fn observe_rejects_unsafe_host_without_writing() {
        let (mut s, dir) = store();
        assert!(s.observe("../evil", "nmap", &[], &[]).is_err());
        // Nothing written anywhere.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(s.get("../evil").is_none());
    }

    #[test]
    fn get_unknown_host_is_none() {
        let (s, _dir) = store();
        assert!(s.get("10.0.0.99").is_none());
        assert!(s.list().is_empty());
    }

    #[test]
    fn list_is_sorted_deterministically() {
        let (mut s, _dir) = store();
        for h in ["10.0.0.2", "10.0.0.10", "10.0.0.1"] {
            s.observe(h, "nmap", &[obs(80, "http", "")], &[]).unwrap();
        }
        let hosts: Vec<String> = s.list().into_iter().map(|x| x.host).collect();
        assert_eq!(hosts, vec!["10.0.0.1", "10.0.0.10", "10.0.0.2"]);
    }

    #[test]
    fn ipv6_host_round_trips() {
        let (mut s, _dir) = store();
        s.observe("fe80::1", "nmap", &[obs(22, "ssh", "")], &[])
            .unwrap();
        assert!(s.get("fe80::1").is_some());
        assert_eq!(s.list()[0].host, "fe80::1");
    }
}
