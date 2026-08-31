//! Target discovery tracking handlers - browse what scans learned about hosts.
//!
//! The [`TargetStore`](raven_report::targets::TargetStore) is fed from the nmap
//! structured parser (both the `run_nmap` handler and completed background
//! nmap scans, via [`record_completed_nmap`]). These handlers expose it:
//! `list_targets` summarises every tracked host, `get_target_info` returns the
//! full per-host record (ports, services, versions, technologies, timestamps).
//!
//! All read-only; scoped to the active engagement like the findings store.

use crate::tools::nmap::NmapScan;
use raven_core::scan_manager::{ScanManager, ScanStatus};
use raven_report::targets::{ServiceObservation, TargetStore};
use rmcp::{model::CallToolResult, schemars};
use std::collections::HashSet;
use std::sync::{Mutex, RwLock};

/// MCP request schema for `get_target_info`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetInfoRequest {
    #[schemars(description = "Host IP or hostname (as reported by the scanner)")]
    pub host: String,
}

/// Merge a parsed nmap scan into the target store. Best-effort: per-host
/// failures are logged and never fail the tool response.
pub(crate) fn record_from_scan(targets: &RwLock<TargetStore>, scan: &NmapScan) {
    let Ok(mut store) = targets.write() else {
        tracing::warn!("target store lock poisoned - discovery data dropped");
        return;
    };
    for host in &scan.hosts {
        let observations: Vec<ServiceObservation> = host
            .ports
            .iter()
            .map(|p| ServiceObservation {
                port: p.port,
                proto: p.proto.clone(),
                state: p.state.clone(),
                service: p.service.clone(),
                version: p.version.clone(),
            })
            .collect();
        let technologies: Vec<String> = host.os.clone();
        if let Err(e) = store.observe(&host.ip, "nmap", &observations, &technologies) {
            tracing::warn!("target store update for {} failed: {e}", host.ip);
        }
    }
}

/// Feed a completed background nmap scan into the target store (once per scan).
///
/// Called from the `get_scan_status` handler: the first poll that observes a
/// completed nmap scan records its discovery data; `recorded` deduplicates
/// across repeated polls. After a server restart the set is empty and the scan
/// is re-recorded - the merge is idempotent apart from `last_seen` bumps.
pub(crate) fn record_completed_nmap(
    targets: &RwLock<TargetStore>,
    recorded: &Mutex<HashSet<String>>,
    manager: &ScanManager,
    scan_id: &str,
) {
    let Ok(info) = manager.status_enriched(scan_id) else {
        return;
    };
    let Some(info) = info else { return };
    if info.tool != "nmap" || info.status != ScanStatus::Completed {
        return;
    }
    let Ok(mut seen) = recorded.lock() else {
        return;
    };
    if !seen.insert(scan_id.to_string()) {
        return; // already recorded on an earlier poll
    }
    drop(seen);

    let output = match manager.output(scan_id) {
        Ok(Some(o)) => o,
        _ => return,
    };
    if let Some(scan) = crate::tools::nmap::parse_nmap_xml_structured(&output) {
        record_from_scan(targets, &scan);
    }
}

/// Full record for one tracked host: services with versions and timestamps,
/// technologies, first/last seen.
pub fn get_target_info(
    targets: &RwLock<TargetStore>,
    req: TargetInfoRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Reject malformed hosts up front with a clear error, using the same rule
    // the store keys on (the store sanitizes again before any filesystem use).
    raven_report::targets::sanitize_host(&req.host)
        .map_err(|e| rmcp::ErrorData::invalid_params(format!("invalid host: {e}"), None))?;

    let store = targets
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("target store lock poisoned", None))?;
    let Some(record) = store.get(&req.host) else {
        return Ok(crate::tools::findings::success_with(
            format!(
                "no discovery data for {} - run nmap (or launch a background nmap scan) against it first",
                req.host
            ),
            serde_json::json!({ "found": false, "host": req.host }),
        ));
    };

    let mut text = format!(
        "Host: {}\nFirst seen: {}\nLast seen: {}\n",
        record.host, record.first_seen, record.last_seen
    );
    if !record.technologies.is_empty() {
        text.push_str(&format!("OS guesses: {}\n", record.technologies.join(", ")));
    }
    if record.services.is_empty() {
        text.push_str("\nNo services recorded.\n");
    } else {
        text.push_str("\nPORT       STATE     SERVICE    VERSION\n");
        for svc in record.services.values() {
            text.push_str(&format!(
                "{}/{}  {:<9} {:<10} {}\n",
                svc.port, svc.proto, svc.state, svc.service, svc.version
            ));
        }
    }

    let structured = serde_json::to_value(&record)
        .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
    Ok(crate::tools::findings::success_with(
        text,
        serde_json::json!({ "found": true, "record": structured }),
    ))
}

/// One line per tracked host: name, open/total service counts, last seen.
pub fn list_targets(targets: &RwLock<TargetStore>) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = targets
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("target store lock poisoned", None))?;
    let summaries = store.list();
    if summaries.is_empty() {
        return Ok(crate::tools::findings::success_with(
            "no targets tracked yet - discovery data is recorded from nmap scans",
            serde_json::json!({ "targets": [] }),
        ));
    }

    let lines: Vec<String> = summaries
        .iter()
        .map(|s| {
            format!(
                "{} | {} open / {} tracked | last seen {}",
                s.host, s.open_ports, s.total_services, s.last_seen
            )
        })
        .collect();
    Ok(crate::tools::findings::success_with(
        lines.join("\n"),
        serde_json::json!({ "targets": summaries }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn store() -> (Arc<RwLock<TargetStore>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(RwLock::new(
            TargetStore::new(dir.path().to_path_buf()).unwrap(),
        ));
        (s, dir)
    }

    #[test]
    fn get_target_info_round_trips_record() {
        let (store, _dir) = store();
        store
            .write()
            .unwrap()
            .observe(
                "10.0.0.5",
                "nmap",
                &[ServiceObservation {
                    port: 22,
                    proto: "tcp".into(),
                    state: "open".into(),
                    service: "ssh".into(),
                    version: "OpenSSH 8.9".into(),
                }],
                &[],
            )
            .unwrap();

        let res = get_target_info(
            &store,
            TargetInfoRequest {
                host: "10.0.0.5".into(),
            },
        )
        .unwrap();
        let text = res.content.first().unwrap().as_text().unwrap().text.clone();
        assert!(text.contains("Host: 10.0.0.5"));
        assert!(text.contains("ssh"));
        assert!(text.contains("OpenSSH 8.9"));
        let structured = res.structured_content.unwrap();
        assert_eq!(structured["found"], true);
        assert_eq!(structured["record"]["host"], "10.0.0.5");
        assert_eq!(structured["record"]["services"]["tcp/22"]["port"], 22);
    }

    #[test]
    fn get_target_info_unknown_host_reports_not_found() {
        let (store, _dir) = store();
        let res = get_target_info(
            &store,
            TargetInfoRequest {
                host: "10.0.0.99".into(),
            },
        )
        .unwrap();
        assert!(res.structured_content.unwrap()["found"] == false);
    }

    #[test]
    fn get_target_info_rejects_malformed_host() {
        let (store, _dir) = store();
        let err = get_target_info(
            &store,
            TargetInfoRequest {
                host: "../etc/passwd".into(),
            },
        );
        assert!(err.is_err(), "path-like host must be rejected");
    }

    #[test]
    fn list_targets_empty_and_populated() {
        let (store, _dir) = store();
        let res = list_targets(&store).unwrap();
        assert!(
            res.content
                .first()
                .unwrap()
                .as_text()
                .unwrap()
                .text
                .contains("no targets")
        );

        store
            .write()
            .unwrap()
            .observe(
                "10.0.0.5",
                "nmap",
                &[ServiceObservation {
                    port: 80,
                    proto: "tcp".into(),
                    state: "open".into(),
                    service: "http".into(),
                    version: "".into(),
                }],
                &[],
            )
            .unwrap();
        let res = list_targets(&store).unwrap();
        let text = res.content.first().unwrap().as_text().unwrap().text.clone();
        assert!(text.contains("10.0.0.5 | 1 open / 1 tracked"));
        let structured = res.structured_content.unwrap();
        assert_eq!(structured["targets"].as_array().unwrap().len(), 1);
    }
}
