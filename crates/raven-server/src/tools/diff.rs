//! Scan diffing - compare two completed nmap scans of the same target set.
//!
//! Given two stored scan outputs (A = baseline, B = after), reports:
//! - hosts that appeared / disappeared,
//! - per common host: ports that appeared / disappeared, and ports whose
//!   state, service, or version changed (e.g. an upgrade or a closure).
//!
//! Only nmap output is diffable today - it is the one background-scannable
//! tool with a structured parser. The comparison itself is a pure function
//! ([`diff_nmap_scans`]) over the structured parse, so it is unit-testable
//! without touching the scan manager.

use crate::tools::nmap::{NmapHost, NmapPort, NmapScan};
use raven_core::scan_manager::ScanManager;
use rmcp::{model::CallToolResult, schemars};
use std::collections::BTreeMap;

/// MCP request schema for `diff_scans`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffScansRequest {
    #[schemars(description = "Baseline scan ID (the 'before' scan)")]
    pub scan_id_a: String,
    #[schemars(description = "Comparison scan ID (the 'after' scan)")]
    pub scan_id_b: String,
}

/// One changed port: before/after service descriptions.
#[derive(Debug, serde::Serialize, PartialEq)]
pub struct PortChange {
    pub port: String,
    pub before: String,
    pub after: String,
}

/// Differences for one host present in both scans.
#[derive(Debug, serde::Serialize)]
pub struct HostDiff {
    pub host: String,
    pub ports_added: Vec<String>,
    pub ports_removed: Vec<String>,
    pub changed: Vec<PortChange>,
}

/// Full diff result between two nmap scans.
#[derive(Debug, Default, serde::Serialize)]
pub struct ScanDiff {
    pub hosts_added: Vec<String>,
    pub hosts_removed: Vec<String>,
    pub hosts: Vec<HostDiff>,
}

/// Human-readable one-line description of a port entry.
fn describe_port(p: &NmapPort) -> String {
    let svc = [p.service.as_str(), p.version.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    if svc.is_empty() {
        p.state.clone()
    } else {
        format!("{} ({svc})", p.state)
    }
}

fn port_key(p: &NmapPort) -> String {
    format!("{}/{}", p.proto, p.port)
}

/// Pure comparison of two structured nmap scans. A = before, B = after.
pub fn diff_nmap_scans(a: &NmapScan, b: &NmapScan) -> ScanDiff {
    let a_hosts: BTreeMap<&str, &NmapHost> = a.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();
    let b_hosts: BTreeMap<&str, &NmapHost> = b.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();

    let hosts_added: Vec<String> = b_hosts
        .keys()
        .filter(|ip| !a_hosts.contains_key(*ip))
        .map(|ip| ip.to_string())
        .collect();
    let hosts_removed: Vec<String> = a_hosts
        .keys()
        .filter(|ip| !b_hosts.contains_key(*ip))
        .map(|ip| ip.to_string())
        .collect();
    let mut hosts = Vec::new();

    for (ip, ha) in &a_hosts {
        let Some(hb) = b_hosts.get(ip) else { continue };
        let a_ports: BTreeMap<String, &NmapPort> =
            ha.ports.iter().map(|p| (port_key(p), p)).collect();
        let b_ports: BTreeMap<String, &NmapPort> =
            hb.ports.iter().map(|p| (port_key(p), p)).collect();

        let mut hd = HostDiff {
            host: (*ip).to_string(),
            ports_added: b_ports
                .keys()
                .filter(|k| !a_ports.contains_key(*k))
                .cloned()
                .collect(),
            ports_removed: a_ports
                .keys()
                .filter(|k| !b_ports.contains_key(*k))
                .cloned()
                .collect(),
            changed: Vec::new(),
        };
        for (key, pa) in &a_ports {
            if let Some(pb) = b_ports.get(key)
                && (&pa.state, &pa.service, &pa.version) != (&pb.state, &pb.service, &pb.version)
            {
                hd.changed.push(PortChange {
                    port: key.clone(),
                    before: describe_port(pa),
                    after: describe_port(pb),
                });
            }
        }
        if !hd.ports_added.is_empty() || !hd.ports_removed.is_empty() || !hd.changed.is_empty() {
            hosts.push(hd);
        }
    }
    ScanDiff {
        hosts_added,
        hosts_removed,
        hosts,
    }
}

/// Render a [`ScanDiff`] as human-readable text (empty string when identical).
fn render_diff(diff: &ScanDiff) -> String {
    let mut out = String::new();
    if !diff.hosts_added.is_empty() {
        out.push_str(&format!("Hosts added: {}\n", diff.hosts_added.join(", ")));
    }
    if !diff.hosts_removed.is_empty() {
        out.push_str(&format!(
            "Hosts removed: {}\n",
            diff.hosts_removed.join(", ")
        ));
    }
    for h in &diff.hosts {
        out.push_str(&format!("\n── {} ──\n", h.host));
        if !h.ports_added.is_empty() {
            out.push_str(&format!("  + ports: {}\n", h.ports_added.join(", ")));
        }
        if !h.ports_removed.is_empty() {
            out.push_str(&format!("  - ports: {}\n", h.ports_removed.join(", ")));
        }
        for c in &h.changed {
            out.push_str(&format!("  ~ {}: {} → {}\n", c.port, c.before, c.after));
        }
    }
    out
}

/// Load one scan's output and parse it as nmap XML.
fn load_nmap_scan(manager: &ScanManager, id: &str) -> Result<NmapScan, rmcp::ErrorData> {
    let output = manager
        .output(id)
        .map_err(crate::error::to_mcp)?
        .ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!(
                    "scan {id} not found or still running - diff_scans needs two completed scans"
                ),
                None,
            )
        })?;
    crate::tools::nmap::parse_nmap_xml_structured(&output).ok_or_else(|| {
        rmcp::ErrorData::invalid_params(
            format!(
                "scan {id} output is not parseable nmap XML - diff_scans compares nmap scans \
                 (launch them via launch_scan with tool 'nmap' or run_nmap)"
            ),
            None,
        )
    })
}

/// Compare two completed nmap scans: added/removed hosts and ports, and
/// per-port state/service/version changes.
pub fn diff_scans(
    manager: &ScanManager,
    req: DiffScansRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let scan_a = load_nmap_scan(manager, &req.scan_id_a)?;
    let scan_b = load_nmap_scan(manager, &req.scan_id_b)?;

    let diff = diff_nmap_scans(&scan_a, &scan_b);
    let text = if render_diff(&diff).is_empty() {
        "No differences between the two scans.".to_string()
    } else {
        render_diff(&diff)
    };
    let structured = serde_json::to_value(&diff)
        .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
    Ok(crate::tools::findings::success_with(text, structured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::nmap::{NmapCve, NmapStats};

    fn port(proto: &str, num: u16, state: &str, service: &str, version: &str) -> NmapPort {
        NmapPort {
            proto: proto.into(),
            port: num,
            state: state.into(),
            service: service.into(),
            version: version.into(),
            cves: Vec::<NmapCve>::new(),
        }
    }

    fn host(ip: &str, ports: Vec<NmapPort>) -> NmapHost {
        NmapHost {
            ip: ip.into(),
            status: "up".into(),
            hostnames: Vec::new(),
            os: Vec::new(),
            ports,
        }
    }

    fn scan(hosts: Vec<NmapHost>) -> NmapScan {
        NmapScan {
            args: None,
            hosts,
            stats: Some(NmapStats {
                elapsed_secs: None,
                hosts_up: None,
                hosts_down: None,
            }),
        }
    }

    #[test]
    fn diff_detects_added_removed_hosts_and_ports() {
        let a = scan(vec![
            host(
                "10.0.0.1",
                vec![
                    port("tcp", 22, "open", "ssh", ""),
                    port("tcp", 80, "open", "http", "nginx 1.18"),
                ],
            ),
            host("10.0.0.2", vec![port("tcp", 443, "open", "https", "")]),
        ]);
        let b = scan(vec![
            host(
                "10.0.0.1",
                vec![
                    port("tcp", 22, "open", "ssh", ""),
                    port("tcp", 8080, "open", "http-proxy", ""),
                ],
            ),
            host("10.0.0.3", vec![port("tcp", 22, "open", "ssh", "")]),
        ]);

        let d = diff_nmap_scans(&a, &b);
        assert_eq!(d.hosts_added, vec!["10.0.0.3"]);
        assert_eq!(d.hosts_removed, vec!["10.0.0.2"]);

        let h1 = d.hosts.iter().find(|h| h.host == "10.0.0.1").unwrap();
        assert_eq!(h1.ports_added, vec!["tcp/8080"]);
        assert_eq!(h1.ports_removed, vec!["tcp/80"]);
        assert!(h1.changed.is_empty());

        let text = render_diff(&d);
        assert!(text.contains("Hosts added: 10.0.0.3"));
        assert!(text.contains("Hosts removed: 10.0.0.2"));
        assert!(text.contains("+ ports: tcp/8080"));
        assert!(text.contains("- ports: tcp/80"));
    }

    #[test]
    fn diff_detects_service_and_state_changes() {
        let a = scan(vec![host(
            "10.0.0.1",
            vec![
                port("tcp", 22, "open", "ssh", "OpenSSH 8.9"),
                port("tcp", 3306, "open", "mysql", "MySQL 8.0"),
            ],
        )]);
        let b = scan(vec![host(
            "10.0.0.1",
            vec![
                port("tcp", 22, "open", "ssh", "OpenSSH 9.0"),
                port("tcp", 3306, "closed", "mysql", "MySQL 8.0"),
            ],
        )]);

        let d = diff_nmap_scans(&a, &b);
        assert_eq!(d.hosts.len(), 1);
        let changes = &d.hosts[0].changed;
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].port, "tcp/22");
        assert_eq!(changes[0].before, "open (ssh OpenSSH 8.9)");
        assert_eq!(changes[0].after, "open (ssh OpenSSH 9.0)");
        assert_eq!(changes[1].port, "tcp/3306");
        assert_eq!(changes[1].before, "open (mysql MySQL 8.0)");
        assert_eq!(changes[1].after, "closed (mysql MySQL 8.0)");

        let text = render_diff(&d);
        assert!(text.contains("~ tcp/22: open (ssh OpenSSH 8.9) → open (ssh OpenSSH 9.0)"));
    }

    #[test]
    fn diff_identical_scans_is_empty() {
        let a = scan(vec![host(
            "10.0.0.1",
            vec![port("tcp", 80, "open", "http", "nginx")],
        )]);
        let b = scan(vec![host(
            "10.0.0.1",
            vec![port("tcp", 80, "open", "http", "nginx")],
        )]);
        let d = diff_nmap_scans(&a, &b);
        assert!(render_diff(&d).is_empty());
        assert!(d.hosts.is_empty());
    }

    #[test]
    fn diff_serialises_to_json() {
        let a = scan(vec![host(
            "10.0.0.1",
            vec![port("tcp", 80, "open", "http", "")],
        )]);
        let b = scan(vec![host("10.0.0.1", vec![])]);
        let value = serde_json::to_value(diff_nmap_scans(&a, &b)).unwrap();
        assert_eq!(value["hosts"][0]["ports_removed"][0], "tcp/80");
    }
}
