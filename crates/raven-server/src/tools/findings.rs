//! Finding management handlers (save, get, list, delete, report generation).
//!
//! These handlers bridge the MCP interface to [`FindingStore`] for persistence
//! and [`markdown::generate_report`](markdown::generate_report)
//! for report output. The store is protected by `RwLock` — reads (list, get)
//! take a shared lock, writes (save, delete) take an exclusive lock.
//!
//! Reports are both returned in the MCP response and saved to disk at
//! `{output_dir}/report-{timestamp}.md`.

use raven_report::finding::{Finding, Severity};
use raven_report::markdown;
use raven_report::store::FindingStore;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::RwLock;

/// MCP request schema for `save_finding`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveFindingRequest {
    #[schemars(description = "Finding title")]
    pub title: String,
    #[schemars(description = "Severity: 'critical', 'high', 'medium', 'low', 'info'")]
    pub severity: String,
    #[schemars(description = "Detailed description of the vulnerability")]
    pub description: String,
    #[schemars(description = "Affected target (IP, URL, hostname)")]
    pub target: String,
    #[schemars(description = "Tool that discovered this finding")]
    pub tool: String,
    #[schemars(description = "Evidence (e.g. raw output excerpt)")]
    pub evidence: Option<String>,
    #[schemars(description = "Suggested remediation")]
    pub remediation: Option<String>,
    #[schemars(description = "CVSS score (0.0-10.0)")]
    pub cvss: Option<f32>,
    #[schemars(description = "CVE identifier (e.g. CVE-2024-1234)")]
    pub cve: Option<String>,
}

/// MCP request schema for `get_finding` and `delete_finding`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingIdRequest {
    #[schemars(description = "Finding ID")]
    pub finding_id: String,
}

/// MCP request schema for `generate_report`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateReportRequest {
    #[schemars(description = "Report title")]
    pub title: Option<String>,
}

/// Parse a severity string (case-insensitive) into a [`Severity`] enum.
fn parse_severity(s: &str) -> Result<Severity, rmcp::ErrorData> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        other => Err(rmcp::ErrorData::invalid_params(
            format!("invalid severity '{other}' — must be: critical, high, medium, low, info"),
            None,
        )),
    }
}

/// Save a new finding to the store. Returns the generated finding ID.
pub fn save_finding(
    store: &RwLock<FindingStore>,
    req: SaveFindingRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let severity = parse_severity(&req.severity)?;
    let mut finding = Finding::new(req.title, severity, req.description, req.target, req.tool);
    finding.evidence = req.evidence;
    finding.remediation = req.remediation;
    finding.cvss = req.cvss;
    finding.cve = req.cve;

    let id = store
        .write()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .insert(finding)
        .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;

    Ok(CallToolResult::success(vec![Content::text(format!(
        "Finding saved. ID: {id}"
    ))]))
}

/// Retrieve a finding by ID, returning its full JSON representation.
pub fn get_finding(
    store: &RwLock<FindingStore>,
    req: FindingIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let text = match store.get(&req.finding_id) {
        Some(f) => {
            serde_json::to_string_pretty(&f).unwrap_or_else(|e| format!("serialisation error: {e}"))
        }
        None => "finding not found".into(),
    };

    Ok(CallToolResult::success(vec![Content::text(text)]))
}

/// List all findings as `ID | [Severity] Title`, sorted by severity.
pub fn list_findings(store: &RwLock<FindingStore>) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let findings = store.list();
    if findings.is_empty() {
        return Ok(CallToolResult::success(vec![Content::text("no findings")]));
    }

    let lines: Vec<String> = findings
        .iter()
        .map(|f| format!("{} | [{}] {}", f.id, f.severity, f.title))
        .collect();

    Ok(CallToolResult::success(vec![Content::text(
        lines.join("\n"),
    )]))
}

/// Delete a finding by ID from the store and disk.
pub fn delete_finding(
    store: &RwLock<FindingStore>,
    req: FindingIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let deleted = store
        .write()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .delete(&req.finding_id);

    let text = if deleted {
        "finding deleted"
    } else {
        "finding not found"
    };
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

/// Generate a Markdown report from all stored findings and save it to disk.
///
/// The report is both returned in the MCP response and persisted to
/// `{output_dir}/report-{timestamp}.md`. If disk write fails, the report
/// is still returned to the client.
pub fn generate_report(
    store: &RwLock<FindingStore>,
    config: &raven_core::config::RavenConfig,
    req: GenerateReportRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let all = store.load_all();
    let refs: Vec<&Finding> = all.iter().collect();
    let title = req.title.as_deref().unwrap_or("Penetration Test Report");
    let report = markdown::generate_report(&refs, title);

    // Persist to disk alongside findings
    let date = chrono::Local::now().format("%Y-%m-%d_%H%M%S");
    let filename = format!("report-{date}.md");
    let path = std::path::Path::new(&config.execution.output_dir).join(&filename);

    if let Err(e) = std::fs::write(&path, &report) {
        tracing::warn!("failed to write report: {e}");
        return Ok(CallToolResult::success(vec![Content::text(report)]));
    }

    // Return a compact summary instead of the full report to save context.
    // The full report is on disk for the operator to review.
    let mut severity_counts = std::collections::HashMap::<&str, usize>::new();
    for f in &refs {
        let sev = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        *severity_counts.entry(sev).or_default() += 1;
    }
    let breakdown: Vec<String> = ["critical", "high", "medium", "low", "info"]
        .iter()
        .filter_map(|s| severity_counts.get(s).map(|c| format!("{c} {s}")))
        .collect();

    let summary = if refs.is_empty() {
        "0 finding(s)".to_string()
    } else {
        format!("{} finding(s): {}", refs.len(), breakdown.join(", "))
    };
    let output = format!("Report saved to: {}\n{summary}", path.display());
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_severity_valid_values() {
        assert_eq!(parse_severity("critical").unwrap(), Severity::Critical);
        assert_eq!(parse_severity("high").unwrap(), Severity::High);
        assert_eq!(parse_severity("medium").unwrap(), Severity::Medium);
        assert_eq!(parse_severity("low").unwrap(), Severity::Low);
        assert_eq!(parse_severity("info").unwrap(), Severity::Info);
    }

    #[test]
    fn parse_severity_case_insensitive() {
        assert_eq!(parse_severity("CRITICAL").unwrap(), Severity::Critical);
        assert_eq!(parse_severity("High").unwrap(), Severity::High);
        assert_eq!(parse_severity("MeDiUm").unwrap(), Severity::Medium);
    }

    #[test]
    fn parse_severity_rejects_invalid() {
        assert!(parse_severity("urgent").is_err());
        assert!(parse_severity("").is_err());
        assert!(parse_severity("severe").is_err());
        assert!(parse_severity("1").is_err());
    }

    #[test]
    fn parse_severity_error_message() {
        let err = parse_severity("urgent").unwrap_err();
        assert!(err.message.contains("invalid severity"));
        assert!(err.message.contains("urgent"));
    }
}
