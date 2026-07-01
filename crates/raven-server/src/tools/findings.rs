//! Finding management handlers (save, get, list, delete, report generation).
//!
//! These handlers bridge the MCP interface to [`FindingStore`] for persistence
//! and [`ReportFormat`](raven_report::report::ReportFormat) for report output
//! (markdown, JSON, SARIF, or HTML). The store is protected by `RwLock` - reads
//! (list, get) take a shared lock, writes (save, delete) take an exclusive lock.
//!
//! Reports are saved to disk in the active engagement's directory as
//! `report-{timestamp}.{ext}` (default store → `{output_dir}`) and a compact
//! summary is returned in the MCP response.

use raven_report::finding::{Finding, Severity};
use raven_report::report::ReportFormat;
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
    #[schemars(description = "OWASP Top 10 category (e.g. 'A03:2021 Injection')")]
    pub owasp_category: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Originating scan ID (UUID), if this finding came from a launched scan"
    )]
    pub scan_id: Option<String>,
}

/// MCP request schema for `get_finding` and `delete_finding`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingIdRequest {
    #[schemars(description = "Finding ID")]
    pub finding_id: String,
}

/// MCP request schema for `list_findings_by_scan`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListByScanRequest {
    #[schemars(description = "Scan ID (UUID) to list findings for")]
    pub scan_id: String,
}

/// MCP request schema for `generate_report`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateReportRequest {
    #[schemars(description = "Report title")]
    pub title: Option<String>,
    #[schemars(description = "Report format: 'markdown' (default), 'json', 'sarif', 'html'")]
    pub format: Option<String>,
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
            format!("invalid severity '{other}' - must be: critical, high, medium, low, info"),
            None,
        )),
    }
}

/// Build a success result carrying both human-readable text and a machine-readable
/// `structured_content` object, so clients can read fields instead of parsing prose.
/// `wrap_result` only mutates text content, so the structured payload passes through
/// uncapped.
pub(crate) fn success_with(
    text: impl Into<String>,
    structured: serde_json::Value,
) -> CallToolResult {
    let mut result = CallToolResult::success(vec![Content::text(text.into())]);
    result.structured_content = Some(structured);
    result
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
    finding.owasp_category = req.owasp_category;
    if let Some(scan_id) = req.scan_id {
        // Validate it parses as a UUID so the scan reverse-index stays consistent
        // with launched scan IDs. source stays Manual (the Finding::new default).
        uuid::Uuid::parse_str(&scan_id).map_err(|_| {
            rmcp::ErrorData::invalid_params(
                format!("invalid scan_id '{scan_id}' - must be a UUID"),
                None,
            )
        })?;
        finding.scan_id = Some(scan_id);
    }

    let id = store
        .write()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .insert(finding)
        .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;

    Ok(success_with(
        format!("Finding saved. ID: {id}"),
        serde_json::json!({ "finding_id": id }),
    ))
}

/// Retrieve a finding by ID, returning its full JSON representation.
pub fn get_finding(
    store: &RwLock<FindingStore>,
    req: FindingIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let (text, structured) = match store.get(&req.finding_id) {
        Some(f) => (
            serde_json::to_string_pretty(&f)
                .unwrap_or_else(|e| format!("serialisation error: {e}")),
            serde_json::json!({ "found": true, "finding": f }),
        ),
        None => (
            "finding not found".to_string(),
            serde_json::json!({ "found": false }),
        ),
    };

    Ok(success_with(text, structured))
}

/// List all findings as `ID | [Severity] Title`, sorted by severity.
pub fn list_findings(store: &RwLock<FindingStore>) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let findings = store.list();
    if findings.is_empty() {
        return Ok(success_with(
            "no findings",
            serde_json::json!({ "findings": [] }),
        ));
    }

    let lines: Vec<String> = findings
        .iter()
        .map(|f| format!("{} | [{}] {}", f.id, f.severity, f.title))
        .collect();

    Ok(success_with(
        lines.join("\n"),
        serde_json::json!({ "findings": findings }),
    ))
}

/// List findings produced by a given scan, sorted by severity.
///
/// Mirrors [`list_findings`] but scopes the results to one scan via
/// [`FindingStore::list_by_scan`]. The `scan_id` must be a UUID.
pub fn list_findings_by_scan(
    store: &RwLock<FindingStore>,
    req: ListByScanRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    uuid::Uuid::parse_str(&req.scan_id).map_err(|_| {
        rmcp::ErrorData::invalid_params(
            format!("invalid scan_id '{}' - must be a UUID", req.scan_id),
            None,
        )
    })?;

    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let findings = store.list_by_scan(&req.scan_id);
    if findings.is_empty() {
        return Ok(success_with(
            "no findings for scan",
            serde_json::json!({ "scan_id": req.scan_id, "findings": [] }),
        ));
    }

    let lines: Vec<String> = findings
        .iter()
        .map(|f| format!("{} | [{}] {}", f.id, f.severity, f.title))
        .collect();

    Ok(success_with(
        lines.join("\n"),
        serde_json::json!({ "scan_id": req.scan_id, "findings": findings }),
    ))
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
    Ok(success_with(
        text,
        serde_json::json!({ "deleted": deleted, "finding_id": req.finding_id }),
    ))
}

/// Generate a report from all stored findings and save it to disk.
///
/// The output format is chosen via `req.format` (`markdown` default, plus
/// `json`, `sarif`, `html`) and the file is persisted to the active engagement's
/// directory as `report-{timestamp}.{ext}`. On disk-write failure the markdown
/// body is still returned (legacy behavior); the other formats return an
/// internal error rather than dumping a large body into the response.
pub fn generate_report(
    store: &RwLock<FindingStore>,
    req: GenerateReportRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let format = match req.format.as_deref() {
        None => ReportFormat::default(),
        Some(s) => ReportFormat::parse(s).ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!("invalid format '{s}' - must be: markdown, json, sarif, html"),
                None,
            )
        })?,
    };

    let store = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let all = store.load_all();
    let refs: Vec<&Finding> = all.iter().collect();
    let title = req.title.as_deref().unwrap_or("Penetration Test Report");
    let report = format.render(&refs, title);

    // Persist to disk alongside findings
    let date = chrono::Local::now().format("%Y-%m-%d_%H%M%S");
    let filename = format!("report-{date}.{}", format.extension());
    // Write into the active engagement's directory (default store -> output_dir).
    let path = store.base_dir().join(&filename);

    if let Err(e) = std::fs::write(&path, &report) {
        tracing::warn!("failed to write report: {e}");
        // Markdown keeps the legacy behavior of returning the body so the
        // operator still receives the report; other formats can be large and
        // machine-oriented, so surface an error instead.
        return match format {
            ReportFormat::Markdown => Ok(CallToolResult::success(vec![Content::text(report)])),
            _ => Err(rmcp::ErrorData::internal_error(
                format!("failed to write report to {}: {e}", path.display()),
                None,
            )),
        };
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
    Ok(success_with(
        output,
        serde_json::json!({
            "path": path.display().to_string(),
            "total": refs.len(),
            "counts": severity_counts,
        }),
    ))
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
