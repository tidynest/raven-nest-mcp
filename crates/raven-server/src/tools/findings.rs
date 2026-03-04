use raven_report::finding::{Finding, Severity};
use raven_report::markdown;
use raven_report::store::FindingStore;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::sync::Mutex;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FindingIdRequest {
    #[schemars(description = "Finding ID")]
    pub finding_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GenerateReportRequest {
    #[schemars(description = "Report title")]
    pub title: Option<String>,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn save_finding(
    store: &Mutex<FindingStore>,
    req: SaveFindingRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let severity = parse_severity(&req.severity);
    let mut finding = Finding::new(req.title, severity, req.description, req.target, req.tool);
    finding.evidence = req.evidence;
    finding.remediation = req.remediation;
    finding.cvss = req.cvss;
    finding.cve = req.cve;

    let id = store
        .lock()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .insert(finding)
        .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;

    Ok(CallToolResult::success(vec![Content::text(format!(
        "Finding saved. ID: {id}"
    ))]))
}

pub fn get_finding(
    store: &Mutex<FindingStore>,
    req: FindingIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .lock()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let text = match store.get(&req.finding_id) {
        Some(f) => {
            serde_json::to_string_pretty(&f).unwrap_or_else(|e| format!("serialisation error: {e}"))
        }
        None => "finding not found".into(),
    };

    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub fn list_findings(store: &Mutex<FindingStore>) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .lock()
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

pub fn delete_finding(
    store: &Mutex<FindingStore>,
    req: FindingIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let deleted = store
        .lock()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .delete(&req.finding_id);

    let text = if deleted {
        "finding deleted"
    } else {
        "finding not found"
    };
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub fn generate_report(
    store: &Mutex<FindingStore>,
    config: &raven_core::config::RavenConfig,
    req: GenerateReportRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let store = store
        .lock()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?;

    let all = store.load_all();
    let refs: Vec<&raven_report::finding::Finding> = all.iter().collect();
    let title = req.title.as_deref().unwrap_or("Penetration Test Report");
    let report = markdown::generate_report(&refs, title);

    // Save to disk
    let date = chrono::Local::now().format("%Y-%m-%d_%H%M%S");
    let filename = format!("report-{date}.md");
    let path = std::path::Path::new(&config.execution.output_dir).join(&filename);

    if let Err(e) = std::fs::write(&path, &report) {
        tracing::warn!("failed to write report: {e}");
        return Ok(CallToolResult::success(vec![Content::text(report)]));
    }

    let output = format!("Report saved to: {}\n\n{report}", path.display());
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
