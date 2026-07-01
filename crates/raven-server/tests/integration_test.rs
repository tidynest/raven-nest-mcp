//! Integration tests for the findings management pipeline.
//!
//! Tests the full path from MCP handler → FindingStore → disk, verifying:
//! - Save and retrieve round-trips.
//! - Optional fields (CVSS, CVE, evidence, remediation).
//! - Severity-sorted listing.
//! - Delete (existing and nonexistent).
//! - Report generation with default and custom titles.
//!
//! These tests use a temporary directory so each test gets an isolated store.

use raven_report::store::FindingStore;
use raven_server::tools::findings::{FindingIdRequest, GenerateReportRequest, SaveFindingRequest};
use rmcp::model::Content;
use std::sync::RwLock;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────

/// Create an isolated FindingStore backed by a temp directory.
fn test_store() -> (RwLock<FindingStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    // Root the store at <dir>/findings (matching production layout) so the
    // store's base_dir() - where reports are written - is <dir>.
    let store = FindingStore::new(dir.path().join("findings")).unwrap();
    (RwLock::new(store), dir)
}

/// Build a minimal SaveFindingRequest with only required fields.
fn save_req(title: &str, severity: &str) -> SaveFindingRequest {
    SaveFindingRequest {
        title: title.into(),
        severity: severity.into(),
        description: "test description".into(),
        target: "192.168.1.1".into(),
        tool: "nmap".into(),
        evidence: None,
        remediation: None,
        cvss: None,
        cve: None,
        owasp_category: None,
        scan_id: None,
    }
}

/// Extract the text content from an MCP CallToolResult.
fn extract_text(content: &[Content]) -> String {
    content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("expected text content")
}

// ── Tests ────────────────────────────────────────────────────

#[test]
fn save_and_retrieve_finding() {
    let (store, _dir) = test_store();
    let result = raven_server::tools::findings::save_finding(&store, save_req("XSS", "high"));
    let text = extract_text(&result.unwrap().content);
    assert!(text.starts_with("Finding saved. ID:"));

    let id = text.trim_start_matches("Finding saved. ID: ");
    let get_result = raven_server::tools::findings::get_finding(
        &store,
        FindingIdRequest {
            finding_id: id.into(),
        },
    )
    .unwrap();
    let get_text = extract_text(&get_result.content);
    assert!(get_text.contains("XSS"));
    assert!(get_text.contains("High"));
}

#[test]
fn save_finding_with_optional_fields() {
    let (store, _dir) = test_store();
    let mut req = save_req("SQLi", "critical");
    req.cvss = Some(9.8);
    req.cve = Some("CVE-2024-1234".into());
    req.evidence = Some("error in query".into());
    req.remediation = Some("parameterized queries".into());

    let result = raven_server::tools::findings::save_finding(&store, req);
    let text = extract_text(&result.unwrap().content);
    let id = text.trim_start_matches("Finding saved. ID: ");

    let get_result = raven_server::tools::findings::get_finding(
        &store,
        FindingIdRequest {
            finding_id: id.into(),
        },
    )
    .unwrap();
    let get_text = extract_text(&get_result.content);
    assert!(get_text.contains("CVE-2024-1234"));
    assert!(get_text.contains("9.8"));
    assert!(get_text.contains("error in query"));
}

#[test]
fn list_findings_empty() {
    let (store, _dir) = test_store();
    let result = raven_server::tools::findings::list_findings(&store).unwrap();
    let text = extract_text(&result.content);
    assert_eq!(text, "no findings");
}

#[test]
fn list_findings_returns_sorted() {
    let (store, _dir) = test_store();
    raven_server::tools::findings::save_finding(&store, save_req("Low one", "low")).unwrap();
    raven_server::tools::findings::save_finding(&store, save_req("Critical one", "critical"))
        .unwrap();
    raven_server::tools::findings::save_finding(&store, save_req("High one", "high")).unwrap();

    let result = raven_server::tools::findings::list_findings(&store).unwrap();
    let text = extract_text(&result.content);
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("Critical"));
    assert!(lines[1].contains("High"));
    assert!(lines[2].contains("Low"));
}

#[test]
fn delete_existing_finding() {
    let (store, _dir) = test_store();
    let result =
        raven_server::tools::findings::save_finding(&store, save_req("To delete", "info")).unwrap();
    let text = extract_text(&result.content);
    let id = text.trim_start_matches("Finding saved. ID: ");

    let del_result = raven_server::tools::findings::delete_finding(
        &store,
        FindingIdRequest {
            finding_id: id.into(),
        },
    )
    .unwrap();
    assert_eq!(extract_text(&del_result.content), "finding deleted");
}

#[test]
fn delete_nonexistent_finding() {
    let (store, _dir) = test_store();
    let result = raven_server::tools::findings::delete_finding(
        &store,
        FindingIdRequest {
            finding_id: "nonexistent-id".into(),
        },
    )
    .unwrap();
    assert_eq!(extract_text(&result.content), "finding not found");
}

#[test]
fn generate_report_produces_markdown() {
    let (store, _dir) = test_store();
    raven_server::tools::findings::save_finding(&store, save_req("XSS", "high")).unwrap();

    let result = raven_server::tools::findings::generate_report(
        &store,
        GenerateReportRequest {
            title: Some("Test Report".into()),
            format: None,
        },
    )
    .unwrap();
    let text = extract_text(&result.content);
    assert!(text.contains("Report saved to:"));
    assert!(text.contains("1 finding(s)"));
    assert!(text.contains("1 high"));
}

#[test]
fn generate_report_uses_default_title() {
    let (store, _dir) = test_store();

    let result = raven_server::tools::findings::generate_report(
        &store,
        GenerateReportRequest {
            title: None,
            format: None,
        },
    )
    .unwrap();
    let text = extract_text(&result.content);
    assert!(text.contains("Report saved to:"));
    assert!(text.contains("0 finding(s)"));
}

#[test]
fn generate_report_writes_each_format_with_correct_extension() {
    for (fmt, ext) in [("json", "json"), ("sarif", "sarif"), ("html", "html")] {
        let (store, dir) = test_store();
        raven_server::tools::findings::save_finding(&store, save_req("XSS", "high")).unwrap();

        let result = raven_server::tools::findings::generate_report(
            &store,
            GenerateReportRequest {
                title: Some("Fmt".into()),
                format: Some(fmt.into()),
            },
        )
        .unwrap();
        let text = extract_text(&result.content);
        assert!(text.contains("Report saved to:"), "format {fmt}");

        // A file with the expected extension must have been written.
        let written = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().is_some_and(|x| x == ext));
        assert!(written, "expected a .{ext} report for format {fmt}");
    }
}

#[test]
fn generate_report_rejects_invalid_format() {
    let (store, _dir) = test_store();

    let err = raven_server::tools::findings::generate_report(
        &store,
        GenerateReportRequest {
            title: None,
            format: Some("pdf".into()),
        },
    )
    .unwrap_err();
    assert!(err.message.contains("invalid format"));
}
