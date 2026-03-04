use raven_report::store::FindingStore;
use raven_server::tools::findings::{FindingIdRequest, GenerateReportRequest, SaveFindingRequest};
use rmcp::model::Content;
use std::sync::Mutex;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────

fn test_store() -> (Mutex<FindingStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = FindingStore::new(dir.path().to_path_buf());
    (Mutex::new(store), dir)
}

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
    }
}

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

    let mut config = raven_core::config::RavenConfig::default();
    config.execution.output_dir = _dir.path().to_str().unwrap().into();

    let result = raven_server::tools::findings::generate_report(
        &store,
        &config,
        GenerateReportRequest {
            title: Some("Test Report".into()),
        },
    )
    .unwrap();
    let text = extract_text(&result.content);
    assert!(text.contains("# Test Report"));
    assert!(text.contains("XSS"));
}

#[test]
fn generate_report_uses_default_title() {
    let (store, _dir) = test_store();

    let mut config = raven_core::config::RavenConfig::default();
    config.execution.output_dir = _dir.path().to_str().unwrap().into();

    let result = raven_server::tools::findings::generate_report(
        &store,
        &config,
        GenerateReportRequest { title: None },
    )
    .unwrap();
    let text = extract_text(&result.content);
    assert!(text.contains("# Penetration Test Report"));
}
