//! MCP resource exposure.
//!
//! Surfaces the server's readable data model - saved findings, generated
//! reports, and background scans - as `raven://` resources so a client can
//! browse or attach them directly instead of round-tripping through a tool
//! call. Complements the tool interface; nothing here mutates state.
//!
//! URIs:
//! - `raven://findings` - JSON index of all findings
//! - `raven://findings/{id}` - one finding as JSON
//! - `raven://reports/{markdown|json|sarif|html}` - a rendered report
//! - `raven://scans` - JSON index of background scans
//! - `raven://scans/{id}` - a scan's captured output

use raven_core::scan_manager::ScanManager;
use raven_report::report::ReportFormat;
use raven_report::store::FindingStore;
use rmcp::model::{
    AnnotateAble, ListResourcesResult, RawResource, ReadResourceResult, Resource, ResourceContents,
};
use std::sync::RwLock;

/// (name, mime type) for each report format exposed under `raven://reports/`.
const REPORT_FORMATS: [(&str, &str); 4] = [
    ("markdown", "text/markdown"),
    ("json", "application/json"),
    ("sarif", "application/sarif+json"),
    ("html", "text/html"),
];

fn resource(uri: impl Into<String>, name: impl Into<String>, desc: &str, mime: &str) -> Resource {
    RawResource::new(uri, name)
        .with_description(desc)
        .with_mime_type(mime)
        .no_annotation()
}

fn not_found(uri: &str) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(format!("no such resource: {uri}"), None)
}

fn poisoned() -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error("finding store lock poisoned", None)
}

fn json_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Enumerate the collections, the four report formats, and one resource per
/// saved finding and tracked scan.
pub fn list(store: &RwLock<FindingStore>, scans: &ScanManager) -> ListResourcesResult {
    let mut resources = vec![
        resource(
            "raven://findings",
            "All findings",
            "JSON index of every saved finding",
            "application/json",
        ),
        resource(
            "raven://scans",
            "All scans",
            "JSON index of background scans",
            "application/json",
        ),
    ];
    for (fmt, mime) in REPORT_FORMATS {
        resources.push(resource(
            format!("raven://reports/{fmt}"),
            format!("Report ({fmt})"),
            "Generated report of all current findings",
            mime,
        ));
    }
    if let Ok(s) = store.read() {
        for m in s.list() {
            resources.push(resource(
                format!("raven://findings/{}", m.id),
                format!("[{}] {}", m.severity, m.title),
                &format!("Finding on {} via {}", m.target, m.tool),
                "application/json",
            ));
        }
    }
    if let Ok(infos) = scans.list() {
        for i in infos {
            resources.push(resource(
                format!("raven://scans/{}", i.id),
                format!("scan: {} {}", i.tool, i.target),
                &format!("{:?}", i.status),
                "text/plain",
            ));
        }
    }
    ListResourcesResult {
        resources,
        ..Default::default()
    }
}

/// Resolve a `raven://` URI to its contents.
pub fn read(
    uri: &str,
    store: &RwLock<FindingStore>,
    scans: &ScanManager,
) -> Result<ReadResourceResult, rmcp::ErrorData> {
    let body = uri.strip_prefix("raven://").ok_or_else(|| not_found(uri))?;

    let text = match body.split_once('/') {
        None if body == "findings" => {
            let s = store.read().map_err(|_| poisoned())?;
            let items: Vec<_> = s
                .list()
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.id,
                        "title": m.title,
                        "severity": m.severity.to_string(),
                        "target": m.target,
                        "tool": m.tool,
                    })
                })
                .collect();
            json_string(&items)
        }
        None if body == "scans" => {
            let items: Vec<_> = scans
                .list()
                .map_err(crate::error::to_mcp)?
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "id": i.id,
                        "tool": i.tool,
                        "target": i.target,
                        "status": format!("{:?}", i.status),
                        "elapsed_secs": i.elapsed_secs,
                        "output_chars": i.output_chars,
                    })
                })
                .collect();
            json_string(&items)
        }
        Some(("findings", id)) => {
            let s = store.read().map_err(|_| poisoned())?;
            let f = s.get(id).ok_or_else(|| not_found(uri))?;
            json_string(&f)
        }
        Some(("reports", fmt)) => {
            let format = ReportFormat::parse(fmt).ok_or_else(|| not_found(uri))?;
            let s = store.read().map_err(|_| poisoned())?;
            let findings = s.load_all();
            let refs: Vec<&raven_report::finding::Finding> = findings.iter().collect();
            format.render(&refs, "Raven Nest Report")
        }
        Some(("scans", id)) => scans
            .output(id)
            .map_err(crate::error::to_mcp)?
            .ok_or_else(|| not_found(uri))?,
        _ => return Err(not_found(uri)),
    };

    Ok(ReadResourceResult::new(vec![ResourceContents::text(
        text, uri,
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_report::finding::{Finding, Severity};
    use std::sync::Arc;

    fn setup() -> (RwLock<FindingStore>, ScanManager, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FindingStore::new(dir.path().join("findings")).unwrap();
        let id = store
            .insert(Finding::new(
                "Reflected XSS".into(),
                Severity::High,
                "desc".into(),
                "app.example.com".into(),
                "nuclei".into(),
            ))
            .unwrap();
        let scans = ScanManager::new(Arc::new(raven_core::config::RavenConfig::default()));
        (RwLock::new(store), scans, id, dir)
    }

    fn text_of(r: &ReadResourceResult) -> String {
        match &r.contents[0] {
            ResourceContents::TextResourceContents { text, .. } => text.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn list_exposes_collections_reports_and_each_finding() {
        let (store, scans, id, _dir) = setup();
        let uris: Vec<String> = list(&store, &scans)
            .resources
            .iter()
            .map(|r| r.uri.clone())
            .collect();
        assert!(uris.contains(&"raven://findings".to_string()));
        assert!(uris.contains(&"raven://reports/sarif".to_string()));
        assert!(uris.contains(&format!("raven://findings/{id}")));
    }

    #[test]
    fn read_dispatches_findings_report_and_rejects_unknown() {
        let (store, scans, id, _dir) = setup();

        let index = read("raven://findings", &store, &scans).unwrap();
        assert!(text_of(&index).contains("Reflected XSS"));

        let one = read(&format!("raven://findings/{id}"), &store, &scans).unwrap();
        assert!(text_of(&one).contains("app.example.com"));

        let report = read("raven://reports/markdown", &store, &scans).unwrap();
        assert!(text_of(&report).contains("# Raven Nest Report"));

        // Unknown format, unknown collection, and non-raven scheme all rejected.
        assert!(read("raven://reports/pdf", &store, &scans).is_err());
        assert!(read("raven://nope", &store, &scans).is_err());
        assert!(read("http://evil", &store, &scans).is_err());
    }
}
