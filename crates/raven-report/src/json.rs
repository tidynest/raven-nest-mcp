//! JSON report generator for pentest findings.
//!
//! Produces a versioned envelope that wraps the summary, the deduplicated tool
//! list, and every [`Finding`](crate::finding::Finding) serialized in full.
//! Intended for machine consumption (dashboards, diffing, downstream tooling).
//!
//! Called by [`raven_server::tools::findings::generate_report`] when the
//! requested format is `json`.

use crate::finding::Finding;
use crate::summary::{count_by_severity, overall_risk, unique_tools};

/// Generate a versioned JSON report from a list of findings.
///
/// The envelope carries a `schema_version`, the report title, an RFC 3339
/// generation timestamp, a severity summary, the tools used, and the full
/// list of findings. Findings are rendered in the order provided (typically
/// pre-sorted by severity).
pub fn generate_report(findings: &[&Finding], title: &str) -> String {
    let counts = count_by_severity(findings);
    let envelope = serde_json::json!({
        "schema_version": "1.0",
        "title": title,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total": findings.len(),
            "counts": {
                "critical": counts.0,
                "high": counts.1,
                "medium": counts.2,
                "low": counts.3,
                "info": counts.4,
            },
            "overall_risk": overall_risk(&counts),
        },
        "tools_used": unique_tools(findings),
        "findings": findings,
    });

    serde_json::to_string_pretty(&envelope)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialisation failed: {e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};

    fn make(title: &str, sev: Severity) -> Finding {
        Finding::new(
            title.into(),
            sev,
            format!("Description of {title}"),
            "10.0.0.1".into(),
            "nmap".into(),
        )
    }

    #[test]
    fn parses_back_with_correct_summary_and_findings() {
        let c = make("RCE", Severity::Critical);
        let h = make("SQLi", Severity::High);
        let findings = vec![&c, &h];
        let out = generate_report(&findings, "Parse Test");

        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["schema_version"], "1.0");
        assert_eq!(v["title"], "Parse Test");
        assert_eq!(v["summary"]["total"], 2);
        assert_eq!(v["summary"]["counts"]["critical"], 1);
        assert_eq!(v["summary"]["counts"]["high"], 1);
        assert_eq!(v["summary"]["overall_risk"], "Critical");
        assert_eq!(v["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn empty_findings_is_valid_json_with_zero_total() {
        let findings: Vec<&Finding> = vec![];
        let out = generate_report(&findings, "Empty");

        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["summary"]["total"], 0);
        assert_eq!(v["summary"]["overall_risk"], "None");
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
        assert_eq!(v["tools_used"].as_array().unwrap().len(), 0);
    }
}
