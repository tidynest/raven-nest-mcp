//! SARIF 2.1.0 report generator for pentest findings.
//!
//! Emits a [Static Analysis Results Interchange Format][sarif] document so
//! findings can be ingested by code-scanning dashboards (GitHub code scanning,
//! Azure DevOps, etc.). Rules are deduplicated by id and referenced from each
//! result via `ruleIndex`.
//!
//! Called by [`raven_server::tools::findings::generate_report`] when the
//! requested format is `sarif`.
//!
//! [sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::finding::{Finding, Severity};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

const DRIVER_NAME: &str = "Raven Nest";
const DRIVER_URI: &str = "https://github.com/tidynest/raven-nest-mcp";
const DRIVER_VERSION: &str = "0.1.0";

/// Generate a SARIF 2.1.0 document from a list of findings.
///
/// Builds one `rule` per unique rule id and one `result` per finding. Each
/// result references its rule by index. SARIF `level` is derived from the
/// finding severity (CVSS does NOT influence level - it is surfaced as the
/// `security-severity` rule property instead).
pub fn generate_report(findings: &[&Finding], _title: &str) -> String {
    // Build deduplicated rules, remembering each rule id's index.
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_index: HashMap<String, usize> = HashMap::new();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let id = rule_id(f);
            let idx = *rule_index.entry(id.clone()).or_insert_with(|| {
                rules.push(build_rule(&id, f));
                rules.len() - 1
            });
            build_result(&id, idx, f)
        })
        .collect();

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": DRIVER_NAME,
                    "informationUri": DRIVER_URI,
                    "version": DRIVER_VERSION,
                    "rules": rules,
                }
            },
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&doc)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialisation failed: {e}\"}}"))
}

/// Stable rule id for a finding: its CVE if present, else a tool/title slug.
fn rule_id(f: &Finding) -> String {
    match &f.cve {
        Some(cve) if !cve.is_empty() => cve.clone(),
        _ => format!("raven-{}-{}", slugify(&f.tool), slugify(&f.title)),
    }
}

/// Lowercase, dash-separated slug - non-alphanumerics collapse to single dashes.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// SARIF `security-severity` string. CVSS if present, else mapped from severity.
///
/// Code-scanning consumers read this as a string, so a numeric CVSS is rendered
/// as text and the severity fallback uses canonical band midpoints.
fn security_severity(f: &Finding) -> String {
    match f.cvss {
        Some(cvss) => format!("{cvss:.1}"),
        None => match f.severity {
            Severity::Critical => "9.5",
            Severity::High => "8.0",
            Severity::Medium => "5.0",
            Severity::Low => "3.0",
            Severity::Info => "0.0",
        }
        .to_string(),
    }
}

/// SARIF result `level`. Only `note`/`warning`/`error` are valid; CVSS is ignored.
fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Build a SARIF reporting descriptor (rule) for a finding.
fn build_rule(id: &str, f: &Finding) -> serde_json::Value {
    let mut tags: Vec<&str> = Vec::new();
    if let Some(owasp) = &f.owasp_category {
        tags.push(owasp);
    }
    tags.push(&f.tool);

    let mut rule = serde_json::json!({
        "id": id,
        "name": f.title,
        "shortDescription": { "text": f.title },
        "fullDescription": { "text": f.description },
        "properties": {
            "security-severity": security_severity(f),
            "tags": tags,
        },
    });

    if let Some(cve) = &f.cve
        && !cve.is_empty()
    {
        rule["helpUri"] =
            serde_json::Value::String(format!("https://nvd.nist.gov/vuln/detail/{cve}"));
    }

    rule
}

/// Build a SARIF result for a finding, referencing its rule by index.
fn build_result(id: &str, idx: usize, f: &Finding) -> serde_json::Value {
    let message = match &f.evidence {
        Some(ev) if !ev.is_empty() => format!("{}\n\nEvidence:\n{ev}", f.description),
        _ => f.description.clone(),
    };

    serde_json::json!({
        "ruleId": id,
        "ruleIndex": idx,
        "level": sarif_level(&f.severity),
        "message": { "text": message },
        // Pentest findings target a network host/URL, not a source file. SARIF
        // `artifactLocation.uri` is read as a repo-relative source path by GitHub
        // code scanning, so putting the target there made results resolve to a
        // nonexistent file and get dropped on ingest. `logicalLocations` is the
        // correct construct for a non-file location; the target is also mirrored
        // into `properties` for consumers that read it there.
        // (If GitHub inline source-anchoring is ever wanted, add a synthetic
        // `physicalLocation.artifactLocation.uri` like `targets/<slug>` instead.)
        "locations": [{
            "logicalLocations": [{
                "name": f.target,
                "fullyQualifiedName": f.target,
            }],
        }],
        "properties": {
            "target": f.target,
        },
        "partialFingerprints": {
            "ravenFingerprint": fingerprint(f),
        },
    })
}

/// Stable hex fingerprint of `title|target|tool` for result de-duplication.
fn fingerprint(f: &Finding) -> String {
    let mut hasher = DefaultHasher::new();
    format!("{}|{}|{}", f.title, f.target, f.tool).hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
            "https://example.com".into(),
            "nuclei".into(),
        )
    }

    #[test]
    fn version_and_critical_level_and_security_severity() {
        let mut f = make("RCE", Severity::Critical);
        f.cvss = Some(9.8);
        let findings = vec![&f];
        let out = generate_report(&findings, "SARIF Test");

        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");

        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["level"], "error");

        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["properties"]["security-severity"], "9.8");
    }

    #[test]
    fn level_mapping_per_severity() {
        let lvl = |s: Severity| {
            let f = make("x", s);
            let findings = vec![&f];
            let v: serde_json::Value =
                serde_json::from_str(&generate_report(&findings, "t")).unwrap();
            v["runs"][0]["results"][0]["level"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(lvl(Severity::Critical), "error");
        assert_eq!(lvl(Severity::High), "error");
        assert_eq!(lvl(Severity::Medium), "warning");
        assert_eq!(lvl(Severity::Low), "note");
        assert_eq!(lvl(Severity::Info), "note");
    }

    #[test]
    fn rules_deduped_by_id() {
        // Two findings, same tool + title => one rule, two results.
        let a = make("Outdated TLS", Severity::Medium);
        let b = make("Outdated TLS", Severity::Medium);
        let findings = vec![&a, &b];
        let v: serde_json::Value = serde_json::from_str(&generate_report(&findings, "t")).unwrap();
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(v["runs"][0]["results"][1]["ruleIndex"], 0);
    }

    #[test]
    fn cve_drives_rule_id_and_help_uri() {
        let mut f = make("Known CVE", Severity::High);
        f.cve = Some("CVE-2024-1234".into());
        let findings = vec![&f];
        let v: serde_json::Value = serde_json::from_str(&generate_report(&findings, "t")).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "CVE-2024-1234");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"],
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        );
    }

    #[test]
    fn evidence_appended_to_message() {
        let mut f = make("XSS", Severity::High);
        f.evidence = Some("<reflected payload>".into());
        let findings = vec![&f];
        let v: serde_json::Value = serde_json::from_str(&generate_report(&findings, "t")).unwrap();
        let msg = v["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(msg.contains("Evidence:"));
        assert!(msg.contains("<reflected payload>"));
    }

    #[test]
    fn empty_findings_valid_with_empty_results() {
        let findings: Vec<&Finding> = vec![];
        let out = generate_report(&findings, "Empty");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn target_is_a_logical_location_not_a_source_uri() {
        let f = make("XSS", Severity::High); // target = https://example.com
        let findings = vec![&f];
        let v: serde_json::Value = serde_json::from_str(&generate_report(&findings, "t")).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(
            result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "https://example.com"
        );
        // The old ingest bug: target rendered as a physical source path.
        assert!(result["locations"][0]["physicalLocation"].is_null());
        assert_eq!(result["properties"]["target"], "https://example.com");
    }

    #[test]
    fn security_severity_falls_back_to_band_midpoint() {
        let f = make("No CVSS", Severity::Medium);
        let findings = vec![&f];
        let v: serde_json::Value = serde_json::from_str(&generate_report(&findings, "t")).unwrap();
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
            "5.0"
        );
    }
}
