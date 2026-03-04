use crate::finding::{Finding, Severity};

pub fn generate_report(findings: &[&Finding], title: &str) -> String {
    let mut report = format!("# {title}\n\n");

    // Executive Summary
    report.push_str("## Executive Summary\n\n");
    let counts = count_by_severity(findings);
    report.push_str(&format!(
        "| Severity | Count |\n|----------|-------|\n\
        | Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| Info | {} |\n\
        | **Total** | **{}** |\n\n",
        counts.0,
        counts.1,
        counts.2,
        counts.3,
        counts.4,
        findings.len(),
    ));

    // Individual findings
    report.push_str("## Findings\n\n");
    for (i, f) in findings.iter().enumerate() {
        report.push_str(&format!("### {}. [{}] {}\n\n", i + 1, f.severity, f.title));
        report.push_str(&format!("- **Target:** {}\n", f.target));
        report.push_str(&format!("- **Tool:** {}\n", f.tool));

        if let Some(cvss) = f.cvss {
            report.push_str(&format!("- **CVSS:** {cvss:.1}\n"));
        }
        if let Some(cve) = &f.cve {
            report.push_str(&format!("- **CVE:** {cve}\n"));
        }

        report.push_str(&format!("\n{}\n\n", f.description));

        if let Some(evidence) = &f.evidence {
            report.push_str(&format!("**Evidence:**\n```\n{evidence}\n```\n\n"));
        }
        if let Some(remediation) = &f.remediation {
            report.push_str(&format!("**Remediation:** {remediation}\n\n"));
        }

        report.push_str("---\n\n");
    }

    report
}

fn count_by_severity(findings: &[&Finding]) -> (usize, usize, usize, usize, usize) {
    let count = |s: &Severity| findings.iter().filter(|f| f.severity == *s).count();
    (
        count(&Severity::Critical),
        count(&Severity::High),
        count(&Severity::Medium),
        count(&Severity::Low),
        count(&Severity::Info),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    fn make(title: &str, sev: Severity) -> Finding {
        Finding::new(
            title.into(),
            sev,
            format!("Description of {title}"),
            "10.0.0.1".into(),
            "nmap".into(),
        )
    }

    fn make_full() -> Finding {
        let mut f = make("RCE via deserialization", Severity::Critical);
        f.cvss = Some(9.8);
        f.cve = Some("CVE-2024-1234".into());
        f.evidence = Some("HTTP/1.1 500 Internal Server Error\njava.io.ObjectInputStream".into());
        f.remediation = Some("Upgrade to patched version".into());
        f
    }

    #[test]
    fn report_contains_title_and_summary_table() {
        let f = make("XSS", Severity::High);
        let findings = vec![&f];
        let report = generate_report(&findings, "Test Report");
        assert!(report.starts_with("# Test Report"));
        assert!(report.contains("Executive Summary"));
        assert!(report.contains("| High | 1 |"));
        assert!(report.contains("| **Total** | **1** |"));
    }

    #[test]
    fn report_severity_counts_are_correct() {
        let c = make("RCE", Severity::Critical);
        let h = make("SQLi", Severity::High);
        let m = make("CSRF", Severity::Medium);
        let l = make("Cookie", Severity::Low);
        let i = make("Info", Severity::Info);
        let findings = vec![&c, &h, &h, &m, &l, &i];
        let report = generate_report(&findings, "Counts");
        assert!(report.contains("| Critical | 1 |"));
        assert!(report.contains("| High | 2 |"));
        assert!(report.contains("| Medium | 1 |"));
        assert!(report.contains("| Low | 1 |"));
        assert!(report.contains("| Info | 1 |"));
        assert!(report.contains("| **Total** | **6** |"));
    }

    #[test]
    fn report_includes_optional_fields() {
        let f = make_full();
        let findings = vec![&f];
        let report = generate_report(&findings, "Full");
        assert!(report.contains("CVE-2024-1234"));
        assert!(report.contains("9.8"));
        assert!(report.contains("ObjectInputStream"));
        assert!(report.contains("Upgrade to patched version"));
    }

    #[test]
    fn report_omits_absent_optional_fields() {
        let f = make("Basic", Severity::Low);
        let findings = vec![&f];
        let report = generate_report(&findings, "Minimal");
        assert!(!report.contains("CVE:"));
        assert!(!report.contains("CVSS:"));
        assert!(!report.contains("Evidence:"));
        assert!(!report.contains("Remediation:"));
    }

    #[test]
    fn report_empty_findings() {
        let findings: Vec<&Finding> = vec![];
        let report = generate_report(&findings, "Empty");
        assert!(report.contains("# Empty"));
        assert!(report.contains("| **Total** | **0** |"));
        // No findings section entries
        assert!(!report.contains("### 1."));
    }

    #[test]
    fn report_finding_numbering() {
        let a = make("First", Severity::High);
        let b = make("Second", Severity::Medium);
        let c = make("Third", Severity::Low);
        let findings = vec![&a, &b, &c];
        let report = generate_report(&findings, "Numbered");
        assert!(report.contains("### 1. [High] First"));
        assert!(report.contains("### 2. [Medium] Second"));
        assert!(report.contains("### 3. [Low] Third"));
    }
}
