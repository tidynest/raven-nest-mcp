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

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(
            title.into(),
            severity,
            "Test description".into(),
            "192.168.1.1".into(),
            "nmap".into(),
        )
    }

    #[test]
    fn empty_findings_produces_header_only() {
        let report = generate_report(&[], "Test Report");
        assert!(report.contains("# Test Report"));
        assert!(report.contains("| **Total** | **0** |"));
    }

    #[test]
    fn single_finding_includes_all_fields() {
        let mut f = make_finding("SQL Injection", Severity::Critical);
        f.cvss = Some(9.8);
        f.cve = Some("CVE-2024-1234".into());
        f.evidence = Some("error-based SQL".into());
        f.remediation = Some("Use parameterized queries".into());

        let report = generate_report(&[&f], "Report");
        assert!(report.contains("CVSS:"));
        assert!(report.contains("CVE-2024-1234"));
        assert!(report.contains("error-based SQL"));
        assert!(report.contains("Use parameterized queries"));
    }

    #[test]
    fn severity_count_table_correct() {
        let f1 = make_finding("A", Severity::Critical);
        let f2 = make_finding("B", Severity::Critical);
        let f3 = make_finding("C", Severity::High);
        let report = generate_report(&[&f1, &f2, &f3], "Report");
        assert!(report.contains("| Critical | 2 |"));
        assert!(report.contains("| High | 1 |"));
    }

    #[test]
    fn findings_numbered_sequentially() {
        let f1 = make_finding("A", Severity::Low);
        let f2 = make_finding("B", Severity::Low);
        let f3 = make_finding("C", Severity::Low);
        let report = generate_report(&[&f1, &f2, &f3], "Report");
        assert!(report.contains("### 1."));
        assert!(report.contains("### 2."));
        assert!(report.contains("### 3."));
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let f = make_finding("XSS", Severity::Medium);
        let report = generate_report(&[&f], "Report");
        assert!(!report.contains("CVSS:"));
        assert!(!report.contains("CVE:"));
    }
}
