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
        counts.0, counts.1, counts.2, counts.3, counts.4,
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