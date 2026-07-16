//! Markdown report generator for pentest findings.
//!
//! Produces a structured report with:
//! 1. **Executive summary** - severity breakdown table with counts.
//! 2. **Findings section** - numbered entries with target, tool, CVSS/CVE,
//!    description, evidence, and remediation.
//!
//! Called by [`raven_server::tools::findings::generate_report`] which also
//! persists the output to `{output_dir}/report-{timestamp}.md`.

use crate::finding::Finding;
use crate::summary::{count_by_severity, overall_risk, time_range, unique_targets, unique_tools};

/// Escape markdown special characters in user-supplied text.
///
/// Prevents injected markdown (e.g. `# Fake Header` in a finding title)
/// from breaking report structure. Applied to titles, descriptions, and
/// remediation text - but NOT to evidence (which is inside a code fence).
fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '#' | '[' | ']' | '*' | '_' | '`' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Longest run of consecutive backticks in `s` (0 if none).
///
/// Used to size the evidence code fence so evidence containing a ``` sequence
/// cannot close the fence early and inject markdown into the report.
fn max_backtick_run(s: &str) -> usize {
    let mut max = 0;
    let mut cur = 0;
    for c in s.chars() {
        if c == '`' {
            cur += 1;
            max = max.max(cur);
        } else {
            cur = 0;
        }
    }
    max
}

/// Generate a complete markdown pentest report from a list of findings.
///
/// Findings are rendered in the order provided - callers typically pass them
/// pre-sorted by severity via [`FindingStore::load_all`](crate::store::FindingStore::load_all).
///
/// Report structure: Table of Contents, Executive Summary (severity table +
/// overall risk), Methodology (PTES), Tools Used, numbered Findings with
/// OWASP categories.
pub fn generate_report(findings: &[&Finding], title: &str) -> String {
    let mut report = format!("# {title}\n\n");
    report.push_str(&format!(
        "_Generated {}_\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    // Table of Contents
    report.push_str("## Table of Contents\n\n");
    report.push_str("- [Executive Summary](#executive-summary)\n");
    report.push_str("- [Methodology](#methodology)\n");
    report.push_str("- [Tools Used](#tools-used)\n");
    report.push_str("- [Scope & Timeline](#scope--timeline)\n");
    report.push_str(&format!("- [Findings ({})](#findings)\n", findings.len()));
    for (i, f) in findings.iter().enumerate() {
        let n = i + 1;
        // Label uses "Sev: title" (no nested brackets, which break link syntax);
        // the anchor is an explicit `finding-N` id emitted at each heading, so it
        // does not depend on GitHub's heading-slug algorithm.
        report.push_str(&format!(
            "  - [{n}. {}: {}](#finding-{n})\n",
            f.severity,
            escape_markdown(&f.title),
        ));
    }
    report.push('\n');

    // Executive Summary - severity breakdown table + overall risk
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
    report.push_str(&format!("**Overall risk:** {}\n\n", overall_risk(&counts)));

    // Methodology
    report.push_str("## Methodology\n\n");
    report.push_str(
        "This assessment followed the Penetration Testing Execution Standard (PTES):\n\n\
        1. **Pre-engagement** - scope and rules of engagement defined\n\
        2. **Intelligence gathering** - passive and active reconnaissance\n\
        3. **Vulnerability analysis** - automated and manual vulnerability identification\n\
        4. **Exploitation** - verification of identified vulnerabilities\n\
        5. **Post-exploitation** - impact assessment and lateral movement testing\n\
        6. **Reporting** - documentation of findings with remediation guidance\n\n",
    );

    // Tools Used - deduplicated list
    report.push_str("## Tools Used\n\n");
    for t in &unique_tools(findings) {
        report.push_str(&format!("- {t}\n"));
    }
    report.push('\n');

    // Scope & Timeline - assessed targets and the engagement window, both
    // derived from the findings themselves.
    report.push_str("## Scope & Timeline\n\n");
    let targets = unique_targets(findings);
    report.push_str(&format!("**Targets assessed:** {}\n\n", targets.len()));
    for t in &targets {
        report.push_str(&format!("- {}\n", escape_markdown(t)));
    }
    match time_range(findings) {
        Some((first, last)) => report.push_str(&format!(
            "\n**Engagement window:** {} to {}\n\n",
            first.to_rfc3339(),
            last.to_rfc3339()
        )),
        None => report.push('\n'),
    }

    // Individual findings
    report.push_str("## Findings\n\n");
    for (i, f) in findings.iter().enumerate() {
        let n = i + 1;
        report.push_str(&format!(
            "<a id=\"finding-{n}\"></a>\n\n### {n}. [{}] {}\n\n",
            f.severity,
            escape_markdown(&f.title)
        ));
        report.push_str(&format!("- **Target:** {}\n", escape_markdown(&f.target)));
        report.push_str(&format!("- **Tool:** {}\n", escape_markdown(&f.tool)));

        if let Some(cvss) = f.cvss {
            report.push_str(&format!("- **CVSS:** {cvss:.1}\n"));
        }
        if let Some(cve) = &f.cve {
            report.push_str(&format!("- **CVE:** {}\n", escape_markdown(cve)));
        }
        if let Some(owasp) = &f.owasp_category {
            report.push_str(&format!("- **OWASP:** {}\n", escape_markdown(owasp)));
        }

        report.push_str(&format!("\n{}\n\n", escape_markdown(&f.description)));

        if let Some(evidence) = &f.evidence {
            // Size the fence to outlast any backtick run in the evidence so a
            // ``` inside it cannot close the fence and inject markdown.
            let fence = "`".repeat(max_backtick_run(evidence).max(2) + 1);
            report.push_str(&format!("**Evidence:**\n{fence}\n{evidence}\n{fence}\n\n"));
        }
        if let Some(remediation) = &f.remediation {
            report.push_str(&format!(
                "**Remediation:** {}\n\n",
                escape_markdown(remediation)
            ));
        }

        report.push_str("---\n\n");
    }

    report
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
        assert!(report.contains("**Overall risk:** High"));
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
    fn report_has_toc_methodology_tools() {
        let f = make("XSS", Severity::High);
        let findings = vec![&f];
        let report = generate_report(&findings, "Sections");
        assert!(report.contains("## Table of Contents"));
        assert!(report.contains("## Methodology"));
        assert!(report.contains("PTES"));
        assert!(report.contains("## Tools Used"));
        assert!(report.contains("- nmap"));
    }

    #[test]
    fn report_includes_owasp_category() {
        let mut f = make_full();
        f.owasp_category = Some("A03:2021 Injection".into());
        let findings = vec![&f];
        let report = generate_report(&findings, "OWASP");
        assert!(report.contains("**OWASP:** A03:2021 Injection"));
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

    #[test]
    fn escape_markdown_handles_special_chars() {
        assert_eq!(escape_markdown("# Header"), "\\# Header");
        assert_eq!(escape_markdown("[link](url)"), "\\[link\\](url)");
        assert_eq!(escape_markdown("**bold**"), "\\*\\*bold\\*\\*");
        assert_eq!(escape_markdown("`code`"), "\\`code\\`");
        assert_eq!(escape_markdown("pipe | table"), "pipe \\| table");
        assert_eq!(escape_markdown("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn escape_markdown_preserves_normal_text() {
        assert_eq!(escape_markdown("normal text 123"), "normal text 123");
        assert_eq!(escape_markdown(""), "");
    }

    #[test]
    fn report_escapes_markdown_injection_in_title() {
        let mut f = make("# Injected Header", Severity::High);
        f.description = "## Injected Section\n\nMalicious content".into();
        let findings = vec![&f];
        let report = generate_report(&findings, "Injection Test");
        // The title should be escaped - no raw "# Injected Header" as an actual heading
        assert!(report.contains("\\# Injected Header"));
        // The description should be escaped
        assert!(report.contains("\\#\\# Injected Section"));
    }

    #[test]
    fn report_does_not_escape_evidence() {
        let mut f = make("Test Finding", Severity::Medium);
        f.evidence = Some("# This should NOT be escaped\n`code here`".into());
        let findings = vec![&f];
        let report = generate_report(&findings, "Evidence Test");
        // Evidence is inside a code fence - should NOT be escaped
        assert!(report.contains("# This should NOT be escaped"));
        assert!(report.contains("`code here`"));
    }

    #[test]
    fn report_escapes_injection_in_target_and_tool() {
        // target/tool come from scan output and must be escaped like title/desc.
        let mut f = make("Finding", Severity::High);
        f.target = "a|b`c".into();
        f.tool = "tool|x".into();
        let findings = vec![&f];
        let report = generate_report(&findings, "T");
        assert!(report.contains("**Target:** a\\|b\\`c"));
        assert!(report.contains("**Tool:** tool\\|x"));
    }

    #[test]
    fn report_evidence_fence_survives_inner_backticks() {
        let mut f = make("Finding", Severity::Medium);
        f.evidence = Some("before\n```\n# injected heading\n```\nafter".into());
        let findings = vec![&f];
        let report = generate_report(&findings, "T");
        // Fence must be longer than the ``` inside, i.e. 4+ backticks.
        assert!(report.contains("````"));
        // Evidence content is still present and unescaped.
        assert!(report.contains("# injected heading"));
    }

    #[test]
    fn report_toc_uses_explicit_anchors() {
        let a = make("First", Severity::High);
        let findings = vec![&a];
        let report = generate_report(&findings, "T");
        assert!(report.contains("(#finding-1)"));
        assert!(report.contains("<a id=\"finding-1\"></a>"));
    }

    #[test]
    fn report_has_scope_timeline_and_timestamp() {
        let mut f = make("XSS", Severity::High);
        f.target = "app.example.com".into();
        let findings = vec![&f];
        let report = generate_report(&findings, "Scope");
        assert!(report.contains("_Generated "));
        assert!(report.contains("## Scope & Timeline"));
        assert!(report.contains("**Targets assessed:** 1"));
        assert!(report.contains("- app.example.com"));
        assert!(report.contains("**Engagement window:**"));
    }
}
