//! Self-contained HTML report generator for pentest findings.
//!
//! Produces a single file with an inlined `<style>` block - no external assets,
//! safe to email or open offline. The palette is a deliberately non-GitHub dark
//! theme (deep slate background, colour-coded severity badges).
//!
//! # Security
//!
//! Every user-supplied field is passed through [`html_escape`] before it reaches
//! the document - including evidence, even though it sits inside `<pre><code>`,
//! because a `</code></pre><script>` payload would otherwise break out of the
//! code block and inject script.
//!
//! Called by [`raven_server::tools::findings::generate_report`] when the
//! requested format is `html`.

use crate::finding::{Finding, Severity};
use crate::summary::{count_by_severity, overall_risk, time_range, unique_targets, unique_tools};

/// Escape the five HTML-significant characters so user text can never break
/// out of its element or attribute context.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Lowercase CSS class suffix for a severity (`critical`, `high`, …).
fn severity_class(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

const STYLE: &str = r#"
:root {
  --bg: #161b22;
  --panel: #1e2530;
  --panel-alt: #232b38;
  --border: #2d3748;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #8b5cf6;
  --crit: #e5484d;
  --high: #e8590c;
  --med: #d9a400;
  --low: #3b82f6;
  --info: #6b7280;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.55;
}
.wrap { max-width: 920px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
header h1 { font-size: 1.9rem; margin: 0 0 .3rem; letter-spacing: -.01em; }
header .meta { color: var(--muted); font-size: .9rem; }
header { border-bottom: 2px solid var(--accent); padding-bottom: 1rem; margin-bottom: 2rem; }
h2 { font-size: 1.25rem; margin: 2.2rem 0 1rem; color: #f1f5f9; }
table.summary { border-collapse: collapse; width: 100%; background: var(--panel); border-radius: 8px; overflow: hidden; }
table.summary th, table.summary td { text-align: left; padding: .65rem 1rem; border-bottom: 1px solid var(--border); }
table.summary th { background: var(--panel-alt); color: var(--muted); font-weight: 600; font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; }
table.summary tr:last-child td { border-bottom: none; font-weight: 700; }
.risk { display: inline-block; margin-top: 1rem; padding: .4rem .9rem; border-radius: 6px; background: var(--panel); border: 1px solid var(--border); }
.risk strong { color: var(--accent); }
.badge { display: inline-block; padding: .15rem .6rem; border-radius: 999px; font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; color: #fff; }
.badge.critical { background: var(--crit); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--med); color: #1a1205; }
.badge.low { background: var(--low); }
.badge.info { background: var(--info); }
.finding { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.4rem; margin: 1rem 0; }
.finding h3 { margin: 0 0 .6rem; font-size: 1.1rem; display: flex; align-items: center; gap: .6rem; }
.finding .num { color: var(--muted); font-weight: 600; }
.kv { color: var(--muted); font-size: .88rem; margin: .15rem 0; }
.kv b { color: var(--text); font-weight: 600; }
.desc { margin: .8rem 0; }
pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: .8rem 1rem; overflow-x: auto; margin: .6rem 0; }
pre code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: .82rem; color: #cbd5e1; }
.section-label { font-weight: 600; color: var(--muted); font-size: .85rem; margin-top: .8rem; }
.tools li { color: var(--muted); }
.empty { color: var(--muted); font-style: italic; }
"#;

/// Generate a complete, self-contained HTML report from a list of findings.
///
/// Sections: title header, severity summary table (with total + overall risk),
/// tools used, then each finding rendered with a colour-coded severity badge.
/// All user-supplied content is HTML-escaped.
pub fn generate_report(findings: &[&Finding], title: &str) -> String {
    let counts = count_by_severity(findings);
    let esc_title = html_escape(title);

    let mut body = String::new();

    // Summary table
    body.push_str(&format!(
        "<table class=\"summary\">\n\
         <tr><th>Severity</th><th>Count</th></tr>\n\
         <tr><td><span class=\"badge critical\">Critical</span></td><td>{}</td></tr>\n\
         <tr><td><span class=\"badge high\">High</span></td><td>{}</td></tr>\n\
         <tr><td><span class=\"badge medium\">Medium</span></td><td>{}</td></tr>\n\
         <tr><td><span class=\"badge low\">Low</span></td><td>{}</td></tr>\n\
         <tr><td><span class=\"badge info\">Info</span></td><td>{}</td></tr>\n\
         <tr><td>Total</td><td>{}</td></tr>\n\
         </table>\n",
        counts.0,
        counts.1,
        counts.2,
        counts.3,
        counts.4,
        findings.len(),
    ));
    body.push_str(&format!(
        "<div class=\"risk\">Overall risk: <strong>{}</strong></div>\n",
        overall_risk(&counts),
    ));

    // Tools used
    body.push_str("<h2>Tools Used</h2>\n");
    let tools = unique_tools(findings);
    if tools.is_empty() {
        body.push_str("<p class=\"empty\">No tools recorded.</p>\n");
    } else {
        body.push_str("<ul class=\"tools\">\n");
        for t in &tools {
            body.push_str(&format!("<li>{}</li>\n", html_escape(t)));
        }
        body.push_str("</ul>\n");
    }

    // Scope & Timeline - assessed targets and engagement window from the findings.
    body.push_str("<h2>Scope &amp; Timeline</h2>\n");
    let targets = unique_targets(findings);
    body.push_str(&format!(
        "<p><b>Targets assessed:</b> {}</p>\n",
        targets.len()
    ));
    if !targets.is_empty() {
        body.push_str("<ul class=\"tools\">\n");
        for t in &targets {
            body.push_str(&format!("<li>{}</li>\n", html_escape(t)));
        }
        body.push_str("</ul>\n");
    }
    if let Some((first, last)) = time_range(findings) {
        body.push_str(&format!(
            "<p><b>Engagement window:</b> {} to {}</p>\n",
            first.to_rfc3339(),
            last.to_rfc3339()
        ));
    }

    // Methodology - parity with the markdown report.
    body.push_str(
        "<h2>Methodology</h2>\n\
         <p>This assessment followed the Penetration Testing Execution Standard \
         (PTES): pre-engagement, intelligence gathering, vulnerability analysis, \
         exploitation, post-exploitation, and reporting.</p>\n",
    );

    // Findings
    body.push_str(&format!("<h2>Findings ({})</h2>\n", findings.len()));
    if findings.is_empty() {
        body.push_str("<p class=\"empty\">No findings recorded.</p>\n");
    }
    for (i, f) in findings.iter().enumerate() {
        body.push_str(&render_finding(i + 1, f));
    }

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{esc_title}</title>\n\
         <style>{STYLE}</style>\n\
         </head>\n<body>\n<div class=\"wrap\">\n\
         <header>\n<h1>{esc_title}</h1>\n\
         <div class=\"meta\">Generated {}</div>\n</header>\n\
         <h2>Executive Summary</h2>\n{body}</div>\n</body>\n</html>\n",
        chrono::Utc::now().to_rfc3339(),
    )
}

/// Render a single finding card. Every field is HTML-escaped.
fn render_finding(n: usize, f: &Finding) -> String {
    let cls = severity_class(&f.severity);
    let mut out = format!(
        "<div class=\"finding\">\n\
         <h3><span class=\"num\">{n}.</span> <span class=\"badge {cls}\">{}</span> {}</h3>\n",
        f.severity,
        html_escape(&f.title),
    );

    out.push_str(&format!(
        "<div class=\"kv\"><b>Target:</b> {}</div>\n",
        html_escape(&f.target)
    ));
    out.push_str(&format!(
        "<div class=\"kv\"><b>Tool:</b> {}</div>\n",
        html_escape(&f.tool)
    ));
    if let Some(cvss) = f.cvss {
        out.push_str(&format!("<div class=\"kv\"><b>CVSS:</b> {cvss:.1}</div>\n"));
    }
    if let Some(cve) = &f.cve {
        out.push_str(&format!(
            "<div class=\"kv\"><b>CVE:</b> {}</div>\n",
            html_escape(cve)
        ));
    }
    if let Some(owasp) = &f.owasp_category {
        out.push_str(&format!(
            "<div class=\"kv\"><b>OWASP:</b> {}</div>\n",
            html_escape(owasp)
        ));
    }

    out.push_str(&format!(
        "<div class=\"desc\">{}</div>\n",
        html_escape(&f.description)
    ));

    if let Some(evidence) = &f.evidence {
        out.push_str(&format!(
            "<div class=\"section-label\">Evidence</div>\n<pre><code>{}</code></pre>\n",
            html_escape(evidence)
        ));
    }
    if let Some(remediation) = &f.remediation {
        out.push_str(&format!(
            "<div class=\"section-label\">Remediation</div>\n<div>{}</div>\n",
            html_escape(remediation)
        ));
    }

    out.push_str("</div>\n");
    out
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
    fn escapes_all_significant_chars() {
        assert_eq!(
            html_escape("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn report_contains_title_and_severity_badge() {
        let f = make("Reflected XSS", Severity::High);
        let findings = vec![&f];
        let out = generate_report(&findings, "HTML Report");
        assert!(out.contains("<title>HTML Report</title>"));
        assert!(out.contains("HTML Report"));
        assert!(out.contains("badge high"));
        assert!(out.contains("Reflected XSS"));
    }

    #[test]
    fn report_empty_findings_renders() {
        let findings: Vec<&Finding> = vec![];
        let out = generate_report(&findings, "Empty");
        assert!(out.contains("No findings recorded."));
        assert!(out.contains("Overall risk: <strong>None</strong>"));
    }

    #[test]
    fn injection_in_title_and_evidence_is_escaped() {
        let mut f = make("<script>alert(1)</script>", Severity::Critical);
        f.evidence = Some("</code></pre><script>alert(2)</script>".into());
        let findings = vec![&f];
        let out = generate_report(&findings, "Injection Test");

        // Escaped form present
        assert!(out.contains("&lt;script&gt;"));
        // Raw payloads absent - neither title nor evidence breaks out
        assert!(!out.contains("<script>alert(1)</script>"));
        assert!(!out.contains("<script>alert(2)</script>"));
        assert!(!out.contains("</code></pre><script>"));
    }

    #[test]
    fn injection_in_title_does_not_appear_raw_in_head() {
        // A naive title injection must not land unescaped in <title>.
        let findings: Vec<&Finding> = vec![];
        let out = generate_report(&findings, "</title><script>alert(3)</script>");
        assert!(!out.contains("<script>alert(3)</script>"));
        assert!(out.contains("&lt;script&gt;alert(3)&lt;/script&gt;"));
    }

    #[test]
    fn report_has_scope_and_methodology() {
        let mut f = make("XSS", Severity::High);
        f.target = "app.example.com".into();
        let findings = vec![&f];
        let out = generate_report(&findings, "Scope");
        assert!(out.contains("Scope &amp; Timeline"));
        assert!(out.contains("Targets assessed:"));
        assert!(out.contains("app.example.com"));
        assert!(out.contains("<h2>Methodology</h2>"));
        assert!(out.contains("PTES"));
    }
}
