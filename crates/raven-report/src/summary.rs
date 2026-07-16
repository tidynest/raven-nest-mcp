//! Shared summary helpers used by every report format.
//!
//! These compute the severity breakdown, overall risk level, and the
//! deduplicated tool list. Lifted out of [`markdown`](crate::markdown) so the
//! JSON, SARIF, and HTML generators share one source of truth - keeping the
//! summary numbers consistent across every output format.

use crate::finding::{Finding, Severity};
use chrono::{DateTime, Utc};

/// Count findings by each severity level. Returns (critical, high, medium, low, info).
pub(crate) fn count_by_severity(findings: &[&Finding]) -> (usize, usize, usize, usize, usize) {
    let count = |s: &Severity| findings.iter().filter(|f| f.severity == *s).count();
    (
        count(&Severity::Critical),
        count(&Severity::High),
        count(&Severity::Medium),
        count(&Severity::Low),
        count(&Severity::Info),
    )
}

/// Determine the overall risk level from severity counts.
///
/// Returns the highest non-zero severity, or `"None"` when there are no findings.
pub(crate) fn overall_risk(counts: &(usize, usize, usize, usize, usize)) -> &'static str {
    if counts.0 > 0 {
        "Critical"
    } else if counts.1 > 0 {
        "High"
    } else if counts.2 > 0 {
        "Medium"
    } else if counts.3 > 0 {
        "Low"
    } else if counts.4 > 0 {
        "Informational"
    } else {
        "None"
    }
}

/// Sorted, deduplicated list of the tools that produced these findings.
pub(crate) fn unique_tools(findings: &[&Finding]) -> Vec<String> {
    let mut tools: Vec<String> = findings.iter().map(|f| f.tool.clone()).collect();
    tools.sort_unstable();
    tools.dedup();
    tools
}

/// Sorted, deduplicated list of the targets these findings were found on.
///
/// Serves as the report's assessed-scope list - honest about what was actually
/// examined, derived from the findings rather than the configured allowlist.
pub(crate) fn unique_targets(findings: &[&Finding]) -> Vec<String> {
    let mut targets: Vec<String> = findings.iter().map(|f| f.target.clone()).collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Earliest and latest finding timestamps (the engagement window), or `None`
/// when there are no findings.
pub(crate) fn time_range(findings: &[&Finding]) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let min = findings.iter().map(|f| f.timestamp).min()?;
    let max = findings.iter().map(|f| f.timestamp).max()?;
    Some((min, max))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    fn make(title: &str, sev: Severity, tool: &str) -> Finding {
        Finding::new(
            title.into(),
            sev,
            "desc".into(),
            "10.0.0.1".into(),
            tool.into(),
        )
    }

    #[test]
    fn counts_each_severity() {
        let c = make("c", Severity::Critical, "nmap");
        let h = make("h", Severity::High, "nmap");
        let m = make("m", Severity::Medium, "nuclei");
        let l = make("l", Severity::Low, "nikto");
        let i = make("i", Severity::Info, "nikto");
        let findings = vec![&c, &h, &h, &m, &l, &i];
        assert_eq!(count_by_severity(&findings), (1, 2, 1, 1, 1));
    }

    #[test]
    fn overall_risk_picks_highest() {
        assert_eq!(overall_risk(&(1, 0, 0, 0, 0)), "Critical");
        assert_eq!(overall_risk(&(0, 1, 0, 0, 0)), "High");
        assert_eq!(overall_risk(&(0, 0, 1, 0, 0)), "Medium");
        assert_eq!(overall_risk(&(0, 0, 0, 1, 0)), "Low");
        assert_eq!(overall_risk(&(0, 0, 0, 0, 1)), "Informational");
        assert_eq!(overall_risk(&(0, 0, 0, 0, 0)), "None");
    }

    #[test]
    fn unique_tools_sorted_and_deduped() {
        let a = make("a", Severity::High, "nuclei");
        let b = make("b", Severity::Low, "nmap");
        let c = make("c", Severity::Info, "nuclei");
        let findings = vec![&a, &b, &c];
        assert_eq!(unique_tools(&findings), vec!["nmap", "nuclei"]);
    }

    #[test]
    fn unique_targets_sorted_and_deduped() {
        let mut a = make("a", Severity::High, "nmap");
        a.target = "b.example.com".into();
        let mut b = make("b", Severity::Low, "nmap");
        b.target = "a.example.com".into();
        let mut c = make("c", Severity::Info, "nuclei");
        c.target = "b.example.com".into();
        let findings = vec![&a, &b, &c];
        assert_eq!(
            unique_targets(&findings),
            vec!["a.example.com", "b.example.com"]
        );
    }

    #[test]
    fn time_range_none_when_empty_else_min_max() {
        use chrono::TimeZone;
        assert!(time_range(&[]).is_none());
        let mut a = make("a", Severity::High, "nmap");
        a.timestamp = Utc.timestamp_opt(2000, 0).unwrap();
        let mut b = make("b", Severity::Low, "nmap");
        b.timestamp = Utc.timestamp_opt(1000, 0).unwrap();
        let (min, max) = time_range(&[&a, &b]).unwrap();
        assert_eq!(min.timestamp(), 1000);
        assert_eq!(max.timestamp(), 2000);
    }
}
