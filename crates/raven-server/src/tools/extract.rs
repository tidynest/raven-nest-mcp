//! Auto-extraction of findings from scanner output.
//!
//! Some scanners emit structured, severity-tagged results that map cleanly onto
//! a [`Finding`]. When `auto_save_findings` is enabled in config, the server
//! parses those results into [`ExtractedFinding`]s and persists the qualifying
//! ones via [`auto_save`] - deduplicated and tagged `source = AutoExtracted`.
//!
//! [`auto_save`] is tool-agnostic; each tool gets an `extract_*` parser that
//! yields rows. Wired: nuclei, nikto, dalfox, nmap, sqlmap, testssl, gitleaks,
//! trufflehog. The secret scanners (gitleaks/trufflehog) deliberately read only
//! location + identifier fields - a secret value never reaches a finding.

use raven_core::config::RavenConfig;
use raven_report::finding::{Finding, FindingSource, Severity};
use raven_report::store::FindingStore;
use std::sync::{Arc, RwLock};

/// A finding parsed from raw scanner output, before persistence.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedFinding {
    pub title: String,
    pub severity: Severity,
    pub evidence: String,
    pub cve: Option<String>,
}

/// Parse a severity token into [`Severity`]. Accepts the lowercase spellings
/// scanners emit (nuclei) and the config's `auto_save_min_severity`.
pub fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" => Some(Severity::Info),
        _ => None,
    }
}

/// Extract findings from nuclei JSONL output (one JSON object per line).
///
/// Mirrors the field access in
/// [`nuclei::parse_nuclei_jsonl`](crate::tools::nuclei::parse_nuclei_jsonl) but
/// yields structured rows. Lines without a parseable severity are skipped - only
/// actionable, severity-tagged detections become findings.
pub fn extract_nuclei(raw: &str) -> Vec<ExtractedFinding> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let info = v.get("info");
        let Some(severity) = info
            .and_then(|i| i.get("severity"))
            .and_then(|s| s.as_str())
            .and_then(parse_severity)
        else {
            continue;
        };
        let template = v.get("template-id").and_then(|s| s.as_str()).unwrap_or("");
        let name = info
            .and_then(|i| i.get("name"))
            .and_then(|s| s.as_str())
            .unwrap_or(template);
        if name.is_empty() {
            continue;
        }
        let matched = v.get("matched-at").and_then(|s| s.as_str()).unwrap_or("");
        // nuclei puts CVEs under info.classification.cve-id (array).
        let cve = info
            .and_then(|i| i.get("classification"))
            .and_then(|c| c.get("cve-id"))
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.as_str())
            .map(str::to_string);
        out.push(ExtractedFinding {
            title: name.to_string(),
            severity,
            evidence: format!("template={template} matched-at={matched}"),
            cve,
        });
    }
    out
}

/// Cap a finding title to `n` chars (UTF-8 safe), appending '…' if cut.
fn truncate_title(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Extract findings from nikto's text output. Nikto emits no severity, so every
/// finding is tagged Low (conservative). Target/banner/run-summary lines are
/// dropped - only the `+`-prefixed findings remain.
pub fn extract_nikto(raw: &str) -> Vec<ExtractedFinding> {
    raw.lines()
        .map(str::trim)
        .filter(|l| l.starts_with('+'))
        .filter_map(|l| {
            let body = l.trim_start_matches('+').trim();
            if body.is_empty()
                || body.starts_with("Target ")
                || body.starts_with("Start Time")
                || body.starts_with("End Time")
                || body.contains("host(s) tested")
                || body.contains("requests:")
                || body.contains("item(s) reported")
            {
                return None;
            }
            Some(ExtractedFinding {
                title: truncate_title(body, 120),
                severity: Severity::Low,
                evidence: body.to_string(),
                cve: None,
            })
        })
        .collect()
}

/// Extract XSS findings from dalfox JSON output (one object per line). Every
/// confirmed injection is High. Mirrors the field access in
/// [`dalfox::parse_dalfox_json`](crate::tools::dalfox).
pub fn extract_dalfox(raw: &str) -> Vec<ExtractedFinding> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let xss_type = v
            .get("inject_type")
            .or_else(|| v.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("XSS");
        let param = v.get("param").and_then(|v| v.as_str()).unwrap_or("?");
        let payload = v
            .get("payload")
            .or_else(|| v.get("data"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if payload.is_empty() {
            continue;
        }
        out.push(ExtractedFinding {
            title: format!("XSS ({xss_type}) in parameter `{param}`"),
            severity: Severity::High,
            evidence: format!("param={param} payload={payload}"),
            cve: None,
        });
    }
    out
}

/// Map a CVSS base score to a [`Severity`] using the official FIRST.org CVSS
/// qualitative severity rating scale - identical in CVSS v3.0/v3.1/v4.0:
/// 9.0-10.0 Critical · 7.0-8.9 High · 4.0-6.9 Medium · 0.1-3.9 Low · 0.0 None.
/// Raven has no `None`, so 0.0 (and any out-of-range value) maps to `Info`.
/// Ref: <https://www.first.org/cvss/v4.0/specification-document> §"Qualitative Severity Rating Scale".
pub fn severity_from_cvss(score: f32) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s >= 0.1 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Extract findings from nmap XML - one per CVE reported by the `vulners` NSE
/// script, severity derived from CVSS. Sorted worst-first so the per-scan cap
/// keeps the most severe. Deduplicated downstream by [`auto_save`].
pub fn extract_nmap(raw: &str) -> Vec<ExtractedFinding> {
    let mut pairs = crate::tools::nmap::collect_vulners(raw);
    pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    pairs
        .into_iter()
        .map(|(cve, cvss)| ExtractedFinding {
            title: format!("{cve} (CVSS {cvss})"),
            severity: severity_from_cvss(cvss),
            evidence: format!("nmap vulners: {cve} CVSS {cvss}"),
            cve: Some(cve),
        })
        .collect()
}

/// Find the first `CVE-YYYY-NNNN` token in a line, if any. Avoids a regex dep:
/// anchors on `CVE-` and consumes the following alphanumeric/`-` run.
fn find_cve(line: &str) -> Option<String> {
    let start = line.find("CVE-")?;
    let rest = &line[start..];
    let end = rest
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_alphanumeric() || c == '-'))
        .map_or(rest.len(), |(i, _)| i);
    let cve = &rest[..end];
    (cve.len() >= 8).then(|| cve.to_string()) // at least "CVE-YYYY"
}

/// Extract SQL-injection findings from sqlmap text output. sqlmap only emits a
/// `Parameter: <p> (<METHOD>)` line inside a confirmed injection-point block, so
/// each such line is one High finding; the following `Type:` lines enrich its
/// evidence. A clean ("not injectable") run yields nothing.
///
/// ponytail: anchors on the `Parameter:`/`Type:` line prefixes - robust to
/// sqlmap's verbose progress noise without parsing the whole block structure.
pub fn extract_sqlmap(raw: &str) -> Vec<ExtractedFinding> {
    let clean = crate::tools::strip_ansi(raw);
    let mut out: Vec<ExtractedFinding> = Vec::new();
    for line in clean.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Parameter: ") {
            out.push(ExtractedFinding {
                title: format!("SQL injection in parameter {rest}"),
                severity: Severity::High,
                evidence: format!("sqlmap: {rest}"),
                cve: None,
            });
        } else if t.starts_with("Type:")
            && let Some(last) = out.last_mut()
        {
            last.evidence.push_str(&format!("; {t}"));
        }
    }
    out
}

/// Extract TLS findings from testssl.sh text output - one per line tagged
/// `VULNERABLE` (the negated "not vulnerable" lines are excluded). testssl's
/// text mode drops its own severity rating, so every confirmed vuln is High;
/// a CVE is pulled from the line when present.
///
/// ponytail: flat High severity. For per-CVE bands, run testssl `--json` and
/// read its `severity` field instead.
pub fn extract_testssl(raw: &str) -> Vec<ExtractedFinding> {
    let clean = crate::tools::strip_ansi(raw);
    clean
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("VULNERABLE") && !l.contains("not vulnerable"))
        .map(|l| {
            let name = l.split("VULNERABLE").next().unwrap_or(l).trim();
            let title = if name.is_empty() {
                "TLS vulnerability".to_string()
            } else {
                truncate_title(name, 120)
            };
            ExtractedFinding {
                title: format!("TLS: {title}"),
                severity: Severity::High,
                evidence: l.to_string(),
                cve: find_cve(l),
            }
        })
        .collect()
}

/// Extract secret findings from a gitleaks JSON report. Each leak is High.
///
/// SECURITY: reads only rule/location/description - the `Secret` and `Match`
/// fields are never touched, so a live secret value cannot reach a finding.
pub fn extract_gitleaks(raw: &str) -> Vec<ExtractedFinding> {
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(raw.trim()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| {
            let rule = v
                .get("RuleID")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let file = v
                .get("File")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if rule.is_empty() && file.is_empty() {
                return None;
            }
            let line = v
                .get("StartLine")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let desc = v
                .get("Description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let commit = v
                .get("Commit")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let loc = if commit.is_empty() {
                format!("{file}:{line}")
            } else {
                format!("{file}:{line} (commit {})", &commit[..commit.len().min(8)])
            };
            Some(ExtractedFinding {
                title: format!("Secret: {rule}"),
                severity: Severity::High,
                evidence: format!("{loc} - {desc}"),
                cve: None,
            })
        })
        .collect()
}

/// Extract secret findings from trufflehog JSONL. A *verified* secret (live
/// credential) is Critical; an unverified detection is High.
///
/// SECURITY: reads only detector/verified/location - the `Raw`/`RawV2`/
/// `Redacted` fields are never touched, so a secret value cannot reach a finding.
pub fn extract_trufflehog(raw: &str) -> Vec<ExtractedFinding> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || !t.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else {
            continue;
        };
        let detector = v
            .get("DetectorName")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if detector.is_empty() {
            continue;
        }
        let verified = v
            .get("Verified")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let fs = v
            .get("SourceMetadata")
            .and_then(|m| m.get("Data"))
            .and_then(|d| d.get("Filesystem"));
        let file = fs
            .and_then(|f| f.get("file"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let line_no = fs
            .and_then(|f| f.get("line"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let (severity, mark) = if verified {
            (Severity::Critical, " (verified)")
        } else {
            (Severity::High, "")
        };
        out.push(ExtractedFinding {
            title: format!("Secret: {detector}{mark}"),
            severity,
            evidence: format!("{file}:{line_no}"),
            cve: None,
        });
    }
    out
}

/// Persist auto-extracted findings, gated by config.
///
/// No-op unless `auto_save_findings` is enabled. Findings less severe than
/// `auto_save_min_severity` are dropped; at most `auto_save_max_per_scan` are
/// saved. Each is deduplicated via [`FindingStore::insert_dedup`] and tagged
/// `source = AutoExtracted`. Silent by design (tracing only) - never affects the
/// tool's response or the context budget.
pub fn auto_save(
    store: &Arc<RwLock<FindingStore>>,
    config: &RavenConfig,
    tool: &str,
    target: &str,
    scan_id: Option<String>,
    findings: Vec<ExtractedFinding>,
) {
    if !config.safety.auto_save_findings || findings.is_empty() {
        return;
    }
    // Validated at startup; fall back to Medium if somehow unset.
    let min = parse_severity(&config.safety.auto_save_min_severity).unwrap_or(Severity::Medium);
    let cap = config.safety.auto_save_max_per_scan;

    let mut store = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut saved = 0usize;
    for f in findings {
        if saved >= cap {
            break;
        }
        // Severity is Ord with Critical first, so "at least as severe as min"
        // means f.severity <= min; drop anything less severe.
        if f.severity > min {
            continue;
        }
        let mut finding = Finding::new(
            f.title,
            f.severity,
            format!("Auto-extracted from {tool} output."),
            target.to_string(),
            tool.to_string(),
        );
        finding.evidence = Some(f.evidence);
        finding.cve = f.cve;
        finding.scan_id = scan_id.clone();
        finding.source = FindingSource::AutoExtracted;
        match store.insert_dedup(finding) {
            Ok((_, true)) => saved += 1,
            Ok((_, false)) => {} // duplicate - silently skipped
            Err(e) => tracing::warn!("auto-save insert failed: {e}"),
        }
    }
    if saved > 0 {
        tracing::info!("auto-saved {saved} finding(s) from {tool} against {target}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSONL: &str = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"type":"http","matched-at":"http://x/api"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"type":"http","matched-at":"http://x/"}
not json
{"template-id":"missing-sev","info":{"name":"NoSev"},"type":"http"}"#;

    fn cfg(enabled: bool, min: &str, cap: usize) -> RavenConfig {
        let mut c = RavenConfig::default();
        c.safety.auto_save_findings = enabled;
        c.safety.auto_save_min_severity = min.into();
        c.safety.auto_save_max_per_scan = cap;
        c
    }

    fn store() -> (Arc<RwLock<FindingStore>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = FindingStore::new(dir.path().join("findings")).unwrap();
        (Arc::new(RwLock::new(s)), dir)
    }

    #[test]
    fn extract_nuclei_parses_severity_and_cve() {
        let f = extract_nuclei(JSONL);
        // critical + info parsed; missing-severity and non-json lines skipped.
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].cve.as_deref(), Some("CVE-2021-44228"));
        assert_eq!(f[1].severity, Severity::Info);
        assert_eq!(f[1].cve, None);
    }

    #[test]
    fn parse_severity_accepts_known_lowercase() {
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity(" info "), Some(Severity::Info));
        assert_eq!(parse_severity("bogus"), None);
    }

    #[test]
    fn auto_save_disabled_is_noop() {
        let (s, _d) = store();
        auto_save(
            &s,
            &cfg(false, "info", 25),
            "nuclei",
            "http://x",
            None,
            extract_nuclei(JSONL),
        );
        assert_eq!(s.read().unwrap().list().len(), 0);
    }

    #[test]
    fn auto_save_respects_min_severity() {
        let (s, _d) = store();
        // min = high: only the critical finding qualifies (info dropped).
        auto_save(
            &s,
            &cfg(true, "high", 25),
            "nuclei",
            "http://x",
            None,
            extract_nuclei(JSONL),
        );
        let guard = s.read().unwrap();
        assert_eq!(guard.list().len(), 1);
        assert_eq!(guard.list()[0].severity, Severity::Critical);
        assert_eq!(guard.list()[0].source, FindingSource::AutoExtracted);
    }

    #[test]
    fn auto_save_caps_then_dedups_on_rerun() {
        let (s, _d) = store();
        // cap = 1: only the first qualifying finding (critical) is saved.
        auto_save(
            &s,
            &cfg(true, "info", 1),
            "nuclei",
            "http://x",
            None,
            extract_nuclei(JSONL),
        );
        assert_eq!(s.read().unwrap().list().len(), 1);
        // Re-run uncapped: critical dedups, info is new → total 2.
        auto_save(
            &s,
            &cfg(true, "info", 25),
            "nuclei",
            "http://x",
            None,
            extract_nuclei(JSONL),
        );
        assert_eq!(s.read().unwrap().list().len(), 2);
    }

    #[test]
    fn extract_nikto_keeps_findings_drops_metadata() {
        let raw = "+ Target IP:          10.0.0.1\n\
                   + Target Port:        80\n\
                   + /: X-Frame-Options header is not present.\n\
                   + OSVDB-3092: /admin/: This might be interesting.\n\
                   + 7915 requests: 0 error(s) and 2 item(s) reported\n\
                   + 1 host(s) tested";
        let f = extract_nikto(raw);
        assert_eq!(f.len(), 2); // target/requests/host lines dropped
        assert!(f.iter().all(|x| x.severity == Severity::Low));
        assert!(f[0].title.contains("X-Frame-Options"));
    }

    #[test]
    fn extract_dalfox_marks_xss_high() {
        let json = "{\"inject_type\":\"inHTML-URL\",\"param\":\"q\",\"payload\":\"<script>alert(1)</script>\"}\n\
                    {\"type\":\"V\",\"param\":\"s\",\"payload\":\"\"}";
        let f = extract_dalfox(json);
        assert_eq!(f.len(), 1); // empty-payload row skipped
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].title, "XSS (inHTML-URL) in parameter `q`");
    }

    #[test]
    fn severity_from_cvss_matches_first_org_bands() {
        assert_eq!(severity_from_cvss(9.8), Severity::Critical);
        assert_eq!(severity_from_cvss(9.0), Severity::Critical);
        assert_eq!(severity_from_cvss(8.9), Severity::High);
        assert_eq!(severity_from_cvss(7.0), Severity::High);
        assert_eq!(severity_from_cvss(4.0), Severity::Medium);
        assert_eq!(severity_from_cvss(3.9), Severity::Low);
        assert_eq!(severity_from_cvss(0.1), Severity::Low);
        assert_eq!(severity_from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn extract_sqlmap_flags_injectable_params() {
        let raw = "sqlmap identified the following injection point(s):\n---\n\
                   Parameter: id (GET)\n    Type: boolean-based blind\n    \
                   Title: AND boolean-based blind\n---\nback-end DBMS: MySQL";
        let f = extract_sqlmap(raw);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].title.contains("id (GET)"));
        assert!(f[0].evidence.contains("boolean-based blind"));
    }

    #[test]
    fn extract_sqlmap_ignores_clean_scan() {
        assert!(extract_sqlmap("[WARNING] parameters do not appear to be injectable").is_empty());
    }

    #[test]
    fn extract_testssl_flags_only_vulnerable_with_cve() {
        let raw = "Heartbleed (CVE-2014-0160)   VULNERABLE (NOT ok)\n\
                   CCS (CVE-2014-0224)          not vulnerable (OK)";
        let f = extract_testssl(raw);
        assert_eq!(f.len(), 1); // "not vulnerable" line excluded
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].cve.as_deref(), Some("CVE-2014-0160"));
        assert!(f[0].title.contains("Heartbleed"));
    }

    #[test]
    fn extract_gitleaks_never_emits_secret_value() {
        let json = r#"[{"RuleID":"generic-api-key","Description":"API key","File":"src/config.js","StartLine":12,"Secret":"AKIALEAKEDVALUE","Match":"key=AKIALEAKEDVALUE","Commit":"abcdef1234567890"}]"#;
        let f = extract_gitleaks(json);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].title.contains("generic-api-key"));
        assert!(f[0].evidence.contains("src/config.js:12"));
        let blob = format!("{}|{}", f[0].title, f[0].evidence);
        assert!(!blob.contains("AKIALEAKEDVALUE")); // SECURITY: no secret leak
    }

    #[test]
    fn extract_trufflehog_verified_is_critical_no_leak() {
        let raw = "{\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"a.env\",\"line\":1}}},\"DetectorName\":\"AWS\",\"Verified\":false,\"Raw\":\"AKIALEAK\"}\n\
                   {\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"k.txt\",\"line\":9}}},\"DetectorName\":\"Github\",\"Verified\":true,\"Raw\":\"ghp_LEAK\"}";
        let f = extract_trufflehog(raw);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::High); // unverified
        assert_eq!(f[1].severity, Severity::Critical); // verified
        assert!(f[1].title.contains("verified"));
        let blob: String = f
            .iter()
            .map(|x| format!("{}{}", x.title, x.evidence))
            .collect();
        assert!(!blob.contains("AKIALEAK") && !blob.contains("ghp_LEAK")); // SECURITY
    }

    #[test]
    fn extract_nmap_maps_vulners_cvss_sorted() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host><ports><port portid="80" protocol="tcp">
    <script id="vulners">
      <table key="cpe:/a:apache">
        <table><elem key="id">CVE-2017-9798</elem><elem key="cvss">7.5</elem></table>
        <table><elem key="id">CVE-2021-44790</elem><elem key="cvss">9.8</elem></table>
      </table>
    </script>
  </port></ports></host>
</nmaprun>"#;
        let f = extract_nmap(xml);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].cve.as_deref(), Some("CVE-2021-44790")); // worst-first
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].severity, Severity::High);
    }
}
