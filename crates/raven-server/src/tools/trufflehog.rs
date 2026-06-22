//! Secret scanning with verification via trufflehog.
//!
//! Scans a directory tree (`trufflehog filesystem`) for secrets and, unlike
//! gitleaks, can *verify* them by testing the credential against its live API.
//! Verification is **off by default** because it makes outbound calls to
//! third-party services with discovered credentials — opt in with `verify` only
//! when that is in scope for the engagement.
//!
//! The scan path is confined to the configured output directory (plus
//! `/usr/share`, `/usr/lib`) by [`validate_file_path`](super::validate_file_path).
//! Secret values (`Raw`/`RawV2`/`Redacted`) are never echoed by the parser —
//! only the detector name and `file:line` are returned. Slow tool — uses a
//! [`ProgressTicker`](crate::progress::ProgressTicker).
//!
//! SECURITY: never pass `--trust-local-git-config` — it enables RCE from a
//! malicious scanned repo (CVE-2025-41390). This handler scans the working
//! tree only and never touches git config.
//!
//! ponytail: filesystem mode only; git-history scanning needs a `file://` URI
//! and is gitleaks' job anyway. Add a `git` mode here only if a use case appears.

use raven_core::{config::RavenConfig, executor};
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

/// MCP request schema for `run_trufflehog`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrufflehogRequest {
    #[schemars(description = "Directory to scan (must be under the output directory)")]
    pub path: String,
    #[schemars(
        description = "Verify secrets against their live APIs — makes outbound calls with found credentials (default false)"
    )]
    pub verify: Option<bool>,
}

/// Execute trufflehog filesystem secret scanning.
pub async fn run(
    config: &RavenConfig,
    req: TrufflehogRequest,
    peer: Option<rmcp::Peer<rmcp::RoleServer>>,
) -> Result<(CallToolResult, Vec<crate::tools::extract::ExtractedFinding>), rmcp::ErrorData> {
    // Confine the scan root to the engagement workspace (same gate as john).
    super::validate_file_path(&req.path, &config.execution.output_dir)?;

    let mut args = vec!["filesystem", req.path.as_str(), "--json"];
    // Default to detection-only: don't phone discovered secrets out to third
    // parties unless the operator explicitly opts in.
    if !req.verify.unwrap_or(false) {
        args.push("--no-verification");
    }
    // Deliberately no --trust-local-git-config (CVE-2025-41390 RCE).

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "trufflehog".into(), req.path.clone()));

    let result = executor::run(config, "trufflehog", &args, Some(300))
        .await
        .map_err(crate::error::to_mcp)?;

    let mut findings = Vec::new();
    let output = if result.success {
        findings = crate::tools::extract::extract_trufflehog(&result.stdout);
        parse_trufflehog(&result.stdout).unwrap_or_else(|| result.stdout.clone())
    } else {
        crate::error::format_result("trufflehog", &result)
    };
    Ok((
        CallToolResult::success(vec![Content::text(output)]),
        findings,
    ))
}

/// One finding from trufflehog's JSONL output. Only the fields used in the
/// summary are deserialized; `Raw`/`RawV2`/`Redacted` are deliberately omitted
/// so a live secret value can never reach the summary text.
#[derive(serde::Deserialize)]
struct TrufflehogFinding {
    #[serde(rename = "DetectorName")]
    detector: String,
    #[serde(rename = "Verified", default)]
    verified: bool,
    #[serde(rename = "SourceMetadata")]
    source_metadata: SourceMetadata,
}

#[derive(serde::Deserialize)]
struct SourceMetadata {
    #[serde(rename = "Data")]
    data: SourceData,
}

#[derive(serde::Deserialize)]
struct SourceData {
    #[serde(rename = "Filesystem", default)]
    filesystem: Option<FsLocation>,
}

#[derive(serde::Deserialize)]
struct FsLocation {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: i64,
}

/// Parse trufflehog JSONL into a compact summary: one line per finding with
/// detector, `file:line`, and a verified marker. Returns `None` only when the
/// output is non-empty but no line parsed (unexpected format) so the caller
/// falls back to the raw output.
fn parse_trufflehog(raw: &str) -> Option<String> {
    let findings: Vec<TrufflehogFinding> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    if findings.is_empty() {
        return if raw.trim().is_empty() {
            Some("No secrets detected.".to_string())
        } else {
            None // had output but couldn't parse it — fall back to raw
        };
    }

    let verified = findings.iter().filter(|f| f.verified).count();
    let mut out = format!(
        "{} secret(s) detected ({verified} verified):\n",
        findings.len()
    );
    for f in &findings {
        let (file, line) = f
            .source_metadata
            .data
            .filesystem
            .as_ref()
            .map(|fs| (fs.file.as_str(), fs.line))
            .unwrap_or(("unknown", 0));
        let mark = if f.verified { " [VERIFIED]" } else { "" };
        out.push_str(&format!("- [{}] {file}:{line}{mark}\n", f.detector));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real trufflehog `filesystem --json` output (captured from v3), plus a
    // second synthetic verified line to exercise the verified count + marker.
    const SAMPLE: &str = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"a.env","line":1}}},"DetectorType":2,"DetectorName":"AWS","Verified":false,"Raw":"AKIA2E0A8F3B244C9986","RawV2":"AKIA2E0A8F3B244C9986:SECRETLEAKVALUE","Redacted":"AKIA2E0A8F3B244C9986"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"config/keys.txt","line":9}}},"DetectorName":"Github","Verified":true,"Raw":"ghp_REALLEAKTOKEN"}"#;

    #[test]
    fn parse_trufflehog_summarizes_without_leaking_secrets() {
        let out = parse_trufflehog(SAMPLE).unwrap();
        assert!(out.contains("2 secret(s) detected (1 verified)"));
        assert!(out.contains("[AWS] a.env:1"));
        assert!(out.contains("[Github] config/keys.txt:9 [VERIFIED]"));
        // No secret value may appear in the summary.
        assert!(!out.contains("AKIA2E0A8F3B244C9986"));
        assert!(!out.contains("SECRETLEAKVALUE"));
        assert!(!out.contains("ghp_REALLEAKTOKEN"));
    }

    #[test]
    fn parse_trufflehog_handles_clean_scan() {
        assert_eq!(parse_trufflehog("").unwrap(), "No secrets detected.");
    }

    #[test]
    fn parse_trufflehog_falls_back_on_garbage() {
        assert!(parse_trufflehog("trufflehog: error: bad path").is_none());
    }
}
