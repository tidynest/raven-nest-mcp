//! Core data types for vulnerability findings.
//!
//! [`Finding`] is the full record persisted to disk as individual JSON files.
//! [`FindingMeta`] is a lightweight projection kept in the
//! [`FindingStore`](crate::store::FindingStore) in-memory index, avoiding
//! disk I/O for listing and sorting operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Vulnerability severity level, ordered from most to least critical.
///
/// Derives `Ord` so findings can be sorted by severity (Critical first)
/// in [`FindingStore::list`](crate::store::FindingStore::list).
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

/// Complete vulnerability finding, persisted as `{id}.json` in the findings directory.
///
/// Created by [`save_finding`](raven_server::tools::findings::save_finding) through
/// the MCP interface. Required fields are set via [`Finding::new`]; optional fields
/// (evidence, remediation, CVSS, CVE) are populated after construction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    /// UUID v4 assigned at creation.
    pub id: String,
    /// Short title summarizing the vulnerability (e.g. "Reflected XSS in search").
    pub title: String,
    pub severity: Severity,
    /// Detailed description of the vulnerability and its impact.
    pub description: String,
    /// Affected target (IP, URL, or hostname).
    pub target: String,
    /// Tool that discovered this finding (e.g. "nuclei", "sqlmap").
    pub tool: String,
    /// Raw output excerpt proving the vulnerability exists.
    pub evidence: Option<String>,
    /// Suggested fix or mitigation.
    pub remediation: Option<String>,
    /// CVSS 3.x base score (0.0–10.0).
    pub cvss: Option<f32>,
    /// CVE identifier (e.g. "CVE-2024-1234").
    pub cve: Option<String>,
    /// When this finding was recorded.
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    /// Create a new finding with required fields. Optional fields default to `None`.
    pub fn new(
        title: String,
        severity: Severity,
        description: String,
        target: String,
        tool: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            severity,
            description,
            target,
            tool,
            evidence: None,
            remediation: None,
            cvss: None,
            cve: None,
            timestamp: Utc::now(),
        }
    }
}

/// Lightweight metadata projection — keeps only index-worthy fields in memory.
///
/// Full finding data (description, evidence, remediation) lives on disk and is
/// loaded on demand by [`FindingStore::get`](crate::store::FindingStore::get).
/// This lets [`FindingStore::list`](crate::store::FindingStore::list) return
/// sorted results with zero disk I/O.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingMeta {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub target: String,
    pub tool: String,
    pub timestamp: DateTime<Utc>,
}

impl From<&Finding> for FindingMeta {
    fn from(f: &Finding) -> Self {
        Self {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
            target: f.target.clone(),
            tool: f.tool.clone(),
            timestamp: f.timestamp,
        }
    }
}
