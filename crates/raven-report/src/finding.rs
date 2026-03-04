use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub target: String,
    pub tool: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cvss: Option<f32>,
    pub cve: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
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