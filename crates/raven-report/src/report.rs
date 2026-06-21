//! Report format selection.
//!
//! [`ReportFormat`] enumerates the output formats and maps each to its
//! generator and file extension. Parsed case-insensitively from a user-supplied
//! string by [`raven_server::tools::findings::generate_report`].

use crate::finding::Finding;
use crate::{html, json, markdown, sarif};

/// Supported report output formats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReportFormat {
    /// Human-readable markdown (the default).
    #[default]
    Markdown,
    /// Versioned JSON envelope for machine consumption.
    Json,
    /// SARIF 2.1.0 for code-scanning dashboards.
    Sarif,
    /// Self-contained dark-themed HTML.
    Html,
}

impl ReportFormat {
    /// Parse a format name case-insensitively. Returns `None` for unknown values.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "markdown" | "md" => Some(Self::Markdown),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// File extension for this format, without the leading dot.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Html => "html",
        }
    }

    /// Render the report body for this format.
    pub fn render(&self, findings: &[&Finding], title: &str) -> String {
        match self {
            Self::Markdown => markdown::generate_report(findings, title),
            Self::Json => json::generate_report(findings, title),
            Self::Sarif => sarif::generate_report(findings, title),
            Self::Html => html::generate_report(findings, title),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(
            ReportFormat::parse("markdown"),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(ReportFormat::parse("MD"), Some(ReportFormat::Markdown));
        assert_eq!(ReportFormat::parse("JSON"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::parse("Sarif"), Some(ReportFormat::Sarif));
        assert_eq!(ReportFormat::parse(" html "), Some(ReportFormat::Html));
    }

    #[test]
    fn parse_rejects_unknown() {
        assert_eq!(ReportFormat::parse("pdf"), None);
        assert_eq!(ReportFormat::parse(""), None);
    }

    #[test]
    fn default_is_markdown() {
        assert_eq!(ReportFormat::default(), ReportFormat::Markdown);
    }

    #[test]
    fn extensions_match() {
        assert_eq!(ReportFormat::Markdown.extension(), "md");
        assert_eq!(ReportFormat::Json.extension(), "json");
        assert_eq!(ReportFormat::Sarif.extension(), "sarif");
        assert_eq!(ReportFormat::Html.extension(), "html");
    }
}
