//! Findings storage and report generation for the Raven Nest toolkit.
//!
//! This crate owns the persistence layer for pentest findings and the
//! multi-format report generators (Markdown, JSON, SARIF, HTML). It has no
//! dependency on MCP or the server —
//! only `raven-server::tools::findings` calls into it.
//!
//! - [`finding`] — Data types: [`Finding`](finding::Finding),
//!   [`FindingMeta`](finding::FindingMeta), [`Severity`](finding::Severity).
//! - [`store`] — File-per-finding persistence with an in-memory index.
//!   Handles legacy migration from the old single-file format.
//! - [`markdown`], [`json`], [`sarif`], [`html`] — Report generators, one per
//!   output format. Each exposes `generate_report(&[&Finding], title) -> String`.
//! - [`summary`] — Shared severity-count / overall-risk / tool-list helpers used
//!   by every generator, so the summary numbers stay consistent across formats.
//! - [`report`] — [`ReportFormat`](report::ReportFormat) selector mapping a
//!   format name to its generator and file extension.

pub mod finding;
pub mod html;
pub mod json;
pub mod markdown;
pub mod report;
pub mod sarif;
pub mod store;
pub(crate) mod summary;
