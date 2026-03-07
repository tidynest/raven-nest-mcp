//! Findings storage and report generation for the Raven Nest toolkit.
//!
//! This crate owns the persistence layer for pentest findings and the
//! markdown report generator. It has no dependency on MCP or the server —
//! only `raven-server::tools::findings` calls into it.
//!
//! - [`finding`] — Data types: [`Finding`](finding::Finding),
//!   [`FindingMeta`](finding::FindingMeta), [`Severity`](finding::Severity).
//! - [`store`] — File-per-finding persistence with an in-memory index.
//!   Handles legacy migration from the old single-file format.
//! - [`markdown`] — Generates structured pentest reports with executive
//!   summary, severity breakdown, and per-finding detail sections.

pub mod finding;
pub mod markdown;
pub mod store;
