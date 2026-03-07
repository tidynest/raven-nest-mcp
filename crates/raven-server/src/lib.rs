//! MCP server crate for the Raven Nest pentesting toolkit.
//!
//! This crate wires together `raven-core` (safety, execution, scans) and
//! `raven-report` (findings, reports) behind an MCP interface:
//!
//! - [`server`] — [`RavenServer`](server::RavenServer) implements the MCP
//!   `ServerHandler` trait and routes tool calls to individual handlers.
//! - [`tools`] — One module per tool (nmap, nuclei, sqlmap, etc.) plus
//!   `scans` (background scan management) and `findings` (persistence/reporting).
//! - [`progress`] — [`ProgressTicker`](progress::ProgressTicker) sends periodic
//!   MCP logging notifications during long-running tool executions.
//! - [`error`] — Maps [`PentestError`](raven_core::error::PentestError) variants
//!   to MCP error codes and formats tool output with quality warnings.

pub mod error;
pub mod progress;
pub mod server;
pub mod tools;
