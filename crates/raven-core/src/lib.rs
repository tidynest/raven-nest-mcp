//! Core library for the Raven Nest pentesting toolkit.
//!
//! This crate provides the foundational layers that `raven-server` and
//! `raven-report` build upon:
//!
//! - [`config`] — TOML-based configuration with safety limits and network settings.
//! - [`error`] — Shared error type used across all three crates.
//! - [`executor`] — Sandboxed command execution with timeout, proxy injection,
//!   and output quality assessment.
//! - [`safety`] — Input validation (allowlisting, target sanitisation, output
//!   truncation) that prevents shell injection and resource abuse.
//! - [`scan_manager`] — Background scan orchestration with concurrency limits
//!   and memory-spill-to-disk for large outputs.

pub mod config;
pub mod error;
pub mod executor;
pub mod safety;
pub mod scan_manager;
