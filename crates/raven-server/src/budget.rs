//! Session-aware output budget tracker for context window management.
//!
//! [`SessionBudget`] tracks cumulative output across an MCP session and
//! dynamically adjusts per-tool output caps to prevent context overflow on
//! local AI models with limited context windows (49-64K).
//!
//! The budget starts with a total based on `context_budget` minus estimated
//! overhead (tool descriptions, instructions, AI reasoning). Each tool call
//! consumes from the remaining budget, and the per-tool cap shrinks as the
//! session progresses.
//!
//! When `context_budget` is 0 (disabled), the tracker is permissive — all
//! tools get [`OutputMode::Full`] with generous caps.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Output verbosity mode, automatically escalated as context budget is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Full parsed output — all findings, all details.
    Full,
    /// Aggressive filtering — only critical/high findings, top-N results.
    Compact,
    /// One-line summary only.
    Minimal,
}

/// Per-tool output allocation returned by [`SessionBudget::allocate`].
#[derive(Debug, Clone)]
pub struct OutputCap {
    /// Maximum characters this tool response may contain.
    pub max_chars: usize,
    /// Recommended output verbosity for parsers.
    pub mode: OutputMode,
}

/// Tracks cumulative context usage across an MCP session.
///
/// Held as `Arc<SessionBudget>` within [`RavenServer`](crate::server::RavenServer)
/// and consulted before/after every tool call.
pub struct SessionBudget {
    /// Total usable chars for tool outputs (context_budget minus overhead).
    usable_budget: usize,
    /// Whether budgeting is active (context_budget > 0).
    enabled: bool,
    /// Cumulative chars sent so far.
    cumulative: AtomicUsize,
    /// Number of tool calls processed.
    call_count: AtomicUsize,
    /// Expected total tool calls per session.
    expected_calls: usize,
}

/// Estimated chars per tool for JSON schema in MCP tool list.
const SCHEMA_CHARS_PER_TOOL: usize = 350;
/// Estimated chars for server instructions.
const INSTRUCTION_OVERHEAD: usize = 500;
/// Estimated chars of AI reasoning per tool call turn.
const REASONING_PER_TURN: usize = 1500;
/// Minimum chars always available (enough for errors and budget status).
const FLOOR: usize = 500;
// Budget status line is always appended; reserve space for it.
// const STATUS_LINE_RESERVE: usize = 100;

impl SessionBudget {
    /// Create a budget tracker from configuration.
    ///
    /// - `context_budget`: model's total context window in characters (0 = disabled).
    /// - `tool_count`: number of registered MCP tools.
    /// - `expected_calls`: anticipated tool calls per session (default 10).
    pub fn new(context_budget: usize, tool_count: usize, expected_calls: usize) -> Self {
        if context_budget == 0 {
            return Self {
                usable_budget: 0,
                enabled: false,
                cumulative: AtomicUsize::new(0),
                call_count: AtomicUsize::new(0),
                expected_calls: 100,
            };
        }

        let tool_overhead = tool_count * SCHEMA_CHARS_PER_TOOL;
        let reasoning_overhead = expected_calls * REASONING_PER_TURN;
        let total_overhead = tool_overhead + INSTRUCTION_OVERHEAD + reasoning_overhead;
        let usable = context_budget.saturating_sub(total_overhead);

        Self {
            usable_budget: usable,
            enabled: true,
            cumulative: AtomicUsize::new(0),
            call_count: AtomicUsize::new(0),
            expected_calls,
        }
    }

    /// Whether budget tracking is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Characters remaining in the session budget.
    pub fn remaining(&self) -> usize {
        if !self.enabled {
            return usize::MAX;
        }
        self.usable_budget
            .saturating_sub(self.cumulative.load(Ordering::Relaxed))
    }

    /// Number of tool calls processed so far.
    pub fn calls_made(&self) -> usize {
        self.call_count.load(Ordering::Relaxed)
    }

    /// Allocate output budget for the next tool call.
    ///
    /// Returns the maximum chars and recommended output mode based on
    /// remaining budget and expected remaining calls.
    pub fn allocate(&self) -> OutputCap {
        if !self.enabled {
            return OutputCap {
                max_chars: 50_000,
                mode: OutputMode::Full,
            };
        }

        let remaining = self.remaining();
        let calls_made = self.calls_made();
        let remaining_calls = self.expected_calls.saturating_sub(calls_made).max(1);

        // Fair share: divide remaining by remaining expected calls
        let per_call = remaining / remaining_calls;

        // Percentage of budget consumed
        let consumed_pct = if self.usable_budget > 0 {
            ((self.usable_budget.saturating_sub(remaining)) * 100) / self.usable_budget
        } else {
            100
        };

        let mode = if remaining < 1000 || consumed_pct > 70 {
            OutputMode::Minimal
        } else if consumed_pct > 40 {
            OutputMode::Compact
        } else {
            OutputMode::Full
        };

        let max_chars = match mode {
            OutputMode::Full => per_call.clamp(FLOOR, 8_000),
            OutputMode::Compact => per_call.clamp(FLOOR, 3_000),
            OutputMode::Minimal => per_call.clamp(200, FLOOR),
        };

        OutputCap { max_chars, mode }
    }

    /// Record chars actually sent for a completed tool call.
    pub fn record(&self, chars: usize) {
        if self.enabled {
            self.cumulative.fetch_add(chars, Ordering::Relaxed);
        }
        self.call_count.fetch_add(1, Ordering::Relaxed);
    }

    /// One-line status appended to every tool response.
    ///
    /// Tells the AI model how much budget remains and what output mode is active,
    /// enabling it to make informed decisions about which tools to run next.
    pub fn status_line(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let remaining = self.remaining();
        let used = self.cumulative.load(Ordering::Relaxed);
        let calls_made = self.calls_made();
        let remaining_calls = self.expected_calls.saturating_sub(calls_made).max(1);
        let per_remaining = remaining / remaining_calls;

        let mode_label = if remaining < 1000 {
            "exhausted"
        } else {
            let consumed_pct = if self.usable_budget > 0 {
                ((self.usable_budget.saturating_sub(remaining)) * 100) / self.usable_budget
            } else {
                100
            };
            if consumed_pct > 70 {
                "minimal"
            } else if consumed_pct > 40 {
                "compact"
            } else {
                "full"
            }
        };

        Some(format!(
            "[budget: {used}/{} used | ~{per_remaining}/call | mode: {mode_label}]",
            self.usable_budget
        ))
    }

    /// Whether the budget is exhausted (< 1000 chars remaining).
    pub fn is_exhausted(&self) -> bool {
        self.enabled && self.remaining() < 1000
    }

    /// Truncate text to fit within a character cap, preserving head (70%) and tail (30%).
    pub fn truncate_to_cap(output: &str, cap: usize) -> String {
        let char_count = output.chars().count();
        if char_count <= cap {
            return output.to_string();
        }

        let head_chars = (cap * 70) / 100;
        let marker = "--- truncated ---\n";
        let tail_chars = cap.saturating_sub(head_chars).saturating_sub(marker.len());

        // Find byte boundaries for char-level slicing
        let head_end = output
            .char_indices()
            .nth(head_chars)
            .map(|(i, _)| i)
            .unwrap_or(output.len());
        let tail_start = output
            .char_indices()
            .rev()
            .nth(tail_chars.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(output.len());

        if tail_start <= head_end || tail_chars == 0 {
            // Not enough room for both; take head only
            let end = output
                .char_indices()
                .nth(cap.saturating_sub(marker.len()))
                .map(|(i, _)| i)
                .unwrap_or(output.len());
            format!("{}{marker}", &output[..end])
        } else {
            format!("{}{marker}{}", &output[..head_end], &output[tail_start..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_budget_returns_full_mode() {
        let budget = SessionBudget::new(0, 22, 10);
        assert!(!budget.is_enabled());
        let cap = budget.allocate();
        assert_eq!(cap.mode, OutputMode::Full);
        assert_eq!(cap.max_chars, 50_000);
    }

    #[test]
    fn enabled_budget_starts_full() {
        let budget = SessionBudget::new(65_536, 22, 10);
        assert!(budget.is_enabled());
        let cap = budget.allocate();
        assert_eq!(cap.mode, OutputMode::Full);
        assert!(cap.max_chars > 0);
    }

    #[test]
    fn budget_shrinks_with_usage() {
        let budget = SessionBudget::new(49_000, 22, 10);
        let initial = budget.remaining();

        // Simulate several large outputs
        budget.record(5_000);
        budget.record(5_000);
        budget.record(5_000);

        assert!(budget.remaining() < initial);
        assert_eq!(budget.calls_made(), 3);
    }

    #[test]
    fn mode_escalates_to_compact() {
        let budget = SessionBudget::new(49_000, 22, 10);
        let usable = budget.usable_budget;

        // Consume ~45% of budget
        budget.record((usable * 45) / 100);

        let cap = budget.allocate();
        assert_eq!(cap.mode, OutputMode::Compact);
    }

    #[test]
    fn mode_escalates_to_minimal() {
        let budget = SessionBudget::new(49_000, 22, 10);
        let usable = budget.usable_budget;

        // Consume ~75% of budget
        budget.record((usable * 75) / 100);

        let cap = budget.allocate();
        assert_eq!(cap.mode, OutputMode::Minimal);
    }

    #[test]
    fn exhausted_budget_detected() {
        let budget = SessionBudget::new(49_000, 22, 10);
        assert!(!budget.is_exhausted());

        // Consume almost everything
        budget.record(budget.usable_budget.saturating_sub(500));
        assert!(budget.is_exhausted());
    }

    #[test]
    fn status_line_present_when_enabled() {
        let budget = SessionBudget::new(65_536, 22, 10);
        budget.record(1_000);
        let status = budget.status_line();
        assert!(status.is_some());
        let line = status.unwrap();
        assert!(line.contains("budget:"));
        assert!(line.contains("mode: full"));
    }

    #[test]
    fn status_line_absent_when_disabled() {
        let budget = SessionBudget::new(0, 22, 10);
        assert!(budget.status_line().is_none());
    }

    #[test]
    fn truncate_short_text_unchanged() {
        let text = "hello world";
        assert_eq!(SessionBudget::truncate_to_cap(text, 100), text);
    }

    #[test]
    fn truncate_long_text_preserves_head_and_tail() {
        let text: String = (0..1000).map(|i| format!("{i:03} ")).collect();
        let truncated = SessionBudget::truncate_to_cap(&text, 200);
        assert!(truncated.len() <= 800); // char count <= 200 but bytes may differ
        assert!(truncated.contains("truncated"));
        // Head preserved
        assert!(truncated.starts_with("000 001 002"));
    }

    #[test]
    fn per_call_allocation_divides_fairly() {
        let budget = SessionBudget::new(65_536, 22, 10);
        let _ = budget.allocate();

        // After 5 calls consuming 2K each
        for _ in 0..5 {
            budget.record(2_000);
        }
        let cap = budget.allocate();

        // Allocation still returns a positive cap
        assert!(cap.max_chars > 0);
        assert_eq!(budget.calls_made(), 5);
    }
}
