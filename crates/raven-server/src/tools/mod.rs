//! Tool handler modules — one per external pentesting tool.
//!
//! Each module exports a `run()` async function that:
//! 1. Validates input via [`safety::validate_target`](raven_core::safety::validate_target).
//! 2. Optionally starts a [`ProgressTicker`](crate::progress::ProgressTicker) for long-running tools.
//! 3. Builds CLI arguments with safety-capped parameters.
//! 4. Delegates execution to [`executor::run`](raven_core::executor::run).
//! 5. Formats output via [`error::format_result`](crate::error::format_result).
//!
//! Additionally, [`scans`] handles background scan launch/poll/cancel, and
//! [`findings`] manages finding persistence and report generation.

/// Detect whether a target URL points to localhost.
///
/// Used by [`feroxbuster`] and [`ffuf`] to reduce default thread counts for
/// local targets, preventing self-DoS during development testing.
pub(crate) fn is_localhost(target: &str) -> bool {
    let lower = target.to_lowercase();
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(&lower);
    host_part.starts_with("localhost")
        || host_part.starts_with("127.0.0.1")
        || host_part.starts_with("[::1]")
}

/// Strip ANSI escape codes from tool output.
///
/// Many CLI tools emit terminal control codes (colors, cursor movement) even
/// in non-interactive mode. These waste context tokens and confuse parsers.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // CSI sequence: ESC [ ... final_byte
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c.is_ascii_alphabetic() || c == '~' {
                        break;
                    }
                }
            } else if matches!(chars.peek(), Some(&'(' | &')' | &'*' | &'+')) {
                chars.next();
                chars.next();
            } else {
                chars.next();
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::is_localhost;

    #[test]
    fn localhost_variants() {
        assert!(is_localhost("http://localhost:3000"));
        assert!(is_localhost("http://127.0.0.1:8080/path"));
        assert!(is_localhost("https://localhost/foo"));
        assert!(is_localhost("http://[::1]:3000"));
        assert!(is_localhost("localhost"));
    }

    #[test]
    fn remote_targets() {
        assert!(!is_localhost("http://example.com"));
        assert!(!is_localhost("https://10.0.0.1:443"));
        assert!(!is_localhost("remote.example.com"));
    }
}

pub mod lenient;

pub mod dalfox;
pub mod dnsrecon;
pub mod enum4linux_ng;
pub mod feroxbuster;
pub mod ffuf;
pub mod findings;
pub mod http;
pub mod hydra;
pub mod john;
pub mod masscan;
pub mod msf_auxiliary;
pub mod msf_exploit;
pub mod msf_module_info;
pub mod msf_post;
pub mod msf_search;
pub mod msf_sessions;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod ping;
pub mod scans;
pub mod sqlmap;
pub mod subfinder;
pub mod testssl;
pub mod whatweb;
pub mod wpscan;
