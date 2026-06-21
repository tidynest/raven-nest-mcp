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

/// Validate that a file path is within allowed directories.
///
/// Pentesting tools like hydra, john, feroxbuster, and ffuf accept file paths
/// for wordlists and hash files. Without validation, an LLM could read arbitrary
/// files (e.g. `/etc/shadow`) by passing them as wordlist paths.
///
/// Allowed prefixes: `/usr/share/`, `/usr/lib/`, and the configured `output_dir`.
/// Rejects paths containing `..` or shell metacharacters.
pub(crate) fn validate_file_path(path: &str, output_dir: &str) -> Result<(), rmcp::ErrorData> {
    if path.is_empty() {
        return Err(rmcp::ErrorData::invalid_params("file path is empty", None));
    }
    // Reject path traversal
    if path.contains("..") {
        return Err(rmcp::ErrorData::invalid_params(
            "file path must not contain '..'",
            None,
        ));
    }
    // Reject shell metacharacters
    if path.contains(|c: char| ";&|`$(){}<!>\n".contains(c)) {
        return Err(rmcp::ErrorData::invalid_params(
            "file path contains invalid characters",
            None,
        ));
    }
    // Check allowed directory prefixes (ensure trailing slash to prevent
    // sibling-directory bypass: /tmp/raven-nest vs /tmp/raven-nestevil/)
    let output_dir_slash = if output_dir.ends_with('/') {
        output_dir.to_string()
    } else {
        format!("{output_dir}/")
    };
    let allowed_prefixes: [&str; 3] = ["/usr/share/", "/usr/lib/", &output_dir_slash];
    if !allowed_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return Err(rmcp::ErrorData::invalid_params(
            format!(
                "file path must be under /usr/share/, /usr/lib/, or the configured output directory ({})",
                output_dir
            ),
            None,
        ));
    }
    Ok(())
}

/// Validate that a port specification contains only digits, commas, and hyphens.
///
/// Nmap and masscan accept port specs like `80,443` or `1-1000`. While
/// `Command::arg()` prevents shell injection, validating the format is
/// defense-in-depth against tools that might split arguments internally.
pub(crate) fn validate_port_spec(spec: &str) -> Result<(), rmcp::ErrorData> {
    if spec.is_empty() {
        return Err(rmcp::ErrorData::invalid_params("port spec is empty", None));
    }
    if !spec
        .chars()
        .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
    {
        return Err(rmcp::ErrorData::invalid_params(
            "port spec must contain only digits, commas, and hyphens (e.g. '80,443' or '1-1000')",
            None,
        ));
    }
    Ok(())
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

#[cfg(test)]
mod path_validation_tests {
    use super::*;

    #[test]
    fn accepts_seclists_wordlist() {
        assert!(
            validate_file_path(
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                "/tmp/raven-nest"
            )
            .is_ok()
        );
    }

    #[test]
    fn accepts_output_dir_path() {
        assert!(validate_file_path("/tmp/raven-nest/hashes.txt", "/tmp/raven-nest").is_ok());
    }

    #[test]
    fn accepts_usr_lib_path() {
        assert!(validate_file_path("/usr/lib/john/password.lst", "/tmp/raven-nest").is_ok());
    }

    #[test]
    fn rejects_etc_shadow() {
        assert!(validate_file_path("/etc/shadow", "/tmp/raven-nest").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_file_path("/usr/share/../../etc/passwd", "/tmp/raven-nest").is_err());
    }

    #[test]
    fn rejects_relative_traversal() {
        assert!(validate_file_path("../../etc/passwd", "/tmp/raven-nest").is_err());
    }

    #[test]
    fn rejects_metacharacters() {
        assert!(validate_file_path("/usr/share/test;rm -rf /", "/tmp/raven-nest").is_err());
        assert!(validate_file_path("/usr/share/test$(whoami)", "/tmp/raven-nest").is_err());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(validate_file_path("", "/tmp/raven-nest").is_err());
    }

    #[test]
    fn rejects_home_directory() {
        assert!(validate_file_path("/home/user/wordlist.txt", "/tmp/raven-nest").is_err());
    }
}

#[cfg(test)]
mod port_validation_tests {
    use super::*;

    #[test]
    fn accepts_single_port() {
        assert!(validate_port_spec("80").is_ok());
    }

    #[test]
    fn accepts_port_list() {
        assert!(validate_port_spec("80,443,8080").is_ok());
    }

    #[test]
    fn accepts_port_range() {
        assert!(validate_port_spec("1-1000").is_ok());
    }

    #[test]
    fn accepts_mixed_spec() {
        assert!(validate_port_spec("22,80,443,8000-9000").is_ok());
    }

    #[test]
    fn rejects_spaces() {
        assert!(validate_port_spec("80 443").is_err());
    }

    #[test]
    fn rejects_flags() {
        assert!(validate_port_spec("80 -sV").is_err());
    }

    #[test]
    fn rejects_semicolons() {
        assert!(validate_port_spec("80;nmap").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_port_spec("").is_err());
    }
}

pub mod lenient;

pub mod dalfox;
pub mod dnsrecon;
pub mod dnsx;
pub mod enum4linux_ng;
pub mod feroxbuster;
pub mod ffuf;
pub mod findings;
pub mod http;
pub mod httpx;
pub mod hydra;
pub mod john;
pub mod katana;
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
