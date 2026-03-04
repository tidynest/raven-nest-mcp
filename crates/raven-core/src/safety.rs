use crate::config::SafetyConfig;
use crate::error::PentestError;
use std::net::IpAddr;

/// Reject if the tool isn't in the allowlist.
pub fn check_allowlist(tool: &str, config: &SafetyConfig) -> Result<(), PentestError> {
    if config.allowed_tools.iter().any(|t| t == tool) {
        Ok(())
    } else {
        Err(PentestError::ToolNotAllowed(tool.to_string()))
    }
}

/// Validate that a target string is a reasonable IP, hostname, or CIDR.
/// Rejects shell metacharacters to prevent injection.
pub fn validate_target(target: &str) -> Result<(), PentestError> {
    if target.is_empty() {
        return Err(PentestError::InvalidTarget("empty target".into()));
    }

    // Rejects shell metacharacters
    const BANNED: &[char] = &[
        ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\n',
    ];
    if let Some(c) = target.chars().find(|c| BANNED.contains(c)) {
        return Err(PentestError::InvalidTarget(format!(
            "forbidden character: '{c}'"
        )));
    }

    // Try parsing as URL first - tools like nuclei/whatweb accept full URLs
    if let Ok(parsed) = url::Url::parse(target) {
        return match parsed.scheme() {
            "http" | "https" => parsed
                .host_str()
                .ok_or_else(|| PentestError::InvalidTarget("URL has no host".into()))
                .map(|_| ()),
            scheme => Err(PentestError::InvalidTarget(format!(
                "unsupported scheme: '{scheme}' (only http/https allowed)"
            ))),
        };
    }

    // Accept valid IP addresses directly
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Accept CIDR notation (e.g. 192.168.1.0/24)
    if let Some((ip_part, mask)) = target.split_once('/') {
        let valid_cidr =
            ip_part.parse::<IpAddr>().is_ok() && mask.parse::<u8>().is_ok_and(|bits| bits <= 128);
        if valid_cidr {
            return Ok(());
        }
    }

    // Accept hostnames: alphanumeric, hyphens, dots, max 253 chars
    if target.len() <= 253
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !target.starts_with('-')
        && !target.ends_with('-')
    {
        return Ok(());
    }

    Err(PentestError::InvalidTarget(target.to_string()))
}

/// Truncate long output, preserving the first 70% and last 30%.
/// This ensures you see both the beginning (headers/metadata) and
/// end (summary/final results) of tool output.
pub fn truncate_output(output: &str, max_chars: usize) -> String {
    if output.len() <= max_chars {
        return output.to_string();
    }

    let head_len = max_chars * 7 / 10;
    let tail_len = max_chars - head_len;

    let head = &output[..head_len];
    let tail = &output[output.len() - tail_len..];
    let omitted = output.len() - max_chars;

    format!("{head}\n\n--- truncated {omitted} chars ---\n\n{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SafetyConfig;

    fn default_safety() -> SafetyConfig {
        SafetyConfig {
            allowed_tools: vec!["nmap".into(), "nuclei".into(), "nikto".into()],
            max_output_chars: 50_000,
        }
    }

    // ── check_allowlist ──────────────────────────────────────

    #[test]
    fn allowlist_permits_listed_tool() {
        assert!(check_allowlist("nmap", &default_safety()).is_ok());
    }

    #[test]
    fn allowlist_rejects_unlisted_tool() {
        let err = check_allowlist("evil", &default_safety()).unwrap_err();
        assert!(matches!(err, PentestError::ToolNotAllowed(_)));
    }

    #[test]
    fn allowlist_empty_rejects_everything() {
        let cfg = SafetyConfig {
            allowed_tools: vec![],
            max_output_chars: 50_000,
        };
        assert!(check_allowlist("nmap", &cfg).is_err());
    }

    // ── validate_target ──────────────────────────────────────

    #[test]
    fn valid_ipv4() {
        assert!(validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn valid_ipv6() {
        assert!(validate_target("::1").is_ok());
    }

    #[test]
    fn valid_hostname() {
        assert!(validate_target("scanme.nmap.org").is_ok());
    }

    #[test]
    fn valid_http_url() {
        assert!(validate_target("https://example.com/path").is_ok());
    }

    #[test]
    fn valid_cidr() {
        assert!(validate_target("10.0.0.0/24").is_ok());
    }

    #[test]
    fn rejects_empty() {
        let err = validate_target("").unwrap_err();
        assert!(matches!(err, PentestError::InvalidTarget(_)));
    }

    #[test]
    fn rejects_shell_metachar_semicolon() {
        let err = validate_target("10.0.0.1; rm -rf /").unwrap_err();
        match err {
            PentestError::InvalidTarget(msg) => assert!(msg.contains("forbidden character")),
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[test]
    fn rejects_shell_metachar_pipe() {
        assert!(validate_target("host | cat /etc/passwd").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let err = validate_target("ftp://evil.com").unwrap_err();
        match err {
            PentestError::InvalidTarget(msg) => assert!(msg.contains("unsupported scheme")),
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[test]
    fn rejects_url_without_host() {
        assert!(validate_target("http://").is_err());
    }

    #[test]
    fn rejects_hostname_with_leading_hyphen() {
        assert!(validate_target("-evil.com").is_err());
    }

    #[test]
    fn rejects_backtick_injection() {
        assert!(validate_target("`whoami`.evil.com").is_err());
    }

    // ── truncate_output ──────────────────────────────────────

    #[test]
    fn no_truncation_under_limit() {
        let input = "short output";
        assert_eq!(truncate_output(input, 100), input);
    }

    #[test]
    fn truncation_preserves_head_and_tail() {
        let input: String = "A".repeat(70) + &"B".repeat(30);
        let result = truncate_output(&input, 50);
        // head = 35 chars of 'A', tail = 15 chars of 'B'
        assert!(result.starts_with(&"A".repeat(35)));
        assert!(result.ends_with(&"B".repeat(15)));
    }

    #[test]
    fn truncation_message_shows_char_count() {
        let input = "X".repeat(200);
        let result = truncate_output(&input, 100);
        assert!(result.contains("truncated 100 chars"));
    }
}
