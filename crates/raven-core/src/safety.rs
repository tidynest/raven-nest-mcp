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

    // Try parsing as URL — only if it looks like one (avoids false positives
    // from url::Url::parse treating IPv6 CIDR like "fe80::/10" as scheme "fe80")
    if (target.starts_with("http://") || target.starts_with("https://"))
        && let Ok(parsed) = url::Url::parse(target)
    {
        return parsed
            .host_str()
            .ok_or_else(|| PentestError::InvalidTarget("URL has no host".into()))
            .map(|_| ());
    }

    // Accept valid IP addresses directly
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Accept CIDR notation (e.g. 192.168.1.0/24) with correct max prefix per IP version
    if let Some((ip_part, mask)) = target.split_once('/')
        && let Ok(ip) = ip_part.parse::<IpAddr>()
    {
        let max_bits: u8 = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if mask.parse::<u8>().is_ok_and(|bits| bits <= max_bits) {
            return Ok(());
        }
    }

    // Accept host:port (e.g. "example.com:443") — split on last colon,
    // validate host as hostname and port as u16
    if let Some((host, port_str)) = target.rsplit_once(':')
        && !host.is_empty()
        && port_str.parse::<u16>().is_ok()
    {
        return validate_hostname(host);
    }

    // Accept bare hostnames
    validate_hostname(target)
}

fn validate_hostname(host: &str) -> Result<(), PentestError> {
    if host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.starts_with('-')
        && !host.ends_with('-')
    {
        Ok(())
    } else {
        Err(PentestError::InvalidTarget(host.to_string()))
    }
}

/// Truncate long output, preserving the first 70% and last 30%.
/// This ensures you see both the beginning (headers/metadata) and
/// end (summary/final results) of tool output.
/// Uses char boundaries to avoid panicking on multi-byte UTF-8.
pub fn truncate_output(output: &str, max_chars: usize) -> String {
    let char_count = output.chars().count();
    if char_count <= max_chars {
        return output.to_string();
    }

    let head_chars = max_chars * 7 / 10;
    let tail_chars = max_chars - head_chars;

    // Find byte offset of the head_chars-th character
    let head_end = output
        .char_indices()
        .nth(head_chars)
        .map_or(output.len(), |(i, _)| i);

    // Find byte offset for the tail (char_count - tail_chars from start)
    let tail_start = output
        .char_indices()
        .nth(char_count - tail_chars)
        .map_or(output.len(), |(i, _)| i);

    let omitted = char_count - max_chars;
    format!(
        "{}\n\n--- truncated {omitted} chars ---\n\n{}",
        &output[..head_end],
        &output[tail_start..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SafetyConfig;

    fn test_config() -> SafetyConfig {
        SafetyConfig {
            allowed_tools: vec!["nmap".into(), "ping".into()],
            max_output_chars: 50_000,
            tool_paths: std::collections::HashMap::new(),
            sqlmap_max_level: 2,
            sqlmap_max_risk: 1,
            hydra_max_tasks: 4,
            masscan_max_rate: 1000,
        }
    }

    // --- check_allowlist ---

    #[test]
    fn allowlist_accepts_listed_tool() {
        assert!(check_allowlist("nmap", &test_config()).is_ok());
    }

    #[test]
    fn allowlist_rejects_unlisted_tool() {
        assert!(check_allowlist("sqlmap", &test_config()).is_err());
    }

    // --- validate_target: valid inputs ---

    #[test]
    fn target_accepts_ipv4() {
        assert!(validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn target_accepts_ipv6() {
        assert!(validate_target("::1").is_ok());
    }

    #[test]
    fn target_accepts_http_url() {
        assert!(validate_target("http://example.com").is_ok());
    }

    #[test]
    fn target_accepts_https_url() {
        assert!(validate_target("https://example.com/path").is_ok());
    }

    #[test]
    fn target_accepts_hostname() {
        assert!(validate_target("scan.example.com").is_ok());
    }

    #[test]
    fn target_accepts_cidr_v4() {
        assert!(validate_target("10.0.0.0/8").is_ok());
        assert!(validate_target("192.168.1.0/32").is_ok());
    }

    #[test]
    fn target_accepts_cidr_v6() {
        assert!(validate_target("fe80::/10").is_ok());
        assert!(validate_target("::1/128").is_ok());
    }

    // --- validate_target: CIDR boundary enforcement ---

    #[test]
    fn target_rejects_ipv4_cidr_over_32() {
        assert!(validate_target("192.168.1.0/33").is_err());
        assert!(validate_target("10.0.0.0/128").is_err());
    }

    #[test]
    fn target_rejects_ipv6_cidr_over_128() {
        assert!(validate_target("fe80::/129").is_err());
    }

    // --- validate_target: shell injection ---

    #[test]
    fn target_rejects_shell_metacharacters() {
        let payloads = [
            "127.0.0.1; rm -rf /",
            "target | cat /etc/passwd",
            "host & whoami",
            "$(command)",
            "`whoami`",
            "host\ninjected",
        ];
        for payload in &payloads {
            assert!(
                validate_target(payload).is_err(),
                "should reject: {payload}"
            );
        }
    }

    #[test]
    fn target_rejects_empty() {
        assert!(validate_target("").is_err());
    }

    #[test]
    fn target_rejects_unsupported_scheme() {
        assert!(validate_target("ftp://files.example.com").is_err());
    }

    // --- validate_target: host:port ---

    #[test]
    fn target_accepts_host_port() {
        assert!(validate_target("example.com:443").is_ok());
        assert!(validate_target("scan.example.com:8080").is_ok());
    }

    #[test]
    fn target_rejects_invalid_host_port() {
        assert!(validate_target(":443").is_err()); // empty host
        assert!(validate_target("example.com:99999").is_err()); // port > u16
    }

    // --- truncate_output ---

    #[test]
    fn truncate_returns_short_output_unchanged() {
        let input = "short output";
        assert_eq!(truncate_output(input, 100), input);
    }

    #[test]
    fn truncate_preserves_head_and_tail() {
        let input: String = (0..100).map(|i| char::from(b'a' + (i % 26))).collect();
        let result = truncate_output(&input, 20);
        // 70% of 20 = 14 head chars, 30% = 6 tail chars
        assert!(result.starts_with(&input[..14]));
        assert!(result.ends_with(&input[94..]));
        assert!(result.contains("--- truncated 80 chars ---"));
    }

    #[test]
    fn truncate_handles_multibyte_utf8() {
        // Each emoji is 4 bytes — this would panic with byte-based slicing
        let input: String = "🔥".repeat(50);
        let result = truncate_output(&input, 20);
        // Should not panic, and should contain valid UTF-8
        assert!(result.contains("--- truncated"));
        // Verify head has 14 fire emojis (70% of 20)
        assert!(result.starts_with(&"🔥".repeat(14)));
    }

    #[test]
    fn truncate_handles_empty_string() {
        assert_eq!(truncate_output("", 10), "");
    }

    #[test]
    fn truncate_exact_boundary() {
        let input = "a".repeat(100);
        // Exactly at limit — should return unchanged
        assert_eq!(truncate_output(&input, 100), input);
        // One over — should truncate
        let result = truncate_output(&input, 99);
        assert!(result.contains("--- truncated 1 chars ---"));
    }

    #[test]
    fn truncate_mixed_multibyte() {
        // Mix of ASCII (1 byte), 2-byte, 3-byte, and 4-byte chars
        let input = "aé中🔥".repeat(10); // 4 chars × 10 = 40 chars
        let result = truncate_output(&input, 20);
        assert!(result.contains("--- truncated"));
        // No panic = success for boundary safety
    }
}
