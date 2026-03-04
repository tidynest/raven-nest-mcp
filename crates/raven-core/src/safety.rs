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
    const BANNED: &[char] = &[';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!','\n'];
    if let Some(c) = target.chars().find(|c| BANNED.contains(c)) {
        return Err(PentestError::InvalidTarget(
            format!("forbidden character: '{c}'"),
        ));
    }

    // Try parsing as URL first - tools like nuclei/whatweb accept full URLs
    if let Ok(parsed) = url::Url::parse(target) {
        return match parsed.scheme() {
            "http" | "https" => {
                parsed.host_str()
                    .ok_or_else(|| PentestError::InvalidTarget("URL has no host".into()))
                    .map(|_| ())
            }
            scheme => Err(PentestError::InvalidTarget(
                format!("unsupported scheme: '{scheme}' (only http/https allowed)"),
            )),
        };
    }

    // Accept valid IP addresses directly
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Accept CIDR notation (e.g. 192.168.1.0/24)
    if let Some((ip_part, mask)) = target.split_once('/') {
        let valid_cidr = ip_part.parse::<IpAddr>().is_ok()
            && mask.parse::<u8>().is_ok_and(|bits| bits <= 128);
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
