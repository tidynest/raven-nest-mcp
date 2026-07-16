//! SMB and Active Directory enumeration via enum4linux-ng.
//!
//! Discovers shares, users, groups, password policies, and OS information.
//! Uses `-A` (all simple enumeration) by default and supports authenticated
//! enumeration with optional SMB credentials.

use raven_core::{config::RavenConfig, safety};
use rmcp::{Peer, RoleServer, model::CallToolResult, schemars};

/// MCP request schema for `run_enum4linux_ng`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Enum4linuxRequest {
    #[schemars(description = "Target IP or hostname")]
    pub target: String,
    #[schemars(description = "SMB username for authenticated enumeration")]
    pub username: Option<String>,
    #[schemars(description = "SMB password")]
    pub password: Option<String>,
    #[schemars(description = "Timeout in seconds")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,
}

/// Execute enum4linux-ng with all simple enumeration and optional credentials.
pub async fn run(
    config: &RavenConfig,
    req: Enum4linuxRequest,
    peer: Option<Peer<RoleServer>>,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "enum4linux-ng".into(), req.target.clone())
    });

    let mut args = vec!["-A".to_string()];

    if let Some(ref user) = req.username {
        args.extend(["-u".into(), user.clone()]);
    }
    if let Some(ref pass) = req.password {
        args.extend(["-p".into(), pass.clone()]);
    }

    args.push(req.target);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "enum4linux-ng", &arg_refs, req.timeout_secs, |s| {
        parse_enum4linux_output(s, result_limit)
    })
    .await
}

/// Section kinds recognised in enum4linux-ng text output.
#[derive(Clone, Copy)]
enum Section {
    Os,
    Shares,
    Users,
    Groups,
    PasswordPolicy,
    Other,
}

/// Parse enum4linux-ng text output into a compact per-section summary.
///
/// Sections are delimited by `====` banner lines whose inner text determines
/// the category (OS, Shares, Users, Groups, Password Policy). Within each
/// section, lines starting with `[+]` (findings) and `[*]` (info) are kept,
/// capped at `max_items` per section.
///
/// Returns `None` if the output contains no actionable `[+]` or `[*]` lines.
pub fn parse_enum4linux_output(raw: &str, max_items: usize) -> Option<String> {
    // Strip ANSI color codes (enum4linux-ng emits colored output by default)
    let raw = &super::strip_ansi(raw);
    let mut current_section = Section::Other;
    let mut os_items = Vec::new();
    let mut share_items = Vec::new();
    let mut user_items = Vec::new();
    let mut group_items = Vec::new();
    let mut policy_items = Vec::new();
    let mut other_items = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();

        // Detect section headers: inner text between "|" delimiters
        if trimmed.starts_with('|') && trimmed.ends_with('|') {
            let inner = trimmed.trim_matches('|').trim().to_lowercase();
            current_section = if inner.contains("os information") {
                Section::Os
            } else if inner.contains("share") {
                Section::Shares
            } else if inner.contains("user") {
                Section::Users
            } else if inner.contains("group") {
                Section::Groups
            } else if inner.contains("password policy") {
                Section::PasswordPolicy
            } else {
                Section::Other
            };
            continue;
        }

        // Skip decorative lines
        if trimmed.starts_with('=') || trimmed.is_empty() {
            continue;
        }

        // Keep finding ([+]) and info ([*]) lines
        if !trimmed.starts_with("[+]") && !trimmed.starts_with("[*]") {
            continue;
        }

        // Strip the prefix marker for cleaner output
        let content = trimmed
            .strip_prefix("[+]")
            .or_else(|| trimmed.strip_prefix("[*]"))
            .unwrap_or(trimmed)
            .trim();

        let bucket = match current_section {
            Section::Os => &mut os_items,
            Section::Shares => &mut share_items,
            Section::Users => &mut user_items,
            Section::Groups => &mut group_items,
            Section::PasswordPolicy => &mut policy_items,
            Section::Other => &mut other_items,
        };
        if bucket.len() < max_items {
            bucket.push(content.to_string());
        }
    }

    let total = os_items.len()
        + share_items.len()
        + user_items.len()
        + group_items.len()
        + policy_items.len()
        + other_items.len();
    if total == 0 {
        return None;
    }

    let mut out = String::new();
    let sections: &[(&str, &[String])] = &[
        ("OS", &os_items),
        ("Shares", &share_items),
        ("Users", &user_items),
        ("Groups", &group_items),
        ("Password Policy", &policy_items),
        ("Other", &other_items),
    ];

    for (label, items) in sections {
        if items.is_empty() {
            continue;
        }
        out.push_str(label);
        out.push_str(": ");
        out.push_str(&items.join(", "));
        out.push('\n');
    }

    Some(out.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_multiple_sections() {
        let raw = r#"
 ==============================
 |    OS Information    |
 ==============================
 [+] OS: Windows 10.0 Build 19041

 ==============================
 |    Shares via SMBv1    |
 ==============================
 [+] ADMIN$  Disk  Remote Admin
 [+] C$      Disk  Default share
 [+] IPC$    IPC   Remote IPC
 [+] SharedDocs  Disk  Shared Documents

 ==============================
 |    Users via RPC    |
 ==============================
 [+] 'administrator' (desc: Built-in account)
 [+] 'guest' (desc: Built-in account)
 [+] 'testuser' (desc: Test account)

 ==============================
 |    Groups via RPC    |
 ==============================
 [+] Administrators
 [+] Users
 [+] Remote Desktop Users

 ==============================
 |    Password Policy via RPC    |
 ==============================
 [+] min length: 7
 [+] lockout threshold: 0
"#;
        let result = parse_enum4linux_output(raw, 20).unwrap();
        assert!(result.contains("OS: "));
        assert!(result.contains("Windows 10.0 Build 19041"));
        assert!(result.contains("Shares: "));
        assert!(result.contains("ADMIN$"));
        assert!(result.contains("SharedDocs"));
        assert!(result.contains("Users: "));
        assert!(result.contains("administrator"));
        assert!(result.contains("Groups: "));
        assert!(result.contains("Remote Desktop Users"));
        assert!(result.contains("Password Policy: "));
        assert!(result.contains("min length: 7"));
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse_enum4linux_output("", 20).is_none());
        assert!(parse_enum4linux_output("some random text\nno findings", 20).is_none());
        assert!(parse_enum4linux_output("======\n|  OS  |\n======\n", 20).is_none());
    }

    #[test]
    fn parse_info_markers_included() {
        let raw = r#"
 ==============================
 |    OS Information    |
 ==============================
 [*] Server allows unauthenticated sessions
 [+] OS: Linux 5.15
"#;
        let result = parse_enum4linux_output(raw, 20).unwrap();
        assert!(result.contains("Server allows unauthenticated sessions"));
        assert!(result.contains("Linux 5.15"));
    }

    #[test]
    fn parse_caps_items_per_section() {
        let mut raw = String::from(
            " ==============================\n |    Users via RPC    |\n ==============================\n",
        );
        for i in 0..30 {
            raw.push_str(&format!(" [+] user{i}\n"));
        }
        let result = parse_enum4linux_output(&raw, 20).unwrap();
        // Only first 20 should appear
        assert!(result.contains("user0"));
        assert!(result.contains("user19"));
        assert!(!result.contains("user20"));
    }
}
