//! NetExec credentialed network-execution handler - gated, off by default.
//!
//! NetExec (`nxc`) authenticates to network services and enumerates them. This
//! handler is deliberately restrictive, because the tool is intrusive and
//! credentialed:
//!
//! - **Disabled by default** - runs only when `[netexec] enabled = true`.
//! - **Read-only actions only** - a curated allowlist (auth + enumeration); no
//!   command execution (`-x`/`-X`), no modules (`-M`), no credential dumping
//!   (`--sam`/`--lsa`/`--ntds`).
//! - **Single scalar credential** - one username + one password OR hash; never a
//!   list/file (no spray), and no `--continue-on-success`.
//! - **Single host** - CIDR, dash-notation IP ranges, comma lists, and target
//!   files are all rejected (one credential across many hosts is spray).
//!
//! `destructive_hint` is set on the tool because failed authentication can lock
//! out accounts.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// Protocols NetExec may target. Curated and explicit.
const PROTOCOLS: &[&str] = &["smb", "winrm", "ssh", "ldap", "mssql", "ftp", "rdp"];

/// Map a curated read-only action to its NetExec flags. Returns `None` for an
/// unknown action. NO command/module execution and NO credential dumping are
/// reachable here - that is the security boundary, not a convenience list.
fn action_flags(action: &str) -> Option<&'static [&'static str]> {
    Some(match action {
        "auth" => &[],
        "shares" => &["--shares"],
        "users" => &["--users"],
        "groups" => &["--groups"],
        "loggedon" => &["--loggedon-users"],
        "sessions" => &["--sessions"],
        "disks" => &["--disks"],
        "pass-pol" => &["--pass-pol"],
        _ => return None,
    })
}

/// MCP request schema for `run_netexec`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetExecRequest {
    #[schemars(description = "Protocol: smb, winrm, ssh, ldap, mssql, ftp, rdp")]
    pub protocol: String,
    #[schemars(description = "Single target host or IP (no CIDR ranges)")]
    pub target: String,
    #[schemars(description = "Username (single value, not a list or file)")]
    pub username: String,
    #[schemars(description = "Password (single). Provide password OR hash, not both.")]
    pub password: Option<String>,
    #[schemars(description = "NTLM hash for pass-the-hash (single). Provide password OR hash.")]
    pub hash: Option<String>,
    #[schemars(
        description = "Read-only action: auth (default), shares, users, groups, loggedon, sessions, disks, pass-pol"
    )]
    pub action: Option<String>,
}

/// Reject credential/identifier values that could inject a flag or be read as a
/// file (NetExec treats a `-u`/`-p` value pointing at an existing file as a
/// *list*). This keeps credentials strictly scalar without rejecting legitimate
/// password characters (spaces, `/`, `\`, symbols are all allowed in a literal).
fn validate_scalar(label: &str, value: &str) -> Result<(), rmcp::ErrorData> {
    if value.is_empty() {
        return Err(rmcp::ErrorData::invalid_params(
            format!("{label} must not be empty"),
            None,
        ));
    }
    if value.starts_with('-') {
        return Err(rmcp::ErrorData::invalid_params(
            format!("{label} must not start with '-' (flag-injection guard)"),
            None,
        ));
    }
    if std::path::Path::new(value).is_file() {
        return Err(rmcp::ErrorData::invalid_params(
            format!("{label} resolves to a file - pass a single value, not a list (no spray)"),
            None,
        ));
    }
    Ok(())
}

/// Reject targets NetExec would expand to MORE than one host: CIDR (`/`),
/// dash-notation IP ranges (`10.0.0.1-20` - a digit-`-`-digit), comma/whitespace
/// lists, or a path to an existing file (NetExec reads a target file as a host
/// list). A single IP or an ordinary hostname (whose hyphens sit beside letters)
/// passes. This is the credential-spray boundary, so it errs toward rejection.
fn reject_multihost_target(target: &str) -> Result<(), rmcp::ErrorData> {
    let multi = target.contains('/')
        || target.contains(',')
        || target.chars().any(char::is_whitespace)
        || std::path::Path::new(target).is_file()
        || target
            .as_bytes()
            .windows(3)
            .any(|w| w[1] == b'-' && w[0].is_ascii_digit() && w[2].is_ascii_digit());
    if multi {
        return Err(rmcp::ErrorData::invalid_params(
            "NetExec targets a single host only - no CIDR, IP ranges (a-b), lists, or target files"
                .to_string(),
            None,
        ));
    }
    Ok(())
}

/// Execute a gated, read-only NetExec enumeration against a single host.
pub async fn run(
    config: &RavenConfig,
    req: NetExecRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    if !config.netexec.enabled {
        return Err(rmcp::ErrorData::invalid_params(
            "NetExec is disabled. Set [netexec] enabled = true in config to use it - \
             it is intrusive and credentialed, so enable it only for authorized engagements.",
            None,
        ));
    }

    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;
    // Single host only - reject anything NetExec would expand to multiple hosts.
    reject_multihost_target(&req.target)?;

    let protocol = req.protocol.to_ascii_lowercase();
    if !PROTOCOLS.contains(&protocol.as_str()) {
        return Err(rmcp::ErrorData::invalid_params(
            format!(
                "unsupported protocol '{protocol}' - allowed: {}",
                PROTOCOLS.join(", ")
            ),
            None,
        ));
    }

    let action = req.action.as_deref().unwrap_or("auth");
    let Some(flags) = action_flags(action) else {
        return Err(rmcp::ErrorData::invalid_params(
            "invalid action - allowed: auth, shares, users, groups, loggedon, sessions, disks, pass-pol"
                .to_string(),
            None,
        ));
    };

    // Exactly one scalar credential: password XOR hash.
    let (cred_flag, cred_value) = match (&req.password, &req.hash) {
        (Some(p), None) => ("-p", p),
        (None, Some(h)) => ("-H", h),
        (Some(_), Some(_)) => {
            return Err(rmcp::ErrorData::invalid_params(
                "provide password OR hash, not both",
                None,
            ));
        }
        (None, None) => {
            return Err(rmcp::ErrorData::invalid_params(
                "a credential is required: provide a password or an NTLM hash",
                None,
            ));
        }
    };
    validate_scalar("username", &req.username)?;
    validate_scalar("credential", cred_value)?;

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "netexec".into(), req.target.clone()));

    let mut args = vec![
        protocol,
        req.target.clone(),
        "-u".to_string(),
        req.username.clone(),
        cred_flag.to_string(),
        cred_value.clone(),
    ];
    args.extend(flags.iter().map(|s| s.to_string()));

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = executor::run(config, "nxc", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    let output = if result.success {
        let mut out = result.stdout.clone();
        if out.trim().is_empty() {
            out = "NetExec completed with no output.".to_string();
        }
        if let Some(ref warning) = result.warning {
            out.push_str(&format!("\n\n⚠ {warning}"));
        }
        out
    } else {
        crate::error::format_result("nxc", &result)
    };
    Ok(CallToolResult::success(vec![Content::text(output)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_flags_allows_only_read_only_actions() {
        assert_eq!(action_flags("auth"), Some(&[][..]));
        assert_eq!(action_flags("shares"), Some(&["--shares"][..]));
        assert_eq!(action_flags("pass-pol"), Some(&["--pass-pol"][..]));
        // Execution / module / dumping actions are NOT reachable.
        assert_eq!(action_flags("exec"), None);
        assert_eq!(action_flags("-x"), None);
        assert_eq!(action_flags("sam"), None);
        assert_eq!(action_flags("ntds"), None);
        assert_eq!(action_flags("modules"), None);
    }

    #[test]
    fn validate_scalar_rejects_flag_and_empty() {
        assert!(validate_scalar("username", "").is_err());
        assert!(validate_scalar("username", "-M").is_err()); // flag injection
        assert!(validate_scalar("username", "administrator").is_ok());
        // Legitimate password characters are allowed in a literal value.
        assert!(validate_scalar("credential", "P@ss/w0rd!").is_ok());
        assert!(validate_scalar("credential", "DOMAIN\\admin").is_ok());
    }

    #[test]
    fn validate_scalar_rejects_existing_file() {
        // A value pointing at a real file would be read by NetExec as a list.
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        assert!(validate_scalar("credential", path).is_err());
    }

    #[test]
    fn protocols_are_curated() {
        assert!(PROTOCOLS.contains(&"smb"));
        assert!(!PROTOCOLS.contains(&"raw"));
    }

    #[test]
    fn reject_multihost_target_blocks_ranges_lists_and_cidr() {
        // single-host forms pass
        assert!(reject_multihost_target("10.0.0.5").is_ok());
        assert!(reject_multihost_target("dc01.corp.local").is_ok());
        assert!(reject_multihost_target("web-01.example.com").is_ok()); // hyphen by letters
        // multi-host forms are rejected (NetExec would expand these)
        assert!(reject_multihost_target("10.0.0.1-254").is_err()); // dash range
        assert!(reject_multihost_target("10.0.0.1-10.0.0.9").is_err());
        assert!(reject_multihost_target("10.0.0.0/24").is_err()); // CIDR
        assert!(reject_multihost_target("10.0.0.1,10.0.0.2").is_err()); // comma list
    }
}
