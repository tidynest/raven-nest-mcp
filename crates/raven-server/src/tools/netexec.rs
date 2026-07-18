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

use raven_core::{config::RavenConfig, safety};
use rmcp::{Peer, RoleServer, model::CallToolResult, schemars};

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
    super::run_and_format(config, "nxc", &arg_refs, None, |s| {
        if s.trim().is_empty() {
            Some("NetExec completed with no output.".to_string())
        } else {
            parse_netexec_output(s)
        }
    })
    .await
}

/// A NetExec output line begins with a known protocol token (`SMB`, `LDAP`,
/// `SSH`, ...); everything else (tracebacks, connection errors) is not.
fn is_nxc_line(l: &str) -> bool {
    l.split_whitespace()
        .next()
        .is_some_and(|tok| PROTOCOLS.contains(&tok.to_ascii_lowercase().as_str()))
}

/// Structure NetExec (`nxc`) output: strip terminal colour, hoist the
/// authentication verdict to the top, and keep the per-host result lines
/// (banner, enumerated shares/users/etc.) in order without duplicates.
///
/// NetExec prefixes every line with `PROTO  IP  PORT  HOST` and marks status
/// with `[*]` (info), `[+]` (success), `[-]` (failure); `(Pwn3d!)` flags
/// privileged access. Returns `None` when no line is NetExec-shaped, so the
/// caller falls back to raw stdout.
pub fn parse_netexec_output(raw: &str) -> Option<String> {
    let clean = super::strip_ansi(raw);
    let lines: Vec<&str> = clean
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if !lines.iter().any(|l| is_nxc_line(l)) {
        return None;
    }

    let verdict = if lines.iter().any(|l| l.contains("(Pwn3d!)")) {
        Some("[+] Authentication succeeded - privileged/admin access (Pwn3d!)")
    } else if lines.iter().any(|l| l.contains("[+]")) {
        Some("[+] Authentication succeeded")
    } else if lines.iter().any(|l| l.contains("[-]")) {
        Some("[-] Authentication failed")
    } else {
        None
    };

    let mut seen = std::collections::HashSet::new();
    let body: Vec<&str> = lines
        .iter()
        .filter(|l| is_nxc_line(l))
        .filter(|l| seen.insert(**l))
        .copied()
        .collect();

    let mut out = String::new();
    if let Some(v) = verdict {
        out.push_str(v);
        out.push_str("\n\n");
    }
    out.push_str(&body.join("\n"));
    Some(out)
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
    fn parse_netexec_hoists_pwned_verdict_and_strips_ansi() {
        let raw = "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 (domain:CORP) (signing:True)\n\
                   \x1b[1m\x1b[32mSMB  10.10.10.5  445  DC01  [+] CORP\\administrator:Passw0rd! (Pwn3d!)\x1b[0m";
        let out = parse_netexec_output(raw).unwrap();
        assert!(out.starts_with("[+] Authentication succeeded - privileged/admin access (Pwn3d!)"));
        assert!(out.contains("(domain:CORP)")); // banner kept
        assert!(out.contains("administrator:Passw0rd!"));
        assert!(!out.contains('\x1b')); // colour stripped
    }

    #[test]
    fn parse_netexec_reports_failure_and_dedups() {
        let line = "SMB  10.10.10.5  445  DC01  [-] CORP\\bob:wrongpass STATUS_LOGON_FAILURE";
        let raw = format!("{line}\n{line}"); // duplicate line
        let out = parse_netexec_output(&raw).unwrap();
        assert!(out.starts_with("[-] Authentication failed"));
        assert_eq!(out.matches("STATUS_LOGON_FAILURE").count(), 1); // deduped
    }

    #[test]
    fn parse_netexec_keeps_enumeration_without_verdict() {
        let raw = "SMB  10.10.10.5  445  DC01  [*] Enumerated shares\n\
                   SMB  10.10.10.5  445  DC01  ADMIN$          READ,WRITE      Remote Admin";
        let out = parse_netexec_output(raw).unwrap();
        assert!(!out.starts_with("[+]") && !out.starts_with("[-]")); // no auth verdict
        assert!(out.contains("ADMIN$"));
    }

    #[test]
    fn parse_netexec_non_nxc_output_falls_back() {
        assert!(parse_netexec_output("").is_none());
        assert!(parse_netexec_output("[-] Connection error: host unreachable").is_none());
        assert!(parse_netexec_output("Traceback (most recent call last):").is_none());
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
