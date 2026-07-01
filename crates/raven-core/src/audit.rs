//! Append-only audit trail of every tool invocation.
//!
//! Hooked into [`executor::run_inner`](crate::executor), this records which tool
//! ran with which arguments and what the outcome was, to a `0600` JSON-lines
//! file at `{output_dir}/audit.log`. The server performs intrusive, sometimes
//! `sudo`-privileged actions on an operator's behalf; an immutable trail makes
//! those actions accountable and reconstructable after the fact.
//!
//! Best-effort by design: a write failure is logged via `tracing` and never
//! fails the tool call. Credential-bearing arguments are redacted (see
//! [`redact`]); the target itself is *not* a secret and stays visible.

use crate::config::RavenConfig;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Flags whose *following* argument is a secret regardless of tool
/// (e.g. `--password hunter2`, sqlmap `--cookie ...`).
const SECRET_FLAGS: &[&str] = &[
    "--cookie",
    "--data",
    "--auth-cred",
    "--password",
    "--passlist",
    "--token",
    "--api-key",
    "--auth",
    "--header",
    "-H", // header (nuclei cookie) / NTLM hash (nxc) - always credential-bearing
];

/// Short flags that carry a credential ONLY for credential-brute tools
/// (hydra `-p <pass>` / `-P <passlist>`). Elsewhere `-p` is benign - e.g.
/// nmap `-p 80,443` is a port list - so gating by tool keeps non-secret
/// args in the trail instead of over-redacting them.
const CRED_SHORT_FLAGS: &[&str] = &["-p", "-P"];

/// Tools for which [`CRED_SHORT_FLAGS`] are treated as secret-bearing
/// (hydra `-p`/`-P`, NetExec `-p` password).
const CRED_TOOLS: &[&str] = &["hydra", "nxc"];

/// Substrings marking an inline argument as carrying a credential
/// (e.g. a hydra form string `user=^USER^&pass=^PASS^`).
const SECRET_SUBSTRINGS: &[&str] = &[
    "password=",
    "passwd=",
    "pass=",
    "pwd=",
    "token=",
    "secret=",
    "authorization:",
    "cookie:",
];

/// Rotate the log once it grows past this size (single generation kept as `.1`).
const AUDIT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Serializes rotation-check + append so two concurrent records can't race the
/// rename. The file is opened per-write (tool calls are infrequent), so no
/// long-lived handle is held.
static AUDIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// One audit record, serialised as a single JSON line.
pub struct AuditEntry<'a> {
    pub tool: &'a str,
    pub args: &'a [&'a str],
    pub exit_code: Option<i32>,
    pub success: bool,
    pub duration_ms: u128,
    pub sudo: bool,
    pub bytes_out: usize,
    pub quality: &'a str,
}

/// Redact secret-bearing arguments: the value after a [`SECRET_FLAGS`] flag, and
/// any argument containing a [`SECRET_SUBSTRINGS`] marker. Everything else
/// (notably the target) passes through verbatim.
fn redact(tool: &str, args: &[&str]) -> Vec<String> {
    let cred_tool = CRED_TOOLS.contains(&tool);
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for &a in args {
        if redact_next {
            out.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }
        if SECRET_FLAGS.contains(&a) || (cred_tool && CRED_SHORT_FLAGS.contains(&a)) {
            out.push(a.to_string());
            redact_next = true;
            continue;
        }
        let lower = a.to_ascii_lowercase();
        if SECRET_SUBSTRINGS.iter().any(|s| lower.contains(s)) {
            out.push("<redacted>".to_string());
        } else {
            out.push(a.to_string());
        }
    }
    out
}

/// Append one JSON line to `{output_dir}/audit.log`, rotating if oversized.
fn append_line(config: &RavenConfig, line: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::path::Path::new(&config.execution.output_dir).join("audit.log");
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > AUDIT_MAX_BYTES
    {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(f, "{line}")
}

/// Record one tool invocation. Best-effort - never fails the caller.
pub fn record(config: &RavenConfig, entry: &AuditEntry) {
    let line = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "tool": entry.tool,
        "args": redact(entry.tool, entry.args),
        "exit_code": entry.exit_code,
        "success": entry.success,
        "duration_ms": entry.duration_ms,
        "sudo": entry.sudo,
        "bytes_out": entry.bytes_out,
        "quality": entry.quality,
    })
    .to_string();

    let lock = AUDIT_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(e) = append_line(config, &line) {
        tracing::warn!("audit log write failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_value_after_secret_flag() {
        let args = [
            "-l",
            "admin",
            "-P",
            "/wordlists/rockyou.txt",
            "ssh://10.0.0.1",
        ];
        let red = redact("hydra", &args);
        assert_eq!(red[2], "-P");
        assert_eq!(red[3], "<redacted>");
        // target stays visible
        assert_eq!(red[4], "ssh://10.0.0.1");
        // non-secret flag value stays
        assert_eq!(red[1], "admin");
    }

    #[test]
    fn redacts_inline_credential_substrings() {
        let args = ["--data", "user=admin&pass=secret", "http://x/login"];
        let red = redact("sqlmap", &args);
        // --data flag redacts the NEXT arg regardless
        assert_eq!(red[1], "<redacted>");
        assert_eq!(red[2], "http://x/login");
    }

    #[test]
    fn passes_through_benign_args() {
        let args = ["-sV", "-T4", "scanme.nmap.org"];
        assert_eq!(redact("nmap", &args), vec!["-sV", "-T4", "scanme.nmap.org"]);
    }

    #[test]
    fn cred_short_flag_is_tool_scoped() {
        // nmap: `-p` is a port list, must NOT be redacted
        let nmap = redact("nmap", &["-p", "80,443", "scanme.nmap.org"]);
        assert_eq!(nmap[1], "80,443");
        // hydra: `-p` is a password, MUST be redacted
        let hydra = redact("hydra", &["-p", "hunter2", "ssh://10.0.0.1"]);
        assert_eq!(hydra[1], "<redacted>");
    }

    #[test]
    fn redacts_netexec_credentials() {
        // nxc password (-p) and hash (-H) must both be redacted; target stays.
        let pw = redact(
            "nxc",
            &["smb", "10.0.0.1", "-u", "admin", "-p", "Secret123"],
        );
        assert_eq!(pw[4], "-p");
        assert_eq!(pw[5], "<redacted>");
        assert_eq!(pw[1], "10.0.0.1");
        let h = redact(
            "nxc",
            &["smb", "10.0.0.1", "-u", "admin", "-H", "aabbcc:ddeeff"],
        );
        assert_eq!(h[4], "-H");
        assert_eq!(h[5], "<redacted>");
    }
}
