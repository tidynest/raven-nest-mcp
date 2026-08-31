//! Hydra network authentication brute-force handler.
//!
//! Hydra tests login credentials against network services (SSH, FTP, HTTP forms,
//! etc.). Parallel task count is capped by [`SafetyConfig::hydra_max_tasks`](raven_core::config::SafetyConfig::hydra_max_tasks)
//! to limit brute-force throughput.
//!
//! The `-f` flag is always set (stop on first valid credential pair), and
//! `http-*-form` services require the `form_params` field to specify the
//! login path, form fields, and failure condition.

use raven_core::{config::RavenConfig, safety};
use rmcp::{Peer, RoleServer, model::CallToolResult, schemars};

/// MCP request schema for `run_hydra`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydraRequest {
    #[schemars(description = "Target IP or hostname")]
    pub target: String,
    #[schemars(description = "Service to attack (e.g. 'ssh', 'ftp', 'http-post-form')")]
    pub service: String,
    #[schemars(description = "Target port (default: service default)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub port: Option<u16>,
    #[schemars(description = "Path to username list file")]
    pub userlist: String,
    #[schemars(description = "Path to password list file")]
    pub passlist: String,
    #[schemars(description = "Number of parallel tasks (capped by config)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub tasks: Option<u16>,
    #[schemars(
        description = "Form attack string for http-post-form/http-get-form (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')"
    )]
    pub form_params: Option<String>,
}

/// Validate a hydra service name.
///
/// The service is passed as a *positional* argument after the target, so a
/// value like `-R` would be parsed by hydra as a flag - the same flag-injection
/// class [`safety::validate_target`](raven_core::safety::validate_target)
/// rejects for targets. Real hydra service names are lowercase alphanumeric
/// with hyphens (`ssh`, `http-post-form`, `oracle-listener`), so this charset
/// is both tight and complete.
fn validate_service(service: &str) -> Result<(), rmcp::ErrorData> {
    let ok = !service.is_empty()
        && !service.starts_with('-')
        && service
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(rmcp::ErrorData::invalid_params(
            "service must use only lowercase letters, digits, and hyphens (e.g. 'ssh', 'http-post-form') and must not start with '-'",
            None,
        ))
    }
}

/// Validate a form-attack string (`/login:user=^USER^&pass=^PASS^:F=incorrect`).
///
/// Also positional, so it must not start with '-' (flag injection); control
/// characters (newlines in particular) are rejected because hydra splits the
/// string on `:` internally. Everything else - `/ : = ^ &` spaces, symbols -
/// is legitimate in a form definition and allowed.
fn validate_form_params(params: &str) -> Result<(), rmcp::ErrorData> {
    if params.is_empty() || params.starts_with('-') || params.chars().any(char::is_control) {
        return Err(rmcp::ErrorData::invalid_params(
            "form_params must be non-empty, must not start with '-', and must not contain control characters",
            None,
        ));
    }
    Ok(())
}

/// Execute hydra with safety-capped parallelism and form-service validation.
pub async fn run(
    config: &RavenConfig,
    req: HydraRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    // Validate wordlist paths - prevent reading arbitrary files
    super::validate_file_path(&req.userlist, &config.execution.output_dir)?;
    super::validate_file_path(&req.passlist, &config.execution.output_dir)?;

    // Both are positional args downstream - guard against flag injection.
    validate_service(&req.service)?;
    if let Some(ref form_params) = req.form_params {
        validate_form_params(form_params)?;
    }

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "hydra".into(), req.target.clone()));

    // Cap parallel tasks to prevent excessive brute-force throughput
    let tasks = req
        .tasks
        .unwrap_or(4)
        .clamp(1, config.safety.hydra_max_tasks);

    // http-*-form services need form_params to know the login path and fields
    let is_form_service = req.service.starts_with("http-") && req.service.contains("form");
    if is_form_service && req.form_params.is_none() {
        return Err(rmcp::ErrorData::invalid_params(
            "form_params is required for http-post-form/http-get-form \
             (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')",
            None,
        ));
    }
    // Conversely: a non-form service must not carry a form string - hydra would
    // take it as an extra positional argument.
    if !is_form_service && req.form_params.is_some() {
        return Err(rmcp::ErrorData::invalid_params(
            "form_params is only valid for http-post-form/http-get-form services",
            None,
        ));
    }

    let mut args = vec![
        "-L".to_string(),
        req.userlist,
        "-P".into(),
        req.passlist,
        "-t".into(),
        tasks.to_string(),
        "-f".into(), // stop on first valid credential pair
    ];

    if let Some(port) = req.port {
        args.extend(["-s".into(), port.to_string()]);
    }

    args.push(req.target);
    args.push(req.service);

    // form_params is passed as a positional arg after the service name
    if let Some(form_params) = req.form_params {
        args.push(form_params);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "hydra", &arg_refs, None, parse_hydra_output).await
}

/// Parse hydra output, extracting found credentials and the summary line.
///
/// Credential lines contain both `login:` and `password:` keywords.
/// The summary line matches "valid password found" or "successfully completed".
/// All other lines (status updates, data info) are discarded.
pub fn parse_hydra_output(raw: &str) -> Option<String> {
    let mut creds = Vec::new();
    let mut summary = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.contains("login:") && trimmed.contains("password:") {
            creds.push(trimmed);
        } else if trimmed.contains("valid password") || trimmed.contains("successfully completed") {
            summary = Some(trimmed);
        }
    }

    if creds.is_empty() && summary.is_none() {
        return None;
    }

    let mut out = String::new();
    if !creds.is_empty() {
        out.push_str(&format!("{} credential(s) found:\n", creds.len()));
        for c in &creds {
            out.push_str(c);
            out.push('\n');
        }
    }
    if let Some(s) = summary {
        out.push_str(s);
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_service_accepts_real_service_names() {
        for s in [
            "ssh",
            "ftp",
            "http-post-form",
            "http-get-form",
            "smb",
            "rdp",
            "oracle-listener",
        ] {
            assert!(validate_service(s).is_ok(), "should accept: {s}");
        }
    }

    #[test]
    fn validate_service_rejects_flag_injection_and_bad_charset() {
        for s in [
            "-R",          // flag injection (positional arg)
            "--restore",   // flag injection, long form
            "",            // empty
            "ssh -oProxy", // space (would split into hydra options)
            "HTTP",        // uppercase not used by hydra service names
            "ssh\nrm",     // control character
            "ssh;id",      // metacharacter
        ] {
            assert!(validate_service(s).is_err(), "should reject: {s:?}");
        }
    }

    #[test]
    fn validate_form_params_allows_legitimate_form_strings() {
        assert!(validate_form_params("/login:user=^USER^&pass=^PASS^:F=incorrect").is_ok());
        assert!(validate_form_params("/login.php:username=^USER^&password=^PASS^:fail").is_ok());
    }

    #[test]
    fn validate_form_params_rejects_flag_and_control_chars() {
        assert!(validate_form_params("-R").is_err()); // flag injection
        assert!(validate_form_params("").is_err()); // empty
        assert!(validate_form_params("/login:a=b:F=x\nsecond-command").is_err()); // newline
        assert!(validate_form_params("/login:a=b:F=x\ttab").is_err()); // control char
    }

    #[test]
    fn parse_hydra_extracts_credentials() {
        let raw = r#"Hydra v9.5 (c) 2023 by van Hauser/THC
[DATA] max 4 tasks per 1 server, overall 4 tasks, 100 login tries
[DATA] attacking ssh://10.0.0.1:22/
[22][ssh] host: 10.0.0.1   login: admin   password: password123
[22][ssh] host: 10.0.0.1   login: root   password: toor
[STATUS] 100.00 tries/min, 100 tries in 00:01h, 0 to do in 00:00h, 4 active
1 of 1 target successfully completed, 2 valid passwords found"#;
        let result = parse_hydra_output(raw).unwrap();
        assert!(result.contains("2 credential(s) found:"));
        assert!(result.contains("login: admin"));
        assert!(result.contains("password: password123"));
        assert!(result.contains("login: root"));
        assert!(result.contains("2 valid passwords found"));
        assert!(!result.contains("[DATA]"));
        assert!(!result.contains("[STATUS]"));
    }

    #[test]
    fn parse_hydra_no_creds_returns_summary() {
        let raw = r#"[DATA] attacking ssh://10.0.0.1:22/
[STATUS] 50.00 tries/min, 50 tries in 00:01h, 50 to do
1 of 1 target successfully completed, 0 valid passwords found"#;
        let result = parse_hydra_output(raw).unwrap();
        assert!(result.contains("0 valid passwords found"));
        assert!(!result.contains("[DATA]"));
    }

    #[test]
    fn parse_hydra_empty_returns_none() {
        assert!(parse_hydra_output("").is_none());
        assert!(parse_hydra_output("some random text\nno credentials here").is_none());
    }
}
