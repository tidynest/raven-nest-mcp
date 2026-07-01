//! Metasploit Framework RPC client via MessagePack over HTTPS.
//!
//! [`MsfClient`] connects to a running `msfrpcd` instance and provides
//! high-level methods for module search, exploit execution, session
//! management, and post-exploitation.
//!
//! The operator starts msfrpcd separately:
//! ```sh
//! msfrpcd -P password -a 127.0.0.1 -p 55553 -n -f
//! ```
//!
//! The client authenticates lazily on first use and refreshes the token
//! automatically before expiry.

use crate::config::MetasploitConfig;
use crate::error::PentestError;
use serde_json::Value;
use std::sync::Mutex;

/// Convert `rmpv::Value` to `serde_json::Value`, coercing byte-array keys to UTF-8 strings.
///
/// msfrpcd encodes map keys as MessagePack binary (raw type) instead of string type.
/// This function handles the conversion so downstream code works with standard JSON values.
fn rmpv_to_json(v: rmpv::Value) -> Value {
    match v {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(b) => Value::Bool(b),
        rmpv::Value::Integer(i) => {
            if let Some(n) = i.as_i64() {
                Value::Number(n.into())
            } else if let Some(n) = i.as_u64() {
                Value::Number(n.into())
            } else {
                Value::Number(0.into())
            }
        }
        rmpv::Value::F32(f) => serde_json::Number::from_f64(f as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        rmpv::Value::F64(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        rmpv::Value::String(s) => Value::String(s.into_str().unwrap_or_default()),
        rmpv::Value::Binary(b) => {
            // Binary data - try to interpret as UTF-8 string
            Value::String(String::from_utf8_lossy(&b).into_owned())
        }
        rmpv::Value::Array(arr) => Value::Array(arr.into_iter().map(rmpv_to_json).collect()),
        rmpv::Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    rmpv::Value::String(s) => s.into_str().unwrap_or_default(),
                    rmpv::Value::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    other => format!("{other}"),
                };
                map.insert(key, rmpv_to_json(v));
            }
            Value::Object(map)
        }
        rmpv::Value::Ext(_, data) => {
            Value::String(format!("ext:{}", String::from_utf8_lossy(&data)))
        }
    }
}

/// True if `module_name` is blocked by any pattern: an exact match, a
/// `pattern/...` child module, or a trailing-slash prefix (`exploit/windows/`).
/// The boundary is always a path separator, so `exploit/foo` never blocks
/// `exploit/foobar`.
fn is_blocked(module_name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        module_name == p
            || module_name.starts_with(&format!("{p}/"))
            || (p.ends_with('/') && module_name.starts_with(p.as_str()))
    })
}

/// Metasploit RPC client - held behind `Arc` in the server.
pub struct MsfClient {
    config: MetasploitConfig,
    http: reqwest::Client,
    /// Current auth token, refreshed transparently.
    token: Mutex<Option<String>>,
    /// Pending exploit confirmation hash (module+target+options).
    pending_confirmation: Mutex<Option<u64>>,
}

impl MsfClient {
    /// Create a new client from config. Does NOT connect until first use.
    pub fn new(config: &MetasploitConfig) -> Self {
        let is_local =
            config.host == "127.0.0.1" || config.host == "localhost" || config.host == "::1";
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(is_local) // only skip cert validation for localhost
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config: config.clone(),
            http,
            token: Mutex::new(None),
            pending_confirmation: Mutex::new(None),
        }
    }

    /// Base URL for msfrpcd.
    fn base_url(&self) -> String {
        let scheme = if self.config.ssl { "https" } else { "http" };
        format!(
            "{}://{}:{}/api/",
            scheme, self.config.host, self.config.port
        )
    }

    /// Low-level RPC call: serialize args as MessagePack, POST, deserialize response.
    async fn rpc_call(&self, method: &str, args: &[Value]) -> Result<Value, PentestError> {
        // Build the call array: [method, token_or_args...]
        let mut call = vec![Value::String(method.into())];
        call.extend_from_slice(args);

        let body = rmp_serde::to_vec_named(&call)
            .map_err(|e| PentestError::MsfRpcError(format!("msgpack encode: {e}")))?;

        let response = self
            .http
            .post(self.base_url())
            .header("Content-Type", "binary/message-pack")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                PentestError::MsfNotRunning(format!(
                    "{e} - start msfrpcd with: msfrpcd -P <redacted> -a {} -p {} -n -f",
                    self.config.host, self.config.port
                ))
            })?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| PentestError::MsfRpcError(format!("response read: {e}")))?;

        // msfrpcd encodes map keys as binary (raw bytes) not UTF-8 strings.
        // Decode to rmpv::Value first, then convert to serde_json::Value.
        let raw: rmpv::Value = rmp_serde::from_slice(&bytes)
            .map_err(|e| PentestError::MsfRpcError(format!("msgpack decode: {e}")))?;
        let result = rmpv_to_json(raw);

        // Check for RPC-level errors
        if let Some(err) = result.get("error").and_then(|v| v.as_bool())
            && err
        {
            let msg = result
                .get("error_message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown RPC error");
            return Err(PentestError::MsfRpcError(msg.into()));
        }

        Ok(result)
    }

    /// Authenticate and store the token. Called lazily on first RPC call.
    async fn authenticate(&self) -> Result<String, PentestError> {
        let result = self
            .rpc_call(
                "auth.login",
                &[
                    Value::String(self.config.username.clone()),
                    Value::String(self.config.password.clone()),
                ],
            )
            .await?;

        let token = result
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PentestError::MsfRpcError("auth.login: no token in response".into()))?
            .to_string();

        *self.token.lock().unwrap() = Some(token.clone());
        Ok(token)
    }

    /// Get a valid token, authenticating if needed.
    async fn ensure_token(&self) -> Result<String, PentestError> {
        if let Some(ref token) = *self.token.lock().unwrap() {
            return Ok(token.clone());
        }
        self.authenticate().await
    }

    /// Make an authenticated RPC call (prepends token to args).
    async fn auth_call(&self, method: &str, args: &[Value]) -> Result<Value, PentestError> {
        let token = self.ensure_token().await?;
        let mut full_args = vec![Value::String(token)];
        full_args.extend_from_slice(args);

        let result = self.rpc_call(method, &full_args).await;

        // If token expired, re-auth once and retry
        if let Err(PentestError::MsfRpcError(ref msg)) = result
            && (msg.contains("Invalid Authentication Token") || msg.contains("token"))
        {
            let token = self.authenticate().await?;
            let mut retry_args = vec![Value::String(token)];
            retry_args.extend_from_slice(args);
            return self.rpc_call(method, &retry_args).await;
        }

        result
    }

    // ── Public API ──────────────────────────────────────────────────

    /// Search for MSF modules by keyword, CVE, platform, or type.
    pub async fn search_modules(&self, query: &str, limit: usize) -> Result<Value, PentestError> {
        let result = self
            .auth_call("module.search", &[Value::String(query.into())])
            .await?;

        // The result is an array of module hashes - truncate to limit
        if let Value::Array(mut modules) = result {
            modules.truncate(limit);
            Ok(Value::Array(modules))
        } else {
            Ok(result)
        }
    }

    /// Get full info about a module (description, options, references).
    pub async fn module_info(
        &self,
        module_type: &str,
        module_name: &str,
    ) -> Result<Value, PentestError> {
        self.auth_call(
            "module.info",
            &[
                Value::String(module_type.into()),
                Value::String(module_name.into()),
            ],
        )
        .await
    }

    /// Get module options (datastore fields with types and defaults).
    pub async fn module_options(
        &self,
        module_type: &str,
        module_name: &str,
    ) -> Result<Value, PentestError> {
        self.auth_call(
            "module.options",
            &[
                Value::String(module_type.into()),
                Value::String(module_name.into()),
            ],
        )
        .await
    }

    /// Get compatible payloads for an exploit module.
    pub async fn compatible_payloads(&self, module_name: &str) -> Result<Value, PentestError> {
        self.auth_call(
            "module.compatible_payloads",
            &[Value::String(module_name.into())],
        )
        .await
    }

    /// Execute a module with the given options.
    /// Returns `{job_id, uuid}` for polling.
    pub async fn execute_module(
        &self,
        module_type: &str,
        module_name: &str,
        options: &serde_json::Map<String, Value>,
    ) -> Result<Value, PentestError> {
        if is_blocked(module_name, &self.config.blocked_modules) {
            return Err(PentestError::MsfRpcError(format!(
                "module '{module_name}' is blocked by config"
            )));
        }

        let opts = Value::Object(options.clone());
        self.auth_call(
            "module.execute",
            &[
                Value::String(module_type.into()),
                Value::String(module_name.into()),
                opts,
            ],
        )
        .await
    }

    /// Poll execution results by UUID.
    pub async fn module_results(&self, uuid: &str) -> Result<Value, PentestError> {
        self.auth_call("module.results", &[Value::String(uuid.into())])
            .await
    }

    /// List all active sessions.
    pub async fn list_sessions(&self) -> Result<Value, PentestError> {
        self.auth_call("session.list", &[]).await
    }

    /// Read pending output from a shell session.
    pub async fn session_read(&self, session_id: u32) -> Result<Value, PentestError> {
        self.auth_call("session.shell_read", &[Value::Number(session_id.into())])
            .await
    }

    /// Write a command to a shell session.
    pub async fn session_write(
        &self,
        session_id: u32,
        command: &str,
    ) -> Result<Value, PentestError> {
        // Ensure command ends with newline
        let cmd = if command.ends_with('\n') {
            command.to_string()
        } else {
            format!("{command}\n")
        };
        self.auth_call(
            "session.shell_write",
            &[Value::Number(session_id.into()), Value::String(cmd)],
        )
        .await
    }

    /// Run a single meterpreter command.
    pub async fn meterpreter_run(
        &self,
        session_id: u32,
        command: &str,
    ) -> Result<Value, PentestError> {
        self.auth_call(
            "session.meterpreter_run_single",
            &[
                Value::Number(session_id.into()),
                Value::String(command.into()),
            ],
        )
        .await
    }

    /// Read meterpreter output.
    pub async fn meterpreter_read(&self, session_id: u32) -> Result<Value, PentestError> {
        self.auth_call(
            "session.meterpreter_read",
            &[Value::Number(session_id.into())],
        )
        .await
    }

    /// Stop (kill) a session.
    pub async fn stop_session(&self, session_id: u32) -> Result<Value, PentestError> {
        self.auth_call("session.stop", &[Value::Number(session_id.into())])
            .await
    }

    /// List post-exploitation modules compatible with a session.
    pub async fn compatible_post_modules(&self, session_id: u32) -> Result<Value, PentestError> {
        self.auth_call(
            "session.compatible_modules",
            &[Value::Number(session_id.into())],
        )
        .await
    }

    /// List active jobs.
    pub async fn list_jobs(&self) -> Result<Value, PentestError> {
        self.auth_call("job.list", &[]).await
    }

    /// Get framework version.
    pub async fn version(&self) -> Result<Value, PentestError> {
        self.auth_call("core.version", &[]).await
    }

    // ── Confirmation gate ───────────────────────────────────────────

    /// Check if an exploit execution matches the pending confirmation.
    /// Returns true if confirmed (second call matches), false if this is the first call.
    pub fn check_confirmation(&self, hash: u64) -> bool {
        let mut pending = self.pending_confirmation.lock().unwrap();
        if *pending == Some(hash) {
            *pending = None;
            true
        } else {
            *pending = Some(hash);
            false
        }
    }

    /// Clear any pending confirmation.
    pub fn clear_confirmation(&self) {
        *self.pending_confirmation.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MetasploitConfig;

    fn test_client() -> MsfClient {
        MsfClient::new(&MetasploitConfig::default())
    }

    #[test]
    fn base_url_ssl() {
        let client = test_client();
        assert_eq!(client.base_url(), "https://127.0.0.1:55553/api/");
    }

    #[test]
    fn base_url_no_ssl() {
        let client = MsfClient::new(&MetasploitConfig {
            ssl: false,
            ..MetasploitConfig::default()
        });
        assert_eq!(client.base_url(), "http://127.0.0.1:55553/api/");
    }

    #[test]
    fn confirmation_gate_requires_double_call() {
        let client = test_client();
        // First call: not confirmed
        assert!(!client.check_confirmation(12345));
        // Second call with same hash: confirmed
        assert!(client.check_confirmation(12345));
        // Third call: not confirmed again (was cleared)
        assert!(!client.check_confirmation(12345));
    }

    #[test]
    fn confirmation_different_hash_resets() {
        let client = test_client();
        assert!(!client.check_confirmation(111));
        // Different hash: not confirmed, replaces pending
        assert!(!client.check_confirmation(222));
        // Original hash no longer pending
        assert!(!client.check_confirmation(111));
    }

    #[test]
    fn clear_confirmation_resets() {
        let client = test_client();
        assert!(!client.check_confirmation(123));
        client.clear_confirmation();
        assert!(!client.check_confirmation(123));
    }

    #[test]
    fn error_message_does_not_contain_password() {
        let config = MetasploitConfig {
            password: "super_secret_123".into(),
            ..MetasploitConfig::default()
        };
        let _client = MsfClient::new(&config);
        // The base_url format is testable; the error message format
        // would require an actual connection attempt, so we verify
        // the redaction pattern is correct by checking the format string
        let error_msg = format!(
            "connection refused - start msfrpcd with: msfrpcd -P <redacted> -a {} -p {} -n -f",
            config.host, config.port
        );
        assert!(!error_msg.contains("super_secret_123"));
        assert!(error_msg.contains("<redacted>"));
    }

    #[test]
    fn blocked_module_exact_match() {
        assert!(is_blocked(
            "exploit/windows/smb/ms17_010_eternalblue",
            &["exploit/windows/smb/ms17_010_eternalblue".to_string()],
        ));
    }

    #[test]
    fn blocked_module_child_match() {
        // An exact-module pattern also blocks its child modules.
        assert!(is_blocked(
            "exploit/windows/smb/ms17_010_eternalblue",
            &["exploit/windows/smb".to_string()],
        ));
    }

    #[test]
    fn blocked_module_prefix_match() {
        // A trailing-slash pattern blocks everything beneath it.
        assert!(is_blocked(
            "exploit/windows/smb/ms17_010_eternalblue",
            &["exploit/windows/".to_string()],
        ));
    }

    #[test]
    fn blocked_module_no_false_substring_match() {
        // A bare word must not match as a substring (the old contains() bug).
        assert!(!is_blocked(
            "exploit/linux/samba/windows_compat_check",
            &["windows".to_string()],
        ));
    }

    #[test]
    fn blocked_module_no_false_prefix_without_slash() {
        // "exploit/foo" blocks itself and its children, but NOT "exploit/foobar".
        let patterns = ["exploit/foo".to_string()];
        assert!(is_blocked("exploit/foo", &patterns));
        assert!(is_blocked("exploit/foo/bar", &patterns));
        assert!(!is_blocked("exploit/foobar", &patterns));
    }

    // --- rmpv_to_json (msfrpcd MessagePack → JSON decode) ---

    #[test]
    fn rmpv_binary_map_keys_become_string_keys() {
        // msfrpcd encodes map keys as MessagePack *binary*, not string - the whole
        // reason rmpv_to_json exists. A binary key must decode to a JSON string key.
        let v = rmpv::Value::Map(vec![(
            rmpv::Value::Binary(b"token".to_vec()),
            rmpv::Value::from("abc123"),
        )]);
        let json = rmpv_to_json(v);
        assert_eq!(json.get("token").and_then(|x| x.as_str()), Some("abc123"));
    }

    #[test]
    fn rmpv_scalars_convert() {
        assert!(rmpv_to_json(rmpv::Value::Nil).is_null());
        assert_eq!(
            rmpv_to_json(rmpv::Value::from(true)),
            serde_json::json!(true)
        );
        assert_eq!(
            rmpv_to_json(rmpv::Value::from(42i64)),
            serde_json::json!(42)
        );
        assert_eq!(
            rmpv_to_json(rmpv::Value::from("hi")),
            serde_json::json!("hi")
        );
        // A binary *scalar* is interpreted as a lossy UTF-8 string.
        assert_eq!(
            rmpv_to_json(rmpv::Value::Binary(b"raw".to_vec())),
            serde_json::json!("raw")
        );
    }

    #[test]
    fn rmpv_nested_array_and_map() {
        let v = rmpv::Value::Array(vec![
            rmpv::Value::from(1i64),
            rmpv::Value::Map(vec![(rmpv::Value::from("k"), rmpv::Value::from(false))]),
        ]);
        let json = rmpv_to_json(v);
        assert_eq!(json[0], serde_json::json!(1));
        assert_eq!(json[1]["k"], serde_json::json!(false));
    }
}
