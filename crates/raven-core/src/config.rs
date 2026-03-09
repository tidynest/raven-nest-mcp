//! TOML-based configuration for the Raven Nest toolkit.
//!
//! [`RavenConfig`] is the root struct, loaded once at server startup and shared
//! (via `Arc`) across all tool handlers in `raven-server`. It groups settings
//! into three sections:
//!
//! - [`SafetyConfig`] — tool allowlisting, output caps, and per-tool aggressiveness limits.
//! - [`ExecutionConfig`] — timeouts, concurrency, and output directory.
//! - [`NetworkConfig`] — optional HTTP/HTTPS proxy settings injected into
//!   tool subprocesses by [`executor::run`](crate::executor::run).
//!
//! Configuration resolves through a fallback chain:
//! `RAVEN_CONFIG` env var → exe-relative `config/default.toml` → CWD fallback → built-in defaults.

use serde::Deserialize;
use std::collections::HashMap;

/// Top-level configuration, deserialized from `config/default.toml`.
///
/// Shared as `Arc<RavenConfig>` by [`RavenServer`](raven_server::server::RavenServer)
/// and passed by reference to every tool handler.
#[derive(Clone, Debug, Deserialize)]
pub struct RavenConfig {
    pub safety: SafetyConfig,
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub network: NetworkConfig,
}

/// Controls which tools may run and how aggressively they operate.
///
/// Every tool invocation passes through [`safety::check_allowlist`](crate::safety::check_allowlist)
/// before execution. Per-tool caps (sqlmap level/risk, hydra tasks, masscan rate)
/// prevent an LLM from escalating beyond operator-approved limits.
#[derive(Clone, Debug, Deserialize)]
pub struct SafetyConfig {
    /// Whitelist of tool names permitted to execute (e.g. `["nmap", "ping"]`).
    pub allowed_tools: Vec<String>,
    /// Maximum characters kept after output truncation (see [`safety::truncate_output`](crate::safety::truncate_output)).
    pub max_output_chars: usize,
    /// Optional map of tool name to absolute binary path.
    /// Falls back to `$PATH` lookup if not specified.
    #[serde(default)]
    pub tool_paths: HashMap<String, String>,
    /// Max sqlmap `--level` (1-5). Default 2 — prevents LLM escalation beyond safe testing.
    #[serde(default = "default_sqlmap_max_level")]
    pub sqlmap_max_level: u8,
    /// Max sqlmap `--risk` (1-3). Default 1 — avoids destructive payloads.
    #[serde(default = "default_sqlmap_max_risk")]
    pub sqlmap_max_risk: u8,
    /// Max hydra parallel tasks. Default 4 — limits brute-force throughput.
    #[serde(default = "default_hydra_max_tasks")]
    pub hydra_max_tasks: u16,
    /// Max masscan packet rate (packets/sec). Default 1000 — prevents network saturation.
    #[serde(default = "default_masscan_max_rate")]
    pub masscan_max_rate: u32,
    /// Model context window size in characters. When set (> 0), derives
    /// `max_output_chars` and HTTP body cap proportionally so that ~4 tool
    /// outputs fit within the budget. `0` disables (uses `max_output_chars` as-is).
    #[serde(default)]
    pub context_budget: usize,
}

fn default_sqlmap_max_level() -> u8 {
    2
}
fn default_sqlmap_max_risk() -> u8 {
    1
}
fn default_hydra_max_tasks() -> u16 {
    4
}
fn default_masscan_max_rate() -> u32 {
    1000
}

/// Execution environment: timeouts, concurrency, and filesystem paths.
#[derive(Clone, Debug, Deserialize)]
pub struct ExecutionConfig {
    /// Global timeout applied when no per-tool override exists (seconds).
    pub default_timeout_secs: u64,
    /// Maximum number of background scans that can run simultaneously.
    /// Enforced by [`ScanManager::launch`](crate::scan_manager::ScanManager::launch).
    pub max_concurrent_scans: usize,
    /// Base directory for scan output files, spilled data, and reports.
    pub output_dir: String,
    /// Per-tool timeout overrides (seconds). Falls back to `default_timeout_secs`.
    #[serde(default)]
    pub timeouts: HashMap<String, u64>,
}

/// Optional proxy configuration injected into tool subprocesses.
///
/// When set, [`executor::run`](crate::executor::run) sets both upper- and
/// lower-case environment variables (`HTTP_PROXY`/`http_proxy`) so that tools
/// using either convention pick up the proxy.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// HTTP proxy URL (e.g. `http://proxy:3128`).
    pub http_proxy: Option<String>,
    /// HTTPS proxy URL.
    pub https_proxy: Option<String>,
    /// Hostnames/IPs that should bypass the proxy.
    #[serde(default)]
    pub no_proxy: Vec<String>,
}

impl ExecutionConfig {
    /// Look up timeout for a specific tool, falling back to the default.
    pub fn timeout_for(&self, tool: &str) -> u64 {
        self.timeouts
            .get(tool)
            .copied()
            .unwrap_or(self.default_timeout_secs)
    }
}

impl SafetyConfig {
    /// Resolve the binary path for a tool: custom path if configured, else bare name for `$PATH`.
    pub fn resolve_tool_binary<'a>(&'a self, tool: &'a str) -> &'a str {
        self.tool_paths
            .get(tool)
            .map(|s| s.as_str())
            .unwrap_or(tool)
    }

    /// Effective subprocess output cap: `context_budget / 4` when set, else `max_output_chars`.
    pub fn effective_max_output_chars(&self) -> usize {
        if self.context_budget > 0 {
            self.context_budget / 4
        } else {
            self.max_output_chars
        }
    }

    /// Effective HTTP response body cap: `context_budget / 6` when set, else 20,000.
    pub fn effective_max_response_body(&self) -> usize {
        if self.context_budget > 0 {
            self.context_budget / 6
        } else {
            20_000
        }
    }
}

impl RavenConfig {
    /// Load configuration from an explicit file path.
    pub fn load(path: &str) -> Result<Self, crate::error::PentestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))?;
        toml::from_str(&content).map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))
    }

    /// Load configuration using a fallback chain:
    /// 1. `RAVEN_CONFIG` environment variable
    /// 2. `config/default.toml` relative to the executable (checks parent dir too)
    /// 3. `config/default.toml` in the current working directory
    /// 4. Built-in defaults (if all else fails)
    pub fn load_with_fallback() -> Self {
        // 1. Environment variable
        if let Ok(path) = std::env::var("RAVEN_CONFIG") {
            match Self::load(&path) {
                Ok(config) => {
                    tracing::info!("config loaded from RAVEN_CONFIG={path}");
                    return config;
                }
                Err(e) => tracing::warn!("RAVEN_CONFIG={path} failed: {e}"),
            }
        }

        // 2. Relative to executable (exe_dir/../config/ or exe_dir/config/)
        if let Ok(exe) = std::env::current_exe() {
            for ancestor in exe.ancestors().skip(1).take(2) {
                let candidate = ancestor.join("config/default.toml");
                if candidate.exists()
                    && let Ok(config) = Self::load(&candidate.to_string_lossy())
                {
                    tracing::info!("config loaded from {}", candidate.display());
                    return config;
                }
            }
        }

        // 3. Current directory (legacy behaviour)
        if let Ok(config) = Self::load("config/default.toml") {
            tracing::info!("config loaded from config/default.toml");
            return config;
        }

        tracing::warn!("no config found, using built-in defaults");
        Self::default()
    }
}

impl Default for RavenConfig {
    fn default() -> Self {
        Self {
            safety: SafetyConfig {
                allowed_tools: vec![
                    "ping".into(),
                    "nmap".into(),
                    "nuclei".into(),
                    "nikto".into(),
                    "whatweb".into(),
                    "testssl.sh".into(),
                    "feroxbuster".into(),
                    "ffuf".into(),
                    "sqlmap".into(),
                    "hydra".into(),
                    "masscan".into(),
                ],
                max_output_chars: 50_000,
                tool_paths: HashMap::new(),
                sqlmap_max_level: default_sqlmap_max_level(),
                sqlmap_max_risk: default_sqlmap_max_risk(),
                hydra_max_tasks: default_hydra_max_tasks(),
                masscan_max_rate: default_masscan_max_rate(),
                context_budget: 0,
            },
            execution: ExecutionConfig {
                default_timeout_secs: 600,
                max_concurrent_scans: 3,
                output_dir: "/tmp/raven-nest".into(),
                timeouts: HashMap::new(),
            },
            network: NetworkConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_timeouts() -> ExecutionConfig {
        ExecutionConfig {
            default_timeout_secs: 600,
            max_concurrent_scans: 3,
            output_dir: "/tmp/test".into(),
            timeouts: HashMap::from([("nmap".into(), 900), ("nuclei".into(), 1200)]),
        }
    }

    #[test]
    fn timeout_for_returns_tool_specific_value() {
        let cfg = config_with_timeouts();
        assert_eq!(cfg.timeout_for("nmap"), 900);
        assert_eq!(cfg.timeout_for("nuclei"), 1200);
    }

    #[test]
    fn timeout_for_falls_back_to_default() {
        let cfg = config_with_timeouts();
        assert_eq!(cfg.timeout_for("nikto"), 600);
        assert_eq!(cfg.timeout_for("unknown"), 600);
    }

    fn test_safety_config(tool_paths: HashMap<String, String>) -> SafetyConfig {
        SafetyConfig {
            allowed_tools: vec![],
            max_output_chars: 50_000,
            tool_paths,
            sqlmap_max_level: default_sqlmap_max_level(),
            sqlmap_max_risk: default_sqlmap_max_risk(),
            hydra_max_tasks: default_hydra_max_tasks(),
            masscan_max_rate: default_masscan_max_rate(),
            context_budget: 0,
        }
    }

    #[test]
    fn resolve_tool_binary_uses_custom_path() {
        let cfg = test_safety_config(HashMap::from([(
            "nmap".into(),
            "/opt/nmap/bin/nmap".into(),
        )]));
        assert_eq!(cfg.resolve_tool_binary("nmap"), "/opt/nmap/bin/nmap");
    }

    #[test]
    fn resolve_tool_binary_falls_back_to_bare_name() {
        let cfg = test_safety_config(HashMap::new());
        assert_eq!(cfg.resolve_tool_binary("nmap"), "nmap");
    }

    #[test]
    fn load_returns_error_on_missing_file() {
        let result = RavenConfig::load("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn load_returns_error_on_malformed_toml() {
        let dir = std::env::temp_dir().join("raven-test-malformed");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.toml");
        std::fs::write(&path, "this is not [valid toml = ").unwrap();
        let result = RavenConfig::load(&path.to_string_lossy());
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_config_has_expected_tools() {
        let cfg = RavenConfig::default();
        assert!(cfg.safety.allowed_tools.contains(&"nmap".to_string()));
        assert!(cfg.safety.allowed_tools.contains(&"ping".to_string()));
        assert_eq!(cfg.execution.default_timeout_secs, 600);
        assert!(cfg.safety.tool_paths.is_empty());
        assert!(cfg.execution.timeouts.is_empty());
    }

    #[test]
    fn network_config_defaults_to_none() {
        let cfg = RavenConfig::default();
        assert!(cfg.network.http_proxy.is_none());
        assert!(cfg.network.https_proxy.is_none());
        assert!(cfg.network.no_proxy.is_empty());
    }

    #[test]
    fn network_config_parses_from_toml() {
        let toml_str = r#"
        [safety]
        allowed_tools = ["nmap"]
        max_output_chars = 50000
        [execution]
        default_timeout_secs = 600
        max_concurrent_scans = 3
        output_dir = "/tmp/test"
        [network]
        http_proxy = "http://proxy:3128"
        https_proxy = "https://proxy:3128"
        no_proxy = ["localhost", "127.0.0.1"]
        "#;
        let cfg: RavenConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.network.http_proxy.as_deref(), Some("http://proxy:3128"));
        assert_eq!(cfg.network.no_proxy, vec!["localhost", "127.0.0.1"]);
    }

    #[test]
    fn context_budget_zero_uses_defaults() {
        let cfg = test_safety_config(HashMap::new());
        assert_eq!(cfg.effective_max_output_chars(), 50_000);
        assert_eq!(cfg.effective_max_response_body(), 20_000);
    }

    #[test]
    fn context_budget_derives_caps() {
        let mut cfg = test_safety_config(HashMap::new());
        cfg.context_budget = 32_768;
        assert_eq!(cfg.effective_max_output_chars(), 8_192); // 32768 / 4
        assert_eq!(cfg.effective_max_response_body(), 5_461); // 32768 / 6

        cfg.context_budget = 131_072;
        assert_eq!(cfg.effective_max_output_chars(), 32_768);
        assert_eq!(cfg.effective_max_response_body(), 21_845);
    }
}
