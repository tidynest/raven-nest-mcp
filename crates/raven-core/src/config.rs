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
    #[serde(default)]
    pub metasploit: MetasploitConfig,
    #[serde(default)]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub netexec: NetExecConfig,
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
    /// Tools that should be invoked via `sudo` for privilege escalation.
    /// The operator must configure passwordless sudo for these binaries
    /// (e.g. via `/etc/sudoers.d/raven-nest`).
    #[serde(default)]
    pub sudo_tools: Vec<String>,
    /// Expected tool calls per session. Used by the session budget tracker to
    /// plan output allocation. Higher values yield smaller per-call caps.
    /// Default 10 — typical pentest workflow is 6-12 tool calls.
    #[serde(default = "default_expected_tool_calls")]
    pub expected_tool_calls: usize,
    /// Auto-save findings extracted from scan output (currently nuclei only).
    /// Off by default — the operator opts in. When true, qualifying findings
    /// are deduplicated and persisted with `source = AutoExtracted`.
    #[serde(default)]
    pub auto_save_findings: bool,
    /// Minimum severity an auto-extracted finding must meet to be saved
    /// (`info|low|medium|high|critical`). Default `"medium"`.
    #[serde(default = "default_auto_save_min_severity")]
    pub auto_save_min_severity: String,
    /// Cap on auto-saved findings per scan — bounds finding spam and disk use.
    /// Default 25.
    #[serde(default = "default_auto_save_max_per_scan")]
    pub auto_save_max_per_scan: usize,
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
fn default_expected_tool_calls() -> usize {
    10
}
fn default_auto_save_min_severity() -> String {
    "medium".into()
}
fn default_auto_save_max_per_scan() -> usize {
    25
}
fn default_scan_retention_secs() -> u64 {
    3600
}
fn default_max_concurrent_execs() -> usize {
    4
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
    /// Seconds to retain a completed/failed/cancelled scan before it is evicted
    /// (and its spilled output file deleted). Default 3600 (1h). Bounds the
    /// otherwise unbounded in-memory scan registry on long-lived servers.
    #[serde(default = "default_scan_retention_secs")]
    pub scan_retention_secs: u64,
    /// Max concurrent *synchronous* tool executions, separate from
    /// `max_concurrent_scans` (which bounds background scans). Default 4 —
    /// prevents an LLM from spawning unbounded subprocesses via parallel calls.
    #[serde(default = "default_max_concurrent_execs")]
    pub max_concurrent_execs: usize,
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

/// Metasploit Framework RPC integration — disabled by default.
///
/// When enabled, the server connects to a running `msfrpcd` instance via
/// MessagePack RPC. The operator must start msfrpcd separately.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct MetasploitConfig {
    /// Master switch — MSF tools only registered when true.
    pub enabled: bool,
    /// msfrpcd host (default 127.0.0.1).
    pub host: String,
    /// msfrpcd port (default 55553).
    pub port: u16,
    /// RPC username (default "msf").
    pub username: String,
    /// RPC password — operator MUST change this.
    pub password: String,
    /// Use SSL for RPC connection (msfrpcd default).
    pub ssl: bool,
    /// Max results returned by module search.
    pub max_search_results: usize,
    /// Max concurrent exploit executions.
    pub max_concurrent_exploits: usize,
    /// Regex patterns for blocked MSF modules.
    #[serde(default)]
    pub blocked_modules: Vec<String>,
    /// Require double-call confirmation for exploit execution.
    pub require_confirmation: bool,
}

impl MetasploitConfig {
    /// Validate MSF config — reject the default "changeme" password when enabled.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.password == "changeme" {
            return Err("metasploit is enabled but password is still 'changeme' — \
                 change it in config before starting the server"
                .into());
        }
        Ok(())
    }
}

impl Default for MetasploitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "127.0.0.1".into(),
            port: 55553,
            username: "msf".into(),
            password: "changeme".into(),
            ssl: true,
            max_search_results: 20,
            max_concurrent_exploits: 1,
            blocked_modules: Vec::new(),
            require_confirmation: true,
        }
    }
}

/// Engagement scope — an operator-configured authorization allowlist.
///
/// Disabled by default (`enabled = false`), preserving current behaviour where
/// any syntactically valid target may be scanned. When enabled, every target is
/// gated by [`safety::check_scope`](crate::safety::check_scope): it must match an
/// `allowed_*` entry and must not match a `denied_*` entry (deny wins).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ScopeConfig {
    /// Master switch — when false (default), no scope gating is applied.
    pub enabled: bool,
    /// In-scope IP ranges (CIDR like `10.0.0.0/8`, or a bare IP = single host).
    pub allowed_cidrs: Vec<String>,
    /// In-scope domains. Matches the domain and its subdomains (`example.com`
    /// matches `example.com` and `api.example.com`, not `notexample.com`).
    pub allowed_domains: Vec<String>,
    /// Explicitly out-of-scope IP ranges — checked before the allow list (deny
    /// wins). Useful for carving out e.g. cloud metadata (`169.254.169.254/32`).
    pub denied_cidrs: Vec<String>,
    /// Explicitly out-of-scope domains — checked before the allow list (deny wins).
    pub denied_domains: Vec<String>,
    /// Always allow loopback targets (`localhost`, `127.0.0.0/8`, `::1`) regardless
    /// of the lists. Default true so local lab targets (Juice Shop, DVWA) keep working.
    pub allow_localhost: bool,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_cidrs: Vec::new(),
            allowed_domains: Vec::new(),
            denied_cidrs: Vec::new(),
            denied_domains: Vec::new(),
            allow_localhost: true,
        }
    }
}

impl ScopeConfig {
    /// Reject malformed CIDR/IP entries at startup so scope failures surface
    /// before any tool runs, not mid-engagement.
    pub fn validate(&self) -> Result<(), String> {
        for entry in self.allowed_cidrs.iter().chain(&self.denied_cidrs) {
            if entry.parse::<ipnet::IpNet>().is_err() && entry.parse::<std::net::IpAddr>().is_err()
            {
                return Err(format!(
                    "scope: '{entry}' is not a valid CIDR or IP address"
                ));
            }
        }
        Ok(())
    }
}

/// NetExec (credentialed network execution) integration — disabled by default.
///
/// NetExec authenticates to network services (SMB/WinRM/SSH/…) with operator
/// credentials. It is intrusive, so it ships **off**; the `run_netexec` handler
/// refuses until `enabled = true`. Even then it exposes only curated read-only
/// enumeration actions against a single host with a single scalar credential.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct NetExecConfig {
    /// Master switch — the `run_netexec` tool refuses unless this is true.
    pub enabled: bool,
}

impl ExecutionConfig {
    /// Look up timeout for a specific tool, falling back to the default.
    pub fn timeout_for(&self, tool: &str) -> u64 {
        self.timeouts
            .get(tool)
            .copied()
            .unwrap_or(self.default_timeout_secs)
    }

    /// Reject zero-valued limits that would break the scan registry or deadlock
    /// the executor (0 permits). Called at startup via [`RavenConfig::validate`].
    pub fn validate(&self) -> Result<(), String> {
        if self.scan_retention_secs == 0 {
            return Err("scan_retention_secs must be > 0".into());
        }
        if self.max_concurrent_execs == 0 {
            return Err("max_concurrent_execs must be > 0".into());
        }
        Ok(())
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

    /// Whether a tool should be invoked via `sudo` for privilege escalation.
    pub fn needs_sudo(&self, tool: &str) -> bool {
        self.sudo_tools.iter().any(|t| t == tool)
    }

    /// Effective HTTP response body cap: `context_budget / 6` when set, else 20,000.
    pub fn effective_max_response_body(&self) -> usize {
        if self.context_budget > 0 {
            self.context_budget / 6
        } else {
            20_000
        }
    }

    /// Validate that safety limits are within acceptable ranges.
    ///
    /// Called at startup to reject misconfigured or tampered configs before
    /// any tool execution. Prevents an operator from accidentally setting
    /// unsafe limits (e.g. sqlmap level 5 = very aggressive).
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=5).contains(&self.sqlmap_max_level) {
            return Err(format!(
                "sqlmap_max_level must be 1-5, got {}",
                self.sqlmap_max_level
            ));
        }
        if !(1..=3).contains(&self.sqlmap_max_risk) {
            return Err(format!(
                "sqlmap_max_risk must be 1-3, got {}",
                self.sqlmap_max_risk
            ));
        }
        if self.hydra_max_tasks == 0 {
            return Err("hydra_max_tasks must be > 0".into());
        }
        if self.masscan_max_rate == 0 {
            return Err("masscan_max_rate must be > 0".into());
        }
        if self.expected_tool_calls == 0 {
            return Err("expected_tool_calls must be > 0".into());
        }
        if !["info", "low", "medium", "high", "critical"]
            .contains(&self.auto_save_min_severity.to_ascii_lowercase().as_str())
        {
            return Err(format!(
                "auto_save_min_severity must be one of info|low|medium|high|critical, got '{}'",
                self.auto_save_min_severity
            ));
        }
        Ok(())
    }
}

impl RavenConfig {
    /// Load configuration from an explicit file path.
    pub fn load(path: &str) -> Result<Self, crate::error::PentestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))?;
        toml::from_str(&content).map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))
    }

    /// Validate all configuration sections at startup.
    pub fn validate(&self) -> Result<(), String> {
        self.safety.validate()?;
        self.metasploit.validate()?;
        self.scope.validate()?;
        self.execution.validate()?;
        Ok(())
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
                    "subfinder".into(),
                    "wpscan".into(),
                    "enum4linux-ng".into(),
                    "dalfox".into(),
                    "dnsrecon".into(),
                    "john".into(),
                    "httpx".into(),
                    "dnsx".into(),
                    "katana".into(),
                    "nxc".into(),
                ],
                max_output_chars: 50_000,
                tool_paths: HashMap::new(),
                sqlmap_max_level: default_sqlmap_max_level(),
                sqlmap_max_risk: default_sqlmap_max_risk(),
                hydra_max_tasks: default_hydra_max_tasks(),
                masscan_max_rate: default_masscan_max_rate(),
                context_budget: 0,
                sudo_tools: Vec::new(),
                expected_tool_calls: default_expected_tool_calls(),
                auto_save_findings: false,
                auto_save_min_severity: default_auto_save_min_severity(),
                auto_save_max_per_scan: default_auto_save_max_per_scan(),
            },
            execution: ExecutionConfig {
                default_timeout_secs: 600,
                max_concurrent_scans: 3,
                output_dir: "/tmp/raven-nest".into(),
                timeouts: HashMap::new(),
                scan_retention_secs: default_scan_retention_secs(),
                max_concurrent_execs: default_max_concurrent_execs(),
            },
            network: NetworkConfig::default(),
            metasploit: MetasploitConfig::default(),
            scope: ScopeConfig::default(),
            netexec: NetExecConfig::default(),
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
            scan_retention_secs: default_scan_retention_secs(),
            max_concurrent_execs: default_max_concurrent_execs(),
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
            sudo_tools: Vec::new(),
            expected_tool_calls: default_expected_tool_calls(),
            auto_save_findings: false,
            auto_save_min_severity: default_auto_save_min_severity(),
            auto_save_max_per_scan: default_auto_save_max_per_scan(),
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
    fn safety_validate_accepts_defaults() {
        let cfg = RavenConfig::default();
        assert!(cfg.safety.validate().is_ok());
    }

    #[test]
    fn safety_validate_rejects_sqlmap_level_zero() {
        let mut cfg = RavenConfig::default();
        cfg.safety.sqlmap_max_level = 0;
        assert!(cfg.safety.validate().is_err());
    }

    #[test]
    fn safety_validate_rejects_sqlmap_level_six() {
        let mut cfg = RavenConfig::default();
        cfg.safety.sqlmap_max_level = 6;
        assert!(cfg.safety.validate().is_err());
    }

    #[test]
    fn safety_validate_rejects_sqlmap_risk_four() {
        let mut cfg = RavenConfig::default();
        cfg.safety.sqlmap_max_risk = 4;
        assert!(cfg.safety.validate().is_err());
    }

    #[test]
    fn safety_validate_rejects_zero_hydra_tasks() {
        let mut cfg = RavenConfig::default();
        cfg.safety.hydra_max_tasks = 0;
        assert!(cfg.safety.validate().is_err());
    }

    #[test]
    fn safety_validate_rejects_zero_masscan_rate() {
        let mut cfg = RavenConfig::default();
        cfg.safety.masscan_max_rate = 0;
        assert!(cfg.safety.validate().is_err());
    }

    #[test]
    fn msf_validate_rejects_changeme_when_enabled() {
        let cfg = MetasploitConfig {
            enabled: true,
            password: "changeme".into(),
            ..MetasploitConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn msf_validate_accepts_changeme_when_disabled() {
        let cfg = MetasploitConfig::default(); // enabled: false, password: "changeme"
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn msf_validate_accepts_changed_password() {
        let cfg = MetasploitConfig {
            enabled: true,
            password: "strong_password_123".into(),
            ..MetasploitConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn raven_config_validate_delegates_to_sections() {
        let mut cfg = RavenConfig::default();
        assert!(cfg.validate().is_ok());
        cfg.safety.sqlmap_max_level = 99;
        assert!(cfg.validate().is_err());
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

    #[test]
    fn auto_save_defaults() {
        let cfg = RavenConfig::default();
        assert!(!cfg.safety.auto_save_findings);
        assert_eq!(cfg.safety.auto_save_min_severity, "medium");
        assert_eq!(cfg.safety.auto_save_max_per_scan, 25);
    }

    #[test]
    fn safety_validate_rejects_bad_auto_save_severity() {
        let mut cfg = RavenConfig::default();
        cfg.safety.auto_save_min_severity = "extreme".into();
        assert!(cfg.safety.validate().is_err());
    }
}
