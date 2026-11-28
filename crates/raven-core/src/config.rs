//! TOML-based configuration for the Raven Nest toolkit.
//!
//! [`RavenConfig`] is the root struct, loaded once at server startup and shared
//! (via `Arc`) across all tool handlers in `raven-server`. It groups settings
//! into three sections:
//!
//! - [`SafetyConfig`] - tool allowlisting, output caps, and per-tool aggressiveness limits.
//! - [`ExecutionConfig`] - timeouts, concurrency, and output directory.
//! - [`NetworkConfig`] - optional HTTP/HTTPS proxy settings injected into
//!   tool subprocesses by [`executor::run`](crate::executor::run).
//!
//! Configuration resolves through a fallback chain:
//! `RAVEN_CONFIG` env var → per-user and system config files → exe-relative
//! `config/default.toml` → CWD fallback → built-in defaults.
//! See [`RavenConfig::load_with_fallback`].

use crate::error::PentestError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// File name of the config under a per-user or system config directory.
const STANDARD_CONFIG_FILE: &str = "raven-nest/config.toml";

/// Per-user and system-wide config locations, most specific first:
/// `$XDG_CONFIG_HOME/raven-nest/config.toml`, falling back to
/// `$HOME/.config/raven-nest/config.toml`, then `/etc/raven-nest/config.toml`.
///
/// Takes the environment values as arguments so it stays a pure function.
/// A relative `XDG_CONFIG_HOME` is ignored, as the XDG base directory
/// specification requires.
fn standard_config_paths(xdg_config_home: Option<&str>, home: Option<&str>) -> Vec<PathBuf> {
    let user_dir = xdg_config_home
        .map(Path::new)
        .filter(|dir| dir.is_absolute())
        .map(Path::to_path_buf)
        .or_else(|| {
            home.filter(|h| !h.is_empty())
                .map(|h| Path::new(h).join(".config"))
        });
    user_dir
        .into_iter()
        .chain(std::iter::once(PathBuf::from("/etc")))
        .map(|dir| dir.join(STANDARD_CONFIG_FILE))
        .collect()
}

/// Put the config source in front of a [`PentestError::ConfigError`] message,
/// so the operator sees which file failed.
fn name_config_source(source: &str, err: PentestError) -> PentestError {
    match err {
        PentestError::ConfigError(msg) => PentestError::ConfigError(format!("{source}: {msg}")),
        other => other,
    }
}

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
    /// Max sqlmap `--level` (1-5). Default 2 - prevents LLM escalation beyond safe testing.
    #[serde(default = "default_sqlmap_max_level")]
    pub sqlmap_max_level: u8,
    /// Max sqlmap `--risk` (1-3). Default 1 - avoids destructive payloads.
    #[serde(default = "default_sqlmap_max_risk")]
    pub sqlmap_max_risk: u8,
    /// Max hydra parallel tasks. Default 4 - limits brute-force throughput.
    #[serde(default = "default_hydra_max_tasks")]
    pub hydra_max_tasks: u16,
    /// Max masscan packet rate (packets/sec). Default 1000 - prevents network saturation.
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
    /// Tools whose binary can already open raw sockets without root or `sudo`,
    /// for example through Linux file capabilities (`setcap cap_net_raw+eip`).
    /// Listing a tool only skips the server's own root pre-check for masscan
    /// and nmap OS detection. It grants nothing: a tool listed here without
    /// the capability fails when it runs.
    #[serde(default)]
    pub raw_socket_tools: Vec<String>,
    /// Expected tool calls per session. Used by the session budget tracker to
    /// plan output allocation. Higher values yield smaller per-call caps.
    /// Default 10 - typical pentest workflow is 6-12 tool calls.
    #[serde(default = "default_expected_tool_calls")]
    pub expected_tool_calls: usize,
    /// Auto-save findings extracted from scan output (currently nuclei only).
    /// Off by default - the operator opts in. When true, qualifying findings
    /// are deduplicated and persisted with `source = AutoExtracted`.
    #[serde(default)]
    pub auto_save_findings: bool,
    /// Minimum severity an auto-extracted finding must meet to be saved
    /// (`info|low|medium|high|critical`). Default `"medium"`.
    #[serde(default = "default_auto_save_min_severity")]
    pub auto_save_min_severity: String,
    /// Cap on auto-saved findings per scan - bounds finding spam and disk use.
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
fn default_min_exec_gap_ms() -> u64 {
    0
}
fn default_per_target_min_gap_ms() -> u64 {
    0
}

/// Execution environment: timeouts, concurrency, and filesystem paths.
#[derive(Clone, Debug, Deserialize)]
pub struct ExecutionConfig {
    /// Global timeout applied when no per-tool override exists (seconds).
    pub default_timeout_secs: u64,
    /// Maximum number of background scans that can run simultaneously.
    /// Enforced by [`ScanManager::launch`](crate::scan_manager::ScanManager::launch).
    pub max_concurrent_scans: usize,
    /// Base directory for scan output files, scan metadata, and reports.
    pub output_dir: String,
    /// Per-tool timeout overrides (seconds). Falls back to `default_timeout_secs`.
    #[serde(default)]
    pub timeouts: HashMap<String, u64>,
    /// Seconds to retain a completed/failed/cancelled scan before it is evicted
    /// (and its output and metadata files deleted). Default 3600 (1h). Bounds the
    /// scan registry and its on-disk footprint on long-lived servers.
    #[serde(default = "default_scan_retention_secs")]
    pub scan_retention_secs: u64,
    /// Max concurrent *synchronous* tool executions, separate from
    /// `max_concurrent_scans` (which bounds background scans). Default 4 -
    /// prevents an LLM from spawning unbounded subprocesses via parallel calls.
    #[serde(default = "default_max_concurrent_execs")]
    pub max_concurrent_execs: usize,
    /// Minimum milliseconds between consecutive tool launches, process-wide. A
    /// proactive cooldown: back-to-back aggressive tools against one target can
    /// trip its WAF or rate-limiter (or get the tester banned). Default 0
    /// (disabled - opt in). Complements the reactive WAF detection in the executor.
    #[serde(default = "default_min_exec_gap_ms")]
    pub min_exec_gap_ms: u64,
    /// Minimum gap (milliseconds) between launches against the same target
    /// host. Unlike `min_exec_gap_ms` (one global launch queue), this keys
    /// the cooldown per host: independent targets proceed in parallel while
    /// a single host is never hit faster than this. Targets are normalised
    /// to their host (URL scheme/port/path dropped); tools without a network
    /// target (john, gitleaks, trufflehog) are exempt. Default 0 (off).
    #[serde(default = "default_per_target_min_gap_ms")]
    pub per_target_min_gap_ms: u64,
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

/// Metasploit Framework RPC integration - disabled by default.
///
/// When enabled, the server connects to a running `msfrpcd` instance via
/// MessagePack RPC. The operator must start msfrpcd separately.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct MetasploitConfig {
    /// Master switch - MSF tools only registered when true.
    pub enabled: bool,
    /// msfrpcd host (default 127.0.0.1).
    pub host: String,
    /// msfrpcd port (default 55553).
    pub port: u16,
    /// RPC username (default "msf").
    pub username: String,
    /// RPC password - operator MUST change this.
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
    /// Validate MSF config - reject the default "changeme" password when enabled.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.password == "changeme" {
            return Err("metasploit is enabled but password is still 'changeme' - \
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

/// Engagement scope - an operator-configured authorization allowlist.
///
/// Disabled by default (`enabled = false`), preserving current behaviour where
/// any syntactically valid target may be scanned. When enabled, every target is
/// gated by [`safety::check_scope`](crate::safety::check_scope): it must match an
/// `allowed_*` entry and must not match a `denied_*` entry (deny wins).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ScopeConfig {
    /// Master switch - when false (default), no scope gating is applied.
    pub enabled: bool,
    /// In-scope IP ranges (CIDR like `10.0.0.0/8`, or a bare IP = single host).
    pub allowed_cidrs: Vec<String>,
    /// In-scope domains. Matches the domain and its subdomains (`example.com`
    /// matches `example.com` and `api.example.com`, not `notexample.com`).
    pub allowed_domains: Vec<String>,
    /// Explicitly out-of-scope IP ranges - checked before the allow list (deny
    /// wins). Useful for carving out e.g. cloud metadata (`169.254.169.254/32`).
    pub denied_cidrs: Vec<String>,
    /// Explicitly out-of-scope domains - checked before the allow list (deny wins).
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

/// NetExec (credentialed network execution) integration - disabled by default.
///
/// NetExec authenticates to network services (SMB/WinRM/SSH/…) with operator
/// credentials. It is intrusive, so it ships **off**; the `run_netexec` handler
/// refuses until `enabled = true`. Even then it exposes only curated read-only
/// enumeration actions against a single host with a single scalar credential.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct NetExecConfig {
    /// Master switch - the `run_netexec` tool refuses unless this is true.
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
        if self.min_exec_gap_ms > 60_000 {
            return Err("min_exec_gap_ms must be <= 60000 (60s)".into());
        }
        if self.per_target_min_gap_ms > 60_000 {
            return Err("per_target_min_gap_ms must be <= 60000 (60s)".into());
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

    /// Whether a raw-socket tool can run without the server itself being root:
    /// it goes through `sudo`, or the operator listed it in `raw_socket_tools`.
    pub fn has_raw_socket_access(&self, tool: &str) -> bool {
        self.needs_sudo(tool) || self.raw_socket_tools.iter().any(|t| t == tool)
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

    /// Load the config at `path` if a file is there.
    ///
    /// `Ok(None)` means no file exists at `path`. A file that exists but cannot
    /// be read or parsed is an error: skipping it would start the server on
    /// settings the operator did not write, possibly with the scope off.
    fn load_if_present(path: &Path) -> Result<Option<Self>, PentestError> {
        if !path.exists() {
            return Ok(None);
        }
        Self::load(&path.to_string_lossy())
            .map(Some)
            .map_err(|e| name_config_source(&path.display().to_string(), e))
    }

    /// Load configuration using a fallback chain. The first file found wins:
    /// 1. The file named in the `RAVEN_CONFIG` environment variable
    /// 2. `$XDG_CONFIG_HOME/raven-nest/config.toml`, or `~/.config/raven-nest/config.toml`
    /// 3. `/etc/raven-nest/config.toml`
    /// 4. `config/default.toml` next to the executable, or up to two directories above it
    /// 5. `config/default.toml` in the current working directory
    /// 6. Built-in defaults, when no file exists in any of those places
    ///
    /// A config file that exists but fails to load is an error, never a reason
    /// to fall through to the next step. The same goes for a `RAVEN_CONFIG`
    /// that names a missing file.
    pub fn load_with_fallback() -> Result<Self, PentestError> {
        // 1. RAVEN_CONFIG names the file outright, so it has to load.
        if let Some(path) = std::env::var("RAVEN_CONFIG").ok().filter(|p| !p.is_empty()) {
            let source = format!("RAVEN_CONFIG={path}");
            let config = Self::load(&path).map_err(|e| name_config_source(&source, e))?;
            tracing::info!("config loaded from {source}");
            return Ok(config);
        }

        // 2-3. Per-user, then system-wide.
        let xdg_config_home = std::env::var("XDG_CONFIG_HOME").ok();
        let home = std::env::var("HOME").ok();
        let standard = standard_config_paths(xdg_config_home.as_deref(), home.as_deref());

        // 4. Relative to executable: exe_dir/config/, then one and two levels up.
        //    Two levels up is the repository root for a target/release/ build.
        let exe = std::env::current_exe().ok();
        let exe_relative = exe
            .iter()
            .flat_map(|exe| exe.ancestors().skip(1).take(3))
            .map(|dir| dir.join("config/default.toml"));

        // 5. Current directory (legacy behaviour)
        let cwd_relative = std::iter::once(PathBuf::from("config/default.toml"));

        for candidate in standard.into_iter().chain(exe_relative).chain(cwd_relative) {
            if let Some(config) = Self::load_if_present(&candidate)? {
                tracing::info!("config loaded from {}", candidate.display());
                return Ok(config);
            }
        }

        tracing::warn!("no config found, using built-in defaults");
        Ok(Self::default())
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
                    "gitleaks".into(),
                    "trufflehog".into(),
                ],
                max_output_chars: 50_000,
                tool_paths: HashMap::new(),
                sqlmap_max_level: default_sqlmap_max_level(),
                sqlmap_max_risk: default_sqlmap_max_risk(),
                hydra_max_tasks: default_hydra_max_tasks(),
                masscan_max_rate: default_masscan_max_rate(),
                context_budget: 0,
                sudo_tools: Vec::new(),
                raw_socket_tools: Vec::new(),
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
                min_exec_gap_ms: default_min_exec_gap_ms(),
                per_target_min_gap_ms: default_per_target_min_gap_ms(),
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
            min_exec_gap_ms: default_min_exec_gap_ms(),
            per_target_min_gap_ms: default_per_target_min_gap_ms(),
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
            raw_socket_tools: Vec::new(),
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
    fn load_if_present_is_none_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = RavenConfig::load_if_present(&dir.path().join("config.toml")).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_if_present_reads_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, include_str!("../../../config/default.toml")).unwrap();
        let loaded = RavenConfig::load_if_present(&path).unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn load_if_present_fails_on_a_broken_file_and_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not [valid toml = ").unwrap();
        let err = RavenConfig::load_if_present(&path).unwrap_err();
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn standard_paths_prefer_xdg_config_home() {
        let paths = standard_config_paths(Some("/xdg"), Some("/home/user"));
        assert_eq!(
            paths,
            [
                PathBuf::from("/xdg/raven-nest/config.toml"),
                PathBuf::from("/etc/raven-nest/config.toml"),
            ]
        );
    }

    #[test]
    fn standard_paths_fall_back_to_home_when_xdg_is_unset_or_relative() {
        let expected = [
            PathBuf::from("/home/user/.config/raven-nest/config.toml"),
            PathBuf::from("/etc/raven-nest/config.toml"),
        ];
        assert_eq!(standard_config_paths(None, Some("/home/user")), expected);
        assert_eq!(
            standard_config_paths(Some("relative/dir"), Some("/home/user")),
            expected
        );
    }

    #[test]
    fn standard_paths_keep_the_system_file_without_a_home() {
        assert_eq!(
            standard_config_paths(None, None),
            [PathBuf::from("/etc/raven-nest/config.toml")]
        );
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
    fn default_allowlist_matches_shipped_configs() {
        let mut built_in = RavenConfig::default().safety.allowed_tools;
        built_in.sort();
        for shipped in [
            include_str!("../../../config/default.toml"),
            include_str!("../../../config/container.toml"),
        ] {
            let shipped: RavenConfig = toml::from_str(shipped).unwrap();
            let mut from_file = shipped.safety.allowed_tools;
            from_file.sort();
            assert_eq!(built_in, from_file);
        }
    }

    #[test]
    fn container_config_is_valid_and_needs_no_sudo() {
        let cfg: RavenConfig =
            toml::from_str(include_str!("../../../config/container.toml")).unwrap();
        cfg.validate().unwrap();
        // The image has no sudo: raw sockets come from file capabilities.
        assert!(cfg.safety.sudo_tools.is_empty());
        assert!(cfg.safety.has_raw_socket_access("nmap"));
        assert!(cfg.safety.has_raw_socket_access("masscan"));
    }

    #[test]
    fn raw_socket_access_comes_from_sudo_or_the_explicit_list() {
        let mut safety = RavenConfig::default().safety;
        assert!(!safety.has_raw_socket_access("masscan"));
        safety.sudo_tools = vec!["masscan".into()];
        assert!(safety.has_raw_socket_access("masscan"));
        assert!(!safety.has_raw_socket_access("nmap"));
        safety.raw_socket_tools = vec!["nmap".into()];
        assert!(safety.has_raw_socket_access("nmap"));
        // Listing a tool here never routes it through sudo.
        assert!(!safety.needs_sudo("nmap"));
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
    fn execution_validate_rejects_oversized_gaps() {
        let mut cfg = RavenConfig::default();
        cfg.execution.per_target_min_gap_ms = 60_001;
        assert!(cfg.validate().is_err());
        cfg.execution.per_target_min_gap_ms = 60_000;
        cfg.execution.min_exec_gap_ms = 60_001;
        assert!(cfg.validate().is_err());
        cfg.execution.min_exec_gap_ms = 60_000;
        assert!(cfg.validate().is_ok());
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
