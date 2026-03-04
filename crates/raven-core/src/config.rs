use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize)]
pub struct RavenConfig {
    pub safety: SafetyConfig,
    pub execution: ExecutionConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SafetyConfig {
    pub allowed_tools: Vec<String>,
    pub max_output_chars: usize,
    /// Optional map of tool name → absolute binary path.
    /// Falls back to $PATH lookup if not specified.
    #[serde(default)]
    pub tool_paths: HashMap<String, String>,
    /// Max sqlmap --level (1-5). Default 2, prevents LLM escalation.
    #[serde(default = "default_sqlmap_max_level")]
    pub sqlmap_max_level: u8,
    /// Max sqlmap --risk (1-3). Default 1.
    #[serde(default = "default_sqlmap_max_risk")]
    pub sqlmap_max_risk: u8,
    /// Max hydra parallel tasks. Default 4.
    #[serde(default = "default_hydra_max_tasks")]
    pub hydra_max_tasks: u16,
    /// Max masscan packet rate (packets/sec). Default 1000.
    #[serde(default = "default_masscan_max_rate")]
    pub masscan_max_rate: u32,
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

#[derive(Clone, Debug, Deserialize)]
pub struct ExecutionConfig {
    pub default_timeout_secs: u64,
    pub max_concurrent_scans: usize,
    pub output_dir: String,
    /// Per-tool timeout overrides (seconds). Falls back to default_timeout_secs.
    #[serde(default)]
    pub timeouts: HashMap<String, u64>,
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
    /// Resolve the binary path for a tool: custom path if configured, else bare name for $PATH.
    pub fn resolve_tool_binary<'a>(&'a self, tool: &'a str) -> &'a str {
        self.tool_paths
            .get(tool)
            .map(|s| s.as_str())
            .unwrap_or(tool)
    }
}

impl RavenConfig {
    pub fn load(path: &str) -> Result<Self, crate::error::PentestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))?;
        toml::from_str(&content).map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))
    }

    /// Resolution chain: RAVEN_CONFIG env → exe-relative config → default.
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

        // 2. Relative to executable (exe_dir/../config/default.toml or exe_dir/config/default.toml)
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
            },
            execution: ExecutionConfig {
                default_timeout_secs: 600,
                max_concurrent_scans: 3,
                output_dir: "/tmp/raven-nest".into(),
                timeouts: HashMap::new(),
            },
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
}
