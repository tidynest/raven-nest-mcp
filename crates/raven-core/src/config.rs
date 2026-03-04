use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RavenConfig {
    pub safety: SafetyConfig,
    pub execution: ExecutionConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SafetyConfig {
    pub allowed_tools: Vec<String>,
    pub max_output_chars: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExecutionConfig {
    pub default_timeout_secs: u64,
    pub max_concurrent_scans: usize,
    pub output_dir: String,
}

impl RavenConfig {
    pub fn load(path: &str) -> Result<Self, crate::error::PentestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))?;
        toml::from_str(&content).map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))
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
                ],
                max_output_chars: 50_000,
            },
            execution: ExecutionConfig {
                default_timeout_secs: 600,
                max_concurrent_scans: 3,
                output_dir: "/tmp/raven-nest".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_tools() {
        let cfg = RavenConfig::default();
        let tools = &cfg.safety.allowed_tools;
        for expected in &["ping", "nmap", "nuclei", "nikto", "whatweb"] {
            assert!(
                tools.iter().any(|t| t == expected),
                "missing tool: {expected}"
            );
        }
    }

    #[test]
    fn load_missing_file_returns_error() {
        let err = RavenConfig::load("/nonexistent/path/config.toml").unwrap_err();
        assert!(matches!(err, crate::error::PentestError::ConfigError(_)));
    }

    #[test]
    fn load_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid [[[ toml").unwrap();
        let err = RavenConfig::load(path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, crate::error::PentestError::ConfigError(_)));
    }
}
