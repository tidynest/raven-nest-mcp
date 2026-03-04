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
    pub fn load(path: &str) -> Result<Self, crate::error::PentestError > {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))?;
        toml::from_str(&content)
            .map_err(|e| crate::error::PentestError::ConfigError(e.to_string()))
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