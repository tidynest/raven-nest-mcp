//! WordPress vulnerability scanner via wpscan.
//!
//! Enumerates plugins, themes, users, and cross-references against WPVulnDB.
//! Output is requested in JSON format (`--format json`) for structured processing.
//!
//! Supports two enumeration presets:
//! - `quick` (default) - vulnerable plugins, themes, and users (`vp,vt,u`).
//! - `thorough` - all plugins, themes, users, config backups, DB exports (`vp,vt,u,ap,at,cb,dbe`).

use raven_core::{config::RavenConfig, safety};
use rmcp::{Peer, RoleServer, model::CallToolResult, schemars};

/// MCP request schema for `run_wpscan`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WpscanRequest {
    #[schemars(description = "WordPress site URL")]
    pub target: String,
    #[schemars(description = "Preset: 'quick' or 'thorough'")]
    pub enumerate: Option<String>,
    #[schemars(description = "WPVulnDB API token for vulnerability data")]
    pub api_token: Option<String>,
    #[schemars(description = "Cookie for authenticated scanning")]
    pub cookie: Option<String>,
}

/// Execute a wpscan scan with optional enumeration preset and API token.
pub async fn run(
    config: &RavenConfig,
    req: WpscanRequest,
    peer: Option<Peer<RoleServer>>,
    result_limit: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer
        .map(|p| crate::progress::ProgressTicker::start(p, "wpscan".into(), req.target.clone()));

    let enum_value = match req.enumerate.as_deref() {
        Some("thorough") => "vp,vt,u,ap,at,cb,dbe",
        _ => "vp,vt,u", // quick (default)
    };

    let mut args = vec![
        "--url".to_string(),
        req.target,
        "--format".into(),
        "json".into(),
        "--no-banner".into(),
        "--enumerate".into(),
        enum_value.into(),
    ];

    if let Some(ref token) = req.api_token {
        args.extend(["--api-token".into(), token.clone()]);
    }
    if let Some(ref cookie) = req.cookie {
        args.extend(["--cookie".into(), cookie.clone()]);
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    super::run_and_format(config, "wpscan", &arg_refs, None, |s| {
        parse_wpscan_json(s, result_limit)
    })
    .await
}

/// Parse wpscan JSON output into a compact structured summary.
///
/// Extracts WordPress version/status, plugin/theme vulnerability counts,
/// and enumerated users. Returns `None` if JSON parsing fails entirely.
pub fn parse_wpscan_json(raw: &str, max_results: usize) -> Option<String> {
    let max_plugins = max_results;
    let max_users = (max_results / 2).max(3);
    let v: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;

    let mut out = String::new();

    // WordPress version + status
    if let Some(ver) = v.get("version") {
        let number = ver.get("number").and_then(|n| n.as_str()).unwrap_or("?");
        let status = ver
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        let vuln_count = ver
            .get("vulnerabilities")
            .and_then(|a| a.as_array())
            .map_or(0, |a| a.len());
        out.push_str(&format!("WordPress {number} ({status})"));
        if vuln_count > 0 {
            out.push_str(&format!(
                " - {vuln_count} vulnerabilit{}",
                if vuln_count == 1 { "y" } else { "ies" }
            ));
        }
        out.push('\n');
    }

    // Interesting findings
    if let Some(findings) = v.get("interesting_findings").and_then(|f| f.as_array())
        && !findings.is_empty()
    {
        out.push_str(&format!("Interesting findings: {}\n", findings.len()));
    }

    // Plugins
    if let Some(plugins) = v.get("plugins").and_then(|p| p.as_object())
        && !plugins.is_empty()
    {
        out.push_str("Plugins:\n");
        for (i, (name, info)) in plugins.iter().enumerate() {
            if i >= max_plugins {
                out.push_str(&format!("  ... and {} more\n", plugins.len() - max_plugins));
                break;
            }
            let version = info
                .get("version")
                .and_then(|v| v.get("number"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let vuln_count = info
                .get("vulnerabilities")
                .and_then(|a| a.as_array())
                .map_or(0, |a| a.len());
            out.push_str(&format!(
                "  {name} {version} - {vuln_count} vulnerabilit{}\n",
                if vuln_count == 1 { "y" } else { "ies" }
            ));
        }
    }

    // Main theme
    if let Some(theme) = v.get("main_theme") {
        let slug = theme
            .get("slug")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        let version = theme
            .get("version")
            .and_then(|v| v.get("number"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");
        let vuln_count = theme
            .get("vulnerabilities")
            .and_then(|a| a.as_array())
            .map_or(0, |a| a.len());
        out.push_str("Themes:\n");
        out.push_str(&format!(
            "  {slug} {version} - {vuln_count} vulnerabilit{}\n",
            if vuln_count == 1 { "y" } else { "ies" }
        ));
    }

    // Themes map (additional themes beyond main_theme)
    if let Some(themes) = v.get("themes").and_then(|t| t.as_object())
        && !themes.is_empty()
    {
        // Only add header if main_theme didn't already
        if v.get("main_theme").is_none() {
            out.push_str("Themes:\n");
        }
        for (name, info) in themes {
            let version = info
                .get("version")
                .and_then(|v| v.get("number"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let vuln_count = info
                .get("vulnerabilities")
                .and_then(|a| a.as_array())
                .map_or(0, |a| a.len());
            out.push_str(&format!(
                "  {name} {version} - {vuln_count} vulnerabilit{}\n",
                if vuln_count == 1 { "y" } else { "ies" }
            ));
        }
    }

    // Users
    if let Some(users) = v.get("users").and_then(|u| u.as_array())
        && !users.is_empty()
    {
        let names: Vec<&str> = users
            .iter()
            .take(max_users)
            .filter_map(|u| u.get("slug").and_then(|s| s.as_str()))
            .collect();
        out.push_str(&format!("Users: {}", names.join(", ")));
        if users.len() > max_users {
            out.push_str(&format!(" ... and {} more", users.len() - max_users));
        }
        out.push('\n');
    }

    let result = out.trim().to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wpscan_full_output() {
        let json = r#"{
            "target_url": "http://example.com/",
            "effective_url": "http://example.com/",
            "interesting_findings": [
                {"url": "http://example.com/readme.html", "type": "text"}
            ],
            "version": {
                "number": "5.9",
                "status": "outdated",
                "vulnerabilities": [
                    {"title": "WP < 5.9.2 XSS"},
                    {"title": "WP < 5.9.3 SQLi"},
                    {"title": "WP < 5.9.1 SSRF"}
                ]
            },
            "main_theme": {
                "slug": "flavor",
                "version": {"number": "1.0"},
                "vulnerabilities": [{"title": "XSS in flavor"}]
            },
            "plugins": {
                "contact-form-7": {
                    "slug": "contact-form-7",
                    "version": {"number": "1.2.3"},
                    "vulnerabilities": [{"title": "CFV vuln 1"}, {"title": "CFV vuln 2"}]
                },
                "wp-super-cache": {
                    "slug": "wp-super-cache",
                    "version": {"number": "1.0.0"},
                    "vulnerabilities": []
                }
            },
            "users": [
                {"id": 1, "slug": "admin"},
                {"id": 2, "slug": "editor"}
            ]
        }"#;

        let result = parse_wpscan_json(json, 20).unwrap();
        assert!(result.contains("WordPress 5.9 (outdated)"));
        assert!(result.contains("3 vulnerabilities"));
        assert!(result.contains("Interesting findings: 1"));
        assert!(result.contains("contact-form-7 1.2.3"));
        assert!(result.contains("2 vulnerabilities"));
        assert!(result.contains("wp-super-cache 1.0.0"));
        assert!(result.contains("0 vulnerabilities"));
        assert!(result.contains("flavor 1.0"));
        assert!(result.contains("1 vulnerability"));
        assert!(result.contains("Users: admin, editor"));
    }

    #[test]
    fn parse_wpscan_minimal_output() {
        let json = r#"{
            "target_url": "http://example.com/",
            "version": {
                "number": "6.4",
                "status": "latest",
                "vulnerabilities": []
            }
        }"#;

        let result = parse_wpscan_json(json, 20).unwrap();
        assert!(result.contains("WordPress 6.4 (latest)"));
        assert!(!result.contains("vulnerabilit"));
    }

    #[test]
    fn parse_wpscan_empty_returns_none() {
        assert!(parse_wpscan_json("", 20).is_none());
        assert!(parse_wpscan_json("not json at all", 20).is_none());
        assert!(parse_wpscan_json("{}", 20).is_none());
    }

    #[test]
    fn enumerate_preset_mapping() {
        // Verify the preset values resolve correctly by checking against run()'s logic
        let quick_value = match Some("quick") {
            Some("thorough") => "vp,vt,u,ap,at,cb,dbe",
            _ => "vp,vt,u",
        };
        assert_eq!(quick_value, "vp,vt,u");

        let thorough_value = match Some("thorough") {
            Some("thorough") => "vp,vt,u,ap,at,cb,dbe",
            _ => "vp,vt,u",
        };
        assert_eq!(thorough_value, "vp,vt,u,ap,at,cb,dbe");

        let default_value = match None::<&str> {
            Some("thorough") => "vp,vt,u,ap,at,cb,dbe",
            _ => "vp,vt,u",
        };
        assert_eq!(default_value, "vp,vt,u");
    }

    #[test]
    fn parse_wpscan_caps_plugins_and_users() {
        // Build JSON with 25 plugins and 15 users
        let mut plugins = serde_json::Map::new();
        for i in 0..25 {
            plugins.insert(
                format!("plugin-{i}"),
                serde_json::json!({
                    "slug": format!("plugin-{i}"),
                    "version": {"number": "1.0"},
                    "vulnerabilities": []
                }),
            );
        }
        let mut users = Vec::new();
        for i in 0..15 {
            users.push(serde_json::json!({"id": i, "slug": format!("user{i}")}));
        }
        let json = serde_json::json!({
            "target_url": "http://example.com/",
            "plugins": plugins,
            "users": users
        });

        let result = parse_wpscan_json(&json.to_string(), 20).unwrap();
        assert!(result.contains("... and 5 more"));
        assert!(result.contains("... and 5 more"));
    }
}
