//! Engagement scoping - switch the active findings store between per-engagement
//! subdirectories so findings and reports for different clients/targets stay
//! separated.
//!
//! An engagement is just a namespace: `{output_dir}/engagements/{name}/`. Its
//! `findings/` subdirectory backs a [`FindingStore`]; switching swaps the
//! server's active store to point there, and report generation follows via
//! [`FindingStore::base_dir`]. The filesystem is the source of truth - there is
//! no in-memory engagement registry, and the "active" engagement is derived from
//! the store's current path rather than tracked separately.

use crate::tools::findings::success_with;
use raven_core::{config::RavenConfig, safety};
use raven_report::store::FindingStore;
use rmcp::{model::CallToolResult, schemars};
use std::path::PathBuf;
use std::sync::RwLock;

/// MCP request schema for `set_engagement`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetEngagementRequest {
    #[schemars(description = "Engagement name (letters, digits, '-', '_', '.')")]
    pub name: String,
}

/// `{output_dir}/engagements`.
fn engagements_root(config: &RavenConfig) -> PathBuf {
    PathBuf::from(&config.execution.output_dir).join("engagements")
}

/// Validate an engagement name so it maps to exactly one subdirectory and can't
/// escape the engagements root. Rejects empty, `.`/`..`, and any character
/// outside `[A-Za-z0-9._-]` (so path separators, spaces, NUL, etc. are refused).
fn sanitize(name: &str) -> Result<&str, rmcp::ErrorData> {
    let n = name.trim();
    let ok = !n.is_empty()
        && n != "."
        && n != ".."
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(n)
    } else {
        Err(rmcp::ErrorData::invalid_params(
            "engagement name must be non-empty and use only letters, digits, '-', '_', '.'"
                .to_string(),
            None,
        ))
    }
}

/// Switch the active findings store to `{output_dir}/engagements/{name}/findings`,
/// creating it (0700) on first use. Subsequent saved/auto-extracted findings and
/// generated reports scope to this engagement.
pub fn set_engagement(
    store: &RwLock<FindingStore>,
    config: &RavenConfig,
    req: SetEngagementRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let name = sanitize(&req.name)?;
    let dir = engagements_root(config).join(name);
    safety::ensure_dir_secure(&dir).map_err(|e| {
        rmcp::ErrorData::internal_error(format!("failed to create engagement dir: {e}"), None)
    })?;
    let new_store = FindingStore::new(dir.join("findings"))
        .map_err(|e| rmcp::ErrorData::internal_error(e, None))?;
    let count = new_store.list().len();
    *store
        .write()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))? = new_store;
    Ok(success_with(
        format!("Switched to engagement '{name}' ({count} existing finding(s))."),
        serde_json::json!({ "engagement": name, "findings": count }),
    ))
}

/// List engagement subdirectories under `{output_dir}/engagements`, marking the
/// active one. `active` is null when the server is on the default unscoped store.
pub fn list_engagements(
    store: &RwLock<FindingStore>,
    config: &RavenConfig,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let active = store
        .read()
        .map_err(|_| rmcp::ErrorData::internal_error("store lock poisoned", None))?
        .base_dir()
        .to_path_buf();

    let root = engagements_root(config);
    let mut names: Vec<String> = match std::fs::read_dir(&root) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();

    let active_name = names.iter().find(|n| root.join(n) == active).cloned();
    let text = if names.is_empty() {
        "No engagements yet. Use set_engagement to create one.".to_string()
    } else {
        names
            .iter()
            .map(|n| {
                if Some(n) == active_name.as_ref() {
                    format!("* {n} (active)")
                } else {
                    format!("  {n}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(success_with(
        text,
        serde_json::json!({ "engagements": names, "active": active_name }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn setup() -> (Arc<RwLock<FindingStore>>, RavenConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = RavenConfig::default();
        config.execution.output_dir = dir.path().to_string_lossy().into_owned();
        let store = Arc::new(RwLock::new(
            FindingStore::new(dir.path().join("findings")).unwrap(),
        ));
        (store, config, dir)
    }

    #[test]
    fn sanitize_rejects_traversal_and_empty() {
        assert!(sanitize("../etc").is_err());
        assert!(sanitize("a/b").is_err());
        assert!(sanitize("").is_err());
        assert!(sanitize(".").is_err());
        assert!(sanitize("..").is_err());
        // valid names are trimmed and accepted
        assert_eq!(sanitize(" acme-corp_1.0 ").unwrap(), "acme-corp_1.0");
    }

    #[test]
    fn set_engagement_switches_store_base() {
        let (store, config, dir) = setup();
        set_engagement(
            &store,
            &config,
            SetEngagementRequest {
                name: "acme".into(),
            },
        )
        .unwrap();
        let expected = dir.path().join("engagements").join("acme");
        assert_eq!(store.read().unwrap().base_dir(), expected);
    }

    #[test]
    fn list_marks_active_engagement() {
        let (store, config, _dir) = setup();
        for name in ["beta", "alpha"] {
            set_engagement(&store, &config, SetEngagementRequest { name: name.into() }).unwrap();
        }
        // Active is the last switched-to engagement (alpha).
        let res = list_engagements(&store, &config).unwrap();
        let structured = res.structured_content.unwrap();
        assert_eq!(structured["active"].as_str(), Some("alpha"));
        assert_eq!(structured["engagements"].as_array().unwrap().len(), 2);
    }
}
