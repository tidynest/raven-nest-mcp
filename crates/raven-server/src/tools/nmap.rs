use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{model::{CallToolResult, Content}, schemars};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NmapRequest {
    #[schemars(description = "Target IP, hostname, or CIDR range")]
    pub target: String,
    #[schemars(description = "Port spec (e.g. '80,443' or '1-1000')")]
    pub ports: Option<String>,
    #[schemars(description = "Scan type: 'quick', 'service', 'os'")]
    pub scan_type: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: NmapRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target)
        .map_err(crate::error::to_mcp)?;

    // OS detection requires root privileges
    // SAFETY: geteuid is a trivial read-only syscall with no invariants
    if req.scan_type.as_deref() == Some("os") && unsafe { libc::geteuid() } != 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "scan_type 'os' requires root privileges (nmap -O needs raw sockets)",
            None,
        ));
    }

    let mut args: Vec<String> = match req.scan_type.as_deref() {
        Some("service") => vec!["-sV".into()],
        Some("os") => vec!["-O".into()],
        Some("vuln") => vec!["-sV".into(), "--script=vuln".into()],
        _ => vec!["-T4".into(), "-F".into()],  // quick (default)
    };

    if let Some(ports) = req.ports {
        args.push("-p".into());
        args.push(ports.clone());
    }

    args.push(req.target);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(
        config,
        "nmap",
        &arg_refs,
        None,
    )
    .await
    .map_err(crate::error::to_mcp)?;

    let output = crate::error::format_result("nmap", &result);
    Ok(CallToolResult::success(vec![Content::text(output)]))
}
