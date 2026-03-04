use raven_core::scan_manager::ScanManager;
use rmcp::{model::{CallToolResult, Content}, schemars, };

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct LaunchScanRequest {
    #[schemars(description = "Tool to run: 'nmap', 'nuclei', 'nikto', 'whatweb'")]
    pub tool: String,
    #[schemars(description = "Target IP, hostname, or URL")]
    pub target: String,
    #[schemars(description = "Tool arguments as a list of strings")]
    pub args: Option<Vec<String>>,
    #[schemars(description = "Scan timeout in seconds (default from config, typically 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanIdRequest {
    #[schemars(description = "Scan ID returned by launch_scan")]
    pub scan_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanResultsRequest {
    #[schemars(description = "Scan ID returned by launch_scan")]
    pub scan_id: String,
    #[schemars(description = "Character offset to start reading from (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Max characters to return (default 10000)")]
    pub limit: Option<usize>,
}

pub fn launch(
    manager: &ScanManager,
    req: LaunchScanRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let args = req.args.unwrap_or_default();
    let id = manager.launch(&req.tool, args, &req.target, req.timeout_secs)
        .map_err(crate::error::to_mcp)?;

    Ok(CallToolResult::success(vec![Content::text(
        format!("Scan launched. ID: {id}"),
    )]))
}

pub fn status(
    manager: &ScanManager,
    req: ScanIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let status = manager.status(&req.scan_id)
        .map_err(crate::error::to_mcp)?;

    let text = match status {
        Some(s) => format!("{s:?}"),
        None => "scan not found".into(),
    };

    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub fn results(
    manager: &ScanManager,
    req: ScanResultsRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let offset = req.offset.unwrap_or(0);
    let limit = req.limit.unwrap_or(10_000);

    let output = manager.results(&req.scan_id, offset, limit)
        .map_err(crate::error::to_mcp)?;

    let text = match output {
        Some(s) if s.is_empty() => "no more output (offset past end)".into(),
        Some(s) => s,
        None => "scan not found or still running".into(),
    };

    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub fn cancel(
    manager: &ScanManager,
    req: ScanIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    manager.cancel(&req.scan_id)
        .map_err(crate::error::to_mcp)?;

    Ok(CallToolResult::success(vec![Content::text("scan cancelled")]))
}

pub fn list_scans(
    manager: &ScanManager,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let scans = manager.list()
        .map_err(crate::error::to_mcp)?;

    if scans.is_empty() {
        return Ok(CallToolResult::success(vec![Content::text("no scans")]));
    }

    let lines: Vec<String> = scans.iter()
        .map(|(id, tool, target, status)| {
            format!("{id} | {tool} | {target} | {status:?}")
        })
        .collect();

    Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
}

