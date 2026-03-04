use raven_core::scan_manager::{ScanManager, ScanStatus};
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};

/// Auto-inline threshold: outputs smaller than this are included directly
/// in the status response, eliminating a separate get_scan_results call.
const AUTO_INLINE_LIMIT: usize = 10_000;

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
    let tool = &req.tool;
    let id = manager
        .launch(tool, args, &req.target, req.timeout_secs)
        .map_err(crate::error::to_mcp)?;

    let poll_hint = match tool.as_str() {
        "nmap" | "whatweb" => "First poll recommended after 10s",
        "nuclei" | "nikto" | "testssl.sh" => "First poll recommended after 30s",
        _ => "First poll recommended after 15s",
    };

    Ok(CallToolResult::success(vec![Content::text(format!(
        "Scan launched. ID: {id}\n{poll_hint}"
    ))]))
}

pub fn status(
    manager: &ScanManager,
    req: ScanIdRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let info = manager
        .status_enriched(&req.scan_id)
        .map_err(crate::error::to_mcp)?;

    let Some(info) = info else {
        return Ok(CallToolResult::success(vec![Content::text(
            "scan not found",
        )]));
    };

    let status_str = match &info.status {
        ScanStatus::Running => "Running".to_string(),
        ScanStatus::Completed => "Completed".to_string(),
        ScanStatus::Failed(e) => format!("Failed: {e}"),
        ScanStatus::Cancelled => "Cancelled".to_string(),
    };

    let mut text = format!(
        "tool: {}\ntarget: {}\nstatus: {}\nelapsed: {}s",
        info.tool, info.target, status_str, info.elapsed_secs
    );

    // Auto-inline: if completed and output fits, include it directly
    if info.status == ScanStatus::Completed
        && let Some(size) = info.output_chars
    {
        text.push_str(&format!("\noutput_size: {size} chars"));

        if size <= AUTO_INLINE_LIMIT {
            if let Ok(Some(output)) = manager.output(&req.scan_id) {
                text.push_str("\n\n--- OUTPUT ---\n");
                text.push_str(&output);
            }
        } else {
            text.push_str(
                "\n\nOutput too large for inline display. \
                 Use get_scan_results with pagination (offset/limit).",
            );
        }
    }

    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub fn results(
    manager: &ScanManager,
    req: ScanResultsRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let offset = req.offset.unwrap_or(0);
    let limit = req.limit.unwrap_or(10_000);

    let output = manager
        .results(&req.scan_id, offset, limit)
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
    manager.cancel(&req.scan_id).map_err(crate::error::to_mcp)?;

    Ok(CallToolResult::success(vec![Content::text(
        "scan cancelled",
    )]))
}

pub fn list_scans(manager: &ScanManager) -> Result<CallToolResult, rmcp::ErrorData> {
    let scans = manager.list().map_err(crate::error::to_mcp)?;

    if scans.is_empty() {
        return Ok(CallToolResult::success(vec![Content::text("no scans")]));
    }

    let lines: Vec<String> = scans
        .iter()
        .map(|info| {
            let status_str = match &info.status {
                ScanStatus::Running => "Running".to_string(),
                ScanStatus::Completed => "Completed".to_string(),
                ScanStatus::Failed(e) => format!("Failed: {e}"),
                ScanStatus::Cancelled => "Cancelled".to_string(),
            };
            format!(
                "{} | {} | {} | {} | {}s elapsed",
                info.id, info.tool, info.target, status_str, info.elapsed_secs
            )
        })
        .collect();

    Ok(CallToolResult::success(vec![Content::text(
        lines.join("\n"),
    )]))
}
