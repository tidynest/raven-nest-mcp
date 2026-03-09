//! MCP server implementation — tool registration and request routing.
//!
//! [`RavenServer`] is the central struct that:
//! - Holds shared state (`Arc<RavenConfig>`, `ScanManager`, `FindingStore`, cookie jar).
//! - Registers all 18+ MCP tools via the `#[tool_router]` macro.
//! - Implements `ServerHandler` to provide server info and capabilities.
//!
//! Tool methods are thin wrappers that extract parameters and delegate to the
//! corresponding module in [`tools`](crate::tools). Long-running tools receive
//! a `Peer<RoleServer>` for progress notifications via [`ProgressTicker`](crate::progress::ProgressTicker).

use crate::tools::scans::{LaunchScanRequest, ScanIdRequest, ScanResultsRequest};
use crate::tools::{
    feroxbuster::FeroxbusterRequest,
    ffuf::FfufRequest,
    findings::{FindingIdRequest, GenerateReportRequest, SaveFindingRequest},
    http::HttpRequest,
    hydra::HydraRequest,
    masscan::MasscanRequest,
    nikto::NiktoRequest,
    nmap::NmapRequest,
    nuclei::NucleiRequest,
    ping::PingRequest,
    sqlmap::SqlmapRequest,
    testssl::TestsslRequest,
    whatweb::WhatwebRequest,
};

use rmcp::{
    Peer, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

/// Central MCP server that owns all shared state and routes tool calls.
///
/// Cloned per-connection by rmcp — all inner state is behind `Arc`/`RwLock`.
#[derive(Clone)]
pub struct RavenServer {
    config: std::sync::Arc<raven_core::config::RavenConfig>,
    tool_router: ToolRouter<Self>,
    pub scan_manager: raven_core::scan_manager::ScanManager,
    finding_store: std::sync::Arc<std::sync::RwLock<raven_report::store::FindingStore>>,
    /// Shared cookie jar for `http_request` — persists cookies across requests within a session.
    cookie_jar: std::sync::Arc<reqwest::cookie::Jar>,
}

#[tool_router]
impl RavenServer {
    /// Create a new server instance, initialising all shared state.
    ///
    /// Creates the output directory, findings store, and scan manager.
    pub fn new(config: raven_core::config::RavenConfig) -> Self {
        let config = std::sync::Arc::new(config);
        let scan_manager =
            raven_core::scan_manager::ScanManager::new(std::sync::Arc::clone(&config));
        let _ = std::fs::create_dir_all(&config.execution.output_dir);
        let findings_dir = std::path::PathBuf::from(&config.execution.output_dir).join("findings");
        let finding_store = std::sync::Arc::new(std::sync::RwLock::new(
            raven_report::store::FindingStore::new(findings_dir),
        ));
        let cookie_jar = std::sync::Arc::new(reqwest::cookie::Jar::default());

        Self {
            config,
            scan_manager,
            tool_router: Self::tool_router(),
            finding_store,
            cookie_jar,
        }
    }

    // ── Fast tools (1-5s) ────────────────────────────────────────────

    #[tool(
        description = "Ping a target to verify connectivity and measure latency",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn ping_target(
        &self,
        Parameters(req): Parameters<PingRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::ping::run(&self.config, req).await
    }

    #[tool(
        description = "Run whatweb to identify web technologies",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_whatweb(
        &self,
        Parameters(req): Parameters<WhatwebRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::whatweb::run(&self.config, req).await
    }

    #[tool(
        description = "Send a crafted HTTP request for manual endpoint testing",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn http_request(
        &self,
        Parameters(req): Parameters<HttpRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::http::run(&self.config, self.cookie_jar.clone(), req).await
    }

    #[tool(
        description = "Run ffuf for web fuzzing with FUZZ keyword substitution",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_ffuf(
        &self,
        Parameters(req): Parameters<FfufRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::ffuf::run(&self.config, req).await
    }

    #[tool(
        description = "Run masscan for high-speed port scanning (requires root)",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_masscan(
        &self,
        Parameters(req): Parameters<MasscanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::masscan::run(&self.config, req).await
    }

    // ── Medium/Slow tools (5-300s) ───────────────────────────────────

    #[tool(
        description = "Run an nmap scan with preset configurations",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_nmap(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<NmapRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nmap::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run nuclei template-based vulnerability scanner",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_nuclei(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<NucleiRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nuclei::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run nikto web server scanner",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_nikto(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<NiktoRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nikto::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run testssl.sh for SSL/TLS configuration auditing",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_testssl(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<TestsslRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::testssl::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run feroxbuster for directory and content discovery",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_feroxbuster(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<FeroxbusterRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::feroxbuster::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run sqlmap for SQL injection detection and exploitation",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn run_sqlmap(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<SqlmapRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::sqlmap::run(&self.config, req, Some(peer)).await
    }

    #[tool(
        description = "Run hydra for network authentication brute-forcing",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn run_hydra(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<HydraRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::hydra::run(&self.config, req, Some(peer)).await
    }

    // ── Background scan management ───────────────────────────────────

    #[tool(
        description = "Launch a background scan (returns scan ID immediately)",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    fn launch_scan(
        &self,
        Parameters(req): Parameters<LaunchScanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::launch(&self.scan_manager, req)
    }

    #[tool(
        description = "Check the status of a background scan",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn get_scan_status(
        &self,
        Parameters(req): Parameters<ScanIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::status(&self.scan_manager, req)
    }

    #[tool(
        description = "Get results from a completed scan (supports pagination)",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn get_scan_results(
        &self,
        Parameters(req): Parameters<ScanResultsRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::results(&self.scan_manager, req)
    }

    #[tool(
        description = "Cancel a running scan",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    fn cancel_scan(
        &self,
        Parameters(req): Parameters<ScanIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::cancel(&self.scan_manager, req)
    }

    #[tool(
        description = "List all scans and their status",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_scans(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::list_scans(&self.scan_manager)
    }

    // ── Findings management ──────────────────────────────────────────

    #[tool(
        description = "Save a vulnerability finding",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    fn save_finding(
        &self,
        Parameters(req): Parameters<SaveFindingRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::save_finding(&self.finding_store, req)
    }

    #[tool(
        description = "Get details of a specific finding",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn get_finding(
        &self,
        Parameters(req): Parameters<FindingIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::get_finding(&self.finding_store, req)
    }

    #[tool(
        description = "List all findings sorted by severity",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_findings(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::list_findings(&self.finding_store)
    }

    #[tool(
        description = "Delete a finding by ID",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    fn delete_finding(
        &self,
        Parameters(req): Parameters<FindingIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::delete_finding(&self.finding_store, req)
    }

    #[tool(
        description = "Generate a markdown pentest report from all findings",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn generate_report(
        &self,
        Parameters(req): Parameters<GenerateReportRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::generate_report(&self.finding_store, &self.config, req)
    }
}

#[tool_handler]
impl ServerHandler for RavenServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_logging()
            .build();
        info.instructions = Some(SERVER_INSTRUCTIONS.into());
        info
    }
}

/// Instructions sent to the MCP client on connection, guiding tool usage order
/// and parallelism strategy.
const SERVER_INSTRUCTIONS: &str = "\
Raven Nest - pentesting toolkit.

## Workflow
1. ping_target first to verify connectivity.
2. Use dedicated tools (not launch_scan): nmap, masscan (root), whatweb for recon; nuclei, nikto, feroxbuster, ffuf for web; sqlmap, hydra for exploitation; testssl for TLS.
3. Targets: bare hostnames/IPs for nmap/ping/masscan; full URLs for web tools.
4. Start with less aggressive scans first.
5. Check output for empty/rate-limited results before saving findings.
6. save_finding for each vuln, then generate_report.

## Tool Timing
- Fast (1-5s): ping_target, run_whatweb, http_request, run_ffuf, run_masscan
- Medium (5-30s): run_nmap (quick/service)
- Slow (30-300s): run_nmap (os/vuln), run_nuclei, run_nikto, run_testssl, run_feroxbuster, run_sqlmap, run_hydra

## Authenticated Scanning
http_request cookie jar persists within a session. Subprocess tools (sqlmap, nikto, etc.) do NOT share it — pass cookies via each tool's `cookie` parameter.";
