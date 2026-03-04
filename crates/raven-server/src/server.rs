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
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

#[derive(Clone)]
pub struct RavenServer {
    config: std::sync::Arc<raven_core::config::RavenConfig>,
    tool_router: ToolRouter<Self>,
    pub scan_manager: raven_core::scan_manager::ScanManager,
    finding_store: std::sync::Arc<std::sync::RwLock<raven_report::store::FindingStore>>,
}

#[tool_router]
impl RavenServer {
    pub fn new(config: raven_core::config::RavenConfig) -> Self {
        let config = std::sync::Arc::new(config);
        let scan_manager =
            raven_core::scan_manager::ScanManager::new(std::sync::Arc::clone(&config));
        let _ = std::fs::create_dir_all(&config.execution.output_dir);
        let findings_dir = std::path::PathBuf::from(&config.execution.output_dir).join("findings");
        let finding_store = std::sync::Arc::new(std::sync::RwLock::new(
            raven_report::store::FindingStore::new(findings_dir),
        ));

        Self {
            config,
            scan_manager,
            tool_router: Self::tool_router(),
            finding_store,
        }
    }

    #[tool(description = "Ping a target to verify connectivity and measure latency")]
    async fn ping_target(
        &self,
        Parameters(req): Parameters<PingRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::ping::run(&self.config, req).await
    }

    #[tool(description = "Run an nmap scan with preset configurations")]
    async fn run_nmap(
        &self,
        Parameters(req): Parameters<NmapRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nmap::run(&self.config, req).await
    }

    #[tool(description = "Run nuclei template-based vulnerability scanner")]
    async fn run_nuclei(
        &self,
        Parameters(req): Parameters<NucleiRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nuclei::run(&self.config, req).await
    }

    #[tool(description = "Run nikto web server scanner")]
    async fn run_nikto(
        &self,
        Parameters(req): Parameters<NiktoRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::nikto::run(&self.config, req).await
    }

    #[tool(description = "Run whatweb to identify web technologies")]
    async fn run_whatweb(
        &self,
        Parameters(req): Parameters<WhatwebRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::whatweb::run(&self.config, req).await
    }

    #[tool(description = "Run testssl.sh for SSL/TLS configuration auditing")]
    async fn run_testssl(
        &self,
        Parameters(req): Parameters<TestsslRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::testssl::run(&self.config, req).await
    }

    #[tool(description = "Run feroxbuster for directory and content discovery")]
    async fn run_feroxbuster(
        &self,
        Parameters(req): Parameters<FeroxbusterRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::feroxbuster::run(&self.config, req).await
    }

    #[tool(description = "Run ffuf for web fuzzing with FUZZ keyword substitution")]
    async fn run_ffuf(
        &self,
        Parameters(req): Parameters<FfufRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::ffuf::run(&self.config, req).await
    }

    #[tool(description = "Run sqlmap for SQL injection detection and exploitation")]
    async fn run_sqlmap(
        &self,
        Parameters(req): Parameters<SqlmapRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::sqlmap::run(&self.config, req).await
    }

    #[tool(description = "Run hydra for network authentication brute-forcing")]
    async fn run_hydra(
        &self,
        Parameters(req): Parameters<HydraRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::hydra::run(&self.config, req).await
    }

    #[tool(description = "Run masscan for high-speed port scanning (requires root)")]
    async fn run_masscan(
        &self,
        Parameters(req): Parameters<MasscanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::masscan::run(&self.config, req).await
    }

    #[tool(description = "Send a crafted HTTP request for manual endpoint testing")]
    async fn http_request(
        &self,
        Parameters(req): Parameters<HttpRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::http::run(req).await
    }

    #[tool(description = "Launch a background scan (returns scan ID immediately)")]
    fn launch_scan(
        &self,
        Parameters(req): Parameters<LaunchScanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::launch(&self.scan_manager, req)
    }

    #[tool(description = "Check the status of a background scan")]
    fn get_scan_status(
        &self,
        Parameters(req): Parameters<ScanIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::status(&self.scan_manager, req)
    }

    #[tool(description = "Get results from a completed scan (supports pagination)")]
    fn get_scan_results(
        &self,
        Parameters(req): Parameters<ScanResultsRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::results(&self.scan_manager, req)
    }

    #[tool(description = "Cancel a running scan")]
    fn cancel_scan(
        &self,
        Parameters(req): Parameters<ScanIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::cancel(&self.scan_manager, req)
    }

    #[tool(description = "List all scans and their status")]
    fn list_scans(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::scans::list_scans(&self.scan_manager)
    }

    #[tool(description = "Save a vulnerability finding")]
    fn save_finding(
        &self,
        Parameters(req): Parameters<SaveFindingRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::save_finding(&self.finding_store, req)
    }

    #[tool(description = "Get details of a specific finding")]
    fn get_finding(
        &self,
        Parameters(req): Parameters<FindingIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::get_finding(&self.finding_store, req)
    }

    #[tool(description = "List all findings sorted by severity")]
    fn list_findings(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::list_findings(&self.finding_store)
    }

    #[tool(description = "Delete a finding by ID")]
    fn delete_finding(
        &self,
        Parameters(req): Parameters<FindingIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        crate::tools::findings::delete_finding(&self.finding_store, req)
    }

    #[tool(description = "Generate a markdown pentest report from all findings")]
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
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Raven Nest - pentesting toolkit.\n\n\
             Workflow:\n\
             1. Use ping_target to verify connectivity before scanning.\n\
             2. Use dedicated tools instead of launch_scan:\n\
                - Recon: run_nmap, run_masscan (root), run_whatweb\n\
                - Web: run_nuclei, run_nikto, run_feroxbuster, run_ffuf\n\
                - Exploitation: run_sqlmap, run_hydra\n\
                - TLS: run_testssl\n\
             3. Targets: bare hostnames/IPs for nmap/ping/masscan; full URLs \
                for nuclei, nikto, whatweb, feroxbuster, ffuf, sqlmap.\n\
             4. Start with less aggressive scans (stealthy/passive modes first).\n\
             5. Check scan output for empty results or rate-limit indicators \
                before saving findings.\n\
             6. Save findings with save_finding, then generate_report for the \
                final report."
                .into(),
        );
        info
    }
}
