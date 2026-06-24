//! MCP server implementation — tool registration and request routing.
//!
//! [`RavenServer`] is the central struct that:
//! - Holds shared state (`Arc<RavenConfig>`, `ScanManager`, `FindingStore`, cookie jar).
//! - Registers all 41 MCP tools via the `#[tool_router]` macro.
//! - Implements `ServerHandler` to provide server info and capabilities.
//!
//! Tool methods are thin wrappers that extract parameters and delegate to the
//! corresponding module in [`tools`](crate::tools). Long-running tools receive
//! a `Peer<RoleServer>` for progress notifications via [`ProgressTicker`](crate::progress::ProgressTicker).

use crate::budget::SessionBudget;
use crate::tools::scans::{LaunchScanRequest, ScanIdRequest, ScanResultsRequest};
use crate::tools::{
    dalfox::DalfoxRequest,
    dnsrecon::DnsreconRequest,
    dnsx::DnsxRequest,
    engagement::SetEngagementRequest,
    enum4linux_ng::Enum4linuxRequest,
    feroxbuster::FeroxbusterRequest,
    ffuf::FfufRequest,
    findings::{FindingIdRequest, GenerateReportRequest, ListByScanRequest, SaveFindingRequest},
    gitleaks::GitleaksRequest,
    http::HttpRequest,
    httpx::HttpxRequest,
    hydra::HydraRequest,
    john::JohnRequest,
    katana::KatanaRequest,
    masscan::MasscanRequest,
    msf_auxiliary::MsfAuxiliaryRequest,
    msf_exploit::MsfExploitRequest,
    msf_module_info::MsfModuleInfoRequest,
    msf_post::MsfPostRequest,
    msf_search::MsfSearchRequest,
    msf_sessions::MsfSessionsRequest,
    netexec::NetExecRequest,
    nikto::NiktoRequest,
    nmap::NmapRequest,
    nuclei::NucleiRequest,
    ping::PingRequest,
    sqlmap::SqlmapRequest,
    subfinder::SubfinderRequest,
    testssl::TestsslRequest,
    trufflehog::TrufflehogRequest,
    whatweb::WhatwebRequest,
    wpscan::WpscanRequest,
};

use rmcp::{
    Peer, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, RawContent, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

/// Central MCP server that owns all shared state and routes tool calls.
///
/// Cloned per-connection by rmcp — all inner state is behind `Arc`/`RwLock`.
#[derive(Clone)]
pub struct RavenServer {
    config: std::sync::Arc<raven_core::config::RavenConfig>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    pub scan_manager: raven_core::scan_manager::ScanManager,
    finding_store: std::sync::Arc<std::sync::RwLock<raven_report::store::FindingStore>>,
    /// Shared cookie jar for `http_request` — persists cookies across requests within a session.
    cookie_jar: std::sync::Arc<reqwest::cookie::Jar>,
    /// Session-aware output budget tracker — dynamically adjusts per-tool caps.
    budget: std::sync::Arc<SessionBudget>,
    /// Metasploit RPC client — `None` when MSF is disabled in config.
    msf_client: Option<std::sync::Arc<raven_core::msf_client::MsfClient>>,
}

#[tool_router]
impl RavenServer {
    /// Create a new server instance, initialising all shared state.
    ///
    /// Creates the output directory, findings store, scan manager, and budget tracker.
    pub fn new(config: raven_core::config::RavenConfig) -> Self {
        let config = std::sync::Arc::new(config);
        // Install the engagement scope process-wide so safety::validate_target —
        // the chokepoint every tool and the scan launcher share — enforces it.
        raven_core::safety::init_scope(config.scope.clone());
        let scan_manager =
            raven_core::scan_manager::ScanManager::new(std::sync::Arc::clone(&config));
        let _ = raven_core::safety::ensure_dir_secure(&config.execution.output_dir);
        let findings_dir = std::path::PathBuf::from(&config.execution.output_dir).join("findings");
        let finding_store = std::sync::Arc::new(std::sync::RwLock::new(
            raven_report::store::FindingStore::new(findings_dir)
                .expect("failed to create findings directory"),
        ));
        let cookie_jar = std::sync::Arc::new(reqwest::cookie::Jar::default());

        // Restore session cookies from disk (survives context clears)
        let cookie_file =
            std::path::PathBuf::from(&config.execution.output_dir).join("session_cookies.json");
        if let Ok(data) = std::fs::read_to_string(&cookie_file)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
            && let (Some(url), Some(cookies)) = (v["url"].as_str(), v["cookies"].as_str())
            && let Ok(parsed) = url.parse::<reqwest::Url>()
        {
            for cookie in cookies.split("; ") {
                cookie_jar.add_cookie_str(cookie, &parsed);
            }
            tracing::info!("restored session cookies from disk");
        }

        // Tool count: 22 security + 6 MSF + ping + http + 5 scan mgmt + 6 findings + 2 engagement = 43
        let tool_count = 43;
        let budget = std::sync::Arc::new(SessionBudget::new(
            config.safety.context_budget,
            tool_count,
            config.safety.expected_tool_calls,
        ));

        let msf_client = if config.metasploit.enabled {
            Some(std::sync::Arc::new(raven_core::msf_client::MsfClient::new(
                &config.metasploit,
            )))
        } else {
            None
        };

        Self {
            config,
            scan_manager,
            tool_router: Self::tool_router(),
            finding_store,
            cookie_jar,
            budget,
            msf_client,
        }
    }

    /// Get the MSF client or return an error if Metasploit is disabled.
    fn require_msf(
        &self,
    ) -> Result<&std::sync::Arc<raven_core::msf_client::MsfClient>, rmcp::ErrorData> {
        self.msf_client.as_ref().ok_or_else(|| {
            rmcp::ErrorData::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                "Metasploit is disabled. Set [metasploit] enabled = true in config.",
                None,
            )
        })
    }

    /// Apply budget enforcement to a tool result: measure, truncate, append status, record.
    fn wrap_result(
        &self,
        result: Result<CallToolResult, rmcp::ErrorData>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if self.budget.is_exhausted() && result.is_ok() {
            return Ok(CallToolResult::success(vec![Content::text(
                "Context budget exhausted. Save findings and generate report.",
            )]));
        }

        let mut call_result = result?;
        let cap = self.budget.allocate();

        // Strip ANSI escape codes and truncate text content.
        // Centralised here so every tool response — parser output, error paths,
        // raw fallback, background scan results — is clean.
        let mut total_chars = 0usize;
        for content in &mut call_result.content {
            if let RawContent::Text(ref mut tc) = content.raw {
                tc.text = crate::tools::strip_ansi(&tc.text);
                let text_len = tc.text.chars().count();
                if text_len > cap.max_chars {
                    tc.text = SessionBudget::truncate_to_cap(&tc.text, cap.max_chars);
                }
                total_chars += tc.text.len();
            }
        }

        // Append budget status line
        if let Some(status) = self.budget.status_line() {
            call_result.content.push(Content::text(status));
            total_chars += 100; // approximate status line size
        }

        self.budget.record(total_chars);
        Ok(call_result)
    }

    // ── Fast tools (1-5s) ────────────────────────────────────────────

    #[tool(
        description = "Ping target for connectivity check",
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
        self.wrap_result(crate::tools::ping::run(&self.config, req).await)
    }

    #[tool(
        description = "Whatweb tech identification",
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
        self.wrap_result(crate::tools::whatweb::run(&self.config, req).await)
    }

    #[tool(
        description = "Manual HTTP request",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn http_request(
        &self,
        Parameters(req): Parameters<HttpRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::http::run(&self.config, self.cookie_jar.clone(), req).await)
    }

    #[tool(
        description = "Ffuf web fuzzer (use FUZZ keyword in URL)",
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
        self.wrap_result(
            crate::tools::ffuf::run(&self.config, req, self.budget.scale_cap(40)).await,
        )
    }

    #[tool(
        description = "Masscan fast port scan (root required)",
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
        self.wrap_result(
            crate::tools::masscan::run(&self.config, req, self.budget.scale_cap(50)).await,
        )
    }

    // ── Medium/Slow tools (5-300s) ───────────────────────────────────

    #[tool(
        description = "Nmap port/service/vuln scanner",
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
        let target = req.target.clone();
        let (result, findings) =
            crate::tools::nmap::run(&self.config, req, Some(peer), self.budget.scale_cap(10))
                .await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "nmap",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Nuclei CVE/vuln template scanner",
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
        let target = req.target.clone();
        let (result, findings) =
            crate::tools::nuclei::run(&self.config, req, Some(peer), self.budget.scale_cap(25))
                .await?;
        // Best-effort auto-save (no-op unless enabled in config); never blocks the response.
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "nuclei",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Nikto web server vuln scanner",
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
        let target = req.target.clone();
        let (result, findings) =
            crate::tools::nikto::run(&self.config, req, Some(peer), self.budget.scale_cap(30))
                .await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "nikto",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Testssl TLS/SSL auditor",
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
        let target = req.target.clone();
        let (result, findings) = crate::tools::testssl::run(&self.config, req, Some(peer)).await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "testssl",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Feroxbuster directory brute-force",
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
        self.wrap_result(
            crate::tools::feroxbuster::run(
                &self.config,
                req,
                Some(peer),
                self.budget.scale_cap(40),
            )
            .await,
        )
    }

    #[tool(
        description = "Sqlmap SQL injection scanner",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn run_sqlmap(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<SqlmapRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let target = req.url.clone();
        let (result, findings) = crate::tools::sqlmap::run(&self.config, req, Some(peer)).await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "sqlmap",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Hydra auth brute-forcer",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn run_hydra(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<HydraRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::hydra::run(&self.config, req, Some(peer)).await)
    }

    #[tool(
        description = "Enum4linux-ng SMB/AD enumerator",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_enum4linux_ng(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<Enum4linuxRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::enum4linux_ng::run(
                &self.config,
                req,
                Some(peer),
                self.budget.scale_cap(20),
            )
            .await,
        )
    }

    #[tool(
        description = "Dalfox XSS scanner",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_dalfox(
        &self,
        Parameters(req): Parameters<DalfoxRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let target = req.target.clone();
        let (result, findings) =
            crate::tools::dalfox::run(&self.config, req, self.budget.scale_cap(20)).await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "dalfox",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Dnsrecon DNS enumerator",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_dnsrecon(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<DnsreconRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::dnsrecon::run(&self.config, req, Some(peer), self.budget.scale_cap(30))
                .await,
        )
    }

    #[tool(
        description = "Katana web crawler/endpoint discovery",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_katana(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<KatanaRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::katana::run(&self.config, req, Some(peer), self.budget.scale_cap(40))
                .await,
        )
    }

    #[tool(
        description = "John password cracker",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    async fn run_john(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<JohnRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::john::run(&self.config, req, Some(peer)).await)
    }

    #[tool(
        description = "gitleaks secret scanner (dir or git-history)",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    async fn run_gitleaks(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<GitleaksRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let target = req.path.clone();
        let (result, findings) = crate::tools::gitleaks::run(&self.config, req, Some(peer)).await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "gitleaks",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "trufflehog secret scanner with optional live verification",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    async fn run_trufflehog(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<TrufflehogRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let target = req.path.clone();
        let (result, findings) =
            crate::tools::trufflehog::run(&self.config, req, Some(peer)).await?;
        crate::tools::extract::auto_save(
            &self.finding_store,
            &self.config,
            "trufflehog",
            &target,
            None,
            findings,
        );
        self.wrap_result(Ok(result))
    }

    #[tool(
        description = "Subfinder subdomain enumerator",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_subfinder(
        &self,
        Parameters(req): Parameters<SubfinderRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::subfinder::run(&self.config, req, self.budget.scale_cap(50)).await,
        )
    }

    #[tool(
        description = "Httpx HTTP prober/fingerprinter",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_httpx(
        &self,
        Parameters(req): Parameters<HttpxRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::httpx::run(&self.config, req, self.budget.scale_cap(30)).await,
        )
    }

    #[tool(
        description = "Dnsx DNS record resolver",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_dnsx(
        &self,
        Parameters(req): Parameters<DnsxRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::dnsx::run(&self.config, req, self.budget.scale_cap(30)).await,
        )
    }

    #[tool(
        description = "Wpscan WordPress vuln scanner",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn run_wpscan(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<WpscanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::wpscan::run(&self.config, req, Some(peer), self.budget.scale_cap(20))
                .await,
        )
    }

    // ── Metasploit tools ──────────────────────────────────────────────

    #[tool(
        description = "Search Metasploit modules",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn msf_search(
        &self,
        Parameters(req): Parameters<MsfSearchRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::msf_search::run(self.require_msf()?, req).await)
    }

    #[tool(
        description = "Get Metasploit module info",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn msf_module_info(
        &self,
        Parameters(req): Parameters<MsfModuleInfoRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::msf_module_info::run(self.require_msf()?, req).await)
    }

    #[tool(
        description = "Run Metasploit exploit (requires confirmation)",
        annotations(destructive_hint = true, open_world_hint = true)
    )]
    async fn msf_exploit(
        &self,
        Parameters(req): Parameters<MsfExploitRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(
            crate::tools::msf_exploit::run(self.require_msf()?, &self.config, req).await,
        )
    }

    #[tool(
        description = "Run Metasploit auxiliary module",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    async fn msf_auxiliary(
        &self,
        Parameters(req): Parameters<MsfAuxiliaryRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::msf_auxiliary::run(self.require_msf()?, req).await)
    }

    #[tool(
        description = "Manage Metasploit sessions",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    async fn msf_sessions(
        &self,
        Parameters(req): Parameters<MsfSessionsRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::msf_sessions::run(self.require_msf()?, req).await)
    }

    #[tool(
        description = "Run Metasploit post-exploitation module",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    async fn msf_post(
        &self,
        Parameters(req): Parameters<MsfPostRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::msf_post::run(self.require_msf()?, req).await)
    }

    // ── Background scan management ───────────────────────────────────

    #[tool(
        description = "Launch background scan",
        annotations(destructive_hint = false, open_world_hint = true)
    )]
    fn launch_scan(
        &self,
        Parameters(req): Parameters<LaunchScanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::scans::launch(&self.scan_manager, req))
    }

    #[tool(
        description = "Check scan status",
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
        self.wrap_result(crate::tools::scans::status(&self.scan_manager, req))
    }

    #[tool(
        description = "Get scan results (paginated)",
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
        self.wrap_result(crate::tools::scans::results(&self.scan_manager, req))
    }

    #[tool(
        description = "Cancel scan",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    fn cancel_scan(
        &self,
        Parameters(req): Parameters<ScanIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::scans::cancel(&self.scan_manager, req))
    }

    #[tool(
        description = "List scans",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_scans(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::scans::list_scans(&self.scan_manager))
    }

    // ── Findings management ──────────────────────────────────────────

    #[tool(
        description = "Save finding",
        annotations(destructive_hint = false, open_world_hint = false)
    )]
    fn save_finding(
        &self,
        Parameters(req): Parameters<SaveFindingRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::findings::save_finding(
            &self.finding_store,
            req,
        ))
    }

    #[tool(
        description = "Get finding by ID",
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
        self.wrap_result(crate::tools::findings::get_finding(
            &self.finding_store,
            req,
        ))
    }

    #[tool(
        description = "List findings by severity",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_findings(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::findings::list_findings(&self.finding_store))
    }

    #[tool(
        description = "List findings for a scan ID",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_findings_by_scan(
        &self,
        Parameters(req): Parameters<ListByScanRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::findings::list_findings_by_scan(
            &self.finding_store,
            req,
        ))
    }

    #[tool(
        description = "Delete finding",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    fn delete_finding(
        &self,
        Parameters(req): Parameters<FindingIdRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::findings::delete_finding(
            &self.finding_store,
            req,
        ))
    }

    #[tool(
        description = "Generate pentest report",
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
        self.wrap_result(crate::tools::findings::generate_report(
            &self.finding_store,
            req,
        ))
    }

    // ── Engagement scoping ───────────────────────────────────────────

    #[tool(
        description = "Switch the active engagement (separate findings + report scope per client/target); creates it on first use",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn set_engagement(
        &self,
        Parameters(req): Parameters<SetEngagementRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::engagement::set_engagement(
            &self.finding_store,
            &self.config,
            req,
        ))
    }

    #[tool(
        description = "List engagements and show which is active",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    fn list_engagements(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::engagement::list_engagements(
            &self.finding_store,
            &self.config,
        ))
    }

    // ── NetExec (gated, credentialed) ────────────────────────────────

    #[tool(
        description = "NetExec: authenticate + read-only enumerate a single host (gated, off by default). Single scalar credential; no command/module execution.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    async fn run_netexec(
        &self,
        peer: Peer<RoleServer>,
        Parameters(req): Parameters<NetExecRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.wrap_result(crate::tools::netexec::run(&self.config, req, Some(peer)).await)
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
        // Advertise the product identity (not the rmcp SDK default) so clients
        // read the real raven-nest name/version from the handshake.
        info.server_info.name = "raven-nest".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
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
2. Recon: nmap, masscan (root), whatweb, httpx (HTTP probe/fingerprint), subfinder (subdomains), dnsx (DNS records), enum4linux-ng (SMB/AD), dnsrecon (DNS).
3. Web: katana (crawl/endpoints), nuclei, nikto, feroxbuster, ffuf, wpscan (WordPress), dalfox (XSS), sqlmap, hydra. testssl for TLS.
4. Password: john (hash cracking).
5. Exploit: msf_search > msf_module_info > msf_exploit (if Metasploit enabled).
6. Targets: bare hostnames/IPs for nmap/ping/masscan; full URLs for web tools.
7. Start with less aggressive scans. Check output for empty/rate-limited results.
8. save_finding for each vuln (pass scan_id to link it to a launched scan; list_findings_by_scan recalls them), then generate_report.

## Tool Timing
- Fast (1-5s): ping_target, run_whatweb, http_request, run_ffuf, run_masscan, run_subfinder, run_httpx, run_dnsx, run_dalfox
- Medium (5-30s): run_nmap (quick/service), run_wpscan, run_dnsrecon, msf_search, msf_module_info
- Slow (30-300s): run_nmap (os/vuln), run_nuclei, run_nikto, run_testssl, run_feroxbuster, run_katana, run_sqlmap, run_hydra, run_enum4linux_ng, run_john, msf_exploit

## Context Budget
Watch the [budget: ...] line in responses. When mode switches to compact/minimal, prioritize saving findings over running more scans.

## Authenticated Scanning
http_request cookie jar persists within a session. Subprocess tools (sqlmap, nikto, etc.) do NOT share it — pass cookies via each tool's `cookie` parameter.";
