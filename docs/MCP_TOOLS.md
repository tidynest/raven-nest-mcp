# MCP Tool Manifest

A machine-readable declaration of every MCP tool Raven Nest exposes: the tool
name and its one-line description, mirrored verbatim from the `#[tool]`
attributes in [`crates/raven-server/src/server.rs`](../crates/raven-server/src/server.rs)
(the source of truth). For the full per-parameter reference, see
[docs/USAGE.md](USAGE.md); for the human-readable category table, see the
[README](../README.md#supported-tools).

Every tool input schema is **strict**: the request structs derive
`#[serde(deny_unknown_fields)]`, the Rust equivalent of JSON Schema
`additionalProperties: false`. An unrecognized argument is rejected with a
descriptive error rather than silently ignored, which both catches LLM
parameter hallucination and prevents unexpected arguments from being smuggled
into a tool call.

The 43 endpoints break down as: 22 wrapped security tools, 6 Metasploit tools
(gated), `ping_target` + `http_request`, 5 scan-management tools, 6
finding/report tools, and 2 engagement tools.

```ts
// Raven Nest MCP declared tool surface (43 tools).
// Every tool input schema is strict: additionalProperties: false.
const tools = [
  { name: "ping_target", description: "Ping target for connectivity check" },
  { name: "run_whatweb", description: "Whatweb tech identification" },
  { name: "http_request", description: "Manual HTTP request" },
  { name: "run_ffuf", description: "Ffuf web fuzzer (use FUZZ keyword in URL)" },
  { name: "run_masscan", description: "Masscan fast port scan (root required)" },
  { name: "run_nmap", description: "Nmap port/service/vuln scanner" },
  { name: "run_nuclei", description: "Nuclei CVE/vuln template scanner" },
  { name: "run_nikto", description: "Nikto web server vuln scanner" },
  { name: "run_testssl", description: "Testssl TLS/SSL auditor" },
  { name: "run_feroxbuster", description: "Feroxbuster directory brute-force" },
  { name: "run_sqlmap", description: "Sqlmap SQL injection scanner" },
  { name: "run_hydra", description: "Hydra auth brute-forcer" },
  { name: "run_enum4linux_ng", description: "Enum4linux-ng SMB/AD enumerator" },
  { name: "run_dalfox", description: "Dalfox XSS scanner" },
  { name: "run_dnsrecon", description: "Dnsrecon DNS enumerator" },
  { name: "run_katana", description: "Katana web crawler/endpoint discovery" },
  { name: "run_john", description: "John password cracker" },
  { name: "run_gitleaks", description: "Scan a directory or git history for committed secrets" },
  { name: "run_trufflehog", description: "trufflehog secret scanner with optional live verification" },
  { name: "run_subfinder", description: "Subfinder subdomain enumerator" },
  { name: "run_httpx", description: "Httpx HTTP prober/fingerprinter" },
  { name: "run_dnsx", description: "Dnsx DNS record resolver" },
  { name: "run_wpscan", description: "Wpscan WordPress vuln scanner" },
  { name: "msf_search", description: "Search Metasploit modules" },
  { name: "msf_module_info", description: "Get Metasploit module info" },
  { name: "msf_exploit", description: "Run Metasploit exploit (requires confirmation)" },
  { name: "msf_auxiliary", description: "Run Metasploit auxiliary module" },
  { name: "msf_sessions", description: "Manage Metasploit sessions" },
  { name: "msf_post", description: "Run Metasploit post-exploitation module" },
  { name: "launch_scan", description: "Launch background scan" },
  { name: "get_scan_status", description: "Check scan status" },
  { name: "get_scan_results", description: "Get scan results (paginated)" },
  { name: "cancel_scan", description: "Cancel scan" },
  { name: "list_scans", description: "List scans" },
  { name: "save_finding", description: "Save finding" },
  { name: "get_finding", description: "Get finding by ID" },
  { name: "list_findings", description: "List findings by severity" },
  { name: "list_findings_by_scan", description: "List findings for a scan ID" },
  { name: "delete_finding", description: "Delete finding" },
  { name: "generate_report", description: "Generate pentest report" },
  { name: "set_engagement", description: "Switch the active engagement (separate findings + report scope per client/target); creates it on first use" },
  { name: "list_engagements", description: "List engagements and show which is active" },
  { name: "run_netexec", description: "NetExec: authenticate + read-only enumerate a single host (gated, off by default). Single scalar credential; no command/module execution." },
];
```

## Keeping this in sync

This file duplicates the tool descriptions that live in `server.rs`. To stop it
drifting, `crates/raven-server/tests/tool_manifest.rs` parses the `#[tool]`
attributes at test time and asserts every description appears here verbatim, so
`cargo test` fails if the two diverge. That test also rejects any description
that would trip a static tool-integrity scanner (hidden-instruction or
exfiltration markers), keeping the declared surface clean by construction.
