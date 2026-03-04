# Raven Nest MCP — Issues & Improvements

Identified during a real scan session against a hardened target (ericjingryd.com, 2026-03-04).
This document serves as the working backlog for fixes and enhancements.

---

## 1. Scan Process Issues

### 1.1 `launch_scan` vs Dedicated Tools — RESOLVED

**Problem:** `launch_scan` bypassed the dedicated tool wrappers and sent raw CLI args straight to `executor::run`, skipping target validation and allowlist checks.

**Resolution:** Added `safety::check_allowlist` and `safety::validate_target` calls at the top of `scan_manager::launch()`, so all background scans now pass through the same safety layers as the dedicated tools.

**Files changed:** `crates/raven-core/src/scan_manager.rs`

### 1.2 Target/URL Validation Rejects Valid Inputs — RESOLVED

**Problem:** `safety::validate_target` only accepted bare hostnames and IPs. URLs with schemes (`https://example.com`) were rejected.

**Resolution:** Extended `validate_target` to parse URLs via the `url` crate first. If the input has a valid `http`/`https` scheme, only the host component is validated. Bare hostnames/IPs/CIDR fall through to the existing logic.

**Files changed:** `crates/raven-core/src/safety.rs`, `crates/raven-core/Cargo.toml`, workspace `Cargo.toml`

### 1.3 Nmap `-O` Requires Root — RESOLVED

**Problem:** The `os` scan type uses nmap `-O` which requires raw sockets (root). Running as a normal user produced a confusing error from nmap itself.

**Resolution:** Added a `libc::geteuid()` check before launching. If the effective UID is non-zero and scan type is `os`, returns a clear `INVALID_PARAMS` error explaining the root requirement.

**Files changed:** `crates/raven-server/src/tools/nmap.rs`, `crates/raven-server/Cargo.toml`, workspace `Cargo.toml`

---

## 2. Result Validation & Quality Control

### 2.1 No Output Validation — RESOLVED

**Problem:** Scan results were returned as raw text with no quality assessment. A scan could "succeed" (exit 0) but return empty or garbage output with no indication to the caller.

**Resolution:** Added `OutputQuality` enum and `assess_quality()` to `executor.rs`. After successful command execution, output is assessed for:
- **Empty output** — below 50 chars triggers an `Empty` quality warning.
- **Rate-limit indicators** — checks for 429, "rate limit", "blocked", "forbidden", "waf", etc.
- **Tool-specific completion markers** — e.g., nmap expects "Nmap done", nuclei expects multi-line output, nikto expects "host(s) tested".

`CommandResult` now carries `quality: OutputQuality` and `warning: Option<String>`. A shared `format_result()` helper in `error.rs` appends warnings to tool output.

**Files changed:** `crates/raven-core/src/executor.rs`, `crates/raven-server/src/error.rs`, all tool handlers in `crates/raven-server/src/tools/`

### 2.2 Rate-Limit / WAF Awareness — RESOLVED

**Problem:** No detection or feedback when tools got rate-limited or blocked by a WAF.

**Resolution:** Integrated into the output quality system (2.1). The `detect_rate_limit()` function scans both stdout and stderr for common rate-limit/WAF indicators and surfaces a warning when detected.

**Files changed:** `crates/raven-core/src/executor.rs`

---

## 3. Report Generation

### 3.1 `generate_report` Doesn't Save to Disk — RESOLVED

**Problem:** `generate_report` returned the report as text but never wrote it to a file. The `output_dir` config field existed but was unused.

**Resolution:** `generate_report` now writes the report to `{output_dir}/report-{date}.md` automatically and returns both the file path and report content. Falls back to returning content only if the write fails.

**Files changed:** `crates/raven-server/src/tools/findings.rs`, `crates/raven-server/src/server.rs`

### 3.2 Findings Are Ephemeral — RESOLVED

**Problem:** `FindingStore` had `save_to_file`/`load_from_file` methods but they were never called. All findings were lost on server exit.

**Resolution:** Added `FindingStore::with_persistence(path)` constructor that loads existing findings from disk and enables auto-saving. `insert()` and `delete()` now automatically persist to `{output_dir}/findings.json`. The server constructor creates the output directory and initialises the store with persistence.

**Files changed:** `crates/raven-report/src/store.rs`, `crates/raven-server/src/server.rs`

---

## 4. Error Handling

### 4.1 Inconsistent MCP Error Codes — RESOLVED

**Problem:** Only `ping_target` used proper MCP error codes. All other tools used generic `INTERNAL_ERROR` for everything, including invalid input.

**Resolution:** Created a centralised `error::to_mcp()` mapper in `crates/raven-server/src/error.rs` that maps `PentestError` variants to correct MCP codes:
- `InvalidTarget` → `INVALID_PARAMS`
- `ToolNotAllowed` → `INVALID_REQUEST`
- `CommandTimeout` / `CommandFailed` / `ConfigError` / `Io` → `INTERNAL_ERROR`

All tool handlers now use `.map_err(crate::error::to_mcp)` instead of inline error construction.

**Files changed:** `crates/raven-server/src/error.rs` (new), `crates/raven-server/src/main.rs`, all tool handlers

### 4.2 `http_request` URL Validation Is Weak — RESOLVED

**Problem:** `req.url.starts_with("http")` matched invalid strings like `httpfoo`.

**Resolution:** Replaced with `reqwest::Url::parse()` and an explicit scheme check for `"http"` or `"https"`.

**File changed:** `crates/raven-server/src/tools/http.rs`

### 4.3 Sibling Tool Call Cascading Failures — MITIGATED

**Problem:** When one MCP tool in a parallel batch errors, the MCP framework fails sibling calls too. This is MCP SDK / client behaviour, not something we control directly.

**Mitigation:** By fixing validation issues (1.2, 4.2) and standardising error codes (4.1), tools error far less often on valid inputs, reducing cascade frequency. No further action planned.

---

## 5. LLM Guidance / Tool Descriptions

### 5.1 Server Instructions Are Minimal — RESOLVED

**Problem:** The server instruction string was a single line giving the LLM almost no workflow guidance.

**Resolution:** Expanded to a 6-step workflow covering: connectivity checks, tool preference, target formats, aggressiveness levels, output quality checks, and the findings-to-report pipeline.

**File changed:** `crates/raven-server/src/server.rs`

---

## Summary

| # | Issue | Status |
|---|-------|--------|
| 1.1 | `launch_scan` bypasses safety | Resolved |
| 1.2 | URL validation rejects valid targets | Resolved |
| 1.3 | Nmap `-O` root requirement | Resolved |
| 2.1 | No output validation | Resolved |
| 2.2 | Rate-limit/WAF awareness | Resolved |
| 3.1 | Report not saved to disk | Resolved |
| 3.2 | Ephemeral findings | Resolved |
| 4.1 | Inconsistent error codes | Resolved |
| 4.2 | Weak URL validation | Resolved |
| 4.3 | Sibling cascading failures | Mitigated (external) |
| 5.1 | Minimal LLM guidance | Resolved |
