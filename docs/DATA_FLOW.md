# Data Flow & Sources of Truth

Single reference for how data moves through Raven Nest and **which module owns
each piece of state**. When two places seem to hold the same fact, the one
listed here is authoritative; the others are caches or views of it.

> Keeping this current: this doc is hand-maintained, not generated. Every row
> cites a `file:line` anchor — when you change one of those sites, update the
> matching row. A generator that parses the source would be the next step *if*
> drift ever becomes a real problem; until then the anchors are enough.

## Request lifecycle

A single tool call travels through these layers:

```
MCP client (LLM / raven-nest-client)
  │  JSON-RPC 2.0 over stdio
  ▼
rmcp  ──►  #[tool] handler in raven-server::server   (routing, shared state)
  │            crates/raven-server/src/server.rs
  ▼
tools::<tool>::run(&config, …, req)                  (per-tool module)
  │   1. safety::validate_target(req.target)         syntax + engagement scope
  │   2. build CLI args from the request struct
  │   3. executor::run(&config, …)                   semaphore-gated subprocess
  │        └─ audit::record(...)  ──► {output_dir}/audit.log
  │   4. parse_<tool>(stdout)  ──► structured summary (falls back to raw)
  ▼
CallToolResult  ──►  server::wrap_result  ──►  PentestError → MCP error code
  │
  ├─(nmap, nuclei, nikto, dalfox only)
  │     extract::auto_save(finding_store, config, tool, target, scan_id, findings)
  │       └─ writes {findings_dir}/{id}.json + updates in-RAM index
  ▼
back to the client as text content (+ structured_content where provided)
```

Background scans take a parallel path: `launch_scan` hands the command to the
`ScanManager`, which runs it in its own task and returns a scan id immediately;
`get_scan_results` reads the stored output later.

## Sources of truth

| Datum | Authoritative owner | Notes |
|-------|--------------------|-------|
| **Configuration** (tool paths, caps, dirs, proxy, scope, netexec) | `RavenConfig::load_with_fallback()` — [config.rs:405](../crates/raven-core/src/config.rs#L405) | Resolution chain: `RAVEN_CONFIG` env → exe-relative `config/default.toml` → CWD fallback → built-in defaults. Loaded once at startup into an `Arc<RavenConfig>`; every layer borrows it. |
| **Engagement scope** (allowed/denied CIDRs + domains) | `SCOPE` OnceLock — [safety.rs:51](../crates/raven-core/src/safety.rs#L51) | Installed once via `init_scope` at [server.rs:81](../crates/raven-server/src/server.rs#L81) from `config.scope`. Enforced by `validate_target` ([safety.rs:68](../crates/raven-core/src/safety.rs#L68)) on every target-taking tool, including `http_request`. |
| **Execution concurrency** | `EXEC_SEM` OnceLock — [executor.rs:27](../crates/raven-core/src/executor.rs#L27) | Sized from `max_concurrent_execs`. Foreground tools take a permit in `executor::run`; background scans use `run_unmetered` and are bounded separately by `max_concurrent_scans`. |
| **Audit trail** (what ran, against what, when) | `{output_dir}/audit.log` — written by `audit::record` [audit.rs:121](../crates/raven-core/src/audit.rs#L121) | Append-only JSON lines, rotated when oversized. Emitted from inside `executor::run` ([executor.rs:261](../crates/raven-core/src/executor.rs#L261)) so every subprocess is logged regardless of caller. |
| **Findings** | `FindingStore` — [store.rs](../crates/raven-report/src/store.rs) | On disk: one `{id}.json` per finding under `findings_dir`. In RAM: `HashMap<String, FindingMeta>` index ([store.rs:28](../crates/raven-report/src/store.rs#L28)) — a rebuildable view of the files, **not** a second source. Held by the server as `Arc<RwLock<FindingStore>>` ([server.rs:63](../crates/raven-server/src/server.rs#L63)). |
| **Background scans** (status + output) | `ScanManager` — [scan_manager.rs](../crates/raven-core/src/scan_manager.rs) | Output lives in memory until it exceeds `SPILL_THRESHOLD` (1 MB, [scan_manager.rs:36](../crates/raven-core/src/scan_manager.rs#L36)), then spills to a file. Terminal scans evicted after `scan_retention_secs` ([scan_manager.rs:111](../crates/raven-core/src/scan_manager.rs#L111)). |
| **HTTP session cookies** | `cookie_jar: Arc<reqwest::cookie::Jar>` — [server.rs:65](../crates/raven-server/src/server.rs#L65) | Shared across `http_request` calls only. Subprocess tools (sqlmap, nikto, …) do **not** see it — they take cookies via their own `cookie` parameter. |
| **Context budget** | `self.budget` — used at e.g. [server.rs:241](../crates/raven-server/src/server.rs#L241) | Scales per-tool result caps (`scale_cap`) so output shrinks as the budget tightens. |
| **Reports** | `generate_report`, rendered from `FindingStore` | Reports are a *view* of findings, never a store. Formats: Markdown (default), JSON, SARIF, HTML. |

## Auto-saved findings

Eight handlers auto-extract findings (`nmap`, `nuclei`, `nikto`, `dalfox`,
`sqlmap`, `testssl`, `gitleaks`, `trufflehog`) via `extract::auto_save` at
[server.rs:283](../crates/raven-server/src/server.rs#L283). The two secret
scanners read only location/identifier fields — a secret value never enters a
finding.
Gated by `auto_save_findings` config, deduped on insert, capped per scan. All
other findings are saved explicitly by the client through `save_finding`.
Either way the `FindingStore` is the single owner — auto-save is just one writer.
