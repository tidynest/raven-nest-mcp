# Roadmap

Server-side additions for `raven-nest-mcp`. Client roadmap in the client repo.
Ordered by impact. Unchecked = not started.

---

### High Priority

- [x] **Auto-finding extraction from scan output** — *shipped (nuclei only; opt-in via `[safety] auto_save_findings`).*
  Extend existing tool parsers to optionally emit structured findings alongside text. Nuclei already tags severity (`[info]`/`[critical]`), nikto flags warnings, nmap identifies vulnerable services. Connect parsers to the finding store with a confidence threshold to filter noise.
  *Affected crates:* `raven-core` (parsers), `raven-report` (store)

- [x] **Target scope management**
  `[scope]` config section with allowed CIDRs, domains, URLs. Gate `validate_target()` against the scope allowlist before every tool invocation. Reject out-of-scope targets with a clear error. Critical for professional engagements.
  *Affected crates:* `raven-core` (config, validation)

- [x] **Scan-to-finding linking**
  Optional `scan_id: Option<Uuid>` on `SaveFindingRequest`. Link findings to their source scan. Enables "show all findings from scan X" and better report traceability.
  *Affected crates:* `raven-report` (finding model, store)

- [x] **Engagement / project management** — *shipped in lean form: filesystem-scoped engagements via `set_engagement` (creates on first use) + `list_engagements`; each scopes its own findings + reports subdir. No separate timeline/client-info metadata.*
  Named engagements with scope, timeline, client info, notes. Each engagement scopes its own output directory, findings, and reports. New tools: `create_engagement`, `switch_engagement`, `list_engagements`.
  *Affected crates:* `raven-core` (new manager), `raven-report` (scoped store)

### Medium Priority

- [x] **Additional report formats (SARIF, JSON, HTML)**
  SARIF for CI/CD and vulnerability management platforms. JSON for programmatic use. HTML for standalone distribution. Finding data model is already structured — mostly serialisation.
  *Affected crates:* `raven-report`

- [x] **Finding deduplication**
  Detect same title + target + tool before saving. Warn or merge. Keeps reports clean during iterative scanning.
  *Affected crates:* `raven-report` (store)

- [ ] **Target discovery tracking**
  Persist discovered hosts, ports, services, technologies across scans. Structure: `target -> [{port, service, version, source_scan}]`. New tools: `get_target_info`, `list_targets`.
  *Affected crates:* `raven-core` or new crate

- [ ] **Scan diffing**
  Compare two scans of the same target. Return added/removed ports, services, vulnerabilities. New tool: `diff_scans`.
  *Affected crates:* `raven-core` (scan manager)

- [ ] **Background scan persistence**
  Serialize scan state to disk. On restart, recover completed scan outputs (not re-run, but preserve results). Currently all scan state is in-process memory.
  *Affected crates:* `raven-core` (scan manager)

- [ ] **Structured scan results**
  Return parsed results as JSON alongside human-readable text. Client can filter/sort without re-parsing. e.g. nmap returns `{hosts: [{ip, ports: [{port, state, service}]}]}` plus the text output.
  *Affected crates:* `raven-core` (parsers, tool handlers)

### Lower Priority

- [ ] **Custom tool registration via config**
  `[tools.my_script]` with command template, timeout, and parser hint. Add tools without recompiling.
  *Affected crates:* `raven-core` (config, tool dispatch)

- [ ] **Webhook notifications**
  Fire webhooks on critical/high findings. Integrates with Slack, Discord, or custom alerting.
  *Affected crates:* `raven-report`

- [ ] **Evidence attachment**
  Link HTTP responses, screenshots, or files to findings. Store in `{output_dir}/evidence/{finding_id}/`.
  *Affected crates:* `raven-report`

- [ ] **Vulnerability database integration**
  CVE lookup from NVD. Auto-populate CVSS, description, remediation when a CVE ID is provided.
  *Affected crates:* `raven-core` or new crate

- [ ] **Finding templates**
  Pre-built descriptions for common vulnerabilities (directory listing, missing headers, default creds). Operator selects template, fills in target specifics.
  *Affected crates:* `raven-report`

- [ ] **Export to external platforms**
  Push findings to Defect Dojo, Jira, GitHub/GitLab Issues via their APIs.
  *Affected crates:* new crate or `raven-report`

- [ ] **Rate limiting per target**
  Cap requests/second to individual targets for HTTP-based tools. Currently only masscan has a rate limit.
  *Affected crates:* `raven-core`

- [ ] **CI/CD mode support**
  Non-interactive execution, SARIF output, exit code based on finding severity. Server-side support for the client's `ci` mode.
  *Affected crates:* `raven-server`, `raven-report`

---

### Future / Potential

Ideas that may become relevant as the project matures.

- [ ] **Finding severity override**
  Pentester overrides auto-extracted severity with justification. Store original + overridden severity and reason. Included in reports as analyst notes.
  *Affected crates:* `raven-report` (finding model)

- [ ] **Remediation tracking**
  Mark findings as "remediated" with timestamp. Re-run the original tool to verify. Confirm fixed or reopen. Enables retest reports with before/after evidence.
  *Affected crates:* `raven-report` (finding lifecycle)

- [ ] **Custom finding fields**
  Engagement-specific metadata on findings (`business_impact`, `affected_users`, `data_classification`). Configurable per engagement, included in reports.
  *Affected crates:* `raven-report` (finding model)

- [ ] **Scan scheduling**
  Cron-like scheduling for recurring scans. Run nuclei nightly against target list, diff against previous results, alert on new findings.
  *Affected crates:* `raven-core` (new scheduler)

- [ ] **Team collaboration**
  Multiple operators sharing a findings store. Move from file-per-finding to a shared database (SQLite or Postgres). Conflict resolution for concurrent edits.
  *Affected crates:* `raven-report` (storage backend)

- [x] **Engagement timeline / audit log** — *partially shipped: append-only `{output_dir}/audit.log` records every tool invocation with redacted args + timestamp. Per-finding/report actions not yet logged.*
  Record every action: scans launched, findings saved, reports generated, with timestamps. Exportable for evidence of methodology in compliance audits.
  *Affected crates:* `raven-core` (new audit module)

- [ ] **Network topology model**
  Build a structured model of the target network from scan results: hosts, ports, services, routes, trust relationships. New tools: `get_topology`, `get_host_profile`.
  *Affected crates:* `raven-core` or new crate
