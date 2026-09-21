# Changelog

All notable changes to Raven Nest MCP are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
minor versions may carry feature additions and refinements).

## [Unreleased]

## [0.4.1] - 2026-09-21

### Changed
- **Migrated to rmcp 2.2.0** (from the exact 1.7.0 pin). The 2.x API rewrite
  replaced `Content` with the `ContentBlock` enum, reworked resource
  construction (`RawResource`/`AnnotateAble` removed; `Resource` builders
  carry annotations inline), and removed the `.raw` accessor on content.
  Server capabilities no longer advertise logging: SEP-2577 deprecates MCP
  logging in favor of stderr/OpenTelemetry, and server operational logging
  already goes to stderr via `tracing`. The 15-second in-flight ticker now
  sends `notifications/progress` carrying the client-supplied `progressToken`
  instead of logging notifications; clients that do not pass a token receive
  no updates, per the protocol. Stdio transport and all tool behavior are
  unchanged.

### Security
- rmcp 2.2.0 clears three advisories against the 1.x line. None were
  reachable in this build, which enables only the server, macros, and
  transport-io features and serves over stdio; the HTTP and OAuth
  transports were never compiled in. Cleared: GHSA-9pj6-vhgr-3mwh (high),
  session-table leak in the Streamable HTTP server transport;
  GHSA-33f5-2c5q-wgwj (high), missing resource-field validation in OAuth
  metadata discovery; GHSA-9g45-5xwm-f3wc (moderate), custom HTTP headers
  leak to cross-origin redirect targets.

## [0.4.0] - 2026-09-21

### Added
- **Background scan persistence.** Terminal background scans now write
  `{output_dir}/scans/{id}.txt` (output, 0o600) and `{id}.json` metadata
  (atomic tmp+rename) at launch, on completion/failure, and on cancel. On
  restart, completed scans are recovered with their output (never re-run),
  scans interrupted mid-flight surface as `failed: interrupted by server
  restart`, and TTL-expired, corrupt, and orphaned files are cleaned up.
  Previously all scan state was in-process memory and lost on restart.
- **Per-target rate limiting.** New `[execution] per_target_min_gap_ms`
  (default 0, max 60000) spaces tool launches against the same host while
  independent targets proceed in parallel, complementing the global
  `min_exec_gap_ms`. Targets normalise to their bare host (URL scheme, port,
  and path dropped); applies to all subprocess tools that take a network
  target, background scans, and `http_request`. Tools without a network
  target (john, gitleaks, trufflehog) are exempt.

### Changed
- All terminal scan outputs are written to disk (previously only outputs over
  1 MB spilled), so results survive restarts; small outputs are still served
  from RAM in-process and memory fallback remains if the disk write fails.
- `launch_scan` now registers the scan entry under the same lock as the
  concurrency-cap check, closing races where a fast tool could complete into
  an unregistered entry or two launches could both pass the cap.
- **Pinned `rmcp` to exactly 1.7.0.** A Dependabot bump to rmcp 2.0.0 (major,
  breaking) had merged to main and broke the build (`Content`, `RawContent`,
  `RawResource` removed, `ContentBlock.raw` gone); rmcp 1.8.0 additionally
  deprecates the logging API (SEP-2577), which fails the build under
  `-D warnings`. The exact pin restores a green build. Migration to rmcp 2.x
  is deferred to a deliberate upgrade.

### Security
- **rustls bumped to 0.23.45** (from 0.23.38), resolving RUSTSEC-2026-0285
  (TLS 1.3 handshake messages incorrectly accepted across encryption-level
  boundaries). rustls is a transitive dependency via reqwest; the advisory is
  independent of the rmcp pin above.

## [0.3.0] - 2026-08-31

### Added
- **Target discovery tracking.** nmap results (both `run_nmap` and completed
  background nmap scans) accumulate into per-host records - ports, states,
  services, versions, OS guesses, first/last-seen - persisted as
  `{output_dir}/targets/{host}.json` (engagement-scoped, restart-safe). Re-scans
  merge rather than overwrite. New tools: `list_targets`, `get_target_info`.
  Host keys are strictly sanitized before use as filenames (scan output is
  target-controlled).
- **Scan diffing.** New tool `diff_scans` compares two completed nmap background
  scans: added/removed hosts and ports, plus per-port state/service/version
  changes, as text and `structured_content`.
- **Structured scan results.** `run_nmap` and `run_nuclei` attach
  machine-readable `structured_content` alongside their text output (hosts,
  ports, CVEs; findings list), uncapped by the context budget, so clients can
  process results without parsing prose.
- **CI: cargo-deny** now runs alongside cargo-audit (advisories, license
  allowlist, bans, sources per `deny.toml`), and an **MSRV 1.93** check job
  verifies the declared `rust-version` on every push.

### Changed
- **Docker image runs as a dedicated non-root user** (`raven`, uid 10001).
  Raw-socket tools (masscan, `nmap -O`) keep working when the container is
  granted `--cap-add=NET_RAW`/`--cap-add=NET_ADMIN` - capabilities are held by
  the container process, not derived from uid.
- `set_engagement` now also swaps the target-discovery store, so discovery data
  is engagement-scoped like findings; its response includes the tracked-host
  count.
- Tool descriptions and docs updated for the 46-endpoint surface
  (`docs/MCP_TOOLS.md` regenerated; README badge and tables).

### Fixed
- **Budget-exhaustion dead end.** When the context budget ran out, *every* tool
  was refused - including `save_finding` and `generate_report`, the exact
  actions the exhaustion message told the model to take. Scan-execution tools
  are still refused (running another scan would overflow the context window),
  but findings/report/engagement/scan-status tools now always work, and the
  refusal message names what remains available. Reachable with the default
  `context_budget = 65536`.
- **Hydra positional-argument flag injection.** `service` and `form_params` were
  passed to hydra as unvalidated positional arguments, so a value like `-R`
  would be parsed by hydra as a flag. `service` is now restricted to the
  lowercase/digit/hyphen charset real service names use; `form_params` must not
  start with `-` or contain control characters; `form_params` on a non-form
  service is rejected. sqlmap `technique` (subset of `BEUSTQ`) and ffuf
  `filter_size` (digits/commas) got the same class of guard.
- **Rate-limit false positives.** The quality assessment matched the bare
  substring `"429"`, so any output containing port 4290 or byte counts like
  1429 was flagged "target may be rate-limiting". HTTP 429 is now matched only
  as a complete number.
- **Unbounded `get_scan_results` limit.** A client-supplied limit (up to
  `usize::MAX`) was honored as-is and the whole spilled output was materialised
  as `Vec<char>` before slicing. The limit is now clamped to 100,000 chars
  (default 10,000) and slicing walks char boundaries without the intermediate
  allocation.
- **Dependency advisory:** h2 updated to 0.4.19 in `Cargo.lock`
  (RUSTSEC-2026-0258, unbounded empty DATA frames; fixed in 0.4.16).
- Minor accounting: the context-budget tracker records characters (not bytes)
  consistently with its caps, and `MIN_OUTPUT_LEN` compares characters as
  documented.

## [0.2.9] - 2026-08-02

### Added
- **Machine-readable tool manifest** ([docs/MCP_TOOLS.md](docs/MCP_TOOLS.md)).
  Declares all 43 tools (name + description) in a format static MCP security
  scanners can parse, since they don't compile the Rust `#[tool]` macros. This
  lets scanners such as the Canopii Trust Index evaluate the tool-integrity
  controls (prompt-injection markers, strict schemas, tool scope) instead of
  reporting them "not checked", raising scan confidence. A new test
  (`crates/raven-server/tests/tool_manifest.rs`) keeps the manifest in lockstep
  with `server.rs` and rejects any description carrying an injection or
  exfiltration marker that would trip a scanner's guard.

### Changed
- **`run_gitleaks` description reworded** to "Scan a directory or git history for
  committed secrets" (was "gitleaks secret scanner ..."). The prior wording
  paired "gitleaks" with "secret", matching the exfiltration-marker heuristic
  used by static tool-integrity scanners; the new wording is clearer and avoids
  the false positive. Behaviour is unchanged.

## [0.2.8] - 2026-07-18

### Added
- **NetExec output parser.** `run_netexec` now structures `nxc` output: it
  strips terminal colour, hoists the authentication verdict (including
  privileged `Pwn3d!` access) to the top, and keeps the per-host banner and
  enumeration rows without duplicates, falling back to raw output when
  unrecognized. Completes structured-output parser coverage across all 22 tools.

### Changed
- **Server identity matches the registry name.** The MCP handshake now
  advertises `serverInfo.name` as `io.github.tidynest/raven-nest-mcp` (was
  `raven-nest`), matching `server.json` so external indexers and scanners can
  correlate the running server with its registry entry.

## [0.2.7] - 2026-07-16

Security and correctness hardening, report improvements, and MCP resources.

### Added
- **MCP resources.** The server advertises the resources capability and serves
  `raven://` resources: a findings index, one resource per saved finding, the
  four report formats rendered on demand, a scans index, and per-scan output.
  Clients can browse or attach this data without a tool call.
- **Report Scope & Timeline.** Markdown and HTML reports gain a Scope & Timeline
  section (assessed targets and the engagement window, derived from the
  findings). Markdown also gains a generation timestamp, and HTML gains the
  Methodology section, reaching parity with the markdown report.

### Fixed
- **Credential redaction gaps in the audit log.** wpscan `--api-token`,
  feroxbuster/ffuf `-b` cookies, and enum4linux-ng `-p` passwords reached
  `audit.log` in cleartext; they are now redacted.
- **Redirect scope bypass in `http_request`.** The scope gate validated only the
  initial host, so a redirect could reach an out-of-scope or internal address.
  Every redirect hop is now re-validated against the engagement scope.
- **UTF-8 truncation panic.** `http_request` body truncation sliced on a byte
  index and could panic on a multibyte character; it now cuts on a character
  boundary, as do the Metasploit and nmap output formatters.
- **Metasploit exploit confirmation bypass.** The confirmation hash omitted
  `options`, `lhost`, and `lport`, so they could change between the confirm and
  execute calls; they are now part of the hash.
- **`launch_scan` rate cap.** The background-scan path ignored
  `masscan_max_rate`; it now clamps to the configured cap like the dedicated
  handler.
- **Finding store durability.** Findings are written via a temp file and atomic
  rename so a crash mid-write cannot drop a finding; a failed delete reports
  failure instead of a false success; and `save_finding` deduplicates.
- **Report determinism and integrity.** Findings sort deterministically
  (severity, timestamp, id); markdown escapes all finding fields and sizes the
  evidence fence to prevent injection; SARIF represents the target as a logical
  location so results are no longer dropped on code-scanning ingest.
- **`http_request` audit trail.** Its requests are now recorded in the audit log
  (method and URL only; credentials excluded).
- **Metasploit RPC lock recovery.** The RPC client recovers from a poisoned lock
  instead of panicking.

## [0.2.6] - 2026-07-02

Metasploit auxiliary output fix and documentation.

### Fixed
- `msf_auxiliary` now captures module console output. It ran modules via
  `module.execute` and returned only the results hash, which scanner modules
  leave empty, so `http_version`, `ssh_version`, and similar reported `null`
  despite running successfully. Auxiliary modules now run through a console
  (create/write/read/destroy) so their `print_good`/`print_status` output is
  captured. Option values and the module path are validated to reject control
  characters that could inject extra console commands.

### Changed
- OCI image description clarified: the container bundles 22 tools but not the
  Metasploit Framework, whose tools require a separate `msfrpcd`.

### Documentation
- README demo GIFs (recon, scan-to-report, and a live Metasploit scan).
- Text normalized to plain ASCII punctuation across docs, config, and source.

## [0.2.5] - 2026-07-01

Completes the `run_httpx` container fix from 0.2.4.

### Fixed
- `run_httpx` hung indefinitely instead of returning. ProjectDiscovery httpx
  probes stdin even when a target is passed with `-u`, and the executor let child
  tools inherit raven-server's own stdin - the stdio MCP pipe, which never reaches
  EOF during a session. Child processes are now spawned with a null stdin, so
  stdin-probing tools see an immediate EOF and proceed. (0.2.4 corrected the httpx
  binary on PATH but this deeper block only surfaced under live MCP traffic.)

## [0.2.4] - 2026-07-01

Container image and logging fixes.

### Fixed
- Container image: `ping_target` failed with `os error 2` because the Kali runtime
  stage never installed `ping` - added `iputils-ping`.
- Container image: `run_httpx` invoked python3-httpx's CLI (which owns `/usr/bin/httpx`
  on Kali) instead of ProjectDiscovery's httpx, failing with `No such option: -u`.
  The PD binary (`httpx-toolkit`) is now symlinked into `/usr/local/bin/httpx`, which
  precedes `/usr/bin` on PATH.
- Logging: the server forced `DEBUG` and ignored `RUST_LOG` (a bare-level directive
  overrode the env filter). It now honors `RUST_LOG` and defaults to `info`, so
  `RUST_LOG=off` silences output and `RUST_LOG=debug` restores verbose logs.
- Bumped `anyhow` to 1.0.103 to patch RUSTSEC-2026-0190 (`Error::downcast_mut`
  unsoundness).

## [0.2.3] - 2026-06-28

Documentation and packaging refinements.

### Added
- Documentation and the default config are now shipped inside the container image
  under `/usr/share/doc/raven-nest-mcp/`.
- OCI image labels (title, description, documentation, licenses) are attached to
  the published image and shown on the package page.
- README "How It Fits Together" section and a cross-link to the companion
  `raven-nest-client` TypeScript client.

### Changed
- CI: `actions/checkout` bumped to v5 (Node 24), clearing the Node 20 deprecation.

## [0.2.2] - 2026-06-24

Packaging release - distribution via container image and the MCP registry.

### Added
- GHCR container image (`ghcr.io/tidynest/raven-nest-mcp`), built on each release
  from a multi-stage Kali-based Dockerfile that bundles all 22 wrapped tools.
- `server.json` and CI publishing to the official MCP registry on release.

## [0.2.1] - 2026-06-24

Maintenance and packaging release - no API or tool changes.

### Added
- Release workflow: pushing a `vX.Y.Z` tag builds `raven-server` and attaches a
  prebuilt binary + SHA256 checksum to the GitHub release.
- AUR source PKGBUILD under `packaging/aur/` (every scanner is an `optdepends`).
- Authorized-use disclaimer in the README, and `rust-toolchain.toml` pinning the
  stable channel for reproducible builds.
- Test coverage: `validate_target` injection-invariant fuzzing, the background
  scan spawn/cancel lifecycle, and the Metasploit module block-list and msgpack
  decoder (326 workspace tests).

### Changed
- All three crates marked `publish = false` - this is an application, not a
  library set, and is never published to crates.io.

### Fixed
- Server-reported tool count corrected from 41 to 43 (gitleaks and trufflehog
  were added after the constant was last updated).

## [0.2.0] - 2026-06-22

First tagged release. 22 security tools plus the Metasploit Framework across 43
MCP endpoints. Highlights accumulated since the initial 0.1.0 state:

### Added
- **Secret scanning** - `run_gitleaks` (working-tree and git-history modes) and
  `run_trufflehog` (filesystem, optional live verification, off by default).
  Scan paths are confined via `validate_file_path`; secret values are never
  echoed in parsed output or persisted findings. trufflehog never passes
  `--trust-local-git-config` (CVE-2025-41390).
- **Recon tools** - `run_httpx`, `run_dnsx`, `run_katana`.
- **Engagement scope** - optional `[scope]` authorization allowlist
  (CIDRs/domains, deny-wins, loopback-aware); off by default.
- **Engagements** - `set_engagement` / `list_engagements`; each scopes its own
  findings and reports directory.
- **Audit logging** - every tool execution appended to `{output_dir}/audit.log`
  (JSON lines, redacted args, 0600, size-rotated).
- **Auto-extracted findings** from eight scanners (nuclei, nikto, dalfox, nmap,
  sqlmap, testssl, gitleaks, trufflehog), opt-in via `auto_save_findings`,
  deduplicated and tagged `AutoExtracted`.
- **Scan↔finding linking** - `scan_id` on findings + `list_findings_by_scan`.
- **Report formats** - JSON, SARIF 2.1.0, and HTML in addition to Markdown
  (`generate_report` `format` parameter).
- **Structured tool output** (`structured_content`) on finding/scan/report tools.
- **NetExec** (`run_netexec`) - gated, read-only credentialed enumeration; off
  by default.
- **Resource controls** - `scan_retention_secs` (scan registry TTL/eviction),
  `max_concurrent_execs` (synchronous execution cap), and `min_exec_gap_ms`
  (proactive per-launch cooldown).

### Changed
- Upgraded `rmcp` 1.1 → 1.7.
- `http_request` now enforces the engagement scope.
- `run_ffuf` pins an explicit `-mc` default
  (`200,204,301,302,307,401,403,405,500`) instead of relying on ffuf's
  version-specific default, which had narrowed to 2XX and hid redirects/401/403.

### Fixed
- `http_request` no longer bypasses scope/target validation.
- Bumped `quinn-proto` to patch RUSTSEC-2026-0185.

### Security
- Engagement scope allowlist, audit logging, proactive launch cooldown, and
  redaction of secret values from secret-scanner findings.

## [0.1.0] - initial

Initial (untagged) MCP server: core safety pipeline (allowlist, target
validation, preset arguments, output sanitisation, quality assessment), the
initial scanner set, background scan management, file-per-finding storage, and
Markdown report generation.

[0.2.1]: https://github.com/tidynest/raven-nest-mcp/releases/tag/v0.2.1
[0.2.0]: https://github.com/tidynest/raven-nest-mcp/releases/tag/v0.2.0
