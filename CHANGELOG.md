# Changelog

All notable changes to Raven Nest MCP are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
minor versions may carry feature additions and refinements).

## [0.2.5] - 2026-07-01

Completes the `run_httpx` container fix from 0.2.4.

### Fixed
- `run_httpx` hung indefinitely instead of returning. ProjectDiscovery httpx
  probes stdin even when a target is passed with `-u`, and the executor let child
  tools inherit raven-server's own stdin — the stdio MCP pipe, which never reaches
  EOF during a session. Child processes are now spawned with a null stdin, so
  stdin-probing tools see an immediate EOF and proceed. (0.2.4 corrected the httpx
  binary on PATH but this deeper block only surfaced under live MCP traffic.)

## [0.2.4] - 2026-07-01

Container image and logging fixes.

### Fixed
- Container image: `ping_target` failed with `os error 2` because the Kali runtime
  stage never installed `ping` — added `iputils-ping`.
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

Packaging release — distribution via container image and the MCP registry.

### Added
- GHCR container image (`ghcr.io/tidynest/raven-nest-mcp`), built on each release
  from a multi-stage Kali-based Dockerfile that bundles all 22 wrapped tools.
- `server.json` and CI publishing to the official MCP registry on release.

## [0.2.1] - 2026-06-24

Maintenance and packaging release — no API or tool changes.

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
- All three crates marked `publish = false` — this is an application, not a
  library set, and is never published to crates.io.

### Fixed
- Server-reported tool count corrected from 41 to 43 (gitleaks and trufflehog
  were added after the constant was last updated).

## [0.2.0] - 2026-06-22

First tagged release. 22 security tools plus the Metasploit Framework across 43
MCP endpoints. Highlights accumulated since the initial 0.1.0 state:

### Added
- **Secret scanning** — `run_gitleaks` (working-tree and git-history modes) and
  `run_trufflehog` (filesystem, optional live verification, off by default).
  Scan paths are confined via `validate_file_path`; secret values are never
  echoed in parsed output or persisted findings. trufflehog never passes
  `--trust-local-git-config` (CVE-2025-41390).
- **Recon tools** — `run_httpx`, `run_dnsx`, `run_katana`.
- **Engagement scope** — optional `[scope]` authorization allowlist
  (CIDRs/domains, deny-wins, loopback-aware); off by default.
- **Engagements** — `set_engagement` / `list_engagements`; each scopes its own
  findings and reports directory.
- **Audit logging** — every tool execution appended to `{output_dir}/audit.log`
  (JSON lines, redacted args, 0600, size-rotated).
- **Auto-extracted findings** from eight scanners (nuclei, nikto, dalfox, nmap,
  sqlmap, testssl, gitleaks, trufflehog), opt-in via `auto_save_findings`,
  deduplicated and tagged `AutoExtracted`.
- **Scan↔finding linking** — `scan_id` on findings + `list_findings_by_scan`.
- **Report formats** — JSON, SARIF 2.1.0, and HTML in addition to Markdown
  (`generate_report` `format` parameter).
- **Structured tool output** (`structured_content`) on finding/scan/report tools.
- **NetExec** (`run_netexec`) — gated, read-only credentialed enumeration; off
  by default.
- **Resource controls** — `scan_retention_secs` (scan registry TTL/eviction),
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
