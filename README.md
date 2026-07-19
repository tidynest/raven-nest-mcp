# Raven Nest MCP

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/tidynest/raven-nest-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tidynest/raven-nest-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tidynest/raven-nest-mcp?sort=semver)](https://github.com/tidynest/raven-nest-mcp/releases)
[![MCP tools: 43](https://img.shields.io/badge/MCP%20tools-43-5A45FF.svg)](https://github.com/tidynest/raven-nest-mcp)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-server-1f6feb.svg)](https://modelcontextprotocol.io)
[![Canopii Trust Score](https://index.canopii.dev/api/badge/io.github.tidynest/raven-nest-mcp)](https://index.canopii.dev/server/io.github.tidynest/raven-nest-mcp)

A pentesting toolkit that runs as an [MCP](https://modelcontextprotocol.io/) server, giving AI assistants structured access to industry-standard security tools through a safety-hardened interface.

> **Authorized use only.** Raven Nest is an offensive-security tool intended solely for testing systems you own or have explicit written permission to assess. Unauthorized scanning, enumeration, or exploitation may be illegal. You are solely responsible for obtaining authorization and complying with all applicable laws. The software is provided "as is", without warranty of any kind - see [LICENSE](LICENSE).

## Demo

Real MCP traffic to the tools - no LLM in the loop, fully deterministic. Targets are the authorized public test hosts `example.com` / `scanme.nmap.org`.

**Scan → structured finding → report**

![Scan to structured finding to report](docs/assets/report.gif)

**Recon flow - connectivity, ports, web stack**

![Recon flow: ping, nmap, whatweb](docs/assets/recon.gif)

**Metasploit module discovery** - *requires an MSF-enabled build; the default container image excludes Metasploit*

![Metasploit search and module info](docs/assets/metasploit.gif)

## What It Does

Raven Nest wraps 22 security tools plus Metasploit Framework behind an MCP interface with input validation, output quality assessment, session-aware context budgeting, and configurable safety limits. It handles tool execution, background scan management, vulnerability finding persistence, and multi-format report generation (Markdown, JSON, SARIF, HTML). Findings, reports, and scans are also exposed as MCP resources for browsing. 43 MCP endpoints total.

### Supported Tools

| Category | Tools |
|----------|-------|
| Recon | nmap, masscan, whatweb, httpx, subfinder, dnsx, dnsrecon |
| Crawling | katana |
| SMB/AD | enum4linux-ng |
| Credentialed enum (gated) | netexec |
| Vulnerability | nuclei, nikto, wpscan, dalfox (XSS) |
| Web fuzzing | feroxbuster, ffuf |
| Exploitation | sqlmap, hydra |
| Password cracking | john |
| Secret scanning | gitleaks, trufflehog |
| TLS/SSL | testssl.sh |
| Metasploit | msf\_search, msf\_module\_info, msf\_exploit, msf\_auxiliary, msf\_sessions, msf\_post |
| Utility | ping\_target, http\_request |
| Scan management | launch\_scan, get\_scan\_status, get\_scan\_results, list\_scans, cancel\_scan |
| Findings | save\_finding, get\_finding, list\_findings, list\_findings\_by\_scan, delete\_finding, generate\_report |
| Engagement | set\_engagement, list\_engagements |

## How It Fits Together

Raven Nest is an MCP **server** - it doesn't do anything on its own. An MCP
**host** launches it over stdio and drives the tools. Pick whichever host suits you:

- **Any MCP host (recommended)** - point Claude Desktop, Cursor, or any MCP client
  at the Docker image below; the host spawns the server for you.
- **Companion REPL** - [`raven-nest-client`](https://github.com/tidynest/raven-nest-client)
  is a TypeScript terminal client (tab-completion, scan/finding/report commands,
  engagement scoping) for driving Raven Nest by hand. It can launch either a local
  `raven-server` build or the Docker image.

The server is the same stdio binary in both cases.

## Quick Start

### Run with Docker (recommended)

The published image bundles `raven-server` **and all 22 wrapped tools** on a Kali
base, so you don't have to install them yourself. Point your MCP client at it
(stdio):

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/tidynest/raven-nest-mcp:latest"]
    }
  }
}
```

`masscan` and `nmap -O` need raw sockets - append `--cap-add=NET_RAW` and
`--cap-add=NET_ADMIN` to `args` if you use them. The server is also listed on the
[MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.tidynest/raven-nest-mcp`.

### Prerequisites

- Rust 1.93+ (2024 edition)
- One or more external tools installed (nmap, nuclei, nikto, etc.)

### Build

```bash
cargo build --release
```

### Configure your MCP client

Create `.mcp.json` in your project root (or configure your MCP client directly):

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "/path/to/raven-server",
      "args": []
    }
  }
}
```

The server communicates over stdio and requires no network ports.

### Configuration

Raven Nest loads configuration from TOML, resolved in order:

1. `RAVEN_CONFIG` environment variable (path to file)
2. `config/default.toml` next to the binary
3. `config/default.toml` in the working directory
4. Built-in defaults

Key configuration sections:

```toml
[safety]
allowed_tools = ["nmap", "nuclei", "nikto", "whatweb", "masscan", ". . ."] 
context_budget = 65536          # Model context window in chars (0 = disabled)
expected_tool_calls = 10        # Anticipated calls per session
sudo_tools = ["masscan", "nmap"] # Tools invoked via passwordless sudo
# auto_save_findings = false     # opt-in: auto-extract findings from scanners

[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"

# [scope]                        # engagement authorization allowlist (deny-wins)
# enabled = true
# allowed_domains = ["example.com"]

# [network]
# http_proxy = "http://127.0.0.1:8080"

# [metasploit]
# enabled = true
# host = "127.0.0.1"
# port = 55553
# password = "changeme"

# [netexec]                      # gated, read-only credentialed enumeration
# enabled = true
```

See [docs/USAGE.md](docs/USAGE.md) for the full parameter reference and per-tool configuration options.

## Safety Architecture

Every tool call passes through six layers:

1. **Allowlist** -- only explicitly permitted tools can execute
2. **Input validation** -- targets must be valid IPs, hostnames, CIDRs, or URLs; shell metacharacters are rejected
3. **Preset arguments** -- users pick scan types, never raw CLI flags
4. **Execution containment** -- configurable timeouts with `kill_on_drop`
5. **Output sanitisation** -- ANSI stripping, truncation at configurable limits (UTF-8 safe)
6. **Quality assessment** -- detects empty results, rate-limiting, and WAF blocks

Additional hardening:

- **Config validation at startup** -- safety limits (sqlmap level/risk, hydra tasks, masscan rate) are range-checked; the server refuses to start with out-of-range values or default MSF credentials
- **Wordlist path validation** -- hydra, john, feroxbuster, and ffuf only accept wordlists under `/usr/share/`, `/usr/lib/`, or the configured `output_dir`; path traversal (`..`) is rejected
- **Port spec validation** -- nmap and masscan port parameters accept only digits, commas, and hyphens
- **File permissions** -- cookie files and scan spill files are created with `0o600` (owner-only)
- **Markdown escaping** -- report generation escapes user-supplied finding fields to prevent markdown injection
- **Finding ID validation** -- finding get/delete operations require valid UUID format, preventing path traversal
- **Engagement scope** -- an optional authorization allowlist (`[scope]`): when enabled, every target must match an allowed CIDR/domain and must not match a denied one (deny wins); loopback is allowed unless disabled. `http_request` re-validates each redirect hop against the scope, so a redirect cannot escape it. Off by default
- **Audit logging** -- every tool execution is appended to `{output_dir}/audit.log` with the tool, target, and redacted arguments
- **Proactive cooldown** -- an optional `min_exec_gap_ms` spaces out consecutive tool launches so back-to-back aggressive tools don't trip a target's WAF or rate-limiter; complements the reactive WAF/rate-limit detection. Off by default

Metasploit integration adds a 5-layer safety model: disabled by default, per-tool allowlisting, path-boundary module blocklist, exploit confirmation gate (double-call to execute), and session command filtering. Passwords are redacted from error messages, and TLS certificate bypass is restricted to localhost connections. See [docs/METASPLOIT.md](docs/METASPLOIT.md).

Tools requiring root (masscan, nmap OS detection) can be run via passwordless `sudo` without elevating the entire server. See `sudo_tools` in the [configuration docs](docs/USAGE.md#sudo_tools--privilege-escalation).

## Context Budget

A session-aware **context budget tracker** dynamically adjusts per-tool output caps based on remaining context window space. This prevents context overflow on local AI models with limited context windows (49-64K tokens).

- **Full mode** -- all findings, all details, up to 8K chars per tool call
- **Compact mode** -- top-N results, critical/high findings only (triggers at 40% consumed)
- **Minimal mode** -- one-line summaries (triggers at 70% consumed)

Parser result caps scale dynamically via `scale_cap()` -- each tool's output parser adjusts its result limit based on the active budget mode. All tool output passes through centralised ANSI stripping and budget-aware truncation in `wrap_result()`.

When the budget is exhausted, the server returns a message directing the AI to save findings and generate a report rather than running additional scans.

## Report Generation

The `generate_report` endpoint produces a structured report -- Markdown by default, or JSON, SARIF, or HTML via the `format` parameter -- containing:

- **Table of Contents** with linked findings
- **Executive Summary** with severity breakdown table and overall risk rating
- **Methodology** section (PTES framework)
- **Tools Used** (deduplicated from findings)
- **Scope & Timeline** -- targets assessed and the engagement window, derived from the findings
- **Numbered Findings** with severity, target, tool, CVSS score, CVE identifier, OWASP Top 10 category, evidence, and remediation guidance

The Markdown and HTML formats render the full narrative (table of contents, methodology, scope, generation timestamp); JSON and SARIF are structured envelopes for tooling. Findings support an `owasp_category` field for mapping vulnerabilities to the OWASP Top 10 (e.g. "A03:2021 Injection").

## MCP Resources

Beyond tools, the server exposes its data as read-only [MCP resources](https://modelcontextprotocol.io/docs/concepts/resources) under the `raven://` scheme, so a client can browse or attach them without a tool call:

- `raven://findings` -- JSON index of every saved finding
- `raven://findings/{id}` -- a single finding as JSON
- `raven://reports/{markdown|json|sarif|html}` -- a report rendered on demand
- `raven://scans` -- JSON index of background scans
- `raven://scans/{id}` -- a scan's captured output

Each saved finding and tracked scan is also listed individually, so they show up as browsable entries in resource-aware clients.

## Output Parsers

Every security tool has a structured output parser that extracts key data from raw tool output:

- **nmap** -- XML parser with NSE script extraction (vulners CVEs by CVSS)
- **nuclei** -- JSONL parser with severity filtering
- **nikto/feroxbuster/ffuf/masscan** -- line-oriented parsers with configurable result caps
- **sqlmap** -- injection type and parameter extraction
- **testssl** -- vulnerability and certificate finding extraction
- **hydra/whatweb** -- credential and technology identification
- **subfinder/dnsrecon/dnsx** -- subdomain and DNS record extraction
- **httpx/katana** -- HTTP fingerprint and crawled-endpoint extraction
- **dalfox/wpscan/enum4linux-ng/john** -- structured finding extraction
- **netexec** -- authentication verdict and per-host enumeration extraction

All parsers return `Option<String>` and fall back to raw output when parsing fails. Result limits scale dynamically based on the active budget mode.

## Authenticated Scanning

The `http_request` tool maintains a shared cookie jar that persists within a session and across context clears (saved to disk). External subprocess tools (sqlmap, nikto, feroxbuster, etc.) do not share this jar -- pass cookies via each tool's `cookie` parameter.

## Testing

344 unit and integration tests across 3 crates:

```bash
cargo test --workspace
```

| Crate | Tests |
|-------|-------|
| raven-core | 104 |
| raven-report | 64 |
| raven-server | 166 |
| Integration | 10 |

A Python-based MCP integration test harness is also available:

```bash
python3 -u tests/manual_test_harness.py all     # full suite
python3 -u tests/manual_test_harness.py phase0   # single phase
```

## Project Structure

```
crates/
  raven-core/     # Safety validation, subprocess execution, config (TOML),
                  # scan manager (background scans with disk spill), audit log
  raven-report/   # Finding types (with OWASP categories), file-per-finding
                  # persistence, multi-format report generators (md/json/sarif/html)
  raven-server/   # MCP server (rmcp), tool handlers (one module per tool),
                  # context budget tracker, output parsers, progress ticker
config/
  default.toml    # Default configuration
  sudoers-raven-nest  # Sudoers drop-in for privilege escalation
tests/
  manual_test_harness.py  # MCP integration test harness
```

## Documentation

- [docs/USAGE.md](docs/USAGE.md) -- tool installation, configuration reference, full parameter docs
- [docs/LOCAL_AI_INTEGRATION.md](docs/LOCAL_AI_INTEGRATION.md) -- using Raven Nest with local models (Ollama, LM Studio)
- [docs/METASPLOIT.md](docs/METASPLOIT.md) -- Metasploit Framework integration setup and safety model
- [docs/DATA_FLOW.md](docs/DATA_FLOW.md) -- data flow and sources of truth: which module owns each piece of state
- [raven-nest-client](https://github.com/tidynest/raven-nest-client) -- companion TypeScript REPL client (versioned in lockstep with the server)
- [CHANGELOG.md](CHANGELOG.md) -- release history (current: v0.2.8)

## License

[Apache-2.0](LICENSE)
