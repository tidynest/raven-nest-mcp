# Raven Nest MCP

A pentesting toolkit that runs as an [MCP](https://modelcontextprotocol.io/) server, giving AI assistants structured access to industry-standard security tools through a safety-hardened interface.

## What It Does

Raven Nest wraps 16 security tools plus Metasploit Framework behind an MCP interface with input validation, output quality assessment, session-aware context budgeting, and configurable safety limits. It handles tool execution, background scan management, vulnerability finding persistence, and markdown report generation. 34 MCP endpoints total.

### Supported Tools

| Category | Tools |
|----------|-------|
| Recon | nmap, masscan, whatweb, subfinder, dnsrecon |
| SMB/AD | enum4linux-ng |
| Vulnerability | nuclei, nikto, wpscan, dalfox (XSS) |
| Web fuzzing | feroxbuster, ffuf |
| Exploitation | sqlmap, hydra |
| Password cracking | john |
| TLS/SSL | testssl.sh |
| Metasploit | msf\_search, msf\_module\_info, msf\_exploit, msf\_auxiliary, msf\_sessions, msf\_post |
| Utility | ping\_target, http\_request |
| Scan management | launch\_scan, get\_scan\_status, get\_scan\_results, list\_scans, cancel\_scan |
| Findings | save\_finding, get\_finding, list\_findings, delete\_finding, generate\_report |

## Quick Start

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
allowed_tools = ["nmap", "nuclei", "nikto", "whatweb", "masscan", ...] 
context_budget = 65536          # Model context window in chars (0 = disabled)
expected_tool_calls = 10        # Anticipated calls per session
sudo_tools = ["masscan", "nmap"] # Tools invoked via passwordless sudo

[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"

# [network]
# http_proxy = "http://127.0.0.1:8080"

# [metasploit]
# enabled = true
# host = "127.0.0.1"
# port = 55553
# password = "changeme"
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

The `generate_report` endpoint produces a structured markdown report containing:

- **Table of Contents** with linked findings
- **Executive Summary** with severity breakdown table and overall risk rating
- **Methodology** section (PTES framework)
- **Tools Used** (deduplicated from findings)
- **Numbered Findings** with severity, target, tool, CVSS score, CVE identifier, OWASP Top 10 category, evidence, and remediation guidance

Findings support an `owasp_category` field for mapping vulnerabilities to the OWASP Top 10 (e.g. "A03:2021 Injection").

## Output Parsers

All 16 security tools have structured output parsers that extract key data from raw tool output:

- **nmap** -- XML parser with NSE script extraction (vulners CVEs by CVSS)
- **nuclei** -- JSONL parser with severity filtering
- **nikto/feroxbuster/ffuf/masscan** -- line-oriented parsers with configurable result caps
- **sqlmap** -- injection type and parameter extraction
- **testssl** -- vulnerability and certificate finding extraction
- **hydra/whatweb** -- credential and technology identification
- **subfinder/dnsrecon** -- subdomain and DNS record extraction
- **dalfox/wpscan/enum4linux-ng/john** -- structured finding extraction

All parsers return `Option<String>` and fall back to raw output when parsing fails. Result limits scale dynamically based on the active budget mode.

## Authenticated Scanning

The `http_request` tool maintains a shared cookie jar that persists within a session and across context clears (saved to disk). External subprocess tools (sqlmap, nikto, feroxbuster, etc.) do not share this jar -- pass cookies via each tool's `cookie` parameter.

## Testing

179 unit and integration tests across 3 crates:

```bash
cargo test --workspace
```

| Crate | Tests |
|-------|-------|
| raven-core | 49 |
| raven-report | 18 |
| raven-server | 104 |
| Integration | 8 |

A Python-based MCP integration test harness is also available:

```bash
python3 -u tests/manual_test_harness.py all     # full suite
python3 -u tests/manual_test_harness.py phase0   # single phase
```

## Project Structure

```
crates/
  raven-core/     # Safety validation, subprocess execution, config (TOML),
                  # scan manager (background scans with disk spill)
  raven-report/   # Finding types (with OWASP categories), file-per-finding
                  # persistence, markdown report generator
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

## License

[Apache-2.0](LICENSE)
