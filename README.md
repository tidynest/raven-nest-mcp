# Raven Nest MCP

A pentesting toolkit that runs as an [MCP](https://modelcontextprotocol.io/) server, giving AI assistants structured access to industry-standard security tools through a safety-hardened interface.

## What It Does

Raven Nest wraps 14 pentesting tools (plus Metasploit Framework integration) behind an MCP interface with input validation, output quality assessment, session-aware context budgeting, and configurable safety limits. It handles tool execution, background scan management, vulnerability finding persistence, and report generation.

### Supported Tools

| Category | Tools |
|----------|-------|
| Recon | nmap, masscan, whatweb, subfinder, ping |
| SMB/AD | enum4linux-ng |
| Vulnerability | nuclei, nikto, wpscan |
| Web fuzzing | feroxbuster, ffuf |
| Exploitation | sqlmap, hydra |
| TLS/SSL | testssl.sh |
| Metasploit | msf_search, msf_module_info, msf_exploit, msf_auxiliary, msf_sessions, msf_post |

Plus: `http_request` for manual HTTP testing, background scan management (launch/poll/cancel), finding storage, and markdown report generation. 31 MCP tools total.

## Quick Start

```bash
cargo build --release
```

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "./target/release/raven-server",
      "args": []
    }
  }
}
```

See [docs/USAGE.md](docs/USAGE.md) for tool installation, configuration, and the full parameter reference.
See [docs/LOCAL_AI_INTEGRATION.md](docs/LOCAL_AI_INTEGRATION.md) for using Raven Nest with local models (Ollama, LM Studio).
See [docs/METASPLOIT.md](docs/METASPLOIT.md) for Metasploit Framework integration setup and safety model.

## Safety Architecture

Every tool call passes through six layers:

1. **Allowlist** — only explicitly permitted tools can execute
2. **Input validation** — targets must be valid IPs, hostnames, CIDRs, or URLs; shell metacharacters are rejected
3. **Preset arguments** — users pick scan types, never raw CLI flags
4. **Execution containment** — configurable timeouts with `kill_on_drop`
5. **Output sanitisation** — truncation at configurable limits (UTF-8 safe)
6. **Quality assessment** — detects empty results, rate-limiting, and WAF blocks

Dangerous tools have additional caps: sqlmap level/risk, hydra task count, and masscan packet rate are all configurable maximums that prevent escalation beyond operator-approved limits.

Metasploit integration adds a 5-layer safety model: disabled by default, per-tool allowlisting, module blocklist, exploit confirmation gate (double-call to execute), and session command filtering. See [docs/METASPLOIT.md](docs/METASPLOIT.md).

A session-aware **context budget tracker** dynamically adjusts per-tool output caps based on remaining context window space, automatically escalating from Full to Compact to Minimal output modes as the budget is consumed. This prevents context overflow on local AI models with limited context windows (49-64K).

Tools requiring root (masscan, nmap OS detection) can be run via passwordless `sudo` without elevating the entire server — see `sudo_tools` in the [configuration docs](docs/USAGE.md#sudo_tools--privilege-escalation).

## Testing

A comprehensive MCP test harness (`tests/manual_test_harness.py`) covers test cases across all tools — parameter validation, injection prevention, lenient deserialization, scan lifecycle, findings CRUD, and output truncation.

```bash
python3 -u tests/manual_test_harness.py all     # full suite
python3 -u tests/manual_test_harness.py phase0   # single phase
```

See `tests/TEST_RESULTS.md` for the latest results.

## Project Structure

```
crates/
  raven-core/     # Safety, execution, config, scan management
  raven-report/   # Finding storage, markdown report generation
  raven-server/   # MCP server, tool handlers
config/
  default.toml    # Default configuration
  sudoers-raven-nest  # Sudoers drop-in for masscan/nmap privilege escalation
tests/
  manual_test_harness.py  # MCP integration test harness (297 tests)
  TEST_RESULTS.md         # Latest test results
```

## License

[Apache-2.0](LICENSE)
