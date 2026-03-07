# Raven Nest MCP

A pentesting toolkit that runs as an [MCP](https://modelcontextprotocol.io/) server, giving AI assistants structured access to industry-standard security tools through a safety-hardened interface.

## What It Does

Raven Nest wraps 11 pentesting tools behind an MCP interface with input validation, output quality assessment, and configurable safety limits. It handles tool execution, background scan management, vulnerability finding persistence, and report generation.

### Supported Tools

| Category | Tools |
|----------|-------|
| Recon | nmap, masscan, whatweb, ping |
| Vulnerability | nuclei, nikto |
| Web fuzzing | feroxbuster, ffuf |
| Exploitation | sqlmap, hydra |
| TLS/SSL | testssl.sh |

Plus: `http_request` for manual HTTP testing, background scan management (launch/poll/cancel), finding storage, and markdown report generation.

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

## Safety Architecture

Every tool call passes through six layers:

1. **Allowlist** — only explicitly permitted tools can execute
2. **Input validation** — targets must be valid IPs, hostnames, CIDRs, or URLs; shell metacharacters are rejected
3. **Preset arguments** — users pick scan types, never raw CLI flags
4. **Execution containment** — configurable timeouts with `kill_on_drop`
5. **Output sanitisation** — truncation at configurable limits (UTF-8 safe)
6. **Quality assessment** — detects empty results, rate-limiting, and WAF blocks

Dangerous tools have additional caps: sqlmap level/risk, hydra task count, and masscan packet rate are all configurable maximums that prevent escalation beyond operator-approved limits.

## Project Structure

```
crates/
  raven-core/     # Safety, execution, config, scan management
  raven-report/   # Finding storage, markdown report generation
  raven-server/   # MCP server, tool handlers
config/
  default.toml    # Default configuration
```

## License

[Apache-2.0](LICENSE)
