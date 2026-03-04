# Raven Nest MCP - Usage Guide

## Prerequisites

### Build

```bash
cd ~/RustroverProjects/raven-nest-mcp
cargo build --release
```

The binary is at `target/release/raven-server`.

### Host Tools

Install the scanning tools you want to use. All are optional — the server
starts regardless, but tool calls will fail if the binary isn't installed.

```bash
paru -S nmap nuclei nikto whatweb
```

`ping` is available by default on all Linux systems.

## Connecting to Claude Code

Create `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "/home/bakri/RustroverProjects/raven-nest-mcp/target/release/raven-server",
      "args": [],
      "cwd": "/home/bakri/RustroverProjects/raven-nest-mcp"
    }
  }
}
```

Restart Claude Code or start a new session in the project directory.
The server communicates over stdio — stdout carries JSON-RPC, logs go to stderr.

## Configuration

Edit `config/default.toml` to customise behaviour:

```toml
[safety]
allowed_tools = ["ping", "nmap", "nuclei", "nikto", "whatweb"]
max_output_chars = 50000

[execution]
default_timeout_secs = 300
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"
```

| Key | Purpose |
|-----|---------|
| `allowed_tools` | Allowlisted binaries. Tool calls for unlisted binaries are rejected. |
| `max_output_chars` | Truncation limit for tool output (keeps first 70%, last 30%). |
| `default_timeout_secs` | Kill subprocess after this many seconds. |
| `max_concurrent_scans` | Max background scans running simultaneously. |
| `output_dir` | Directory for reports, findings persistence, and scan output. Created automatically on startup. |

If the config file is missing or invalid, built-in defaults are used.

## Tools Reference

### Reconnaissance

#### `ping_target`
Verify connectivity and measure latency.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP address or hostname |
| `count` | no | Number of packets, 1-10 (default 4) |

#### `run_nmap`
Port scanning and service detection.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP, hostname, or CIDR range |
| `ports` | no | Port spec (e.g. `80,443` or `1-1000`) |
| `scan_type` | no | `quick` (default), `service`, `os`, `vuln` |

Scan type presets:
- **quick** — `-T4 -F` (top 100 ports, aggressive timing)
- **service** — `-sV` (version detection)
- **os** — `-O` (OS fingerprinting, **requires root** — returns an error if not running as root)
- **vuln** — `-sV --script=vuln` (vulnerability scripts)

#### `run_whatweb`
Identify web technologies (CMS, frameworks, server software).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL or hostname |
| `aggression` | no | `stealthy` (default), `passive`, `aggressive` |

### Vulnerability Scanning

#### `run_nuclei`
Template-based vulnerability scanning.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL or hostname |
| `severity` | no | `info`, `low`, `medium`, `high`, `critical` |
| `tags` | no | Template tags (e.g. `cve,oast`) |

#### `run_nikto`
Web server misconfiguration scanner.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Hostname or URL |
| `port` | no | Port number (default 80) |
| `tuning` | no | `quick` (default), `thorough`, `injection`, `fileupload` |

### HTTP Testing

#### `http_request`
Send crafted HTTP requests for manual endpoint testing.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `url` | yes | Full URL (`http://` or `https://` only) |
| `method` | no | HTTP method (default `GET`) |
| `headers` | no | Key-value header pairs |
| `body` | no | Request body string |
| `auth_token` | no | Bearer token for Authorization header |
| `timeout_secs` | no | Timeout in seconds (default 30, max 120) |
| `follow_redirects` | no | Follow redirects (default true) |

### Background Scans

For long-running scans, use the launch/poll pattern:

#### `launch_scan`
Start a scan in the background, returns a scan ID immediately. The target is
validated and the tool is checked against the allowlist before launching.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tool` | yes | Tool name (`nmap`, `nuclei`, `nikto`, `whatweb`) |
| `target` | yes | Target IP, hostname, or URL |
| `args` | no | Tool arguments as a string list |

#### `get_scan_status`
Check whether a scan is Running, Completed, Failed, or Cancelled.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scan_id` | yes | ID returned by `launch_scan` |

#### `get_scan_results`
Fetch output from a completed scan with pagination.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scan_id` | yes | ID returned by `launch_scan` |
| `offset` | no | Character offset (default 0) |
| `limit` | no | Max characters to return (default 10000) |

#### `cancel_scan`
Cancel a running scan.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `scan_id` | yes | ID returned by `launch_scan` |

#### `list_scans`
List all scans and their current status. No parameters.

### Findings and Reports

#### `save_finding`
Record a vulnerability finding. Each finding is stored as an individual JSON file
under `{output_dir}/findings/` and indexed in memory for fast listing. There is no
hard cap on finding count — the store scales to tens of thousands of findings with
bounded memory (only metadata is kept in RAM; full data lives on disk).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `title` | yes | Finding title |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `info` |
| `description` | yes | Detailed description |
| `target` | yes | Affected target |
| `tool` | yes | Tool that discovered it |
| `evidence` | no | Raw output excerpt |
| `remediation` | no | Suggested fix |
| `cvss` | no | CVSS score (0.0-10.0) |
| `cve` | no | CVE identifier |

#### `get_finding`
Retrieve full details of a finding as JSON.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `finding_id` | yes | Finding ID |

#### `list_findings`
List all findings sorted by severity (Critical first). No parameters.

#### `delete_finding`
Remove a finding. The individual file is deleted from disk and the index is updated.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `finding_id` | yes | Finding ID |

#### `generate_report`
Generate a markdown pentest report from all saved findings. The report is
automatically saved to `{output_dir}/report-{timestamp}.md`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `title` | no | Report title (default "Penetration Test Report") |

## Safety Architecture

Every tool call passes through six layers:

1. **Allowlist** — binary must be in `config.safety.allowed_tools`
2. **Input validation** — target must be a valid IP, hostname, CIDR, or URL (`http`/`https` only); shell metacharacters rejected
3. **Argument building** — users pick presets, never raw CLI flags
4. **Execution containment** — configurable timeout, `kill_on_drop` on all subprocesses
5. **Output sanitisation** — truncation at `max_output_chars` (70% head / 30% tail)
6. **Output quality assessment** — checks for empty results, missing tool completion markers, and rate-limit/WAF indicators; appends warnings when detected

## Example Workflow

```
You: "Ping scanme.nmap.org to check if it's up"
Claude: [calls ping_target with target: "scanme.nmap.org"]

You: "Run a service scan on it, ports 22,80,443"
Claude: [calls run_nmap with target: "scanme.nmap.org", ports: "22,80,443", scan_type: "service"]

You: "Check for vulnerabilities with nuclei"
Claude: [calls run_nuclei with target: "scanme.nmap.org", severity: "high"]

You: "Save that open SSH finding"
Claude: [calls save_finding with title, severity, description, target, tool]

You: "Generate the pentest report"
Claude: [calls generate_report]
```
