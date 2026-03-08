# Raven Nest MCP - Usage Guide

## Prerequisites

### Build

```bash
git clone https://github.com/tidynest/raven-nest-mcp.git
cd raven-nest-mcp
cargo build --release
```

The binary is at `target/release/raven-server`.

### Host Tools

Install the scanning tools you want to use. All are optional — the server
starts regardless, but tool calls will fail if the binary isn't installed.

```bash
# Core tools (official repos)
sudo pacman -S nmap nikto whatweb testssl.sh sqlmap hydra masscan

# AUR tools
yay -S feroxbuster-bin ffuf-bin

# Installed via Go/GitHub releases
nuclei   # see https://github.com/projectdiscovery/nuclei
```

`ping` is available by default on all Linux systems.

Note: The Arch `testssl.sh` package installs the binary as `testssl`. If
the tool config references `testssl.sh`, create a symlink:
`sudo ln -s /usr/bin/testssl /usr/bin/testssl.sh`

## Connecting to an MCP Client

Create `.mcp.json` in the project root (adjust paths to your system):

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "./target/release/raven-server",
      "args": [],
      "cwd": "."
    }
  }
}
```

Restart your MCP client or start a new session in the project directory.
The server communicates over stdio — stdout carries JSON-RPC, logs go to stderr.

## Configuration

Edit `config/default.toml` to customise behaviour:

```toml
[safety]
allowed_tools = [
    "ping", "nmap", "nuclei", "nikto", "whatweb",
    "testssl.sh", "feroxbuster", "ffuf",
    "sqlmap", "hydra", "masscan",
]
max_output_chars = 50000

# Safety limits for dangerous tools (prevents LLM escalation)
# sqlmap_max_level = 2    # 1-5, default 2
# sqlmap_max_risk = 1     # 1-3, default 1
# hydra_max_tasks = 4     # parallel tasks, default 4
# masscan_max_rate = 1000 # packets/sec, default 1000

# Optional: custom binary paths for tools not on $PATH
# [safety.tool_paths]
# nmap = "/opt/nmap-dev/bin/nmap"

[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"

# Optional: per-tool timeout overrides (seconds)
# [execution.timeouts]
# nmap = 900
# nuclei = 1200
```

| Key | Purpose |
|-----|---------|
| `allowed_tools` | Allowlisted binaries. Tool calls for unlisted binaries are rejected. |
| `max_output_chars` | Truncation limit for tool output (keeps first 70%, last 30%). Uses char boundaries for UTF-8 safety. |
| `default_timeout_secs` | Kill subprocess after this many seconds. |
| `max_concurrent_scans` | Max background scans running simultaneously. |
| `output_dir` | Directory for reports, findings persistence, and scan output. Created automatically on startup. |
| `sqlmap_max_level` | Caps sqlmap `--level` to prevent LLM from escalating aggressiveness. |
| `sqlmap_max_risk` | Caps sqlmap `--risk` similarly. |
| `hydra_max_tasks` | Max parallel threads for hydra brute-forcing. |
| `masscan_max_rate` | Max packets/sec for masscan. |
| `tool_paths` | Custom binary paths for tools not on `$PATH`. |
| `execution.timeouts` | Per-tool timeout overrides in seconds. |

Config resolution: `RAVEN_CONFIG` env var > exe-relative > CWD > built-in defaults.

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
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_masscan`
High-speed port scanning. **Requires root** — returns an error if not running as root.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP, hostname, or CIDR range |
| `ports` | yes | Port spec (e.g. `80,443` or `0-65535`) |
| `rate` | no | Packets/sec (clamped to `masscan_max_rate` config, default 100) |

### Vulnerability Scanning

#### `run_nuclei`
Template-based vulnerability scanning.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL or hostname |
| `severity` | no | `info`, `low`, `medium`, `high`, `critical` |
| `tags` | no | Template tags (e.g. `cve,oast`) |
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_nikto`
Web server misconfiguration scanner.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Hostname or URL |
| `port` | no | Port number (default 80) |
| `tuning` | no | `quick` (default), `thorough`, `injection`, `fileupload` |
| `cookie` | no | Cookie string for authenticated scanning |
| `timeout_secs` | no | Override default timeout |

### Web Fuzzing & Discovery

#### `run_feroxbuster`
Directory brute-forcing / content discovery.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL |
| `wordlist` | no | Path to wordlist (default: raft-medium-directories.txt) |
| `extensions` | no | File extensions to check (e.g. `php,html,js`) |
| `threads` | no | Concurrent threads (default 50, reduced to 10 for localhost; max 200) |
| `status_codes` | no | Status codes to include (e.g. `200,301,403`) |
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_ffuf`
Web fuzzing with FUZZ keyword.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `url` | yes | URL containing `FUZZ` keyword (e.g. `https://example.com/FUZZ`) |
| `wordlist` | no | Path to wordlist |
| `method` | no | HTTP method (default `GET`) |
| `headers` | no | Custom headers (comma-separated `Name: Value` pairs) |
| `match_codes` | no | Match HTTP status codes (e.g. `200,301,302`) |
| `filter_size` | no | Filter responses by size (bytes) |
| `threads` | no | Concurrent threads (default 40, reduced to 10 for localhost; max 150) |
| `cookie` | no | Cookie string for authenticated fuzzing |

### Exploitation

#### `run_sqlmap`
SQL injection testing. Always runs in `--batch` mode (non-interactive).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL with injectable parameter |
| `data` | no | POST data |
| `cookie` | no | Cookie header value |
| `level` | no | Test level 1-5 (clamped to `sqlmap_max_level` config) |
| `risk` | no | Risk level 1-3 (clamped to `sqlmap_max_risk` config) |
| `technique` | no | SQLi technique (e.g. `BEUSTQ`) |

#### `run_hydra`
Authentication brute-forcing.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Target host |
| `service` | yes | Service to attack (e.g. `ssh`, `ftp`, `http-post-form`) |
| `userlist` | yes | Path to username list |
| `passlist` | yes | Path to password list |
| `tasks` | no | Parallel tasks (clamped to `hydra_max_tasks` config) |
| `form_params` | no* | Form attack string for `http-post-form`/`http-get-form` (e.g. `'/login:user=^USER^&pass=^PASS^:F=incorrect'`). **Required** when service is a form type. |

### TLS / SSL

#### `run_testssl`
SSL/TLS configuration audit.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Hostname, host:port, or URL |
| `severity` | no | Minimum severity to report |
| `quick` | no | Quick mode (`--quiet --sneaky`, fewer checks) |

### HTTP Testing

#### `http_request`
Send crafted HTTP requests for manual endpoint testing. Cookies are
automatically persisted across requests within the same session.

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
| `tool` | yes | Any allowlisted tool name (e.g. `nmap`, `nuclei`, `nikto`, `whatweb`) |
| `target` | yes | Target IP, hostname, or URL |
| `args` | no | Tool arguments as a string list |
| `timeout_secs` | no | Scan timeout in seconds (default from config) |

#### `get_scan_status`
Check whether a scan is Running, Completed, Failed, or Cancelled.
Completed scans with output under 10K chars include the output inline.

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
Assistant: [calls ping_target with target: "scanme.nmap.org"]

You: "Run a service scan on it, ports 22,80,443"
Assistant: [calls run_nmap with target: "scanme.nmap.org", ports: "22,80,443", scan_type: "service"]

You: "Check for vulnerabilities with nuclei"
Assistant: [calls run_nuclei with target: "scanme.nmap.org", severity: "high"]

You: "Save that open SSH finding"
Assistant: [calls save_finding with title, severity, description, target, tool]

You: "Generate the pentest report"
Assistant: [calls generate_report]
```
