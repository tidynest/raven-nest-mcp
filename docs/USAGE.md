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
# Core tools (official repos — Arch Linux)
sudo pacman -S nmap nikto whatweb testssl.sh sqlmap hydra masscan

# AUR tools
yay -S feroxbuster-bin ffuf-bin

# Nuclei — installed via Go or GitHub releases
# Download the latest release from https://github.com/projectdiscovery/nuclei
# or install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# After install, update templates: nuclei -ut
```

`ping` is available by default on all Linux systems.

> **Arch note:** The `testssl.sh` package installs the binary as `testssl`.
> If the tool config references `testssl.sh`, create a symlink:
> `sudo ln -s /usr/bin/testssl /usr/bin/testssl.sh`

---

## Connecting to an MCP Client

The server communicates over stdio — stdout carries JSON-RPC, logs go to stderr.

### Claude Code

Create `.mcp.json` in the project root (or `~/.claude/.mcp.json` for global access):

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "/absolute/path/to/raven-server",
      "args": [],
      "cwd": "/absolute/path/to/raven-nest-mcp"
    }
  }
}
```

Restart Claude Code or start a new session. The server's tools appear
automatically.

### Generic MCP Clients

Any MCP client that supports stdio transport works. Point the client at the
binary with the working directory set to the repo root (so the config resolves
correctly):

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

### Local AI (ollmcp)

When using local models (Ollama, llama.cpp), rename the server to avoid
hyphens — many local models struggle with tool names containing hyphens:

```json
{
  "mcpServers": {
    "raven": {
      "command": "/absolute/path/to/raven-server",
      "args": []
    }
  }
}
```

Launch: `ollmcp --model <model> -j ~/.mcphost.json`

For small-context models (32K-64K), set `context_budget` in the config —
see the [Configuration](#configuration) section.

---

## Configuration

Edit `config/default.toml` to customise behaviour. The config file has three
sections: `[safety]`, `[execution]`, and `[network]`.

### Config Resolution Chain

The server searches for config in this order, using the first one found:

1. **`RAVEN_CONFIG` env var** — explicit file path (e.g. `RAVEN_CONFIG=/etc/raven.toml`)
2. **Exe-relative** — `config/default.toml` relative to the binary (checks parent dir too, for `target/release/` layouts)
3. **CWD** — `config/default.toml` in the current working directory
4. **Built-in defaults** — hardcoded fallback if nothing else is found

If all fail, the server starts with safe defaults (all 11 tools allowed, 600s
timeout, output at `/tmp/raven-nest`).

### `[safety]` — Tool Allowlisting and Limits

```toml
[safety]
allowed_tools = [
    "ping", "nmap", "nuclei", "nikto", "whatweb",
    "testssl.sh", "feroxbuster", "ffuf",
    "sqlmap", "hydra", "masscan",
]
max_output_chars = 50000
# context_budget = 32768

# Safety limits for dangerous tools
# sqlmap_max_level = 2
# sqlmap_max_risk = 1
# hydra_max_tasks = 4
# masscan_max_rate = 1000

# Custom binary paths
# [safety.tool_paths]
# nmap = "/opt/nmap-dev/bin/nmap"
# nuclei = "/home/user/.local/bin/nuclei"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allowed_tools` | string list | all 11 tools | Allowlisted tool binaries. Calls for unlisted tools are rejected before execution. Remove tools to restrict what the AI can invoke. |
| `max_output_chars` | integer | 50000 | Truncation limit for subprocess output. When exceeded, keeps 70% from the start and 30% from the end with a marker in between. Uses char boundaries for UTF-8 safety. Overridden by `context_budget` when set. |
| `context_budget` | integer | 0 (disabled) | Model context window size in characters. When > 0, derives output caps automatically so ~4 tool outputs fit in the context. See table below. |
| `sqlmap_max_level` | integer (1-5) | 2 | Caps sqlmap `--level`. Higher levels add more injection vectors but are slower and noisier. |
| `sqlmap_max_risk` | integer (1-3) | 1 | Caps sqlmap `--risk`. Risk 2+ may cause data modification; risk 3 adds OR-based payloads. |
| `hydra_max_tasks` | integer | 4 | Max parallel threads for hydra brute-forcing. Prevents account lockout and network saturation. |
| `masscan_max_rate` | integer | 1000 | Max packets/sec for masscan. High rates can disrupt networks — increase only with explicit authorisation. |
| `tool_paths` | table | empty | Map of tool name to absolute binary path, for tools not on `$PATH`. Falls back to `$PATH` lookup if not specified. |
| `sudo_tools` | string list | `[]` | Tools invoked via `sudo` for privilege escalation. See [sudo_tools](#sudo_tools--privilege-escalation) below. |

#### Context Budget

The `context_budget` setting is designed for local AI models with limited context
windows. When set, it overrides `max_output_chars` and the HTTP response body
cap proportionally:

| `context_budget` | Tool output cap (`/4`) | HTTP body cap (`/6`) | Recommended for |
|-----------------|----------------------|---------------------|-----------------|
| 0 (disabled) | uses `max_output_chars` (50K) | 20,000 | Claude, GPT-4, large-context models |
| 32768 | 8,192 | 5,461 | Qwen3 8B at default 32K context |
| 65536 | 16,384 | 10,922 | Models with q8_0 KV cache doubling |
| 131072 | 32,768 | 21,845 | Qwen3 14B, models with 128K context |

**When to set this:** Only when using models with limited context windows. Leave
at 0 (disabled) for Claude or other large-context models — `max_output_chars`
alone handles truncation fine.

#### `sudo_tools` — Privilege Escalation

Some tools require root privileges:
- **masscan** — raw socket access for SYN scanning
- **nmap** with `scan_type: "os"` — raw sockets for OS fingerprinting

Instead of running the entire server as root, you can grant passwordless `sudo`
for just these binaries:

1. Install the sudoers drop-in (included in the repo):

```bash
sudo install -m 0440 config/sudoers-raven-nest /etc/sudoers.d/raven-nest
```

2. Enable in `config/default.toml`:

```toml
[safety]
sudo_tools = ["masscan", "nmap"]
```

3. Verify:

```bash
sudo -n nmap --version     # should print version without password prompt
sudo -n masscan --version   # same
```

When a tool is listed in `sudo_tools`, the executor invokes it as
`sudo /usr/bin/nmap <args>` instead of `nmap <args>`. The tool handlers skip
their root-privilege check when sudo is configured.

The included `config/sudoers-raven-nest` file grants the `bakri` user
passwordless sudo for `/usr/bin/masscan` and `/usr/bin/nmap` only. Edit the
username and paths for your environment.

### `[execution]` — Timeouts, Concurrency, Output

```toml
[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"

# Per-tool timeout overrides (seconds)
# [execution.timeouts]
# nmap = 900
# nuclei = 1200
# nikto = 600
# testssl.sh = 900
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_timeout_secs` | integer | 600 | Global subprocess timeout. The process is killed after this many seconds. |
| `max_concurrent_scans` | integer | 3 | Max background scans (`launch_scan`) running simultaneously. Additional launches are rejected until a slot opens. |
| `output_dir` | string | `/tmp/raven-nest` | Base directory for reports, findings, and scan output. Created automatically on startup. |
| `timeouts` | table | empty | Per-tool timeout overrides in seconds. Falls back to `default_timeout_secs` for tools not listed. |

**When to change timeouts:** Vulnerability scans (`nuclei`, `nikto`, `testssl.sh`)
and OS detection (`nmap -O`) can take several minutes on large targets. Increase
their specific timeouts rather than raising the global default.

### `[network]` — Proxy Configuration

```toml
[network]
http_proxy = "http://127.0.0.1:8080"
https_proxy = "http://127.0.0.1:8080"
no_proxy = ["127.0.0.1", "localhost"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `http_proxy` | string | none | HTTP proxy URL. Injected as `HTTP_PROXY` and `http_proxy` env vars into all tool subprocesses. |
| `https_proxy` | string | none | HTTPS proxy URL. Injected similarly. |
| `no_proxy` | string list | empty | Hostnames/IPs that should bypass the proxy. |

**When to set this:** Route traffic through a proxy like Burp Suite or ZAP for
request inspection. Both upper- and lower-case env vars are set, so tools using
either convention pick up the proxy automatically. The `http_request` tool also
honours these proxy settings.

---

## Tools Reference

The server exposes 22 tools across 6 categories.

### Reconnaissance

#### `ping_target`
Verify connectivity and measure latency.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP address or hostname |
| `count` | no | Number of packets, 1-10 (default 4) |

#### `run_nmap`
Port scanning and service detection. Output is parsed from nmap's XML format
into a structured summary (host addresses, port states with service/version,
NSE script results per port and host-level, OS detection matches, run stats).
For `vuln` scans, the `vulners` script output is compressed to the top 5 CVEs
by CVSS score; other scripts are summarised to single-line entries.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP, hostname, or CIDR range |
| `ports` | no | Port spec (e.g. `80,443` or `1-1000`) |
| `scan_type` | no | `quick` (default), `service`, `os`, `vuln` |

Scan type presets:
- **quick** — `-T4 -F` (top 100 ports, aggressive timing)
- **service** — `-sV` (version detection)
- **os** — `-O` (OS fingerprinting, requires root or `sudo_tools` config)
- **vuln** — `-sV --script=vuln` (vulnerability scripts)

#### `run_whatweb`
Identify web technologies (CMS, frameworks, server software). Output is parsed
to extract technology identification lines with bracket-notation tags.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL or hostname |
| `aggression` | no | `stealthy` (default), `passive`, `aggressive` |
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_masscan`
High-speed port scanning. Requires root or `sudo_tools` config — returns an
error if neither is available. Output is parsed to extract discovered open ports.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | IP, hostname, or CIDR range |
| `ports` | yes | Port spec (e.g. `80,443` or `0-65535`) |
| `rate` | no | Packets/sec (clamped to `masscan_max_rate` config, default 100) |

### Vulnerability Scanning

#### `run_nuclei`
Template-based vulnerability scanning. Output is parsed from JSONL format into
compact lines: `[SEVERITY] template-id - name @ url (type)`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL or hostname |
| `severity` | no | `info`, `low`, `medium`, `high`, `critical` |
| `tags` | no | Template tags (e.g. `cve,oast`) |
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_nikto`
Web server misconfiguration scanner. Output is parsed to extract finding lines
(prefixed with `+`), filtering out help text.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Hostname or URL |
| `port` | no | Port number (default 80) |
| `tuning` | no | `quick` (default), `thorough`, `injection`, `fileupload` |
| `cookie` | no | Cookie string for authenticated scanning |
| `timeout_secs` | no | Override default timeout |

### Web Fuzzing & Discovery

#### `run_feroxbuster`
Directory brute-forcing / content discovery. Output is parsed to extract
status-code + URL pairs, filtering out 404 responses.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL |
| `wordlist` | no | Path to wordlist (default: raft-medium-directories.txt) |
| `extensions` | no | File extensions to check (e.g. `php,html,js`) |
| `threads` | no | Concurrent threads (default 50; reduced to 10 for localhost targets; max 200) |
| `status_codes` | no | Status codes to include (e.g. `200,301,403`) |
| `cookie` | no | Cookie string for authenticated scanning |

#### `run_ffuf`
Web fuzzing with FUZZ keyword. Output is parsed to extract result lines
containing status codes, sizes, and word counts.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `url` | yes | URL containing `FUZZ` keyword (e.g. `http://example.com/FUZZ`) |
| `wordlist` | no | Path to wordlist |
| `method` | no | HTTP method (default `GET`) |
| `headers` | no | Custom headers (comma-separated `Name: Value` pairs) |
| `match_codes` | no | Match HTTP status codes (e.g. `200,301,302`) |
| `filter_size` | no | Filter responses by size (bytes) |
| `threads` | no | Concurrent threads (default 40; reduced to 10 for localhost targets; max 150) |
| `cookie` | no | Cookie string for authenticated fuzzing |

### Exploitation

#### `run_sqlmap`
SQL injection testing. Always runs in `--batch` mode (non-interactive). Output
is parsed to extract injection points (parameter/type/title/payload), DBMS
info, and critical errors. Non-injectable verdicts are preserved.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | URL with injectable parameter |
| `data` | no | POST data |
| `cookie` | no | Cookie header value |
| `level` | no | Test level 1-5 (clamped to `sqlmap_max_level` config) |
| `risk` | no | Risk level 1-3 (clamped to `sqlmap_max_risk` config) |
| `technique` | no | SQLi technique (e.g. `BEUSTQ`) |

#### `run_hydra`
Authentication brute-forcing. Output is parsed to extract discovered
credentials and the summary line (valid passwords found/completed).

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
SSL/TLS configuration audit. Output is parsed to extract vulnerability
assessments, certificate details (CN, SAN, issuer, expiry, trust, CT), and
overall rating.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | yes | Hostname, host:port, or URL |
| `severity` | no | Minimum severity to report |
| `quick` | no | Quick mode (`--quiet --sneaky`, fewer checks) |

### HTTP Testing

#### `http_request`
Send crafted HTTP requests for manual endpoint testing. Cookies are
automatically persisted across requests within the same session via a shared
cookie jar (see [Session Features](#session-features)).

HTML responses are automatically stripped of tags, scripts, and styles, with
entity decoding applied. Only security-relevant headers are shown in the
response (see [Output Processing](#output-processing)).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `url` | yes | Full URL (`http://` or `https://` only) |
| `method` | no | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` (default `GET`). Other methods are rejected. |
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
automatically saved to `{output_dir}/report-{timestamp}.md`. Returns a brief
summary (finding count by severity) instead of the full report content to
conserve context.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `title` | no | Report title (default "Penetration Test Report") |

---

## Safety Architecture

Every tool call passes through multiple validation layers before any subprocess
is spawned:

1. **Allowlist** — the tool binary must be in `config.safety.allowed_tools`. Calls
   for unlisted tools are rejected immediately.

2. **Input validation** — targets are validated against strict rules:
   - Must be a valid IP (v4/v6), hostname, CIDR range, `host:port`, or
     HTTP(S) URL.
   - Shell metacharacters are rejected: `` ; | & $ ` ( ) { } < > ! \n ``
   - Only `http://` and `https://` URL schemes are accepted.
   - CIDR masks are range-checked (IPv4: /0-/32, IPv6: /0-/128).
   - Hostnames: alphanumerics, hyphens, dots; max 253 chars; no
     leading/trailing hyphens; per-label validation (each dot-separated
     label must not start or end with a hyphen, and must not be empty).

3. **Argument building** — users pick presets (e.g. `scan_type: "service"`),
   never raw CLI flags. The server translates presets into safe argument lists.

4. **Parameter validation** — all 18 request structs use `deny_unknown_fields`,
   which rejects any parameter the tool doesn't recognise. This catches LLM
   parameter hallucination with clear error messages (e.g. "unknown field
   `verbosity`"). Numeric parameters also accept string-encoded numbers
   (e.g. `"2"` instead of `2`) via a lenient deserializer, handling a common
   LLM serialisation quirk.

5. **Safety caps** — dangerous tools have configurable upper limits that the
   AI cannot exceed:
   - sqlmap: `--level` clamped to `sqlmap_max_level`, `--risk` to `sqlmap_max_risk`
   - hydra: `-t` (parallel tasks) clamped to `hydra_max_tasks`
   - masscan: `--rate` clamped to `masscan_max_rate`

6. **Execution containment** — configurable timeout per tool, `kill_on_drop` on
   all subprocesses (no orphaned processes), concurrent scan limit enforced.

7. **Output sanitisation** — truncation at `max_output_chars` (70% head / 30%
   tail), with structured parsing to reduce noise before truncation.

8. **Output quality assessment** — checks for empty results, missing tool
   completion markers, and rate-limit/WAF indicators; appends warnings when
   detected (e.g. "Output appears empty", "Possible rate limiting detected").

---

## Output Processing

Tool output goes through a multi-stage pipeline before reaching the AI model:

### Structured Parsers

All 10 subprocess tools have output parsers that extract the essential
information and discard noise. Parsers return `Option<String>` — if parsing
fails, the raw output is used as a fallback.

| Tool | Parser | What It Extracts |
|------|--------|-----------------|
| nmap | XML parser | Host addresses, port states (proto/port/state/service/version), NSE script results (per-port and host-level; vulners top-5 CVEs by CVSS score, other scripts compressed to one-line summaries), OS matches, run stats |
| nuclei | JSONL parser | `[SEVERITY] template-id - name @ url (type)` per finding |
| nikto | Line filter | Lines starting with `+` (findings); filters help text |
| feroxbuster | Line filter | Status-code + URL pairs; filters 404s |
| testssl | Section parser | Vulnerability assessments, certificate details (CN, SAN, issuer, expiry), rating |
| sqlmap | Block parser | Injection points (parameter/type/title/payload), DBMS/OS/tech info, error messages |
| hydra | Line filter | Discovered credentials (`login:` + `password:`), summary |
| whatweb | Line filter | Technology lines starting with URLs and containing bracket tags |
| masscan | Line filter | `Discovered open port` lines (port/proto/IP) |
| ffuf | Line filter | Result lines containing `[Status:` with size/word counts |

### HTTP Response Processing

The `http_request` tool applies additional processing to HTTP responses:

- **HTML stripping** — removes `<script>` and `<style>` blocks, strips all
  HTML tags (inserting newlines for block elements), decodes HTML entities
  (named like `&amp;`, numeric like `&#169;`), and collapses blank lines.
- **Header filtering** — only security-relevant headers are shown:
  `server`, `x-powered-by`, `set-cookie`, `content-type`, `location`,
  `www-authenticate`, `x-frame-options`, `content-security-policy`,
  `strict-transport-security`, `x-content-type-options`,
  `access-control-allow-origin`, `x-xss-protection`.
- **Body cap** — response bodies are truncated to the effective cap (default
  20,000 chars; derived from `context_budget / 6` when set).

### Truncation

After parsing, output that still exceeds `max_output_chars` (or
`context_budget / 4` when set) is truncated with a 70/30 split: the first
70% of chars and last 30% are kept, with a marker in between showing how many
chars were omitted.

---

## Session Features

### Cookie Jar

The `http_request` tool maintains a shared cookie jar that persists across
requests within the same server session. This enables authenticated workflows:

1. Send a login request via `http_request` (cookies are captured automatically).
2. Subsequent `http_request` calls to the same domain include the session cookies.
3. Session cookies are displayed in the response under `--- Session Cookies ---`.

**Important:** Subprocess tools (sqlmap, nikto, feroxbuster, ffuf, nuclei,
whatweb) run as separate processes and do **not** share the cookie jar. Pass
cookies explicitly via each tool's `cookie` parameter for authenticated scanning.

### Scan Spill-to-Disk

Background scans (`launch_scan`) keep output in memory by default. When a
scan's output exceeds **1 MB** (1,048,576 bytes), it is automatically spilled
to disk at `{output_dir}/scans/{scan_id}.txt`. This prevents memory exhaustion
from large scan outputs (e.g. full nuclei runs) while keeping small outputs
fast. The `get_scan_results` tool reads from disk transparently when needed,
supporting the same pagination interface.

### Auto-Inline Small Outputs

When `get_scan_status` is called on a completed scan, if the output is under
10,000 characters, it is included directly in the status response. This saves
a follow-up `get_scan_results` call for quick scans.

### Localhost Thread Reduction

When scanning `localhost`, `127.0.0.1`, or `[::1]`, thread-heavy tools
automatically reduce their default concurrency to prevent self-DoS:

| Tool | Default threads | Localhost threads | Max threads |
|------|----------------|------------------|-------------|
| feroxbuster | 50 | 10 | 200 |
| ffuf | 40 | 10 | 150 |

This only affects the default — explicit `threads` values are still honoured
(up to the max).

---

## Example Workflow

### Basic Reconnaissance

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

### Authenticated Scanning

```
You: "Log in to http://target.example.com/login with admin:password"
Assistant: [calls http_request with url, method: "POST",
           body: "username=admin&password=password"]
→ Session cookies are captured automatically.

You: "Now scan the authenticated area for SQL injection"
Assistant: [reads session cookie from http_request response]
           [calls run_sqlmap with target: "http://target.example.com/search?q=test",
            cookie: "PHPSESSID=abc123"]
→ Cookie passed explicitly because sqlmap runs as a subprocess.

You: "Run nikto against the same target"
Assistant: [calls run_nikto with target: "http://target.example.com",
            cookie: "PHPSESSID=abc123"]
→ Same cookie passed to nikto for authenticated scanning.
```
