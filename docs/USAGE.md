# Raven Nest MCP - Usage Guide

## Prerequisites

### Run with Docker (skips host-tool install)

The published image bundles `raven-server` and all 22 tools - see the
[README Quick Start](../README.md#run-with-docker-recommended). The host-tool
setup below is only needed for a from-source install.

### Build

```bash
git clone https://github.com/tidynest/raven-nest-mcp.git
cd raven-nest-mcp
cargo build --release
```

The binary is at `target/release/raven-server`.

### Host Tools

Install the scanning tools you want to use. All are optional - the server
starts regardless, but tool calls will fail if the binary isn't installed.

```bash
# Core tools (official repos - Arch Linux)
sudo pacman -S nmap nikto whatweb testssl.sh sqlmap hydra masscan wpscan john gitleaks

# AUR tools
yay -S feroxbuster-bin ffuf-bin enum4linux-ng dalfox-bin trufflehog-bin

# Go tools (ProjectDiscovery) - nuclei, subfinder, httpx, dnsx, katana
# go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# go install github.com/projectdiscovery/katana/cmd/katana@latest
# After install, update nuclei templates: nuclei -ut

# Python tools
# pip install dnsrecon
# pipx install netexec    # provides the `nxc` binary - gated, off by default
```

`ping` is available by default on all Linux systems.

> **Arch note:** The `testssl.sh` package installs the binary as `testssl`.
> If the tool config references `testssl.sh`, create a symlink:
> `sudo ln -s /usr/bin/testssl /usr/bin/testssl.sh`

### Wordlists

`feroxbuster` and `ffuf` default to [SecLists](https://github.com/danielmiessler/SecLists)
wordlists. Install them for fuzzing to work out of the box:

```bash
# Arch Linux
sudo pacman -S seclists

# Debian/Ubuntu
sudo apt install seclists

# Manual (any distro)
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

Default wordlist paths:
- **feroxbuster** - `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- **ffuf** - `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`

You can override these per-call via the `wordlist` parameter.

---

## Connecting to an MCP Client

The server communicates over stdio - stdout carries JSON-RPC, logs go to stderr.

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
hyphens - many local models struggle with tool names containing hyphens:

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

For small-context models (32K-64K), set `context_budget` in the config -
see the [Configuration](#configuration) section.

---

## Configuration

Edit `config/default.toml` to customise behaviour. The config file has these
sections: `[safety]`, `[scope]`, `[execution]`, `[network]`, `[metasploit]`, and
`[netexec]`.

### Config Resolution Chain

The server searches for config in this order, using the first one found:

1. **`RAVEN_CONFIG` env var** - explicit file path (e.g. `RAVEN_CONFIG=/etc/raven.toml`)
2. **Exe-relative** - `config/default.toml` relative to the binary (checks parent dir too, for `target/release/` layouts)
3. **CWD** - `config/default.toml` in the current working directory
4. **Built-in defaults** - hardcoded fallback if nothing else is found

If all fail, the server starts with safe defaults (all tools allowed, 600s
timeout, output at `/tmp/raven-nest`).

### `[safety]` - Tool Allowlisting and Limits

```toml
[safety]
allowed_tools = [
    "ping", "nmap", "nuclei", "nikto", "whatweb",
    "testssl.sh", "feroxbuster", "ffuf",
    "sqlmap", "hydra", "masscan",
    "subfinder", "wpscan", "enum4linux-ng",
    "dalfox", "dnsrecon", "john",
    "httpx", "dnsx", "katana",
    "nxc", "gitleaks", "trufflehog",
]
max_output_chars = 50000
# context_budget = 65536
# expected_tool_calls = 10

# Auto-save findings extracted from scan output (8 scanners - see table). Opt-in.
# auto_save_findings = false
# auto_save_min_severity = "medium"   # info|low|medium|high|critical
# auto_save_max_per_scan = 25

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
| `allowed_tools` | string list | all tools | Allowlisted tool binaries. Calls for unlisted tools are rejected before execution. Remove tools to restrict what the AI can invoke. |
| `max_output_chars` | integer | 50000 | Truncation limit for subprocess output. When exceeded, keeps 70% from the start and 30% from the end with a marker in between. Uses char boundaries for UTF-8 safety. Overridden by `context_budget` when set. |
| `context_budget` | integer | 0 (disabled) | Model context window size in characters. When > 0, derives output caps automatically so ~4 tool outputs fit in the context. See table below. |
| `sqlmap_max_level` | integer (1-5) | 2 | Caps sqlmap `--level`. Higher levels add more injection vectors but are slower and noisier. |
| `sqlmap_max_risk` | integer (1-3) | 1 | Caps sqlmap `--risk`. Risk 2+ may cause data modification; risk 3 adds OR-based payloads. |
| `hydra_max_tasks` | integer | 4 | Max parallel threads for hydra brute-forcing. Prevents account lockout and network saturation. |
| `masscan_max_rate` | integer | 1000 | Max packets/sec for masscan. High rates can disrupt networks - increase only with explicit authorisation. |
| `tool_paths` | table | empty | Map of tool name to absolute binary path, for tools not on `$PATH`. Falls back to `$PATH` lookup if not specified. |
| `sudo_tools` | string list | `[]` | Tools invoked via `sudo` for privilege escalation. See [sudo_tools](#sudo_tools--privilege-escalation) below. |
| `expected_tool_calls` | integer | 10 | Expected tool calls per session. Used by the session budget tracker to plan per-call output allocation. Higher values yield smaller per-call caps. Typical pentest: 6-12 calls. |
| `auto_save_findings` | bool | `false` | Auto-extract findings from scan output (nmap, nuclei, nikto, dalfox, sqlmap, testssl, gitleaks, trufflehog) into the finding store. Opt-in. |
| `auto_save_min_severity` | string | `medium` | Minimum severity an auto-extracted finding must meet to be saved (`info`-`critical`). |
| `auto_save_max_per_scan` | integer | 25 | Cap on auto-extracted findings saved per scan. |

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
at 0 (disabled) for Claude or other large-context models - `max_output_chars`
alone handles truncation fine.

#### Session Budget Tracker

When `context_budget` is set, the server tracks cumulative output across the
entire session and dynamically adjusts per-tool caps. This prevents context
overflow during multi-tool pentest sessions.

The tracker appends a status line to every tool response:
```
[budget: 4200/38500 used | ~3430/call | mode: full]
```

Three output modes escalate automatically as the budget is consumed:

| Mode | Trigger | Behaviour |
|------|---------|-----------|
| **Full** | >60% budget remaining | Normal parsed output, all findings and details |
| **Compact** | 30-60% remaining | Output truncated more aggressively per tool |
| **Minimal** | <30% remaining | Output heavily compressed |

**Hard safety floor:** Below 1,000 chars remaining, the server refuses new
tool calls and returns: "Context budget exhausted. Save findings and generate
report."

The `expected_tool_calls` setting controls how the budget is divided. With
`expected_tool_calls = 10`, the tracker assumes 10 total calls and allocates
accordingly. If you typically run longer sessions, increase this value.

#### Parser Result Caps

Output parsers cap results to prevent any single tool from consuming excessive
context, regardless of the budget tracker. These caps are dynamically scaled by
the budget system (Full = 100%, Compact = 50%, Minimal = 25%, minimum 3):

| Parser | Max results (Full mode) | Overflow |
|--------|-------------------------|----------|
| nuclei | 25 findings | "+N more finding(s)" |
| nikto | 30 findings | "+N more finding(s)" |
| feroxbuster | 40 URLs | "+N more URL(s)" |
| ffuf | 40 results | "+N more result(s)" |
| masscan | 50 ports | "+N more port(s)" |
| nmap | 10 hosts | "(+N more hosts)" |
| subfinder | 50 subdomains | "+N more" |
| wpscan | 20 plugins, 10 users | truncated with count |
| enum4linux-ng | 20 items per section | truncated per section |
| dalfox | 20 XSS findings | "+N more" |
| dnsrecon | 30 DNS records | "+N more" |
| httpx | 30 results | "+N more" |
| dnsx | 30 records | "+N more" |
| katana | 40 endpoints | "+N more" |

These caps are applied before the budget tracker's per-call enforcement.

#### `sudo_tools` - Privilege Escalation

Some tools require root privileges:
- **masscan** - raw socket access for SYN scanning
- **nmap** with `scan_type: "os"` - raw sockets for OS fingerprinting

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

Edit the username and paths in the sudoers file for your environment.

### `[scope]` - Engagement Authorization

Off by default - any syntactically valid target may be scanned. When
`enabled = true`, `validate_target` (the chokepoint every tool and the scan
launcher share) requires each target to match an allowed entry **and** not match
a denied entry (deny wins). Loopback is always allowed unless `allow_localhost = false`.

```toml
# [scope]
# enabled = true
# allowed_cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
# allowed_domains = ["example.com"]          # matches the domain and its subdomains
# denied_cidrs = ["169.254.169.254/32"]      # e.g. cloud metadata endpoint
# denied_domains = []
# allow_localhost = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. When false, no scope checks run. |
| `allowed_cidrs` | string list | `[]` | Permitted IP ranges. A target IP must fall within one. |
| `allowed_domains` | string list | `[]` | Permitted domains; matches the domain and its subdomains. |
| `denied_cidrs` | string list | `[]` | Blocked IP ranges (deny wins over allow). |
| `denied_domains` | string list | `[]` | Blocked domains (deny wins over allow). |
| `allow_localhost` | bool | `true` | Allow loopback (`localhost`, `127.0.0.0/8`, `::1`) regardless of the allowlists. |

### `[execution]` - Timeouts, Concurrency, Output

```toml
[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/tmp/raven-nest"
# max_concurrent_execs = 4      # cap on parallel synchronous run_* executions
# scan_retention_secs = 3600    # seconds a finished scan is kept before eviction
# min_exec_gap_ms = 0           # proactive cooldown between tool launches (0 = off)

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
| `max_concurrent_execs` | integer | 4 | Cap on concurrent synchronous tool executions (`run_*`). Separate from `max_concurrent_scans`; bounds parallel subprocesses an agent can spawn. |
| `scan_retention_secs` | integer | 3600 | Seconds to retain a finished background scan (and its spilled output) before eviction from the registry. |
| `min_exec_gap_ms` | integer | 0 | Proactive cooldown: minimum milliseconds between consecutive tool launches (process-wide). Spaces out back-to-back aggressive tools so they don't trip a target's WAF/rate-limiter. 0 disables; max 60000. Complements the reactive WAF detection. |

**When to change timeouts:** Vulnerability scans (`nuclei`, `nikto`, `testssl.sh`)
and OS detection (`nmap -O`) can take several minutes on large targets. Increase
their specific timeouts rather than raising the global default.

### `[network]` - Proxy Configuration

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

### `[metasploit]` - Metasploit Framework Integration

Disabled by default. See [docs/METASPLOIT.md](METASPLOIT.md) for full setup.

```toml
[metasploit]
enabled = true
host = "127.0.0.1"
port = 55553
username = "msf"
password = "changeme"    # CHANGE THIS
ssl = true
max_search_results = 20
max_concurrent_exploits = 1
require_confirmation = true
# blocked_modules = ["exploit/multi/misc/msf_rpc_console"]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch - MSF tools only registered when true |
| `host` | string | `127.0.0.1` | msfrpcd host |
| `port` | integer | `55553` | msfrpcd port |
| `username` | string | `msf` | RPC username |
| `password` | string | `changeme` | RPC password - **change this** |
| `ssl` | bool | `true` | Use SSL (msfrpcd default) |
| `max_search_results` | integer | `20` | Cap module search results |
| `max_concurrent_exploits` | integer | `1` | Max simultaneous exploit executions |
| `require_confirmation` | bool | `true` | Require double-call to execute exploits |
| `blocked_modules` | string list | `[]` | Regex patterns for blocked modules |

### `[netexec]` - Credentialed Enumeration (Gated)

Disabled by default. The `run_netexec` tool refuses to run unless
`enabled = true`. Even when enabled it permits only **read-only enumeration**
(auth, shares, users, groups, loggedon, sessions, disks, pass-pol) against a
**single host** with a **single scalar credential** - no command/module
execution, no credential lists or spraying, no CIDR ranges. Requires the `nxc`
binary on `PATH` (or set `[safety.tool_paths].nxc`).

```toml
# [netexec]
# enabled = true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch - `run_netexec` returns an error when false. |

---

## Tools Reference

The server exposes all 43 tools regardless of configuration. The 6 Metasploit
tools and `run_netexec` are always listed, but they are gated at call time:
each returns a clear "disabled" error unless enabled (`[metasploit] enabled = true`
or `[netexec] enabled = true`), rather than being hidden from the tool list.

### Tool Timing Overview

| Category | Tools | Expected Duration |
|----------|-------|-------------------|
| **Fast** (1-5s) | `ping_target`, `run_whatweb`, `http_request`, `run_ffuf`, `run_masscan`, `run_subfinder`, `run_httpx`, `run_dnsx`, `run_dalfox` | Immediate results |
| **Medium** (5-30s) | `run_nmap` (quick/service), `run_wpscan`, `run_dnsrecon`, `msf_search`, `msf_module_info` | Wait for completion |
| **Slow** (30-300s) | `run_nmap` (os/vuln), `run_nuclei`, `run_nikto`, `run_testssl`, `run_feroxbuster`, `run_katana`, `run_sqlmap`, `run_hydra`, `run_enum4linux_ng`, `run_john`, `run_gitleaks`, `run_trufflehog`, `run_netexec`, `msf_exploit` | Consider `launch_scan` for background execution |

---

### Utility

#### `ping_target`
Verify target connectivity and measure latency. Typically the first tool in a session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | IP address or hostname |
| `count` | integer | no | Number of ICMP packets, 1-10 (default 4) |

#### `http_request`
Send crafted HTTP requests for manual endpoint testing. Cookies are
automatically persisted across requests within the same session via a shared
cookie jar (see [Session Features](#session-features)).

HTML responses are automatically stripped of tags, scripts, and styles, with
entity decoding applied. Only security-relevant headers are shown in the
response (see [Output Processing](#output-processing)).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | Full URL (`http://` or `https://` only) |
| `method` | string | no | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` (default `GET`) |
| `headers` | object | no | Request headers as key-value pairs |
| `body` | string | no | Request body string |
| `auth_token` | string | no | Bearer token for Authorization header |
| `timeout_secs` | integer | no | Timeout in seconds (default 30, max 120) |
| `follow_redirects` | boolean | no | Follow redirects (default true) |

---

### Reconnaissance

#### `run_nmap`
Port scanning and service detection. Output is parsed from nmap's XML format
into a structured summary (host addresses, port states with service/version,
NSE script results per port and host-level, OS detection matches, run stats).
For `vuln` scans, the `vulners` script output is compressed to the top 5 CVEs
by CVSS score; other scripts are summarised to single-line entries.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | IP, hostname, or CIDR range |
| `ports` | string | no | Port spec (e.g. `80,443` or `1-1000`) |
| `scan_type` | string | no | `quick` (default), `service`, `os`, `vuln` |

Scan type presets:
- **quick** - `-T4 -F` (top 100 ports, aggressive timing). When `ports` is specified, `-F` is omitted.
- **service** - `-sV` (version detection)
- **os** - `-O` (OS fingerprinting, requires root or `sudo_tools` config)
- **vuln** - `-sV --script=vuln` (vulnerability scripts)

#### `run_whatweb`
Identify web technologies (CMS, frameworks, server software). Output is parsed
to extract technology identification lines with bracket-notation tags.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | URL or hostname |
| `aggression` | string | no | `stealthy` (default, level 1), `passive` (level 2), `aggressive` (level 4) |
| `cookie` | string | no | Cookie string for authenticated scanning (e.g. `PHPSESSID=abc123`) |

#### `run_masscan`
High-speed port scanning. Requires root or `sudo_tools` config - returns an
error if neither is available. Output is parsed to extract discovered open ports.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | IP, hostname, or CIDR range (e.g. `10.0.0.0/24`) |
| `ports` | string | yes | Port spec (e.g. `80,443` or `0-65535`) |
| `rate` | integer | no | Packets/sec (clamped to `masscan_max_rate` config, default 100) |

> **Limitation:** masscan uses raw SYN packets that bypass the kernel TCP
> stack. It **cannot scan localhost** (`127.0.0.1`) or Docker bridge IPs
> (`172.17.x.x`) - the kernel short-circuits loopback traffic, and Docker's
> iptables NAT rules don't apply to raw packets. Use nmap for local/Docker
> targets. masscan works correctly against targets on real network interfaces.

#### `run_subfinder`
Passive subdomain enumeration via certificate transparency logs, DNS databases,
and search engine scraping. Does not actively probe the target - purely passive.
Output is parsed from JSONL format into `host (source)` lines.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Domain to enumerate (e.g. `example.com`) |
| `sources` | string | no | Comma-separated source filter (e.g. `crtsh,hackertarget`) |
| `timeout_secs` | integer | no | Scan timeout in seconds |

> **Internet access required:** subfinder queries online APIs (crt.sh,
> HackerTarget, etc.). It won't find subdomains for purely local targets.

#### `run_dnsrecon`
DNS enumeration with support for standard lookups, zone transfers, and SRV
record discovery. Output is parsed from JSON format into `TYPE NAME VALUE`
record lines.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Domain to enumerate |
| `scan_type` | string | no | `standard` (default), `zone_transfer`, `srv` |
| `timeout_secs` | integer | no | Timeout in seconds |

#### `run_httpx`
HTTP/HTTPS prober and fingerprinter. Probes a host or URL for live web services,
status codes, titles, technologies, and TLS details. Output is parsed into
compact per-URL lines.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | URL or host to probe |
| `scan_type` | string | no | `probe` (default), `fingerprint`, `full` |
| `timeout_secs` | integer | no | Timeout in seconds |

#### `run_dnsx`
Fast DNS resolver and record toolkit. Resolves A/AAAA and queries record types
(MX, NS, TXT, CNAME, etc.). Output is parsed into record lines.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Domain to resolve |
| `scan_type` | string | no | `resolve` (default), `records`, `recon` |
| `timeout_secs` | integer | no | Timeout in seconds |

#### `run_enum4linux_ng`
SMB and Active Directory enumeration. Discovers shares, users, groups,
password policies, and OS information. Useful for internal pentests against
Windows/Samba environments. Uses `-A` (all simple enumeration) by default.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Target IP or hostname |
| `username` | string | no | SMB username for authenticated enumeration |
| `password` | string | no | SMB password |
| `timeout_secs` | integer | no | Scan timeout in seconds |

Output is parsed into sections: OS info, shares, users, groups, and password
policy. Each section is capped at 20 items.

---

### Web Scanning

#### `run_nuclei`
Template-based vulnerability scanning. Output is parsed from JSONL format into
compact lines: `[SEVERITY] template-id - name @ url (type)`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | URL or hostname |
| `severity` | string | no | Severity filter: `info`, `low`, `medium`, `high`, `critical` |
| `tags` | string | no | Template tags to include (e.g. `cve,oast`) |
| `cookie` | string | no | Cookie string for authenticated scanning (e.g. `PHPSESSID=abc123`) |

#### `run_nikto`
Web server misconfiguration scanner. Output is parsed to extract finding lines
(prefixed with `+`), filtering out help text.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Hostname or URL |
| `port` | integer | no | Port number (default 80). Ignored when `target` is a full URL. |
| `tuning` | string | no | `quick` (default), `thorough`, `injection`, `fileupload` |
| `cookie` | string | no | Cookie string for authenticated scanning (e.g. `PHPSESSID=abc123`) |
| `timeout_secs` | integer | no | Scan timeout in seconds (default 600) |

Tuning presets map to nikto's `-T` flag:
- **quick** - `-T 1234` (interesting files, misconfigs, info disclosure, XSS)
- **thorough** - `-T 123456789abc` (all test categories)
- **injection** - `-T 9` (SQL/command injection tests)
- **fileupload** - `-T 0` (file upload tests)

> **URL vs hostname:** When `target` is a full URL (starts with `http://`),
> the `port` parameter is ignored - nikto v2.6+ rejects the `-p` flag when
> given a URL. Use the port in the URL instead (e.g. `http://localhost:3000`).
> When `target` is a bare hostname, `-p` is added automatically. Port 443
> automatically enables SSL.

#### `run_wpscan`
WordPress vulnerability scanner. Enumerates plugins, themes, and users, then
cross-references against the WPVulnDB vulnerability database. Output is parsed
from JSON into a structured summary of versions, vulnerabilities, and users.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | WordPress site URL |
| `enumerate` | string | no | `quick` (default) or `thorough` |
| `api_token` | string | no | WPVulnDB API token for full vulnerability data |
| `cookie` | string | no | Cookie string for authenticated scanning |

Enumerate presets:
- **quick** - `--enumerate vp,vt,u` (vulnerable plugins, vulnerable themes, users)
- **thorough** - `--enumerate vp,vt,u,ap,at,cb,dbe` (all plugins, all themes, users, config backups, DB exports)

> **API token:** Without a WPVulnDB API token, wpscan still identifies
> versions and plugins but cannot look up their known vulnerabilities.
> Register at https://wpscan.com/ for a free API key.

#### `run_dalfox`
XSS vulnerability scanning via parameter analysis and injection testing. Output
is parsed from JSON into compact finding lines with injection type, parameter,
and payload.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | URL to test for XSS |
| `parameters` | string | no | Comma-separated parameter names to test (e.g. `q,search`) |
| `cookie` | string | no | Cookie string for authenticated scanning |
| `timeout_secs` | integer | no | Timeout in seconds |

#### `run_testssl`
SSL/TLS configuration audit. Output is parsed to extract vulnerability
assessments, certificate details (CN, SAN, issuer, expiry, trust, CT), and
overall rating.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Hostname, host:port, or URL |
| `quick` | boolean | no | Quick mode (`--quiet --sneaky`, fewer checks) |
| `severity` | string | no | Minimum severity to report: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

The `severity` parameter accepts any case (`high`, `HIGH`, `High`) and is
normalised internally. Invalid values are silently ignored.

> **Non-TLS targets:** If the target has no TLS service, testssl returns
> minimal output or a connection error. This is expected - the tool is
> designed for TLS analysis only.

---

### Web Fuzzing and Discovery

#### `run_feroxbuster`
Directory brute-forcing / content discovery. Output is parsed to extract
status-code + URL pairs, filtering out 404 responses.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Target URL (e.g. `http://example.com`) |
| `wordlist` | string | no | Path to wordlist (default: raft-medium-directories.txt) |
| `extensions` | string | no | File extensions to check (e.g. `php,html,js`) |
| `threads` | integer | no | Concurrent threads (default 50; 10 for localhost; max 200) |
| `status_codes` | string | no | HTTP status codes to include (e.g. `200,301,403`) |
| `cookie` | string | no | Cookie string for authenticated scanning (e.g. `PHPSESSID=abc123`) |

#### `run_ffuf`
Web fuzzing with FUZZ keyword substitution. The URL must contain the `FUZZ`
keyword - requests are rejected without it. Output is parsed to extract result
lines containing status codes, sizes, and word counts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | URL containing `FUZZ` keyword (e.g. `http://example.com/FUZZ`) |
| `wordlist` | string | no | Path to wordlist (default: raft-medium-words.txt) |
| `method` | string | no | HTTP method (default `GET`) |
| `headers` | string | no | Custom headers (comma-separated `Name: Value` pairs) |
| `match_codes` | string | no | Match HTTP status codes (e.g. `200,301,302`) or `all`. Defaults to `200,204,301,302,307,401,403,405,500` - pinned so results don't depend on ffuf's version-specific default (which narrowed to 2XX, hiding redirects and 401/403). |
| `filter_size` | string | no | Filter responses by size in bytes |
| `threads` | integer | no | Concurrent threads (default 40; 10 for localhost; max 150) |
| `cookie` | string | no | Cookie string for authenticated fuzzing (e.g. `PHPSESSID=abc123`) |

#### `run_katana`
Web crawler and endpoint discovery. Crawls a target to enumerate URLs, forms,
and JavaScript endpoints. Output is parsed into a deduplicated endpoint list.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | URL to crawl |
| `scan_type` | string | no | `passive`, `standard` (default), `deep` |
| `depth` | integer | no | Crawl depth, 1-5 (default 3) |
| `timeout_secs` | integer | no | Timeout in seconds |

---

### Exploitation

#### `run_sqlmap`
SQL injection testing. Always runs in `--batch` mode (non-interactive). Output
is parsed to extract injection points (parameter/type/title/payload), DBMS
info, and critical errors. Non-injectable verdicts are preserved.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | URL with injectable parameter |
| `data` | string | no | POST body data (e.g. `user=test&pass=test`) |
| `cookie` | string | no | Cookie string for authenticated testing |
| `level` | integer | no | Test level 1-5 (default 1, clamped to `sqlmap_max_level` config) |
| `risk` | integer | no | Risk level 1-3 (default 1, clamped to `sqlmap_max_risk` config) |
| `technique` | string | no | SQL injection techniques: `B`oolean, `E`rror, `U`nion, `S`tacked, `T`ime, `Q`uery (e.g. `BEUSTQ`) |

#### `run_hydra`
Authentication brute-forcing. Stops on first valid credential (`-f` flag).
Output is parsed to extract discovered credentials and the summary line.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | yes | Target IP or hostname |
| `service` | string | yes | Service to attack (e.g. `ssh`, `ftp`, `http-post-form`) |
| `port` | integer | no | Target port (default: service default) |
| `userlist` | string | yes | Path to username list file |
| `passlist` | string | yes | Path to password list file |
| `tasks` | integer | no | Parallel tasks (default 4, clamped to `hydra_max_tasks` config) |
| `form_params` | string | conditional | Form attack string for `http-post-form`/`http-get-form`. **Required** when service is a form type. Format: `/login:user=^USER^&pass=^PASS^:F=incorrect` |

---

### Password Cracking

#### `run_john`
John the Ripper password hash cracking. Runtime is capped via `--max-run-time`
to prevent runaway sessions. Output is parsed to extract cracked credentials
and session status.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hash_file` | string | yes | Path to hash file (shell metacharacters rejected) |
| `wordlist` | string | no | Path to wordlist file |
| `format` | string | no | Hash format (e.g. `raw-md5`, `bcrypt`, `sha512crypt`) |
| `max_run_time` | integer | no | Max runtime in seconds (default 300, max 600) |

---

#### `run_gitleaks`
Scan a directory's working tree or a git repo's full commit history for
committed secrets (API keys, tokens, private keys) via gitleaks. The scan path
is confined to the configured output directory (same gate as `run_john`), so
clone target repos into the engagement workspace first. Secret values are
redacted by default and never echoed in the summary - only the rule id and
`file:line` (plus short commit, in history mode) are returned. Exit code 1
(secrets found) is treated as success, not an error.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Directory or git repo to scan (must be under the output directory) |
| `scan_git_history` | boolean | no | Scan full git commit history instead of the working tree (default false) |
| `show_secrets` | boolean | no | Reveal secret values instead of redacting them (default false) |

---

#### `run_trufflehog`
Scan a directory tree for secrets via trufflehog. Unlike gitleaks it can
*verify* a secret by testing it against its live API - this is **off by
default** because verification makes outbound calls to third-party services
with discovered credentials; enable `verify` only when that is in scope. Path
is confined to the output directory (same gate as `run_john`). Secret values
are never echoed in the summary - only the detector name and `file:line`.

> **Safety:** this handler never passes `--trust-local-git-config`
> (CVE-2025-41390 RCE); it scans the working tree only.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Directory to scan (must be under the output directory) |
| `verify` | boolean | no | Verify secrets against their live APIs - makes outbound calls with found credentials (default false) |

---

### NetExec (Gated)

Disabled by default - see [`[netexec]`](#netexec--credentialed-enumeration-gated).
Read-only, single-host, single-credential enumeration only.

#### `run_netexec`
Authenticate to a host and run a read-only enumeration action via NetExec
(`nxc`). Refuses to run unless `netexec.enabled = true`. Rejects CIDR ranges,
credential lists/files, and any command/module execution.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `protocol` | string | yes | `smb`, `winrm`, `ssh`, `ldap`, `mssql`, `ftp`, `rdp` |
| `target` | string | yes | Single host or IP (no CIDR ranges) |
| `username` | string | yes | Username (single value, not a list or file) |
| `password` | string | conditional | Password (single). Provide `password` **or** `hash`, not both. |
| `hash` | string | conditional | NTLM hash for pass-the-hash (single). Provide `password` **or** `hash`. |
| `action` | string | no | Read-only action: `auth` (default), `shares`, `users`, `groups`, `loggedon`, `sessions`, `disks`, `pass-pol` |

---

### Metasploit Framework

Metasploit integration is **disabled by default** and requires a running
`msfrpcd` instance. See [docs/METASPLOIT.md](METASPLOIT.md) for full setup,
safety model, and troubleshooting.

#### `msf_search`
Search for exploit, auxiliary, and post-exploitation modules. Results show
module path, rank, and description.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g. `cve:2021-44228`, `type:exploit smb`) |
| `limit` | integer | no | Max results (default 20) |

#### `msf_module_info`
Get details about a module - description, references (CVEs, EDB IDs), required
options with defaults, and compatible payloads (for exploit modules, top 5).
Module type is inferred from the path prefix.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | string | yes | Module path (e.g. `exploit/multi/http/log4shell_header_injection`) |

#### `msf_exploit`
Execute an exploit module. When `require_confirmation` is enabled (default),
the first call shows a plan summary. Calling again with identical parameters
executes the exploit. Polls for completion with exponential backoff and reports
any new sessions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | string | yes | Exploit module path |
| `target` | string | yes | Target host or IP (validated against allowlist) |
| `port` | integer | no | Target port (sets RPORT) |
| `payload` | string | no | Payload module (auto-selects if omitted) |
| `lhost` | string | no | Listener host for reverse payloads (sets LHOST) |
| `lport` | integer | no | Listener port for reverse payloads (default 4444, sets LPORT) |
| `options` | object | no | Additional module options as key-value pairs (cannot override RHOSTS) |

#### `msf_auxiliary`
Run auxiliary modules (scanners, fuzzers). Polls for completion with
exponential backoff.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | string | yes | Auxiliary module path |
| `target` | string | yes | Target host, IP, or CIDR (validated, sets RHOSTS) |
| `port` | integer | no | Target port (sets RPORT) |
| `options` | object | no | Additional module options as key-value pairs (cannot override RHOSTS) |

#### `msf_sessions`
Manage active Metasploit sessions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | yes | `list`, `interact`, `stop`, `compatible_modules` |
| `session_id` | integer | conditional | Session ID. Required for `interact`, `stop`, `compatible_modules`. |
| `command` | string | conditional | Command to execute. Required for `interact`. |

Actions:
- **list** - show all active sessions with type, tunnel, and platform
- **interact** - run a command in a session (output read after 2s delay, max 4096 chars)
- **stop** - terminate a session
- **compatible_modules** - list post modules compatible with a session (top 20)

Blocked session commands: `rm`, `del`, `format`, `mkfs`, `dd`, `shutdown`,
`reboot`, `halt`, `poweroff`, `upload`.

#### `msf_post`
Run post-exploitation modules on an active session. Polls for completion with
exponential backoff.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `module` | string | yes | Post module path (e.g. `post/multi/gather/env`) |
| `session_id` | integer | yes | Session ID to run on (sets SESSION) |
| `options` | object | no | Additional module options as key-value pairs |

---

### Scan Management

For long-running scans, use the launch/poll pattern. A scan transitions
through these states:

```
launch_scan -> Running -> Completed (success)
                       -> Failed (non-zero exit or timeout)
             cancel_scan -> Cancelled
```

The server enforces a concurrency cap (default 3, set via
`max_concurrent_scans`). Launching a scan when all slots are occupied
returns an error - cancel or wait for a running scan to finish first.

During execution, the server sends progress notifications every 15 seconds
to keep the MCP client informed.

#### `launch_scan`
Start a scan in the background, returns a scan ID immediately. The target is
validated and the tool is checked against the allowlist before launching.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool` | string | yes | Any allowlisted tool name (e.g. `nmap`, `nuclei`, `nikto`, `whatweb`) |
| `target` | string | yes | Target IP, hostname, or URL |
| `timeout_secs` | integer | no | Scan timeout in seconds (default from config, typically 600) |

Each tool uses safe preset arguments (e.g. sqlmap `--batch --level 1 --risk 1`,
nmap `-T4 -F -oX -`). Custom arguments are not accepted - use the dedicated
tool handlers (e.g. `run_nmap`, `run_sqlmap`) for fine-grained control.

#### `get_scan_status`
Check whether a scan is Running, Completed, Failed, or Cancelled.
Completed scans with output under 10K chars include the output inline
(auto-inline), saving a follow-up `get_scan_results` call.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | string | yes | ID returned by `launch_scan` |

#### `get_scan_results`
Fetch output from a completed scan with character-based pagination.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | string | yes | ID returned by `launch_scan` |
| `offset` | integer | no | Character offset to start reading from (default 0) |
| `limit` | integer | no | Max characters to return (default 10000) |

#### `cancel_scan`
Cancel a running scan by aborting its background task.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | string | yes | ID returned by `launch_scan` |

#### `list_scans`
List all scans and their current status. No parameters.

---

### Findings and Reports

#### `save_finding`
Record a vulnerability finding. Each finding is stored as an individual JSON file
under `{output_dir}/findings/` and indexed in memory for fast listing. There is no
hard cap on finding count - the store scales to tens of thousands of findings with
bounded memory (only metadata is kept in RAM; full data lives on disk).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `title` | string | yes | Finding title |
| `severity` | string | yes | `critical`, `high`, `medium`, `low`, `info` |
| `description` | string | yes | Detailed description of the vulnerability |
| `target` | string | yes | Affected target (IP, URL, hostname) |
| `tool` | string | yes | Tool that discovered this finding |
| `evidence` | string | no | Raw output excerpt as evidence |
| `remediation` | string | no | Suggested remediation steps |
| `cvss` | float | no | CVSS score (0.0-10.0) |
| `cve` | string | no | CVE identifier (e.g. `CVE-2024-1234`) |
| `owasp_category` | string | no | OWASP Top 10 category (e.g. `A03:2021 Injection`) |
| `scan_id` | string | no | Originating scan ID (UUID) - links the finding to a launched scan; recall via `list_findings_by_scan` |

#### `get_finding`
Retrieve full details of a finding as JSON.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `finding_id` | string | yes | Finding ID |

#### `list_findings`
List all findings sorted by severity (Critical first). No parameters.
Returns `ID | [Severity] Title` for each finding.

#### `list_findings_by_scan`
List findings linked to a specific scan ID (set via `save_finding`'s `scan_id`).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | string | yes | Scan ID (UUID) to list findings for |

#### `delete_finding`
Remove a finding. The individual file is deleted from disk and the index is updated.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `finding_id` | string | yes | Finding ID |

#### `generate_report`
Generate a pentest report from all saved findings. Markdown (default) and HTML
include a table of contents, methodology section, tools used, a scope & timeline
section (assessed targets and the engagement window), OWASP category mapping,
findings grouped by severity, and a generation timestamp; JSON and SARIF are
structured envelopes, also available via `format`. The report is automatically saved to
`{output_dir}/report-{timestamp}.{ext}` (extension per format). Returns a brief
summary (finding count by severity) instead of the full report to conserve context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `title` | string | no | Report title (default "Penetration Test Report") |
| `format` | string | no | `markdown` (default), `json`, `sarif`, `html` |

> **Persistence:** Findings are stored as individual JSON files at
> `{output_dir}/findings/{uuid}.json` and survive server restarts. The
> server loads all existing findings from disk on startup. Reports are
> written to `{output_dir}/report-{timestamp}.{ext}` and are never deleted
> automatically. With an active engagement, findings and reports are scoped to
> `{output_dir}/engagements/{name}/` instead (see [Engagement](#engagement)).

### Engagement

Engagements scope findings and reports to a per-client/per-target subdirectory,
so separate jobs don't co-mingle. Switching is filesystem-backed - the active
engagement's findings live under `{output_dir}/engagements/{name}/findings/` and
its reports alongside.

#### `set_engagement`
Switch the active engagement, creating it on first use. Subsequent
`save_finding` / `generate_report` calls scope to it.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Engagement name (letters, digits, `-`, `_`, `.`) |

#### `list_engagements`
List all engagements and show which is active. No parameters.

## MCP Resources

Alongside the tools, the server exposes read-only resources under the `raven://`
scheme, so a resource-aware client can browse or attach data without a tool call.

| URI | Contents |
|-----|----------|
| `raven://findings` | JSON index of every saved finding |
| `raven://findings/{id}` | a single finding as JSON |
| `raven://reports/{format}` | a report rendered on demand (`markdown`, `json`, `sarif`, `html`) |
| `raven://scans` | JSON index of background scans |
| `raven://scans/{id}` | a scan's captured output |

Each saved finding and tracked scan is also listed individually. Resources are a
read-only view over the same `FindingStore` and `ScanManager` the tools use, not
a separate store, so they reflect the active engagement's findings.

---

## Input Validation Reference

The `validate_target` function accepts targets in these formats:

| Format | Example | Accepted by |
|--------|---------|-------------|
| IPv4 | `192.168.1.1` | all tools |
| IPv6 | `::1`, `fe80::1` | all tools |
| CIDR v4 | `10.0.0.0/24` (prefix 0-32) | nmap, masscan |
| CIDR v6 | `fe80::/10` (prefix 0-128) | nmap |
| Hostname | `scan.example.com` | all tools |
| host:port | `example.com:443` | testssl |
| HTTP URL | `http://example.com/path?q=1&r=2` | web tools, http_request |
| HTTPS URL | `https://example.com` | web tools, http_request |

**Rejected:**
- Empty strings
- Shell metacharacters: `` ; | & $ ` ( ) { } < > ! \n ``
- Non-HTTP URL schemes (`ftp://`, `file://`, etc.)
- CIDR prefix out of range (`/33` for IPv4, `/129` for IPv6)
- Hostnames longer than 253 characters
- Hostname labels starting or ending with hyphens (`-evil.com`, `test-.com`)
- Empty hostname labels (`a..b`)

URL query strings are allowed to contain `&` - it is safe because tool
arguments are passed directly to `Command::arg()`, not through a shell.

### Lenient Deserialization

All optional numeric parameters accept both JSON numbers and string-encoded
numbers. This handles a common LLM quirk where models serialize `2` as `"2"`.

Fields with lenient deserialization: `count` (ping), `port` (nikto, hydra,
msf_exploit, msf_auxiliary), `threads` (feroxbuster, ffuf), `rate` (masscan),
`level` (sqlmap), `risk` (sqlmap), `tasks` (hydra), `timeout_secs` (nikto,
http_request, launch_scan, subfinder, enum4linux-ng, dalfox, dnsrecon, httpx,
dnsx, katana, john `max_run_time`), `depth` (katana), `offset` (get_scan_results),
`limit` (get_scan_results, msf_search), `lport` (msf_exploit), `session_id` (msf_sessions).

Invalid strings (e.g. `"abc"`) produce a clear parse error. `null` and
omitted fields both resolve to `None` (the default is used).

### Error Message Formats

When the server rejects a request, errors follow predictable formats:

| Cause | Error message example |
|-------|---------------------|
| Unknown parameter | `unknown field 'verbosity', expected one of 'target', 'ports', 'scan_type'` |
| Empty target | `invalid target: empty target` |
| Shell metachar | `invalid target: forbidden character: ';'` |
| Tool not allowed | `tool not allowed: burpsuite` |
| Invalid CIDR | `invalid target: 192.168.1.0/33` |
| Root required | `masscan requires root privileges - either run the server as root or add "masscan" to sudo_tools in config` |
| Timeout | `command timed out after nmap time out after 600s` |
| Tool exit error | `nmap failed (exit exit status: 1): <stderr output>` |
| FUZZ keyword missing | `URL must contain the FUZZ keyword (e.g. http://example.com/FUZZ)` |
| Form params missing | `form_params is required for http-post-form/http-get-form` |
| Invalid scan type | `invalid scan_type 'brute' - must be: standard, zone_transfer, srv` |

---

## Safety Architecture

Every tool call passes through multiple validation layers before any subprocess
is spawned:

1. **Allowlist** - the tool binary must be in `config.safety.allowed_tools`. Calls
   for unlisted tools are rejected immediately.

2. **Input validation** - targets are validated against strict rules:
   - Must be a valid IP (v4/v6), hostname, CIDR range, `host:port`, or
     HTTP(S) URL.
   - Shell metacharacters are rejected: `` ; | & $ ` ( ) { } < > ! \n ``
   - Only `http://` and `https://` URL schemes are accepted.
   - CIDR masks are range-checked (IPv4: /0-/32, IPv6: /0-/128).
   - Hostnames: alphanumerics, hyphens, dots; max 253 chars; no
     leading/trailing hyphens; per-label validation (each dot-separated
     label must not start or end with a hyphen, and must not be empty).
   - When `[scope]` is enabled, the target must match an allowed CIDR/domain
     and must not match a denied one (deny wins); loopback allowed unless disabled.

3. **Argument building** - users pick presets (e.g. `scan_type: "service"`),
   never raw CLI flags. The server translates presets into safe argument lists.

4. **Parameter validation** - all request structs use `deny_unknown_fields`,
   which rejects any parameter the tool doesn't recognise. This catches LLM
   parameter hallucination with clear error messages (e.g. "unknown field
   `verbosity`"). Numeric parameters also accept string-encoded numbers
   (e.g. `"2"` instead of `2`) via a lenient deserializer, handling a common
   LLM serialisation quirk.

5. **Safety caps** - dangerous tools have configurable upper limits that the
   AI cannot exceed:
   - sqlmap: `--level` clamped to `sqlmap_max_level`, `--risk` to `sqlmap_max_risk`
   - hydra: `-t` (parallel tasks) clamped to `hydra_max_tasks`
   - masscan: `--rate` clamped to `masscan_max_rate`
   - john: `--max-run-time` capped at 600 seconds

6. **Execution containment** - configurable timeout per tool, `kill_on_drop` on
   all subprocesses (no orphaned processes), concurrent scan limit enforced.

7. **Output sanitisation** - truncation at `max_output_chars` (70% head / 30%
   tail), with structured parsing to reduce noise before truncation.

8. **Output quality assessment** - checks for empty results, missing tool
   completion markers, and rate-limit/WAF indicators; appends warnings when
   detected (e.g. "Output appears empty", "Possible rate limiting detected").

9. **Session budget tracking** - when `context_budget` is set, tracks cumulative
   output across all tool calls and dynamically shrinks per-call caps. Escalates
   through Full -> Compact -> Minimal output modes. Hard floor at 1,000 chars
   remaining refuses new calls.

10. **Metasploit safety** - when MSF is enabled, an additional 5-layer model
    applies: disabled by default, per-tool allowlisting, module blocklist,
    exploit confirmation gate, and session command filtering. See
    [docs/METASPLOIT.md](METASPLOIT.md).

11. **Audit logging** - every tool invocation is appended to
    `{output_dir}/audit.log` (JSON lines) with the tool, target, and
    credential-redacted arguments. Best-effort; never blocks the tool call.

---

## Output Processing

Tool output goes through a multi-stage pipeline before reaching the AI model:

### Structured Parsers

All subprocess tools have output parsers that extract the essential
information and discard noise. Parsers return `Option<String>` - if parsing
fails, the raw output is used as a fallback. Each parser has a result cap to
prevent context overflow (see [Parser Result Caps](#parser-result-caps)).

| Tool | Parser | What It Extracts |
|------|--------|-----------------|
| nmap | XML parser | Host addresses, port states, NSE scripts (vulners top-5 CVEs, other scripts compressed), OS matches, run stats. Capped at 10 hosts. |
| nuclei | JSONL parser | `[SEVERITY] template-id - name @ url (type)`. Capped at 25 findings. |
| nikto | Line filter | Lines starting with `+` (findings); filters help text. Capped at 30. |
| wpscan | JSON parser | WordPress version/status, plugins with vuln counts, themes, users. |
| feroxbuster | Line filter | Status-code + URL pairs; filters 404s. Capped at 40. |
| ffuf | Line filter | Result lines with `[Status:` and size/word counts. Capped at 40. |
| sqlmap | Block parser | Injection points, DBMS/OS/tech info, error messages. |
| hydra | Line filter | Discovered credentials (`login:` + `password:`), summary. |
| testssl | Section parser | Vulnerability assessments, certificate details, rating. |
| whatweb | Line filter | Technology lines with bracket tags. |
| masscan | Line filter | `Discovered open port` lines. Capped at 50. |
| subfinder | JSONL parser | `host (source)` lines. Capped at 50. |
| enum4linux-ng | Section parser | OS, shares, users, groups, password policy. 20 items/section. |
| dalfox | JSON parser | XSS findings with injection type, parameter, payload. Capped at 20. |
| dnsrecon | JSON parser | DNS records as `TYPE NAME VALUE`. Capped at 30. |
| httpx | Line parser | Per-URL status, title, tech, TLS. Capped at 30. |
| dnsx | Line parser | Resolved records as `TYPE NAME VALUE`. Capped at 30. |
| katana | Line parser | Crawled/deduplicated endpoints. Capped at 40. |
| john | Line filter | Cracked `password (username)` pairs, session status. |

### HTTP Response Processing

The `http_request` tool applies additional processing to HTTP responses:

- **HTML stripping** - removes `<script>` and `<style>` blocks, strips all
  HTML tags (inserting newlines for block elements), decodes HTML entities
  (named like `&amp;`, numeric like `&#169;`), and collapses blank lines.
- **Header filtering** - only security-relevant headers are shown:
  `server`, `x-powered-by`, `set-cookie`, `content-type`, `location`,
  `www-authenticate`, `x-frame-options`, `content-security-policy`,
  `strict-transport-security`, `x-content-type-options`,
  `access-control-allow-origin`, `x-xss-protection`.
- **Body cap** - response bodies are truncated to the effective cap (default
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
whatweb, wpscan, dalfox) run as separate processes and do **not** share the
cookie jar. Pass cookies explicitly via each tool's `cookie` parameter for
authenticated scanning.

### Scan Spill-to-Disk

Background scans (`launch_scan`) keep output in memory by default. When a
scan's output exceeds **1 MB** (1,048,576 bytes), it is automatically spilled
to disk at `{output_dir}/scans/{scan_id}.txt` with `0o600` permissions
(owner-only read/write). This prevents memory exhaustion from large scan
outputs (e.g. full nuclei runs) while keeping small outputs fast. The
`get_scan_results` tool reads from disk transparently when needed, supporting
the same pagination interface.

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

This only affects the default - explicit `threads` values are still honoured
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
-> Session cookies are captured automatically.

You: "Now scan the authenticated area for SQL injection"
Assistant: [reads session cookie from http_request response]
           [calls run_sqlmap with url: "http://target.example.com/search?q=test",
            cookie: "PHPSESSID=abc123"]
-> Cookie passed explicitly because sqlmap runs as a subprocess.

You: "Run nikto against the same target"
Assistant: [calls run_nikto with target: "http://target.example.com",
            cookie: "PHPSESSID=abc123"]
-> Same cookie passed to nikto for authenticated scanning.
```

---

## Testing

A comprehensive test harness at `tests/manual_test_harness.py` spawns the
MCP server as a subprocess and communicates via JSON-RPC 2.0 over stdin/stdout.
Additionally, 314 Rust unit and integration tests cover parsers, config,
safety, budget tracking, and request validation.

```bash
# Run all phases
python3 -u tests/manual_test_harness.py all

# Run specific phases
python3 -u tests/manual_test_harness.py phase0          # ping_target
python3 -u tests/manual_test_harness.py phase1          # nmap, whatweb, masscan, testssl
python3 -u tests/manual_test_harness.py phase2          # nuclei, nikto, feroxbuster, ffuf
python3 -u tests/manual_test_harness.py phase3          # sqlmap, hydra
python3 -u tests/manual_test_harness.py phase4          # http_request
python3 -u tests/manual_test_harness.py phase5          # background scan lifecycle
python3 -u tests/manual_test_harness.py phase6          # findings CRUD + report generation
python3 -u tests/manual_test_harness.py phase7          # cross-cutting validation
python3 -u tests/manual_test_harness.py phase0 phase4   # multiple phases
```

Use `-u` (unbuffered) when piping output to avoid buffering delays.

Phases 2-3 run actual scans against live targets (bWAPP, Juice Shop) and
take 30-60 minutes total. Phases 0, 4-7 complete in under 5 minutes.

See `tests/TEST_RESULTS.md` for the latest results.

---

## Troubleshooting

### masscan finds nothing on localhost

masscan uses raw SYN packets that bypass the kernel TCP stack. It cannot
scan `127.0.0.1`, `::1`, or Docker bridge IPs (`172.17.x.x`). Use nmap
for local targets. masscan is designed for scanning remote hosts on real
network interfaces.

### nikto times out

nikto full scans can take 5-10+ minutes depending on the target. The
default timeout is 600 seconds. If nikto consistently times out:

- Use `tuning: "quick"` (default) instead of `"thorough"`
- Set a higher timeout: `timeout_secs: 900`
- Or increase the per-tool timeout in config: `[execution.timeouts] nikto = 900`

### nuclei takes very long

nuclei runs all templates by default, which can take 2-5 minutes. To
speed it up:

- Filter by severity: `severity: "high"` (skips info/low/medium templates)
- Filter by tags: `tags: "cve"` (only CVE-related templates)
- Both can be combined: `severity: "high", tags: "cve"`

### feroxbuster/ffuf "file not found" error

The default wordlists point to SecLists paths under `/usr/share/seclists/`.
Install SecLists (see [Wordlists](#wordlists)) or specify a custom path
via the `wordlist` parameter.

### "tool not allowed" error

The tool binary isn't in the `allowed_tools` list in `config/default.toml`.
Add it to the list and restart the server.

### "unknown field" error

All request structs use `deny_unknown_fields`. This means misspelled or
extra parameters are rejected. Check the exact parameter names in the
[Tools Reference](#tools-reference). Common mistakes:
- `target` vs `url` - nmap/ping/masscan use `target`; sqlmap/ffuf/http_request use `url`
- `data` vs `body` - sqlmap uses `data`; http_request uses `body`

### testssl returns minimal output

The target likely doesn't have TLS configured. testssl only analyses
SSL/TLS - it won't produce meaningful results for plain HTTP services.

### Quality warnings in output

The server appends warnings when output quality is suspect:
- **"returned minimal output (N chars)"** - tool produced less than 50
  characters. The scan may have failed silently or the target returned
  nothing.
- **"output missing expected completion indicators"** - the tool ran but
  didn't include its normal completion marker (e.g. nmap's "Nmap done").
  Results may be incomplete.
- **"target may be rate-limiting requests"** - output contains indicators
  like "429", "blocked", or "access denied". Consider reducing scan
  aggressiveness or adding delays.
- **"exited with error (code N) and produced no output"** - the tool
  returned a non-zero exit code with empty stdout. Check that the tool
  is installed correctly and the target is reachable.
