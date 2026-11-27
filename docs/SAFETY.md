# Safety model

This page says what the server
- stops,
- gates,
- caps,
- writes down.

It also shows where its protection ends.

Every statement here was checked against the source, and each section names
the file to read if you would like to check it yourself.

**In short:**
The model never writes a command line. It picks a tool and
fills in typed fields. The server builds the argument list, runs the binary
directly with no shell in between, and records what ran.

## Contents

- [What happens to one tool call](#what-happens-to-one-tool-call)
- [Always on](#always-on)
- [Off until you turn it on](#off-until-you-turn-it-on)
- [Capped](#capped)
- [Engagement scope](#engagement-scope)
- [Metasploit](#metasploit)
- [NetExec](#netexec)
- [Audit log](#audit-log)
- [Files on disk](#files-on-disk)
- [What this does not protect you from](#what-this-does-not-protect-you-from)
- [Hardening checklist](#hardening-checklist)

## What happens to one tool call

1. **The MCP layer deserialises the arguments into a request struct**. Every
   struct ***rejects unknown fields***, so a made-up parameter is an error and never
   reaches a tool.
2. **The handler** ***validates the target and any other free-text field***.
3. **The handler builds the argument list** from ***presets and typed
   values***.
4. **`executor::run_inner` checks the allowlist**, waits for any configured
   cooldown, and starts the binary with `tokio::process::Command`. There is
   ***no `sh -c` anywhere in the workspace***.
5. **The child runs under a timeout**. Its stdin is closed, and it is
   ***killed if the call is cancelled***.
6. **The server truncates the output**, parses it into a summary where a
   parser exists, strips ANSI codes, and ***fits it to the context budget***.
7. **The executor** ***appends one line to the audit log***.

**Source:**
- `crates/raven-core/src/executor.rs`,
- `crates/raven-core/src/safety.rs`,
- `crates/raven-server/src/server.rs`.

## Always on

These apply to every call and ***cannot be switched off in config***.

### Tool allowlist

A binary runs ***only if its name is in `[safety] allowed_tools`***.

The check sits in the only places that start a process:
- the executor,
- the background scan launcher,
- the `ping_target` handler.

### Target validation

A target must parse as one of
- an IPv4 or IPv6 address,
- a CIDR range with a valid prefix length,
- `host:port`,
- an `http` or `https` URL,
- a hostname.

Outside a URL query string ***these characters are rejected***:

```
; | & $ ` ( ) { } < > ! newline
```

Hostnames are limited to letters, digits, dots and hyphens, and a label may
not start or end with a hyphen.

That last rule is what stops a target such as `-oN/tmp/evil` from being
***read as a flag by the tool***.

### Presets, not flags

Tools take choices such as `scan_type: "service"`.

***No tool takes a raw argument string***.

### Strict schemas

Every request struct uses `deny_unknown_fields`, so ***an unknown parameter
is an error***.

Numeric fields also accept a quoted number, because small models often send
`"2"` where `2` is expected.

### Guards on free-text arguments

Values that end up as positional arguments are checked so they ***cannot be
re-read as flags***:

| Field | Rule |
|-------|------|
| nmap and masscan `ports` | digits, commas and hyphens only |
| hydra `service` | lowercase letters, digits and hyphens |
| hydra `form_params` | no leading `-`, no control characters |
| sqlmap `technique` | a subset of `BEUSTQ` |
| ffuf `filter_size` | digits and commas |
| NetExec username, password and hash | not empty, no leading `-`, not a path to an existing file |

### File path confinement

These paths are confined:
- wordlists for hydra, john, feroxbuster and ffuf,
- the john hash file,
- the directory that gitleaks or trufflehog scans.

Each one ***must sit under*** one of
- `/usr/share/`,
- `/usr/lib/`,
- the configured `output_dir`.

Paths containing `..` are rejected.

### Timeouts and process limits

**Each tool has a timeout**, 600 seconds unless you override it.

By default, these are the most that run at once:
- four synchronous tools,
- three background scans.

A model that fires many calls in parallel ***cannot start an unbounded number
of processes***.

### Startup checks

The server ***exits at startup*** if
- a safety limit is out of range,
- a scope entry is not a valid CIDR or IP,
- Metasploit is enabled with the password still set to `changeme`.

### Identifier checks

- **Finding IDs** must be UUIDs.
- **Engagement names** are limited to letters, digits, `-`, `_` and `.`.

Neither can be used to ***walk out of the output directory***.

### Report escaping

Finding fields are escaped when a Markdown or HTML report is generated.

Text that a scanner lifted from a target ***cannot inject markup into the
report***.

## Off until you turn it on

| Feature | Default | How to enable |
|---------|---------|---------------|
| Metasploit, all six `msf_*` tools | off | `[metasploit] enabled = true` and a running `msfrpcd` |
| NetExec, `run_netexec` | off | `[netexec] enabled = true` |
| trufflehog live verification of found secrets | off | `verify: true` on the call |
| gitleaks showing secret values | off, values are redacted | `show_secrets: true` on the call |
| Running a tool through `sudo` | off in the built-in defaults | list the tool in `[safety] sudo_tools` |
| Saving findings straight from scanner output | off | `[safety] auto_save_findings = true` |

The disabled tools ***still appear in the tool list***. Calling one returns
an error that says it is disabled.

**About `sudo_tools`:**
- the built-in defaults leave it empty,
- the `config/default.toml` in this repository lists `masscan` and `nmap`.

If you start from that file on a machine without the matching sudoers rule,
or inside the container, ***set `sudo_tools = []`***.

## Capped

The model can ask for less than these limits and ***never more***.

You set them in `[safety]`, and the server checks the range at startup.

| Tool | Limit | Default | Allowed range |
|------|-------|---------|---------------|
| sqlmap | `--level` | 2 | 1 to 5 |
| sqlmap | `--risk` | 1 | 1 to 3 |
| hydra | parallel tasks | 4 | 1 or more |
| masscan | packets per second | 1000 | 1 or more |
| john | run time | 300 s | hard maximum of 600 s |

The masscan cap also applies when masscan is started through `launch_scan`.

**Two optional cooldowns space out launches:**
- `min_exec_gap_ms` sets a gap between any two launches,
- `per_target_min_gap_ms` sets a gap per host while other hosts continue in
  parallel.

Both are ***off by default***, and both cover `http_request` as well as the
subprocess tools.

## Engagement scope

The scope is an allowlist of what you are authorised to test.

***It is off by default***. Until you enable it, the server accepts any
target that passes syntax validation.

```toml
[scope]
enabled = true
allowed_cidrs = ["10.20.0.0/16"]
allowed_domains = ["example.com"]
denied_cidrs = ["169.254.169.254/32"]
allow_localhost = true
```

**With the scope on:**

- **A target must match an allowed entry** and must not match a denied one.
  ***A deny always wins***.
- **A domain entry covers the domain and its subdomains**. `example.com`
  matches `api.example.com` and does not match `notexample.com`.
- **A CIDR target must fit entirely inside an allowed range** and must not
  overlap a denied one.
- **Loopback is allowed** unless you set `allow_localhost = false`.
- **The check runs in `validate_target`**, which every target-taking tool and
  the background scan launcher call.
- **`http_request` re-checks the host on every redirect hop** and ***stops at
  the first hop outside the scope***.
- **A rejection tells the model** that this is an authorisation boundary and
  that it should not retry with a reformatted target.

**Limits of the scope check:**

- **It compares the string you pass**. It ***does not resolve DNS***, so an
  allowed hostname that resolves to an address outside your allowed ranges
  still passes.
- **It runs once, before launch**. The server ***does not watch what a
  wrapped tool does afterwards***. A crawler or scanner that follows links or
  redirects on its own is governed by that tool's behaviour, not by this
  scope.
- **`msf_post` and `msf_sessions`** act on sessions that already exist and
  take no target, so the scope does not apply to them.
- **john, gitleaks and trufflehog** work on local files and have no network
  target.

**Source:**
- `check_scope` in `crates/raven-core/src/safety.rs`,
- the redirect policy in `crates/raven-server/src/tools/http.rs`.

## Metasploit

Metasploit is reached over RPC to an `msfrpcd` that you start yourself.

Setup is in [METASPLOIT.md](METASPLOIT.md).

**The controls:**

- **Off by default**. Every `msf_*` call returns "Metasploit is disabled"
  until you enable it.
- **No default password**. The server ***refuses to start*** if Metasploit is
  enabled and the password is `changeme`. The password is redacted from error
  messages.
- **Target validation and scope** apply to `msf_exploit` and `msf_auxiliary`.
  Extra options ***cannot override `RHOSTS`***.
- **Module blocklist**. `blocked_modules` matches whole path segments, so
  `exploit/foo` blocks `exploit/foo` and `exploit/foo/bar` and leaves
  `exploit/foobar` alone. The list is ***empty by default***, so nothing is
  blocked until you add entries.
- **Second call to run an exploit**. The first `msf_exploit` call returns the
  plan and ***runs nothing***. A second call with the same module, target,
  port and payload runs it.
- **Session command filter**. `msf_sessions` refuses commands that start with
  `rm`, `del`, `format`, `mkfs`, `dd`, `shutdown`, `reboot`, `halt`,
  `poweroff` or `upload`.
- **TLS**. Certificate checks are skipped ***only when `msfrpcd` is on
  localhost***.

**Be clear about what two of these are worth:**

- **The second call is made by the same model that made the first**. It
  forces the model to state the plan before acting, and it gives a client
  that shows tool calls a moment where a person can stop it. It is ***not a
  human approval step***. If you would like one, use your MCP client's own
  approval prompt for `msf_exploit`.
- **The session filter is a prefix match on the start of the command**. It
  catches the obvious accident. Anything with shell access can get around
  it, so ***treat a session as full access to the target***.

Metasploit module runs are ***not written to the audit log today***. See the
next section.

## NetExec

`run_netexec` exists for one job, which is checking a credential and reading
back what it can see.

**Once enabled it still refuses anything else:**

- **Eight read-only actions**: `auth`, `shares`, `users`, `groups`,
  `loggedon`, `sessions`, `disks` and `pass-pol`. There is ***no path to
  command execution, modules or credential dumping***.
- **One host per call**. CIDR ranges, dash ranges, lists and target files are
  rejected.
- **One username with one password or one hash**. A value that points at an
  existing file is rejected, because NetExec would read it as a list.

The tool is marked destructive in its MCP annotations because ***failed
logins can lock accounts***.

## Audit log

The server appends one JSON line per run to `{output_dir}/audit.log`, mode
`0600`:

```json
{"ts":"2026-11-27T19:23:18.004512331+00:00","tool":"nmap","args":["-T4","-F","-oX","-","10.20.0.5"],"exit_code":0,"success":true,"duration_ms":4212,"sudo":false,"bytes_out":1893,"quality":"Complete"}
```

**Replaced with `<redacted>`:**
- values that follow credential flags such as `--cookie`, `--password`, `-H`
  and `--api-token`,
- any argument that contains `password=`, `token=`, `cookie:` and similar
  markers.

The target is kept.

**What is logged:**

- **Every subprocess the executor ran to completion**, whether it succeeded
  or failed, including background scans.
- **Every `http_request` call**.

**What is not logged today:**

- **Calls the server rejected before launch**, such as an out-of-scope target
  or a tool missing from the allowlist. Those appear only in the server's
  stderr log.
- **Runs that hit the timeout** or failed to start.
- **`ping_target`**, which starts `ping` itself and does not go through the
  executor.
- **Anything done through Metasploit RPC**.
- **Saving or deleting findings**, and generating reports.

**Good to know:**

- **The log is best effort**. A failed write is reported on stderr and does
  not fail the tool call.
- **The file rotates at 16 MB** and keeps one older generation.
- **It is an ordinary file** owned by the user that runs the server, so
  ***that user can edit it***. If you need a tamper-evident record, ship it
  somewhere else.

## Files on disk

Everything the server keeps lives under `output_dir`:

| Path | Contents |
|------|----------|
| `audit.log` | the audit log |
| `findings/` | one JSON file per finding |
| `targets/` | one JSON file per discovered host |
| `scans/` | output and metadata of background scans |
| `report-*.md` and other formats | generated reports |
| `session_cookies.json` | the `http_request` cookie jar |
| `engagements/{name}/` | findings, targets and reports for a named engagement |

**File modes:**
- `output_dir` is created with mode `0700`,
- scan files, the cookie file and the audit log are written with mode `0600`.

The mode is set when the directory is created. ***An existing directory keeps
whatever mode it had***.

**The default `output_dir` is `/tmp/raven-nest`**. `/tmp` is shared with every
user on the machine and is usually cleared on reboot.

For real work, ***point `output_dir` at a directory you own***.

## What this does not protect you from

- **A model that picks the wrong legitimate action**. With the scope off,
  the model can ***scan any host it can name***. With the scope on, it can
  still run every allowed tool against every host in scope.
- **Prompt injection in scan output**. A page or banner on the target can
  contain text aimed at the model. The server limits what any tool call can
  do, and it ***does not inspect tool output for instructions***.
- **What the wrapped tools do**. They are the stock binaries. sqlmap, hydra
  and nuclei can ***change or disrupt a target*** while working exactly as
  designed. The MCP annotations mark only `msf_exploit`, `msf_post` and
  `run_netexec` as destructive, and those annotations are hints to the
  client, not controls.
- **A hostile local user**. The server trusts its config file and its own
  user account.
- **Bugs**. This is pre-1.0 software written by one person and it has ***not
  had an outside security audit***. If you find a way past any control on
  this page, please report it as described in [SECURITY.md](../SECURITY.md).

## Hardening checklist

1. **Turn on `[scope]`** and list ***only what the contract covers***.
2. **Trim `allowed_tools`** to what the engagement needs.
3. **Move `output_dir`** off `/tmp`.
4. **Leave Metasploit and NetExec off** unless the engagement calls for them.
5. **Keep your MCP client's approval prompt on** for the destructive tools.
6. **Read the first lines of the server's stderr log** and confirm it says
   `config loaded from` followed by your file. If the file named in
   `RAVEN_CONFIG` is missing or does not parse, the server logs a warning and
   carries on with the next config it finds, which may be ***the built-in
   defaults with the scope off***.
7. **Copy `audit.log` out** when the engagement ends.
