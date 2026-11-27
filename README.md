# Raven Nest MCP

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/tidynest/raven-nest-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tidynest/raven-nest-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v0.4.2-blue.svg)](https://github.com/tidynest/raven-nest-mcp/releases)
[![MCP tools: 46](https://img.shields.io/badge/MCP%20tools-46-5A45FF.svg)](docs/MCP_TOOLS.md)
[![Canopii Trust Score](https://index.canopii.dev/api/badge/io.github.tidynest/raven-nest-mcp)](https://index.canopii.dev/server/io.github.tidynest/raven-nest-mcp)

**An [MCP](https://modelcontextprotocol.io/) server that lets an AI agent run
nmap, nuclei, sqlmap and 19 other pentesting tools, plus Metasploit, without
giving the agent a shell.**

The quick way to let an agent pentest is to hand it a terminal. Then the model
writes every command line, and an invented flag or a line of hostile text in a
scan result is enough to run something you never approved. Raven Nest puts a
fixed interface in between. The model picks a tool and fills in typed fields.
The server checks the target, builds the arguments itself, starts the binary
with no shell, limits how aggressive it can be, and writes down what ran.

- **The model never writes a command line.** Tools take presets and typed
  fields. Unknown parameters are rejected and no tool accepts a raw flag
  string.
- **You decide what it may touch.** A scope allowlist of CIDR ranges and
  domains rejects every other target, and a deny entry always wins. A second
  allowlist does the same for which binaries may run.
- **The intrusive parts start switched off.** Metasploit and credentialed
  NetExec stay disabled until you enable them. sqlmap, hydra, masscan and john
  run under limits the model cannot raise.
- **It works with a small local model.** Output is parsed into short
  summaries and fitted to a context budget, so an 8B model on an 8 GB GPU can
  get through a multi-step session. Your targets and findings then stay on
  your machine.
- **There is a record.** Each subprocess the server runs is appended to a
  JSON audit log with credentials redacted.
- **Findings become a report.** Save findings as you go and export Markdown,
  HTML, JSON or SARIF.

> **Authorized use only.** Raven Nest is an offensive-security tool intended
> solely for testing systems you own or have explicit written permission to
> assess. Unauthorized scanning, enumeration or exploitation may be illegal.
> You are solely responsible for obtaining authorization and complying with
> all applicable laws. The software is provided "as is", without warranty of
> any kind. See [LICENSE](LICENSE).

## Contents

- [Is this for you](#is-this-for-you)
- [Demo](#demo)
- [Quick start](#quick-start)
- [What is safe, what is gated, what is logged](#what-is-safe-what-is-gated-what-is-logged)
- [Keeping engagement data on your machine](#keeping-engagement-data-on-your-machine)
- [How it compares](#how-it-compares)
- [Supported tools](#supported-tools)
- [Beyond running tools](#beyond-running-tools)
- [Other ways to install](#other-ways-to-install)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Community and contributing](#community-and-contributing)
- [Project status](#project-status)

## Is this for you

It probably is if you:

- already use these tools and want an agent to drive recon and the routine
  scanning while you watch and decide
- test under a contract or NDA and cannot send client data to a hosted AI
  service
- build agent workflows and want a tool layer with fixed, typed inputs
- practise on labs such as Juice Shop or DVWA and want to see how far a local
  model gets

It probably is not if you:

- want a scanner with a user interface. This is a server, and it does nothing
  until an MCP client and a model drive it.
- want to leave an agent unattended on a production network. The controls
  here narrow what a model can do. They do not make it right.
- need native Windows or ARM builds. See [Project status](#project-status).
- need a tool that has been through an independent security audit. This one
  has not.

## Demo

These recordings are real MCP traffic to the tools with no model in the loop,
so they replay the same way every time. The targets are the public test hosts
`example.com` and `scanme.nmap.org`.

**A scan, a saved finding and a report**

![Scan to structured finding to report](docs/assets/report.gif)

**Recon: connectivity, ports and web stack**

![Recon flow: ping, nmap, whatweb](docs/assets/recon.gif)

**Metasploit module search.** This needs a build with Metasploit enabled. The
container image does not include Metasploit.

![Metasploit search and module info](docs/assets/metasploit.gif)

## Quick start

Raven Nest is a server. It does nothing on its own. An MCP client such as
Claude Desktop, Claude Code, Cursor or a local-model client starts it over
stdio and calls its tools.

The container image carries the server and all 22 wrapped tools on a Kali
base, so there is nothing else to install. Add this to your MCP client
config:

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/tidynest/raven-nest-mcp:latest"]
    }
  }
}
```

Then ask your agent for something small against a host you may scan:

```
Ping scanme.nmap.org, run a quick nmap scan, and save anything notable as a finding.
```

That entry is enough to try it. It runs on built-in defaults, with the scope
allowlist off and all output lost when the container exits. Before real work,
read [docs/INSTALL.md](docs/INSTALL.md#container-image). It shows how to
mount your own config, keep findings and the audit log on a volume, add
wordlists, and grant raw sockets to `masscan`.

If you would sooner drive the tools by hand,
[raven-nest-client](https://github.com/tidynest/raven-nest-client) is a
terminal client for this server with tab completion and commands for scans,
findings, reports and engagements. It starts either a local build or the
container.

## What is safe, what is gated, what is logged

| | |
|---|---|
| **Always enforced** | The tool allowlist. Target validation that rejects shell metacharacters and anything that is not an IP, CIDR, `host:port`, URL or hostname. Presets in place of raw flags. Strict schemas that reject unknown parameters. Wordlists and scan paths confined to `/usr/share/`, `/usr/lib/` and the output directory. A timeout per tool and a limit on parallel processes. |
| **Off until you turn it on** | The engagement scope. Metasploit. NetExec. trufflehog's live verification of found secrets. Running any tool through `sudo`. |
| **Needs a second call** | `msf_exploit`. The first call returns the plan and runs nothing. A second call with the same module, target, port and payload runs it. |
| **Capped** | sqlmap level and risk, hydra parallel tasks, masscan packet rate and john run time. The model can ask for less and never more. |
| **Written to the audit log** | Every subprocess the server ran to completion, and every `http_request`, with tool, arguments, exit code, duration and whether `sudo` was used. Credential values are redacted. |

Four things a sceptical reader should know before trusting that table:

1. **The scope allowlist is off by default.** Out of the box the server
   accepts any target that is well formed. Turn `[scope]` on before you point
   an agent at anything that matters.
2. **The second call for an exploit is not human approval.** The same model
   makes both calls. It forces the plan into the open, and your MCP client's
   own approval prompt is what puts a person in the loop.
3. **The audit log has gaps.** Rejected calls, timed-out runs, `ping_target`
   and Metasploit RPC calls are not in it today.
4. **A config that fails to load is skipped, not fatal.** If the file in
   `RAVEN_CONFIG` is missing or broken, the server warns on stderr and starts
   on the next config it finds, which can mean built-in defaults with the
   scope off. Check the first log line.

The wrapped tools are the stock binaries. sqlmap and hydra can disrupt a
target while doing exactly what they were built to do, and nothing
here inspects scan output for text aimed at the model. This is pre-1.0
software from one maintainer and it has had no outside security audit.

The full account, including what each control does not cover and a hardening
checklist, is in [docs/SAFETY.md](docs/SAFETY.md). To report a way past any
of these controls, see [SECURITY.md](SECURITY.md).

## Keeping engagement data on your machine

When an agent runs a pentest, every tool result passes through the model:
target addresses, service banners, findings, and any credentials that turn
up. With a hosted model, all of that goes to the provider. Under a contract
or an NDA that is often not allowed.

Raven Nest was built to be driven by a small model running on the same
machine. The server itself is a local process that talks to its client over
stdio. It has no telemetry and no AI provider client in it. The only network
connections it opens itself are the requests you make with `http_request`
and, if you enable Metasploit, the RPC connection to your own `msfrpcd`. So
with a local model the whole loop stays on your hardware:

```
local model  <->  MCP client  <->  raven-server  <->  scanners  <->  target
```

Small models have short context windows and make more tool-calling mistakes,
so the server does some work to meet them:

- A context budget tracks how much output the session has used and shrinks
  each tool's allowance as it fills. When it runs out, scan tools are refused
  and the model is told to save findings and write the report.
- Each tool's raw output is parsed into a short summary before the model sees
  it.
- A wrong parameter name gets an error that names the field, and a number
  sent as a string is accepted.
- With auto-save turned on, the server saves findings straight from scanner
  output, so the report does not depend on the model remembering to do it.

What I have tested, on a laptop with an 8 GB GPU through Ollama: Qwen3 8B at
a 64K context completes an eight-step session and is the one I use
interactively. Qwen3.5 9B writes better findings, and only when given all the
steps in a single prompt. Most other models I tried, 14 in total, could not
call tools reliably enough to be useful. The full table, the client setup
and the failure modes are in
[docs/LOCAL_AI_INTEGRATION.md](docs/LOCAL_AI_INTEGRATION.md).

What this does not promise:

- A local model is weaker than a large hosted one. Expect to guide it step by
  step and to check what it reports.
- If you connect a hosted model, every tool result goes to that provider.
  The server cannot tell the difference and does not try to.
- Some wrapped tools contact third parties as part of their normal work.
  subfinder queries public data sources about the domain. nmap's `vuln` scan
  type runs scripts that look up service versions online. wpscan sends data
  to its vulnerability API when you pass a token. trufflehog tests found
  secrets against the issuing service if you ask it to verify. Leave those
  out of the tool allowlist if the engagement rules them out.
  [docs/DATA_FLOW.md](docs/DATA_FLOW.md#what-leaves-the-machine) has the list.

## How it compares

The usual alternative is an agent with a shell or a generic "run command"
tool. This is how the two differ, going only by what this code does:

| | Agent with a shell | Raven Nest |
|---|---|---|
| Who writes the command line | the model | the server, from presets and typed fields |
| Which programs can run | anything the shell can reach, unless your client restricts it | only the names on the allowlist |
| Which targets | nothing checks | syntax always, and a scope allowlist when enabled |
| How aggressive | whatever flags the model picks | caps set in config |
| Exploitation | a command like any other | off by default, then a second call |
| Output | raw, straight into the context window | parsed summaries fitted to a budget |
| Record | your client's transcript | an audit log, plus findings and reports on disk |
| Flexibility | everything the tools can do | only what the handlers expose |

The last row is the cost. If a tool flag is not exposed as a preset, the
agent cannot use it, and you run that step yourself or open a discussion
asking for it.

Other MCP servers for security tools exist. I have not run them side by
side with this one, so there is no feature table against them here. If you
maintain one and want a fair comparison written up, start a thread in
[Discussions](https://github.com/tidynest/raven-nest-mcp/discussions).

## Supported tools

The server exposes 46 MCP tools: 22 wrappers around external security tools,
6 for Metasploit, and 18 for utilities, background scans, findings,
engagements and discovery data.

| Category | Tools |
|----------|-------|
| Recon | nmap, masscan, whatweb, httpx, subfinder, dnsx, dnsrecon |
| Crawling | katana |
| SMB and AD | enum4linux-ng |
| Credentialed enumeration, gated | netexec |
| Vulnerability scanning | nuclei, nikto, wpscan, dalfox |
| Web fuzzing | feroxbuster, ffuf |
| Exploitation | sqlmap, hydra |
| Password cracking | john |
| Secret scanning | gitleaks, trufflehog |
| TLS | testssl.sh |
| Metasploit, gated | msf\_search, msf\_module\_info, msf\_exploit, msf\_auxiliary, msf\_sessions, msf\_post |
| Utility | ping\_target, http\_request |
| Background scans | launch\_scan, get\_scan\_status, get\_scan\_results, list\_scans, cancel\_scan |
| Findings | save\_finding, get\_finding, list\_findings, list\_findings\_by\_scan, delete\_finding, generate\_report |
| Engagements | set\_engagement, list\_engagements |
| Discovery | get\_target\_info, list\_targets, diff\_scans |

Every parameter of every tool is documented in
[docs/USAGE.md](docs/USAGE.md#tools-reference). The exact names and
descriptions the server sends to a client are in
[docs/MCP_TOOLS.md](docs/MCP_TOOLS.md).

## Beyond running tools

- **Findings and reports.** Findings are stored one file each and survive
  restarts. `generate_report` writes Markdown or HTML with a summary, a
  methodology section, scope and timeline, and numbered findings carrying
  severity, CVSS, CVE and OWASP category. JSON and SARIF are there for other
  tooling. See [Findings and reports](docs/USAGE.md#findings-and-reports).
- **Engagements.** `set_engagement` gives each client or target its own
  findings and reports, kept apart from the others. See
  [Engagement](docs/USAGE.md#engagement).
- **Background scans.** Long scans run in the background and are polled by
  ID. Finished results survive a server restart, and a scan that was cut off
  shows up as failed. See
  [Scan persistence](docs/USAGE.md#scan-persistence-and-restart-recovery).
- **Discovery tracking and scan diffing.** nmap results build up a record
  per host of open ports and service versions, with first-seen and last-seen
  times. `diff_scans` compares two scans and lists what changed. See
  [Target discovery tracking](docs/USAGE.md#target-discovery-tracking).
- **Structured results and MCP resources.** nmap and nuclei return
  machine-readable results next to the text. Saved findings and scans can
  also be browsed as `raven://` resources. See
  [Structured outputs](docs/USAGE.md#structured-outputs) and
  [MCP resources](docs/USAGE.md#mcp-resources).
- **Authenticated scanning.** `http_request` keeps a cookie jar for the
  session. The subprocess tools do not share it, so you pass the cookie to
  each one. See [Cookie jar](docs/USAGE.md#cookie-jar).
- **Output quality warnings.** The server flags empty results and signs of
  rate limiting or a WAF, so the model can slow down and try again. See
  [Output processing](docs/USAGE.md#output-processing).

## Other ways to install

| Method | Brings the scanners | Platform |
|--------|---------------------|----------|
| Container image | yes | x86_64 Linux image |
| Prebuilt binary from [Releases](https://github.com/tidynest/raven-nest-mcp/releases) | no | x86_64 Linux |
| `cargo build --release` | no | Linux, Rust 1.93 or newer |
| Arch Linux PKGBUILD in `packaging/aur` | no | x86_64 Arch |

Steps for each, and how the server finds its config, are in
[docs/INSTALL.md](docs/INSTALL.md). The image is also listed on the
[MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.tidynest/raven-nest-mcp`.

## Configuration

Configuration is one TOML file. The server reads the file named in
`RAVEN_CONFIG`, then looks for `config/default.toml` near the binary and in
the working directory, and falls back to built-in defaults. The settings most
people touch:

```toml
[safety]
allowed_tools = ["ping", "nmap", "nuclei", "whatweb", "httpx"]
max_output_chars = 50000
context_budget = 65536       # context window in characters, 0 turns the budget off
sudo_tools = []              # tools started through passwordless sudo

[scope]
enabled = true
allowed_cidrs = ["10.20.0.0/16"]
allowed_domains = ["example.com"]
denied_cidrs = ["169.254.169.254/32"]

[execution]
default_timeout_secs = 600
max_concurrent_scans = 3
output_dir = "/var/lib/raven-nest"
```

[config/default.toml](config/default.toml) is a commented starting point and
[docs/USAGE.md](docs/USAGE.md#configuration) documents every key.

## Documentation

| Document | What is in it |
|----------|---------------|
| [docs/INSTALL.md](docs/INSTALL.md) | container, binary, source and Arch installs, config lookup, volumes, raw sockets |
| [docs/USAGE.md](docs/USAGE.md) | client setup, the configuration reference, every tool parameter, troubleshooting |
| [docs/SAFETY.md](docs/SAFETY.md) | each control, what it does not cover, the audit log format, a hardening checklist |
| [docs/LOCAL_AI_INTEGRATION.md](docs/LOCAL_AI_INTEGRATION.md) | running with Ollama or LM Studio, tested models, context budgets, prompting |
| [docs/METASPLOIT.md](docs/METASPLOIT.md) | Metasploit setup and the `msf_*` tool reference |
| [docs/DATA_FLOW.md](docs/DATA_FLOW.md) | which module owns which state, and what leaves the machine |
| [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md) | the tool names and descriptions exactly as declared in the source |
| [CHANGELOG.md](CHANGELOG.md) | release history |
| [ROADMAP.md](ROADMAP.md) | what is planned and what has shipped |

## Community and contributing

- **Questions and ideas** go to
  [Discussions](https://github.com/tidynest/raven-nest-mcp/discussions).
  [docs/DISCUSSIONS.md](docs/DISCUSSIONS.md) says what belongs in which
  category.
- **Bugs** go to [Issues](https://github.com/tidynest/raven-nest-mcp/issues).
- **Security problems** are reported privately. See
  [SECURITY.md](SECURITY.md).
- **Code** is welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers building,
  testing, the checks a pull request has to pass, and how to add a tool
  wrapper without opening a hole.

## Project status

Raven Nest is pre-1.0 and maintained by one person. Minor versions can change
tool parameters and config keys, and the [changelog](CHANGELOG.md) says when
they do.

The container image and the release binary are both x86_64 Linux. The code
has not been tested on macOS or Windows.

[raven-nest-client](https://github.com/tidynest/raven-nest-client) is
released with the same version number as the server.

## License

[Apache-2.0](LICENSE)
