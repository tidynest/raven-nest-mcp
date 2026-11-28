# Using Raven Nest with Local AI Models

Guide for connecting local LLMs to Raven Nest as MCP clients, through Ollama,
LM Studio and similar runtimes.

**Why do this:**
Data control. Every tool result passes through the model, so
- with a hosted model, your targets and findings ***go to that provider***,
- with a model on your own machine, they stay there.

The server sends nothing anywhere on its own account. Some wrapped tools do
contact third parties, and
[DATA_FLOW.md](DATA_FLOW.md#what-leaves-the-machine) lists which ones.

**The trade:**
Capability. Of the 14 models tested below, ***only the Qwen3 and Qwen3.5
family was usable***, and even those need step-by-step guidance.

## Contents

- [Prerequisites](#prerequisites)
- [MCP Client Options](#mcp-client-options)
- [Server Naming: Avoid Hyphens](#server-naming-avoid-hyphens)
- [Tool Installation](#tool-installation)
- [Model Compatibility](#model-compatibility)
- [Context Budget System](#context-budget-system)
- [ANSI Stripping](#ansi-stripping)
- [Findings: owasp_category Field](#findings-owasp_category-field)
- [Known Issues and Workarounds](#known-issues-and-workarounds)
- [Cookie Passthrough for Authenticated Scanning](#cookie-passthrough-for-authenticated-scanning)
- [Prompting Strategies](#prompting-strategies)
- [ollmcp Configuration](#ollmcp-configuration)
- [Reproduction Testing (severity=info)](#reproduction-testing-severityinfo)
- [Live Testing Results (2026-03-10)](#live-testing-results-2026-03-10)
- [Resource Considerations](#resource-considerations)

## Prerequisites

You need
- Raven Nest built with `cargo build --release`,
- Ollama installed with a supported model pulled,
- an MCP client, picked from the table below,
- the underlying security tools installed, such as nmap and nuclei.

## MCP Client Options

| Client | Language | Notes |
|--------|----------|-------|
| [ollmcp](https://github.com/jonigl/mcp-client-for-ollama) | Python | TUI with human-in-the-loop confirmation, `pipx install ollmcp` |
| [mcphost](https://github.com/mark3labs/mcphost) | Go | CLI, `go install` from GitHub |
| LM Studio | Desktop | Built-in MCP support via `.lmstudio/mcp.json` |

All three use `~/.mcphost.json` or their own config file to define MCP
servers.

## Server Naming: Avoid Hyphens

Many local models ***tokenise hyphens unpredictably***.

They mangle tool names like `raven-nest.run_nmap` into
`raven_nest.run_nmap`, or drop the prefix entirely.

**Fix:**
Rename the server in your MCP config to a single unhyphenated word:

```json
{
  "mcpServers": {
    "raven": {
      "command": "/path/to/raven-server",
      "args": []
    }
  }
}
```

Tools then appear as `raven.run_nmap`, `raven.list_findings` and so on,
which is much easier for smaller models to handle.

## Tool Installation

Raven Nest exposes ***46 MCP endpoints***:
- 22 security tool wrappers,
- 6 Metasploit tools,
- ping and http,
- 5 for scan management,
- 6 for finding management,
- 2 for engagements,
- 3 for target discovery.

### Core Tools (likely already installed)

| Tool | Binary | Package Manager |
|------|--------|----------------|
| nmap | `nmap` | `pacman -S nmap` / `apt install nmap` |
| nuclei | `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| nikto | `nikto` | `pacman -S nikto` / `apt install nikto` |
| whatweb | `whatweb` | `pacman -S whatweb` / `apt install whatweb` |
| testssl.sh | `testssl.sh` | `pacman -S testssl.sh` / clone from GitHub |
| feroxbuster | `feroxbuster` | `pacman -S feroxbuster` / `apt install feroxbuster` |
| ffuf | `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| sqlmap | `sqlmap` | `pacman -S sqlmap` / `apt install sqlmap` |
| hydra | `hydra` | `pacman -S hydra` / `apt install hydra` |
| masscan | `masscan` | `pacman -S masscan` / `apt install masscan` |

### Additional Tools

| Tool | Binary | Install |
|------|--------|---------|
| subfinder | `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| wpscan | `wpscan` | `gem install --user-install wpscan` |
| enum4linux-ng | `enum4linux-ng` | `pipx install enum4linux-ng` |
| dalfox | `dalfox` | `go install github.com/hahwul/dalfox/v2@latest` |
| dnsrecon | `dnsrecon` | `pipx install dnsrecon` |
| john | `john` | `pacman -S john` / `apt install john` |
| httpx | `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| dnsx | `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| katana | `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| netexec | `nxc` | `pipx install netexec` - gated; set `[netexec] enabled = true` |

### Tool Paths Configuration

For tools not in `$PATH`, add custom binary paths in your config TOML:

```toml
[safety.tool_paths]
wpscan = "~/.local/share/gem/ruby/3.4.0/bin/wpscan"
subfinder = "~/go/bin/subfinder"
dalfox = "~/go/bin/dalfox"
enum4linux-ng = "~/.local/bin/enum4linux-ng"
dnsrecon = "~/.local/bin/dnsrecon"
```

### Metasploit Integration

Metasploit needs ***`msfrpcd` running separately***.

Six MCP tools are provided:
- `msf_search`,
- `msf_module_info`,
- `msf_exploit`,
- `msf_auxiliary`,
- `msf_sessions`,
- `msf_post`.

Enable in config:

```toml
[metasploit]
enabled = true
host = "127.0.0.1"
port = 55553
username = "msf"
password = "changeme"    # CHANGE THIS
ssl = true
```

Start the daemon: `msfrpcd -P <password> -a 127.0.0.1 -p 55553 -n -f`

**Read more:**
`docs/METASPLOIT.md` has the full setup.

## Model Compatibility

### Recommended Models (by tool-calling reliability)

The table runs from best to worst for Raven Nest tool calling.

**The Notes column** is hands-on testing against this server.

**The Tool F1 column** is ***not hands-on testing***. Those scores are the
tool-selection F1 published in the
[Docker practical evaluation](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)
and measured on Docker's own test set. That study dates from June 2025 and
covers 21 models and 3570 test cases.

| Model | Size | VRAM (8GB fit?) | Tool F1 (Docker eval) | Notes |
|-------|------|-----------------|-----------------------|-------|
| Qwen3 8B @64K (dense) | ~5 GB | Yes | 0.919 at Q4_K_M, 0.933 at F16 | **Daily driver.** Zero param hallucination, no interactive fabrication. 8/8 batch steps at 64K context. ~40 tok/s. |
| Qwen3.5 9B @49K (dense) | ~6.6 GB | Yes (tight, 7.3/8.2 GB) | ~0.93 (own estimate) | **Best batch model.** 6+ granular findings, professional reports. Batch-only - fabricates in interactive mode. ~30 tok/s. |
| Qwen3 14B (dense) | ~10 GB | No (CPU offload) | 0.971 at Q4_K_M | Tested. Correct tool selection in batch mode. Fabricates in interactive. ~8 tok/s with partial offload. |

Qwen3.5 9B was released after the Docker study, so it has no published score
there.

Its figure is my own estimate from running it against this server, ***not a
measured F1***.

**In short:**
14 models were tested, and ***only the Qwen3/3.5 family produces usable
results***.

**Dense models outperform MoE for tool calling**. All parameters take part
in structured output generation, which reduces parameter name hallucination.

**BFCL benchmark scores do not predict Ollama compatibility**. The models
ranked \#3 and #4 on BFCL both failed because their tool-calling format
doesn't match Ollama's protocol.

### Tested Models (14 total)

| Model | Size | Tool Calling | Verdict |
|-------|------|-------------|---------|
| Qwen3 8B @64K | 5 GB | Excellent | **Daily driver** - no fabrication in interactive mode, 8/8 batch steps, 0 param hallucination. Saves 1 finding per run. |
| Qwen3.5 9B @49K | 6.6 GB | Excellent (batch) | **Best batch model** - 6 findings, professional reports. Fabricates in interactive mode. VRAM tight (7.3/8.2 GB). |
| Qwen3 14B | 9 GB | Good (batch) | Correct tool selection, sqlmap finds 4 injection types. Fabricates in interactive. ~8 tok/s. |
| Qwen3.5 35B-A3B (MoE) | 23 GB | Good (batch) | Excellent in batch mode, fabricates in single-step interactive. 32K context. |
| Hermes 3 8B | 4.7 GB | Marginal | Individual tool calls work, but can't chain in batch. Tool substitution (whatweb->http_request). sqlmap always silent. |
| Granite 4.0 (3.4B) | 2.1 GB | Marginal | Chains 2-4 calls autonomously (best non-Qwen chaining). Param hallucination: passes cookie to nmap, invalid scan_type values. |
| Llama 3-Groq 8B | 4.7 GB | Limited | Uses Ollama tool API correctly, but 8K context fatally small for 46 tools. Can't chain calls or call generate_report. |
| Granite 3.3 8B | 5 GB | **Incompatible** | Outputs tool names as plain text instead of structured API calls. |
| xLAM-2-8B-fc-r | 8.5 GB | **Incompatible** | Outputs tool calls as JSON arrays in text. Correct tool names and params, but ollmcp can't intercept them. |
| Phi-4-mini (3.8B) | 2.5 GB | **Incompatible** | Outputs tool calls as Python-like pseudo-code text. Never triggers Ollama tool API. |
| Dolphin 3.0 8B | 4.9 GB | **Incompatible** | No `tools` capability in Ollama - ollmcp refuses tool mode entirely. |
| Qwen 2.5 Coder 14B | 9 GB | **Incompatible** | Outputs tool calls as JSON text instead of using the tool-calling API. |
| Devstral 24B | 14 GB | **Not recommended** | ~90s/call (CPU offload), frequent empty responses, incorrect tool mapping. |
| Qwen3-Coder 32B | 18 GB | **Not recommended** | Overly autonomous - scans everything but saves 0 findings. Ollama XML crash. ~60s/call. |

### Models to Avoid

- **Ministral 3B/8B** fails silently with more than 2 tools attached, which
  is ***fatal for 46 tools***.
- **Mistral Nemo 12B** has an MCP role bug that breaks multi-turn tool use.
- **xLAM 8B** scored F1 0.570 in the Docker evaluation as
  `llama-xlam:8B-Q4_K_M`, and frequently misses tools.
- **xLAM-2-8B-fc-r**, the v2 model, outputs JSON text instead of using the
  Ollama tool API, despite BFCL #4.
- **Phi-4-mini** outputs pseudo-code instead of structured tool calls.
- **Dolphin 3.0** has ***no tool-calling support in Ollama*** at all.
- **DeepSeek models** need thinking mode disabled for tool calling.
- **Any model under 3B parameters** is unreliable for structured tool
  calling. Granite 4.0 at 3.4B is borderline.

## Context Budget System

The server tracks cumulative output across all tool calls in a session.

It dynamically adjusts the per-tool output caps to ***prevent context
overflow***.

### How It Works

On startup, the budget subtracts estimated overhead from `context_budget`:
- tool schema descriptions, at ~350 chars x 46 tools = ~16,100 chars,
- server instructions, at ~500 chars,
- AI reasoning per turn, at ~1,500 chars x `expected_tool_calls`.

The remainder is the **usable budget**. It is divided fairly among the
remaining expected tool calls.

As the session progresses, ***per-call caps shrink automatically***.

### Output Modes

Three modes escalate automatically as budget is consumed:

| Mode | Trigger | Per-call cap | Effect |
|------|---------|-------------|--------|
| Full | <40% consumed | Up to 8,000 chars | Normal parsed output, all findings |
| Compact | 40-70% consumed | Up to 3,000 chars | Aggressive truncation, top-N results only |
| Minimal | >70% consumed | Up to 500 chars | One-line summaries |

### Budget Status Line

Every tool response includes a status line:

```
[budget: 4200/38500 used | ~3430/call | mode: full]
```

This tells the AI model
- how much budget remains,
- the per-call allocation,
- the current output mode.

When the mode switches to compact or minimal, the model should ***prioritise
saving findings*** over running more scans.

### Adaptive Result Caps

Output parsers use `scale_cap()` to dynamically scale their result limits:
- **Full mode** uses 100% of the parser's default cap,
- **Compact mode** uses 50%, with a minimum of 3 results,
- **Minimal mode** uses 25%, with a minimum of 3 results.

These tools use adaptive caps:
- nmap at 10,
- nuclei at 25,
- nikto at 30,
- feroxbuster at 40,
- ffuf at 40,
- masscan at 50,
- subfinder at 50,
- enum4linux-ng at 20,
- dnsrecon at 30,
- wpscan at 20,
- dalfox at 20,
- httpx at 30,
- dnsx at 30,
- katana at 40.

### Truncation

When output exceeds the per-call cap, ***it is truncated***.

The head, 70%, and the tail, 30%, are preserved, with a `--- truncated ---`
marker between them.

### Recommended Context Budgets

| Model | context_budget | expected_tool_calls | Notes |
|-------|---------------|---------------------|-------|
| Qwen3 8B @64K | 65536 | 10 | Daily driver, interactive. Best balance of speed and capacity. |
| Qwen3.5 9B @49K | 49152 | 8 | Batch mode only. Tight VRAM - no room for thinking mode. |
| Qwen3 14B @40K | 40960 | 8 | Batch mode only. Partial CPU offload. |
| Cloud models | 0 (disabled) | - | Set `context_budget = 0` to disable budget tracking entirely. |

Configure in `config/default.toml`:

```toml
[safety]
context_budget = 65536
expected_tool_calls = 10
```

### Disabling the Budget

Set `context_budget = 0` to ***disable budgeting entirely***.

All tools then get `OutputMode::Full` with a generous 50,000-char cap, which
suits cloud models with large context windows.

## ANSI Stripping

All tool responses pass through centralised ANSI escape code stripping in
`wrap_result()` before they are sent to the model.

This covers every code path:
- parser output,
- raw fallback,
- error messages,
- background scan results.

***No ANSI codes leak through***, whichever tool or mode is used.

## Findings: owasp_category Field

The `save_finding` tool accepts an ***optional `owasp_category` field*** for
classifying findings by OWASP Top 10 category, such as
`"A03:2021 Injection"`.

It appears in generated reports alongside
- severity,
- CVSS,
- CVE.

## Known Issues and Workarounds

### Parameter Name Hallucination

Local models may use ***wrong parameter names*** based on their training
data.

For example, Qwen 3.5 used `"data"` instead of `"body"` for `http_request`.
That was likely influenced by Python's `requests.post(data=...)`.

**Built-in protection:**
Every request struct uses `#[serde(deny_unknown_fields)]`. A misnamed
parameter produces an explicit error message that names the invalid field,
and is ***not silently ignored***.

**Mitigation for users:**
When a tool call fails with a field error, check whether the model used the
correct parameter names from the schema.

Using explicit parameter names in your prompts helps:

```
Use raven.http_request to POST to http://example.com/login
with body "user=admin&pass=test"
```

The word "body" in the prompt primes the model to use the correct field name.

### Numeric Parameters Sent as Strings

Some models serialise numbers as JSON strings, sending `"2"` instead of
`2`.

This affected fields across all tool request structs, such as
- `level`,
- `risk`,
- `threads`,
- `port`,
- `timeout_secs`.

**Built-in protection:**
All numeric `Option` fields use a lenient deserialiser that ***accepts both
the number `2` and the string `"2"`***.

Invalid strings like `"abc"` still produce a clear parse error.

### Context Window Exhaustion

Local models have limited context, typically 32-64K tokens.

Raven Nest includes several built-in mitigations to reduce context
consumption.

**Context budget tracker:**
It automatically scales output verbosity from Full to Compact to Minimal as
the session progresses. See Context Budget System above.

**Built-in output parsers:**
Tool outputs are parsed into ***compact summaries*** instead of raw verbose
output.

- **sqlmap** extracts injection points and DBMS info, and strips progress
  lines.
- **nuclei** parses JSONL into a `[severity] template - name @ url` table.
- **nikto** keeps only finding lines, which are prefixed with `+`.
- **feroxbuster** extracts `status URL` pairs and filters 404s.
- **testssl** extracts vulnerability assessments and certificate info.
- **nmap** parses XML into a structured port/service table, with NSE script
  results and host scripts. In the NSE results, vulners is cut to the top-5
  CVEs by CVSS and other scripts are compressed to single-line summaries.
- **hydra** extracts cracked credentials.
- **whatweb** extracts technology identifications.
- **masscan** extracts open port/protocol pairs.
- **ffuf** extracts discovered URLs with status codes.
- **httpx** extracts per-URL status, title, tech and TLS.
- **dnsx** extracts resolved DNS records.
- **katana** extracts crawled/deduplicated endpoints.

**HTTP response reduction:**

- **HTML responses are automatically stripped to plain text**. Scripts and
  styles are removed along with the tags. HTML entities such as `&copy;` and
  `&#169;` are decoded to characters.
- **HTML comments**, written as `<!-- ... -->`, are fully stripped, with no
  residual `-->` fragments.
- **Only security-relevant response headers are returned**, such as server,
  set-cookie, content-type and location.
- **The response body is capped** at 20K characters.

**Report generation:**
It returns a severity breakdown summary and a file path instead of the full
report content.

**Server instructions:**
They are trimmed to essentials, ~600 chars against ~1500.

**Symptoms of exhaustion:**
After receiving a large tool response, the model
- returns an empty response, shown as "No content response received" in
  ollmcp,
- enters repetition loops,
- forgets tool names,
- generates incoherent output.

**Live-tested context budgets:**

- **Qwen3 8B at 32K** manages 3-4 tool calls before exhaustion.
- **Qwen3 8B at 64K with the q8_0 KV cache** completes ***8/8 steps with no
  exhaustion***. The context problem is solved.
- **Qwen3.5 9B at 49K** completes 8/8 steps, but thinking mode causes empty
  responses because it is VRAM-limited.
- **Thinking mode accelerates exhaustion**. Disable it for simple tool
  calls.
- **After clearing context** with `cc` in ollmcp, the model ***must
  re-authenticate***, since the session cookie is lost from context.

**Additional workarounds:**

- **Use `list_findings`**, which is compact at one line per finding, instead
  of reading full report files.
- **Use `get_finding`** to retrieve individual findings by ID rather than
  loading everything at once.
- **Keep loop limits modest**, at 10-15, to prevent runaway context growth.
- **Batch multiple steps into a single prompt** to maximise work per context
  fill. Qwen3 8B can chain 5-6 tool calls in one multi-step prompt.
- **When the model goes silent**, type `cc` to clear context and re-prompt
  for the remaining steps. Re-authenticate first.

### Interactive Fabrication (Qwen3.5 Variants)

All Qwen3.5 variants, both 9B dense and 35B-A3B MoE, ***fabricate tool
outputs*** in interactive single-step mode.

This is a universal architecture issue. The model generates
plausible-looking tool responses instead of actually calling tools.

Once one fake response enters context, the pattern persists even with
explicit tool names in the prompt.

**Workaround:**

- **Use Qwen3 8B for interactive work**. It does not fabricate.
- **Use Qwen3.5 9B for batch mode only**. Give all steps in a single prompt
  and the model calls tools correctly.

### Info-Level Finding Gap

Neither model reliably saves ***info-level findings*** in batch mode.

Both prioritise higher-severity results from nikto/sqlmap.

When nuclei is the only tool, which is individual mode, Qwen3 8B does save
the info finding.

**Mitigation, shipped:**
Enable server-side auto-save. Set `auto_save_findings = true` under
`[safety]`, and optionally `auto_save_min_severity = "info"` as well.

Qualifying findings from nuclei and seven other scanners are then extracted
and saved automatically, ***whether or not the model remembers to call
`save_finding`***.

The seven other scanners are
- nmap,
- nikto,
- dalfox,
- sqlmap,
- testssl,
- gitleaks,
- trufflehog.

### Tool Discovery Failures

Some clients, mcphost for one, or models may only "see" a subset of the
available tools.

If the model only uses filesystem tools and ignores raven tools:

1. **Check that the server name matches** what the model expects, with ***no
   hyphens***.
2. **Verify tools are listed** in the client's tool discovery output.
3. **Try explicitly naming the tool in your prompt**. Say "Use
   raven.run_nmap" rather than "scan the target".

## Cookie Passthrough for Authenticated Scanning

Many web targets require a session cookie.

The `http_request` cookie jar persists across `http_request` calls within a
session.

**Subprocess tools** run as separate OS processes and ***cannot access the
jar***. They are
- sqlmap,
- nikto,
- nuclei,
- feroxbuster,
- ffuf,
- whatweb,
- wpscan,
- dalfox.

Pass cookies explicitly:

```
Step 1: Use raven.http_request to POST to http://localhost/login.php
        with body "user=admin&pass=secret"
        -> the response includes a "Session Cookies" section with the
          PHPSESSID value (e.g. PHPSESSID=abc123; security_level=0)

Step 2: Use raven.run_sqlmap with url "http://localhost/page.php?id=1"
        and cookie "PHPSESSID=abc123;security_level=0"
```

The `http_request` response ***always includes a `--- Session Cookies ---`
section*** showing the cookies stored in the jar for that URL.

All web scanning tools accept a `cookie` parameter to pass these explicitly.

## Prompting Strategies

### Be Explicit with Tool Names

Weaker models struggle to map natural language to the right tool.

Instead of "scan for vulnerabilities", say "use raven.run_nuclei".

Once you confirm the model can call tools by name, you can gradually test
natural language.

### Batch vs Interactive

- **Interactive, with Qwen3 8B**. Go one step at a time: inspect the output,
  then decide the next action. It is ***the only mode where no fabrication
  occurs***.
- **Batch, with Qwen3.5 9B or 35B-A3B**. Give all steps in a single prompt
  and the model chains tool calls autonomously. It produces 6+ granular
  findings with professional reports. It ***must not be used
  interactively***.

### Thinking Mode

- **Disable thinking mode for simple tool invocations**, with `tm` in
  ollmcp. It wastes context budget and can cause empty responses at tight
  VRAM.
- **At Qwen3.5 9B**, with 7.3/8.2 GB VRAM, thinking mode is ***unusable***.
- **Thinking mode is useful** for complex reasoning about scan results.

### System Prompt Recommendations

When configuring the system prompt for your local model, include
- the exact tool prefix, for example "Tools are prefixed with `raven.`",
- a reminder that this is a controlled lab environment, which prevents the
  model from generating excessive safety disclaimers,
- parameter names for commonly used tools, which reduces hallucination,
- a note about context limits: "Keep responses concise. Do not reproduce
  full tool output in your response."

### Example System Prompt

```
You are a penetration testing assistant with access to security scanning
tools prefixed with "raven." (e.g., raven.run_nmap, raven.run_sqlmap).

Target environment: controlled security lab on localhost. All scanning is
authorised.

Key tool parameters:
- http_request: url, method, body, headers
- run_sqlmap: url, cookie, level, risk, data
- run_nuclei: target, severity, tags, cookie
- run_nikto: target, port, tuning, cookie
- run_feroxbuster: target, wordlist, extensions, cookie
- run_ffuf: url, wordlist, method, cookie
- run_nmap: target, ports, scan_type
- run_httpx: target, scan_type
- run_dnsx: target, scan_type
- run_katana: target, scan_type, depth
- run_subfinder: domain
- run_wpscan: url, cookie, api_token
- run_enum4linux_ng: target
- run_dalfox: url, cookie
- run_dnsrecon: domain, record_type
- run_john: hash_file, wordlist, format
- save_finding: title, severity, description, target, tool, owasp_category
- msf_search: query
- msf_exploit: module, options

All scanning tools accept a "cookie" parameter - pass session cookies
explicitly after authenticating with http_request.

Keep responses concise. Do not repeat raw tool output - summarise key
findings instead.
```

## ollmcp Configuration

### One-Time Setup

```bash
# Build the server
cargo build --release

# Install ollmcp
pipx install ollmcp

# Configure MCP server definition
cat > ~/.mcphost.json << 'EOF'
{
  "mcpServers": {
    "raven": {
      "command": "/path/to/raven-server",
      "args": [],
      "cwd": "/path/to/raven-nest-mcp"
    }
  }
}
EOF

# Configure ollmcp (system prompt, context, loop limit)
# See ~/.config/ollmcp/config.json - set num_ctx to match context_budget, loopLimit: 15

# Launch ollmcp once and disable HIL confirmations permanently:
# Type: hil > d > y, then save-config (sc)
```

### Per-Session Workflow

**Interactive, Qwen3 8B @64K:**
```bash
ollmcp --model qwen3:8b -j ~/.mcphost.json
# In ollmcp config: num_ctx=65536, context_budget=65536 in default.toml
```

**Batch pentesting, Qwen3.5 9B @49K:**
```bash
ollmcp --model qwen3.5:9b -j ~/.mcphost.json
# In ollmcp config: num_ctx=49152, context_budget=49152 in default.toml
```

Give a single prompt that batches all the steps:

```
Perform a full pentest of bWAPP at localhost. Execute these steps in order,
passing the session cookie to each scanning tool:
1. Login: POST to http://localhost/login.php with body
   "login=bee&password=bug&security_level=0&form=submit"
2. run_whatweb on http://localhost with the cookie
3. run_nmap on localhost ports 22,80,443
4. run_nikto on localhost with the cookie
5. run_feroxbuster on http://localhost with the cookie
6. run_sqlmap on http://localhost/sqli_1.php?title=test&action=search with the cookie
7. run_nuclei on http://localhost with the cookie
8. Save each vulnerability as a finding (include owasp_category), then generate a report
```

At 64K context, Qwen3 8B ***completes all 8 steps*** without exhaustion.

Qwen3.5 9B produces 6+ granular findings with professional reports.

### Monitoring Scans

For **background scans** launched via `launch_scan`:
- `list_scans` shows all running and completed background scans with their
  IDs,
- `get_scan_status(scan_id)` checks whether a specific scan is running,
  completed or failed,
- `get_scan_results(scan_id)` retrieves the output of a completed scan.

For **findings and reports:**
- `list_findings` lists all saved findings sorted by severity,
- `get_finding(finding_id)` gets the full finding details,
- `generate_report(title, format)` generates a report from all findings, in
  markdown by default or in json, sarif or html.

Direct tool calls such as run_nuclei and run_nmap ***return when done***.

During execution the MCP server sends progress notifications to the client,
when the client supplies a `progressToken` with the call.

## Reproduction Testing (severity=info)

Results from 3x identical runs per configuration:

**Qwen3 8B @64K, individual, nuclei severity=info only:**
- 3/3 runs produced exactly 1 info finding, from WAF/SNMPv3/SSH detection,
- the wording varies slightly but the detections are consistent.

**Qwen3 8B @64K, batch, full pentest with nuclei severity=info:**
- 3/3 runs produced exactly 1 high finding, SQL injection from sqlmap,
- info-level nuclei findings were ***never saved***, in 0/3 runs.

**Qwen3.5 9B @49K, batch, full pentest with nuclei severity=info:**
- the runs produced 6, 7 and 8 findings respectively, improving each time,
- an info-level finding was saved in ***only 1/3 runs***, the WAF detection,
- consistent across runs were SQLi as critical, outdated Apache/PHP as high,
  and missing headers as medium.

## Live Testing Results (2026-03-10)

### Model Comparison Summary

| Metric | Qwen3 8B @64K | Qwen3.5 9B @49K | Qwen3 14B @40K | Qwen3.5 35B-A3B @32K |
|--------|--------------|-----------------|---------------|---------------------|
| Architecture | Dense 8B | Dense 9B | Dense 14B | MoE 35B (3B active) |
| Batch mode | 8/8 steps | 8/8 steps, 6 findings | 9-17 tools | 15+ tools |
| Interactive mode | **No fabrication** | Fabricates at call #2 | Fabricates at call #3 | Fabricates |
| Cookie passthrough | Correct | Correct | Correct | Correct |
| Param hallucination | Zero | Zero (structured) | 1 (CVE) | Minor |
| Findings saved | 1 per run | 6 per run | 0-1 per run | 3-5 per run |
| Report quality | Poor (1 finding) | **Professional** | Poor | Good |
| Context exhaustion | None at 64K | None at 49K | None | None |
| VRAM usage | ~5 GB | 7.3 GB (tight) | CPU offload | CPU offload |
| Speed | ~40 tok/s | ~30 tok/s | ~8 tok/s | MoE variable |
| Recommendation | **Daily driver** | **Best batch** | Not recommended | Batch-only |

### Scaling to Larger Models

All Ollama models support layer splitting between GPU, which uses VRAM, and
CPU, which uses RAM, via `OLLAMA_NUM_GPU_LAYERS`.

This lets you ***run models larger than your VRAM***:

```bash
# Run 32B model: 20 layers on GPU, rest on CPU
OLLAMA_NUM_GPU_LAYERS=20 ollama run qwen3-coder:32b
```

Upgrade path for 8 GB VRAM + 32 GB RAM:

| Model | Context | VRAM Use | Speed | Use Case |
|-------|---------|----------|-------|----------|
| Qwen3 8B @64K | 64K | ~5 GB (full GPU) | ~40 tok/s | **Daily driver** - interactive + batch, no fabrication |
| Qwen3.5 9B @49K | 49K | ~7.3 GB (tight) | ~30 tok/s | **Best batch** - 6+ findings, professional reports |
| Qwen3 14B | 40K+ | GPU + CPU split | ~8 tok/s | Batch-only, CVE hallucination, not recommended |
| Devstral Small 2 24B | 128K | GPU + CPU split | ~6 tok/s | Not recommended - empty responses, slow |
| Qwen3-Coder 32B | 128K | GPU + CPU split | ~3-5 tok/s | Not recommended - no finding discipline |

## Resource Considerations

| Model | VRAM | Disk | Inference Speed |
|-------|------|------|----------------|
| Qwen3 8B (dense) | ~5 GB | ~5 GB | ~40 tok/s (tested, recommended) |
| Qwen3 14B (dense) | ~10 GB | ~10 GB | ~8 tok/s with partial offload |
| Qwen 3.5 35B-A3B (Q4) | ~22 GB | ~23 GB | Moderate (MoE, only 3B active) |
| Qwen3-Coder 32B | ~20 GB | ~20 GB | ~3-5 tok/s with layer splitting |

Running both Ollama and Raven Nest simultaneously is lightweight. The MCP
server is a single Rust binary with a minimal memory footprint.

***The LLM is the bottleneck***.

### Ollama KV Cache Optimisation

Halve KV cache VRAM cost to double effective context:

```bash
# Add to ~/.config/systemd/user/ollama.service [Service] section:
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
```

This is what lets Qwen3 8B run at ***64K context on 8GB VRAM***.
