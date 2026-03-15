# Using Raven Nest with Local AI Models

Guide for connecting local LLMs (via Ollama, LM Studio, etc.) to Raven Nest
as MCP clients.

## MCP Client Options

| Client | Language | Notes |
|--------|----------|-------|
| [ollmcp](https://github.com/jonirrings/ollmcp) | Python | TUI with human-in-the-loop confirmation, `pipx install ollmcp` |
| [mcphost](https://github.com/nicobailon/mcphost) | Go | CLI, `go install` from GitHub |
| LM Studio | Desktop | Built-in MCP support via `.lmstudio/mcp.json` |

All three use `~/.mcphost.json` or their own config file to define MCP
servers.

## Server Naming: Avoid Hyphens

Many local models tokenize hyphens unpredictably, causing them to mangle
tool names like `raven-nest.run_nmap` into `raven_nest.run_nmap` or drop the
prefix entirely.

**Fix:** rename the server in your MCP config to a single unhyphenated word:

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

Tools then appear as `raven.run_nmap`, `raven.list_findings`, etc. — much
easier for smaller models to handle.

## Model Compatibility

### Recommended Models (by tool-calling reliability)

Best-to-worst for Raven Nest tool calling, based on the
[Docker practical evaluation](https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/)
(21 models, 3570 test cases) and hands-on testing.

| Model | Size | VRAM (8GB fit?) | Tool F1 | Notes |
|-------|------|-----------------|---------|-------|
| Qwen3 8B @64K (dense) | ~5 GB | Yes | 0.933 | **Daily driver.** Zero param hallucination, no interactive fabrication. 8/8 batch steps at 64K context. ~40 tok/s. |
| Qwen3.5 9B @49K (dense) | ~6.6 GB | Yes (tight, 7.3/8.2 GB) | ~0.93+ | **Best batch model.** 6+ granular findings, professional reports. Batch-only — fabricates in interactive mode. ~30 tok/s. |
| Qwen3 14B (dense) | ~10 GB | No (CPU offload) | 0.971 | Tested. Correct tool selection in batch mode. Fabricates in interactive. ~8 tok/s with partial offload. |

14 models tested — only the Qwen3/3.5 family produces usable results.
Dense models outperform MoE for tool calling — all parameters participate
in structured output generation, reducing parameter name hallucination.
BFCL benchmark scores do not predict Ollama compatibility — models ranked
\#3 and #4 on BFCL both failed because their tool-calling format doesn't
match Ollama's protocol.

### Tested Models (14 total)

| Model | Size | Tool Calling | Verdict |
|-------|------|-------------|---------|
| Qwen3 8B @64K | 5 GB | Excellent | **Daily driver** — no fabrication in interactive mode, 8/8 batch steps, 0 param hallucination. Saves 1 finding per run. |
| Qwen3.5 9B @49K | 6.6 GB | Excellent (batch) | **Best batch model** — 6 findings, professional reports. Fabricates in interactive mode. VRAM tight (7.3/8.2 GB). |
| Qwen3 14B | 9 GB | Good (batch) | Correct tool selection, sqlmap finds 4 injection types. Fabricates in interactive. ~8 tok/s. |
| Qwen3.5 35B-A3B (MoE) | 23 GB | Good (batch) | Excellent in batch mode, fabricates in single-step interactive. 32K context. |
| Hermes 3 8B | 4.7 GB | Marginal | Individual tool calls work, but can't chain in batch. Tool substitution (whatweb→http_request). sqlmap always silent. |
| Granite 4.0 (3.4B) | 2.1 GB | Marginal | Chains 2-4 calls autonomously (best non-Qwen chaining). Param hallucination: passes cookie to nmap, invalid scan_type values. |
| Llama 3-Groq 8B | 4.7 GB | Limited | Uses Ollama tool API correctly, but 8K context fatally small for 36 tools. Can't chain calls or call generate_report. |
| Granite 3.3 8B | 5 GB | **Incompatible** | Outputs tool names as plain text instead of structured API calls. |
| xLAM-2-8B-fc-r | 8.5 GB | **Incompatible** | Outputs tool calls as JSON arrays in text. Correct tool names and params, but ollmcp can't intercept them. |
| Phi-4-mini (3.8B) | 2.5 GB | **Incompatible** | Outputs tool calls as Python-like pseudo-code text. Never triggers Ollama tool API. |
| Dolphin 3.0 8B | 4.9 GB | **Incompatible** | No `tools` capability in Ollama — ollmcp refuses tool mode entirely. |
| Qwen 2.5 Coder 14B | 9 GB | **Incompatible** | Outputs tool calls as JSON text instead of using the tool-calling API. |
| Devstral 24B | 14 GB | **Not recommended** | ~90s/call (CPU offload), frequent empty responses, incorrect tool mapping. |
| Qwen3-Coder 32B | 18 GB | **Not recommended** | Overly autonomous — scans everything but saves 0 findings. Ollama XML crash. ~60s/call. |

### Models to Avoid

- **Ministral 3B/8B** — fails silently with >2 tools attached (fatal for 18+ tools)
- **Mistral Nemo 12B** — MCP role bug breaks multi-turn tool use
- **xLAM 8B (v1)** — F1 score 0.570, frequently misses tools
- **xLAM-2-8B-fc-r (v2)** — despite BFCL #4, outputs JSON text instead of using Ollama tool API
- **Phi-4-mini** — outputs pseudo-code instead of structured tool calls
- **Dolphin 3.0** — no tool-calling support in Ollama at all
- **DeepSeek models** — tool calling requires thinking mode disabled
- **Any model under 3B parameters** — unreliable for structured tool calling (Granite 4.0 at 3.4B is borderline)

## Known Issues and Workarounds

### Parameter Name Hallucination

Local models may use wrong parameter names based on their training data.
For example, Qwen 3.5 used `"data"` instead of `"body"` for
`http_request` — likely influenced by Python's `requests.post(data=...)`.

**Built-in protection:** all 18 request structs use
`#[serde(deny_unknown_fields)]`, so misnamed parameters produce an
explicit error message naming the invalid field instead of being silently
ignored.

**Mitigation for users:** when a tool call fails with a field error,
check whether the model used the correct parameter names from the schema.
Using explicit parameter names in your prompts helps:

```
Use raven.http_request to POST to http://example.com/login
with body "user=admin&pass=test"
```

The word "body" in the prompt primes the model to use the correct field name.

### Numeric Parameters Sent as Strings

Some models serialize numbers as JSON strings (`"2"` instead of `2`).
This affected fields like `level`, `risk`, `threads`, `port`, and
`timeout_secs` across all tool request structs.

**Built-in protection:** all numeric `Option` fields use a lenient
deserializer that accepts both `2` (number) and `"2"` (string). Invalid
strings like `"abc"` still produce a clear parse error.

### Context Window Exhaustion

Local models have limited context (typically 32K tokens). Raven Nest
includes several built-in mitigations to reduce context consumption:

**Built-in output parsers** — tool outputs are parsed into compact
summaries instead of raw verbose output:
- **sqlmap** — extracts injection points, DBMS info; strips progress lines
- **nuclei** — parses JSONL into `[severity] template — name @ url` table
- **nikto** — keeps only finding lines (prefixed with `+`)
- **feroxbuster** — extracts `status URL` pairs, filters 404s
- **testssl** — extracts vulnerability assessments and certificate info
- **nmap** — parses XML into structured port/service table, NSE script results (vulners top-5 CVEs by CVSS, other scripts compressed to single-line summaries), host scripts

**HTTP response reduction:**
- HTML responses are automatically stripped to plain text (scripts, styles,
  tags removed); HTML entities (`&copy;`, `&#169;`) decoded to characters
- HTML comments (`<!-- ... -->`) fully stripped, no residual `-->` fragments
- Only security-relevant response headers are returned (server,
  set-cookie, content-type, location, etc.)
- Response body capped at 20K characters

**Report generation** returns a severity breakdown summary + file path
instead of the full markdown report content.

**Server instructions** are trimmed to essentials (~600 chars vs ~1500).

**Symptoms of exhaustion:** the model returns an empty response
("No content response received" in ollmcp), enters repetition loops,
forgets tool names, or generates incoherent output after receiving a
large tool response.

**Live-tested context budgets:**
- Qwen3 8B at 32K: 3-4 tool calls before exhaustion
- Qwen3 8B at 64K (q8_0 KV cache): **8/8 steps with no exhaustion** — context problem solved
- Qwen3.5 9B at 49K: 8/8 steps, but thinking mode causes empty responses (VRAM-limited)
- Thinking mode accelerates exhaustion — disable it for simple tool calls
- After clearing context (`cc` in ollmcp), the model must re-authenticate
  since the session cookie is lost from context

**Additional workarounds:**
- Use `list_findings` (compact one-line-per-finding) instead of reading
  full report files
- Use `get_finding` to retrieve individual findings by ID rather than
  loading everything at once
- Keep loop limits modest (10-15) to prevent runaway context growth
- Batch multiple steps into a single prompt to maximise work per context
  fill — Qwen3 8B can chain 5-6 tool calls in one multi-step prompt
- When the model goes silent, type `cc` to clear context and re-prompt
  for remaining steps (re-authenticate first)

### Tool Discovery Failures

Some clients (mcphost) or models may only "see" a subset of available
tools. If the model only uses filesystem tools and ignores raven tools:

1. Check that the server name matches what the model expects (no hyphens)
2. Verify tools are listed in the client's tool discovery output
3. Try explicitly naming the tool in your prompt: "Use raven.run_nmap"
   rather than "scan the target"

## Prompting Strategies

### Be Explicit with Tool Names

Weaker models struggle to map natural language to the right tool. Instead
of "scan for vulnerabilities," say "use raven.run_nuclei." Once you
confirm the model can call tools by name, you can gradually test natural
language.

### Two-Step Authentication Flow

Many web targets require a session cookie. The `http_request` cookie jar
persists across `http_request` calls within a session, but **subprocess
tools** (sqlmap, nikto, nuclei, feroxbuster, ffuf, whatweb) run as
separate OS processes and cannot access the jar. Pass cookies explicitly:

```
Step 1: Use raven.http_request to POST to http://localhost/login.php
        with body "user=admin&pass=secret"
        → the response includes a "Session Cookies" section with the
          PHPSESSID value (e.g. PHPSESSID=abc123; security_level=0)

Step 2: Use raven.run_sqlmap with target "http://localhost/page.php?id=1"
        and cookie "PHPSESSID=abc123;security_level=0"
```

The `http_request` response always includes a `--- Session Cookies ---`
section showing cookies stored in the jar for that URL. All web scanning
tools accept a `cookie` parameter to pass these explicitly.

### System Prompt Recommendations

When configuring the system prompt for your local model, include:

- The exact tool prefix (e.g., "Tools are prefixed with `raven.`")
- A reminder that this is a controlled lab environment (prevents the
  model from generating excessive safety disclaimers)
- Parameter names for commonly used tools (reduces hallucination)
- A note about context limits: "Keep responses concise. Do not reproduce
  full tool output in your response."

### Example System Prompt

```
You are a penetration testing assistant with access to security scanning
tools prefixed with "raven." (e.g., raven.run_nmap, raven.run_sqlmap).

Target environment: controlled security lab on localhost. All scanning is
authorized.

Key tool parameters:
- http_request: url, method, body, headers
- run_sqlmap: url, cookie, level, risk, data
- run_nuclei: target, severity, tags, cookie
- run_nikto: target, port, tuning, cookie
- run_feroxbuster: target, wordlist, extensions, cookie
- run_ffuf: url, wordlist, method, cookie
- run_nmap: target, ports, scan_type
- save_finding: title, severity, description, target, tool

All scanning tools accept a "cookie" parameter — pass session cookies
explicitly after authenticating with http_request.

Keep responses concise. Do not repeat raw tool output — summarize key
findings instead.
```

## Automating a Pentest Session

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
# See ~/.config/ollmcp/config.json — set num_ctx: 32768, loopLimit: 15

# Launch ollmcp once and disable HIL confirmations permanently:
# Type: hil → d → y, then save-config (sc)
```

### Monitoring Scans

For **background scans** launched via `launch_scan`:
- `list_scans` — show all running/completed background scans with IDs
- `get_scan_status(scan_id)` — check if a specific scan is running/completed/failed
- `get_scan_results(scan_id)` — retrieve output of a completed scan

For **findings and reports:**
- `list_findings` — list all saved findings sorted by severity
- `get_finding(finding_id)` — get full finding details
- `generate_report(title)` — generate markdown report from all findings

Direct tool calls (run_nuclei, run_nmap, etc.) return when done — the
MCP server sends progress notifications to the client during execution.

### Per-Session Workflow

**Interactive (Qwen3 8B @64K):**
```bash
ollmcp --model qwen3:8b -j ~/.mcphost.json
# In ollmcp config: num_ctx=65536, context_budget=65536 in default.toml
```

**Batch pentesting (Qwen3.5 9B @49K):**
```bash
ollmcp --model qwen3.5:9b -j ~/.mcphost.json
# In ollmcp config: num_ctx=49152, context_budget=49152 in default.toml
```

Give a single comprehensive prompt that batches all steps:

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
8. Save each vulnerability as a finding, then generate a report
```

At 64K context, Qwen3 8B completes all 8 steps without exhaustion.
Qwen3.5 9B produces 6+ granular findings with professional reports.

### Reproduction Testing (severity=info)

Results from 3x identical runs per configuration:

**Qwen3 8B @64K — Individual (nuclei severity=info only):**
- 3/3 runs produced exactly 1 info finding (WAF/SNMPv3/SSH detection)
- Wording varies slightly but detections are consistent

**Qwen3 8B @64K — Batch (full pentest with nuclei severity=info):**
- 3/3 runs produced exactly 1 high finding (SQL injection from sqlmap)
- Info-level nuclei findings were never saved (0/3 runs)

**Qwen3.5 9B @49K — Batch (full pentest with nuclei severity=info):**
- Runs produced 6, 7, and 8 findings respectively (improving)
- Info-level finding saved in only 1/3 runs (WAF detection)
- Consistent: SQLi (critical), outdated Apache/PHP (high), missing headers (medium)

**Key gap:** Neither model reliably saves info-level findings in batch mode.
Both prioritize higher-severity results from nikto/sqlmap. When nuclei is
the only tool (individual mode), Qwen3 8B does save the info finding.

### Current Limitations

- **Interactive fabrication** — all Qwen3.5 variants fabricate tool
  outputs in interactive single-step mode. Use Qwen3 8B for interactive,
  Qwen3.5 9B for batch only
- **Qwen3 8B finding granularity** — saves only 1 summarized finding per
  batch instead of individual findings for each vulnerability
- **Info-level findings not saved** — both models skip info-severity
  nuclei results when higher-severity findings exist in the same batch
- **No non-interactive mode** — ollmcp requires a TTY; you cannot pipe
  prompts from a script
- **Thinking mode** can waste token budget on short prompts — disable it
  (`tm`) for simple tool invocations. At tight VRAM (Qwen3.5 9B), thinking
  mode causes empty responses

### Scaling to Larger Models

All Ollama models support layer splitting between GPU (VRAM) and CPU
(RAM) via `OLLAMA_NUM_GPU_LAYERS`. This lets you run models larger than
your VRAM:

```bash
# Run 32B model: 20 layers on GPU, rest on CPU
OLLAMA_NUM_GPU_LAYERS=20 ollama run qwen3-coder:32b
```

Upgrade path for 8 GB VRAM + 32 GB RAM:

| Model | Context | VRAM Use | Speed | Use Case |
|-------|---------|----------|-------|----------|
| Qwen3 8B @64K | 64K | ~5 GB (full GPU) | ~40 tok/s | **Daily driver** — interactive + batch, no fabrication |
| Qwen3.5 9B @49K | 49K | ~7.3 GB (tight) | ~30 tok/s | **Best batch** — 6+ findings, professional reports |
| Qwen3 14B | 40K+ | GPU + CPU split | ~8 tok/s | Batch-only, CVE hallucination, not recommended |
| Devstral Small 2 24B | 128K | GPU + CPU split | ~6 tok/s | Not recommended — empty responses, slow |
| Qwen3-Coder 32B | 128K | GPU + CPU split | ~3-5 tok/s | Not recommended — no finding discipline |

Larger context (128K) eliminates the biggest pain point: models can
chain 15+ tool calls without going silent, enabling full automated
pentest sessions without manual intervention.

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

### Qwen3 8B (Dense, 32K context)

Tested against bWAPP (localhost:80) via ollmcp + Qwen3 8B. All 7 context
reduction bugfixes verified end-to-end with the local model driving tool
calls.

### Fixes Verified

| Fix | Issue | Test | Result |
|-----|-------|------|--------|
| 1 | nikto `-cookie` flag doesn't exist | nikto ran with real findings (32 items), not help text | Pass |
| 2 | sqlmap "resumed" injection points lost | All 4 injection types preserved in resumed output | Pass |
| 3 | nikto help text parsed as finding | No `+ requires a value` lines, all real findings | Pass |
| 4 | HTML comments not stripped | Zero `-->` residue in http_request body | Pass |
| 5 | HTML entities not decoded | `© 2014` decoded correctly (not `&copy;`) | Pass |
| 6 | feroxbuster includes 404s | 220 URLs discovered, zero 404 entries | Pass |
| 7 | Empty report has trailing `: ` | Clean `0 finding(s)` output | Pass |

### Interventions Required

7 manual interventions were needed during the session:

| # | Issue | Root Cause |
|---|-------|------------|
| 1 | HIL confirmation dialogs | ollmcp defaults to HIL=on; required 3 inputs to disable |
| 2 | Qwen3 silent on portal.php fetch | Thinking mode consumed all output tokens |
| 3 | Qwen3 silent on feroxbuster prompt | Context exhausted after 4 tool calls |
| 4 | Qwen3 silent on "Generate report" x2 | Thinking mode + short prompt = zero response budget |
| 5 | Qwen3 silent with thinking off | Prompt with quotes confused the model; rephrasing fixed it |

### Tools Exercised

7 of 22 tools were exercised: `ping_target`, `http_request`, `run_nikto`,
`run_sqlmap`, `run_feroxbuster`, `save_finding`, `generate_report`.

Not tested (not part of the fix verification scope): `run_nmap`,
`run_nuclei`, `run_whatweb`, `run_ffuf`, `run_testssl`, `run_hydra`,
`run_masscan`, background scan management, finding management tools.

### Key Observations

- Qwen3 8B produces zero parameter hallucination — `deny_unknown_fields`
  was never triggered
- Multi-step prompts work better than sequential single-step prompts —
  the model chains tool calls efficiently when given all steps upfront
- Context exhaustion is predictable: 32K fills after nikto (~2K) +
  sqlmap (~1.5K) + feroxbuster (~3K) + accumulated prompt/response tokens
- Disabling thinking mode recovers ~30% of context budget for simple tasks

## Improvement Roadmap

### Context Efficiency (highest impact)
- Add filtered 404 count to feroxbuster output (e.g. "220 URLs, 42
  filtered") for coverage context without extra tokens
- Consider an adaptive output budget — detect model context size from
  server instructions and truncate more aggressively for smaller models
- Group nikto findings by category (headers, directories, outdated
  software) instead of one-per-line to reduce token count

### Automation
- Document ollmcp config for pre-disabling HIL and setting thinking mode
- Investigate programmatic interfaces (non-TTY) for scripted pentesting
- Consider a "session resume" mechanism that preserves cookies across
  context clears

### Tool Coverage
- Test remaining tools (nmap, nuclei, whatweb, ffuf, testssl, hydra,
  masscan, background scans) through ollmcp

## Resource Considerations

| Model | VRAM | Disk | Inference Speed |
|-------|------|------|----------------|
| Qwen3 8B (dense) | ~5 GB | ~5 GB | ~40 tok/s (tested, recommended) |
| Qwen3 14B (dense) | ~10 GB | ~10 GB | ~8 tok/s with partial offload |
| Qwen 3.5 35B-A3B (Q4) | ~22 GB | ~23 GB | Moderate (MoE, only 3B active) |
| Qwen3-Coder 32B | ~20 GB | ~20 GB | ~3-5 tok/s with layer splitting |

Running both Ollama and Raven Nest simultaneously is lightweight — the MCP
server is a single Rust binary with minimal memory footprint. The LLM is
the bottleneck.
