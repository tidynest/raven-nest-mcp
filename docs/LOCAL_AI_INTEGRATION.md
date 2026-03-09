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
| Qwen3 8B (dense) | ~5 GB | Yes | 0.933 | Tested and recommended. Zero param hallucination, correct tool semantics. ~40 tok/s. Context exhausts after 3-4 large tool outputs at 32K. |
| Qwen3 14B (dense) | ~10 GB | No (CPU offload) | 0.971 | Near GPT-4 accuracy. ~8 tok/s with partial offload. |
| Qwen3-Coder 32B | ~20 GB | No (RAM) | Excellent | Community gold standard for MCP/agent tool calling. |
| Granite 3.3 8B (IBM) | ~5 GB | Yes | Good | Designed for tool use. Companion Guardian model for hallucination detection. |
| Mistral Small 3.1 24B | ~14 GB | No (CPU offload) | Good | Native tool calling, competitive with Llama 3.3 70B in general benchmarks. |
| Hermes 3 8B | ~5 GB | Yes | Moderate | Fine-tuned for function calling but uses own template, not Ollama native. |

Dense models outperform MoE for tool calling — all parameters participate
in structured output generation, reducing parameter name hallucination.

### Tested Models

| Model | Size | Tool Calling | Notes |
|-------|------|-------------|-------|
| Qwen 3.5 35B-A3B (MoE) | 23 GB | Partial | Calls tools but hallucinates parameter names. MoE routing inconsistency. 32K context. |
| Qwen 2.5 Coder 14B | 9 GB | Broken | Outputs tool calls as JSON text instead of using the tool-calling API — never executes tools. |
| Qwen 2.5 Coder 7B/1.5B | 4.7/1.3 GB | Untested | Likely too small for reliable multi-tool orchestration. |

### Models to Avoid

- **xLAM 8B** — F1 score 0.570, frequently misses tools
- **DeepSeek models** — tool calling requires thinking mode disabled
- **Any model under 4B parameters** — unreliable for structured tool calling

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
- **nmap** — parses XML into structured port/service table (existing)

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

**Live-tested context budget (Qwen3 8B, 32K context):**
- 3-4 tool calls with large outputs (nikto, sqlmap) before exhaustion
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

### Per-Session Workflow

```bash
ollmcp --model qwen3:8b -j ~/.mcphost.json
```

Give a single comprehensive prompt that batches all steps:

```
Login to bWAPP at localhost (bee/bug). Run nikto with quick tuning and
sqlmap on http://localhost/sqli_1.php?title=test&action=search.
Save any SQL injection findings and generate a final report.
```

Qwen3 8B chains 5-6 tool calls autonomously: login → nikto → sqlmap →
save_finding → generate_report. When it goes silent (context full),
type `cc` to clear context and re-prompt for remaining steps.

### Current Limitations

- **Context exhaustion** is the main bottleneck — clearing context loses
  the session cookie, requiring re-authentication
- **No non-interactive mode** — ollmcp requires a TTY; you cannot pipe
  prompts from a script
- **Thinking mode** can waste token budget on short prompts — disable it
  (`tm`) for simple tool invocations, re-enable for multi-step reasoning

### Scaling to Larger Models

All Ollama models support layer splitting between GPU (VRAM) and CPU
(RAM) via `OLLAMA_NUM_GPU_LAYERS`. This lets you run models larger than
your VRAM:

```bash
# Run 32B model: 20 layers on GPU, rest on CPU
OLLAMA_NUM_GPU_LAYERS=20 ollama run qwen3-coder:32b
```

Upgrade path for 8 GB VRAM + 32 GB RAM:

| Model | Context | VRAM Use | Speed | Improvement |
|-------|---------|----------|-------|-------------|
| Qwen3 8B (current) | 32K | 5 GB (full GPU) | ~40 tok/s | Baseline — exhausts after 3-4 tools |
| Qwen3 14B dense | 128K | 8 GB (GPU) + 2 GB (RAM) | ~8 tok/s | 4x context, near-perfect tool F1 |
| Devstral Small 2 24B | 128K | 8 GB (GPU) + 6 GB (RAM) | ~6 tok/s | Agentic coding model, native tool calling |
| Qwen3-Coder 32B | 128K | 8 GB (GPU) + 12 GB (RAM) | ~3-5 tok/s | Gold standard for MCP, no context exhaustion |

Larger context (128K) eliminates the biggest pain point: models can
chain 15+ tool calls without going silent, enabling full automated
pentest sessions without manual intervention.

## Live Testing Results (2026-03-09)

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
- Add output parsers for tools that don't have them yet (hydra, whatweb,
  masscan, ffuf)

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
