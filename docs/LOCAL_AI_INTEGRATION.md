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
| Qwen3 8B (dense) | ~5 GB | Yes | 0.933 | Best balance of speed, accuracy, and VRAM fit. ~40 tok/s in VRAM. |
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

Local models have limited context (typically 32K tokens). Raven Nest's
tool outputs can be large — a full pentest report can exceed 20K
characters, consuming most of the context in one go.

**Symptoms:** model enters repetition loops, forgets tool names, or
generates incoherent output after receiving a large tool response.

**Workarounds:**
- Use `list_findings` (compact one-line-per-finding) instead of reading
  full report files
- Use `get_finding` to retrieve individual findings by ID rather than
  loading everything at once
- Keep loop limits modest (10-15) to prevent runaway context growth
- Avoid asking the model to "summarize everything" — it will try to
  reproduce the entire output

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

## Resource Considerations

| Model | VRAM | Disk | Inference Speed |
|-------|------|------|----------------|
| Qwen 3.5 35B-A3B (Q4) | ~22 GB | ~23 GB | Moderate (MoE architecture, only 3B active) |
| Qwen 2.5 Coder 14B (Q4) | ~10 GB | ~9 GB | Fast but doesn't support tool calling |

Running both Ollama and Raven Nest simultaneously is lightweight — the MCP
server is a single Rust binary with minimal memory footprint. The LLM is
the bottleneck.
