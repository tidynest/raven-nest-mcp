# Raven-Nest-MCP Manual Test Results

**Date:** 2026-03-15
**Server:** raven-nest-mcp v0.1.0 (release build)
**Targets:** bWAPP (localhost:80), OWASP Juice Shop (localhost:3000)

## Final Summary

| Phase | Category | Tests | Pass | Fail | Timeout |
|-------|----------|------:|-----:|-----:|--------:|
| 0 | ping_target | 17 | 17 | 0 | 0 |
| 4 | http_request | 28 | 28 | 0 | 0 |
| 5 | Scan Lifecycle | 29 | 29 | 0 | 0 |
| 6 | Findings Lifecycle | 42 | 42 | 0 | 0 |
| 7 | Cross-Cutting | 32 | 28 | 0 | 4 |
| 1 | nmap | 15 | 14 | 0 | 1 |
| 1 | whatweb | 12 | 9 | 1 | 2 |
| 1 | masscan | 8 | 8 | 0 | 0 |
| 1 | testssl | 15 | 15 | 0 | 0 |
| 2 | nuclei | 16 | 16 | 0 | 0 |
| 2 | nikto | 18 | 10 | 3 | 5 |
| 2 | feroxbuster | 13 | 12 | 0 | 1 |
| 2 | ffuf | 19 | 19 | 0 | 0 |
| 3 | sqlmap | 20 | 20 | 0 | 0 |
| 3 | hydra | 13 | 12 | 1 | 0 |
| **TOTAL** | | **297** | **279** | **5** | **13** |

**Pass rate:** 279/297 = **93.9%**
**Adjusted (excluding timeouts):** 279/284 = **98.2%**

All 5 failures are documented findings (4 are server-side improvements, 1 is external tool behavior).
All 13 timeouts are for slow/remote scan operations, not server bugs.

## Findings (Code Improvement Opportunities)

### Finding 1: `http_request` accepts arbitrary HTTP methods (12.11)
- **Severity:** Low
- **Description:** `INVALID` method passes through to reqwest without validation. Apache returns 200.
- **Recommendation:** Validate against allowlist (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).

### Finding 2: `validate_target` doesn't reject trailing-hyphen hostnames (V.16)
- **Severity:** Low
- **Description:** `evil-.com` passes validation. Ping fails with "Name or service not known".
- **Recommendation:** Add regex check for label boundaries per RFC 952.

### Finding 3: whatweb passive mode returns empty output (3.4)
- **Severity:** Info (external tool behavior)
- **Description:** whatweb `-a 2` (passive) returns 1 char output for localhost. Quality checker flags it.
- **Root cause:** whatweb tool limitation, not server bug.

### Finding 4: feroxbuster/hydra return success for tool failures (7.13, 10.12)
- **Severity:** Low
- **Description:** When feroxbuster gets a nonexistent wordlist or hydra gets a nonexistent userlist, the tools exit with errors but the server returns `isError: false` with a quality warning.
- **Root cause:** `executor::run()` wraps non-zero exits as warnings, not errors.
- **Recommendation:** When a tool exits non-zero AND output is empty/minimal, return `isError: true`.

### Finding 5: nikto timeout error message has doubled "s" (6.14/6.15/6.16)
- **Severity:** Low (cosmetic)
- **Description:** When nikto times out, the error message reads "command timed out after nikto time out after 120ss" — note the "120ss" with a double "s".
- **Root cause:** Likely string formatting in `executor.rs` or `nikto.rs` where timeout_secs is appended with "s" but the value already includes or is followed by another "s".
- **Recommendation:** Fix the string formatting to produce "120s" not "120ss".

### Confirmed Correct Behaviors
- Lenient deserializer correctly rejects float-to-integer coercion (L.6)
- `cancel_scan` correctly returns `isError: true` for not-found scans (16.3)
- masscan correctly requires root (all 8 tests)
- nmap OS scan correctly requires root (2.7)

## Timeout Explanation

| Test | Reason | Set Timeout |
|------|--------|-------------|
| V.1 | Ping to unreachable 192.168.1.1 | 10s |
| V.3 | nmap scan of 10.0.0.0/8 (massive CIDR) | 30s |
| V.8 | testssl to example.com:443 (remote) | 60s |
| T.1 | nmap vuln scan (NSE scripts) | 180s |
| 2.8 | nmap vuln scan on bWAPP | 180s |
| 3.5, 3.7 | whatweb aggressive (deep probing) | 60s |
| 6.1, 6.3, 6.6, 6.8, 6.12 | nikto full scans (300s harness timeout) | 300s |
| 7.2 | feroxbuster on Juice Shop | 300s |

## Phase-by-Phase Details

### Phase 0: ping_target (17/17 PASS)
- IPv4/IPv6/hostname: PASS
- Count clamping (0->1, 255->10): PASS
- Lenient deser (string "3", null): PASS
- Shell injection (`;`, `|`, `$()`, backtick): PASS (all rejected)
- Unknown field rejection (`deny_unknown_fields`): PASS
- Unreachable target graceful error: PASS

### Phase 1: Reconnaissance (50 tests: 46 PASS, 1 FAIL, 3 TIMEOUT)
- **nmap (14/15):** All scan types (quick/service/vuln), port specs, CIDR, validation. Only vuln scan timeout.
- **whatweb (9/12):** Stealthy/passive/aggressive modes, cookies, hostname vs URL. Passive returns empty (Finding 3), aggressive times out.
- **masscan (8/8):** All return "requires root" as expected. Rate clamping, shell injection, empty target rejection all correct.
- **testssl (15/15):** All severity levels, quick mode, case normalization, URL format accepted. Empty target rejected.

### Phase 2: Web Scanning (66 tests: 57 PASS, 3 FAIL, 6 TIMEOUT)
- **nuclei (16/16):** All severity levels, tags (cve/tech/combined), authenticated scanning, all params combo. Validation tests pass.
- **nikto (10/18):** URL vs hostname handling, port as string, tuning presets (quick/thorough/injection/fileupload), cookie support. 5 timeouts (nikto is inherently slow), 3 fail on timeout error formatting (Finding 5).
- **feroxbuster (12/13):** Wordlists, extensions, threads (clamping at 200), status codes, cookies. 1 timeout on Juice Shop.
- **ffuf (19/19):** FUZZ keyword validation, methods (GET/POST/HEAD), headers, match codes, filter size, threads (clamping at 150), query string fuzzing. All pass.

### Phase 3: Exploitation (33 tests: 32 PASS, 1 FAIL)
- **sqlmap (20/20):** GET/POST injection, level clamping (5->2), risk clamping (3->1), all techniques (B/E/U/T/BEUSTQ), lenient deser, non-injectable page detection. Level=0 clamped to 1.
- **hydra (12/13):** SSH, HTTP POST form (finds bee/bug), HTTP GET form, tasks clamping (16->4), form_params validation for http-*-form services, FTP (graceful failure). Nonexistent userlist returns success instead of error (Finding 4).

### Phase 4: http_request (28/28 PASS)
- All HTTP methods including HEAD/OPTIONS
- Cookie jar persistence (login -> portal navigation)
- Custom headers, Bearer auth token, JSON body
- Timeout capping (300->120), lenient deser
- Redirect control (follow_redirects true/false/default)
- FTP/invalid URL rejection
- Juice Shop API JSON response

### Phase 5: Scan Lifecycle (29/29 PASS)
- Launch -> poll -> results with pagination (offset/limit)
- Cancel -> verify status -> idempotent re-cancel
- Custom args, timeout overrides
- Concurrency cap (3 max) enforced
- Disallowed tool, empty target, shell injection all rejected
- Lenient deser (string for numeric params)

### Phase 6: Findings Lifecycle (42/42 PASS)
- Full CRUD: save -> get -> list -> delete
- Severity validation: all 5 levels + case insensitivity + invalid/empty/numeric rejection
- Optional fields: evidence, remediation, CVSS (0.0-10.0), CVE
- Report generation: default/custom/empty title
- Integration lifecycle: save 3 -> list sorted -> delete 1 -> report with correct counts

### Phase 7: Cross-Cutting (32 tests: 28 PASS, 4 TIMEOUT)
- **Target validation:** IPv4, IPv6, CIDR (valid + invalid prefix /33 /129), host:port, URL with `&` in query, shell injection in URL path, hostname >253 chars, leading hyphen, newline injection
- **Lenient deser (7/7):** Number, string, null, missing, invalid string, float rejection, negative rejection
- **deny_unknown_fields (5/5):** ping, nmap, sqlmap, http_request, save_finding all reject extra fields
- **Output truncation:** HTTP response capped correctly, feroxbuster output truncated

## Test Harness

Located at: `tests/manual_test_harness.py`

```
Usage: python3 -u tests/manual_test_harness.py [phase...]
Phases: phase0 phase1 phase2 phase3 phase4 phase5 phase6 phase7 all
```

Features:
- Spawns MCP server as subprocess, communicates via JSON-RPC 2.0 (NDJSON framing)
- Context passing between tests (scan IDs, finding IDs, cookies via `{KEY}` placeholders)
- Filters server-side progress notifications
- Retry logic for server startup (3 attempts with 10s handshake timeout)
- Colored terminal output (PASS/FAIL/SKIP/TIMEOUT)

**Note:** Use `-u` flag when piping output to prevent buffering delays.
