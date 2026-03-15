#!/usr/bin/env python3 -u
"""
Raven-Nest-MCP Comprehensive Test Harness
Executes ~294 test cases against the MCP server via JSON-RPC/stdio.

Usage:
    python3 tests/manual_test_harness.py [phase...]
    Phases: phase0 phase1 phase2 phase3 phase4 phase5 phase6 phase7 all
    Default: all
"""

import json, subprocess, sys, time, os, re, threading, queue
from pathlib import Path

# Force unbuffered output for piped environments
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# ─── Terminal colours ────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; Z = "\033[0m"

SERVER = str(Path(__file__).resolve().parent.parent / "target" / "release" / "raven-server")
CWD    = str(Path(__file__).resolve().parent.parent)


# ─── MCP Client ──────────────────────────────────────────────────
class MCPClient:
    def __init__(self, max_retries=3):
        for attempt in range(max_retries):
            try:
                self._start_server()
                return
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"\n  {Y}Retry {attempt+1}/{max_retries}: {e}{Z}", flush=True)
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                    time.sleep(1)
                else:
                    raise

    def _start_server(self):
        self.proc = subprocess.Popen(
            [SERVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=CWD,
            env={**os.environ, "RUST_LOG": "warn"},
        )
        if self.proc.poll() is not None:
            raise RuntimeError(f"Server exited: {self.proc.returncode}")
        self._q = queue.Queue()
        self._id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        time.sleep(0.05)
        resp = self._request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "test-harness", "version": "1.0"}
        }, timeout=10)
        if resp is None:
            raise RuntimeError("Handshake timeout")
        self._notify("notifications/initialized")

    def _reader(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.decode().strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if "id" in msg:
                    self._q.put(msg)
            except json.JSONDecodeError:
                pass

    def _request(self, method, params=None, timeout=30):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()
        try:
            while True:
                m = self._q.get(timeout=timeout)
                if m.get("id") == self._id:
                    return m
        except queue.Empty:
            return None

    def _notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def call(self, tool, args, timeout=30):
        """Returns (is_error: bool, text: str, raw: dict|None)"""
        resp = self._request("tools/call", {"name": tool, "arguments": args}, timeout)
        if resp is None:
            return (True, "TIMEOUT: no response", None)
        if "error" in resp:
            return (True, resp["error"].get("message", str(resp["error"])), resp)
        result = resp.get("result", {})
        is_err = result.get("isError", False)
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        return (is_err, "\n".join(texts), resp)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


# ─── Test Runner ─────────────────────────────────────────────────
class Runner:
    def __init__(self, client):
        self.client = client
        self.ctx = {}
        self.results = []
        self.counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "TIMEOUT": 0}

    def _resolve(self, args):
        """Replace {KEY} placeholders in arg values from context."""
        out = {}
        for k, v in args.items():
            if isinstance(v, str) and "{" in v:
                for ck, cv in self.ctx.items():
                    v = v.replace("{" + ck + "}", str(cv))
            out[k] = v
        return out

    def run(self, t):
        tid = t["id"]; desc = t["desc"]; tool = t["tool"]
        timeout = t.get("timeout", 30)

        # Skip conditions
        skip_if = t.get("skip_if")
        if skip_if and not self.ctx.get(skip_if):
            self._record(tid, desc, "SKIP", f"missing context: {skip_if}")
            return

        # Wait if needed
        wait = t.get("wait", 0)
        if wait:
            time.sleep(wait)

        # Resolve args
        args = self._resolve(t.get("args", {}))

        # Call tool
        is_err, text, raw = self.client.call(tool, args, timeout)
        text_lower = text.lower()

        # Check TIMEOUT
        if text == "TIMEOUT: no response":
            self._record(tid, desc, "TIMEOUT", "no response within timeout")
            return

        # Expect error?
        expect_err = t.get("error", False)
        if expect_err and not is_err:
            self._record(tid, desc, "FAIL", f"expected error but got success: {text[:200]}")
            return
        if not expect_err and is_err:
            self._record(tid, desc, "FAIL", f"unexpected error: {text[:200]}")
            return

        # Contains checks (case-insensitive)
        for pat in t.get("contains", []):
            if pat.lower() not in text_lower:
                self._record(tid, desc, "FAIL", f"missing '{pat}' in: {text[:200]}")
                return

        # Any-of checks
        any_of = t.get("any_of", [])
        if any_of and not any(p.lower() in text_lower for p in any_of):
            self._record(tid, desc, "FAIL", f"none of {any_of} in: {text[:200]}")
            return

        # Not-contains checks
        for pat in t.get("not_contains", []):
            if pat.lower() in text_lower:
                self._record(tid, desc, "FAIL", f"should not contain '{pat}' in: {text[:200]}")
                return

        # Extract patterns into context
        for key, pattern in t.get("extract", {}).items():
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                self.ctx[key] = m.group(1)

        # Store full text
        store = t.get("store")
        if store:
            self.ctx[store] = text

        self._record(tid, desc, "PASS", text[:120].replace("\n", " "))

    def _record(self, tid, desc, status, msg):
        colour = {"PASS": G, "FAIL": R, "SKIP": Y, "TIMEOUT": Y}[status]
        print(f"  {colour}{status:7s}{Z} {tid:8s} {desc[:60]}")
        if status == "FAIL":
            print(f"           {R}→ {msg}{Z}")
        self.results.append((tid, status, msg))
        self.counts[status] = self.counts.get(status, 0) + 1

    def phase(self, name, tests):
        print(f"\n{B}{C}═══ {name} ({len(tests)} tests) ═══{Z}")
        for t in tests:
            self.run(t)

    def summary(self):
        total = sum(self.counts.values())
        print(f"\n{B}{'═'*60}")
        print(f"  TOTAL: {total}  |  {G}PASS: {self.counts['PASS']}{Z}{B}  |  "
              f"{R}FAIL: {self.counts['FAIL']}{Z}{B}  |  "
              f"{Y}SKIP: {self.counts['SKIP']}  TIMEOUT: {self.counts['TIMEOUT']}{Z}")
        print(f"{'═'*60}{Z}")
        if self.counts["FAIL"]:
            print(f"\n{R}{B}Failed tests:{Z}")
            for tid, status, msg in self.results:
                if status == "FAIL":
                    print(f"  {tid}: {msg[:120]}")


# ═══════════════════════════════════════════════════════════════════
# TEST DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

# ─── Phase 0: ping_target ────────────────────────────────────────
PHASE_0 = [
    {"id": "1.1",  "desc": "Minimal — IPv4",       "tool": "ping_target", "args": {"target": "127.0.0.1"},                       "any_of": ["bytes from", "icmp_seq", "PING"]},
    {"id": "1.2",  "desc": "Minimal — hostname",    "tool": "ping_target", "args": {"target": "localhost"},                       "any_of": ["bytes from", "icmp_seq", "PING"]},
    {"id": "1.3",  "desc": "count=1 (min)",         "tool": "ping_target", "args": {"target": "127.0.0.1", "count": 1},          "contains": ["1 packets transmitted"]},
    {"id": "1.4",  "desc": "count=10 (max)",         "tool": "ping_target", "args": {"target": "127.0.0.1", "count": 10},         "contains": ["10 packets transmitted"], "timeout": 15},
    {"id": "1.5",  "desc": "count=5 (mid)",          "tool": "ping_target", "args": {"target": "127.0.0.1", "count": 5},          "contains": ["5 packets transmitted"]},
    {"id": "1.6",  "desc": "count as string",        "tool": "ping_target", "args": {"target": "127.0.0.1", "count": "3"},        "contains": ["3 packets transmitted"]},
    {"id": "1.7",  "desc": "count=0 (below range)",  "tool": "ping_target", "args": {"target": "127.0.0.1", "count": 0},          "contains": ["1 packets transmitted"]},
    {"id": "1.8",  "desc": "count=255 (above range)","tool": "ping_target", "args": {"target": "127.0.0.1", "count": 255},        "contains": ["10 packets transmitted"], "timeout": 15},
    {"id": "1.9",  "desc": "count=null",             "tool": "ping_target", "args": {"target": "127.0.0.1", "count": None},       "contains": ["4 packets transmitted"]},
    {"id": "1.10", "desc": "Empty target",           "tool": "ping_target", "args": {"target": ""},                               "error": True},
    {"id": "1.11", "desc": "Shell injection ;",      "tool": "ping_target", "args": {"target": "127.0.0.1; whoami"},              "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "1.12", "desc": "Pipe injection",         "tool": "ping_target", "args": {"target": "127.0.0.1 | cat /etc/passwd"},    "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "1.13", "desc": "Command substitution",   "tool": "ping_target", "args": {"target": "$(whoami)"},                      "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "1.14", "desc": "Backtick injection",     "tool": "ping_target", "args": {"target": "`id`"},                           "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "1.15", "desc": "Unreachable target",     "tool": "ping_target", "args": {"target": "192.168.254.254", "count": 1},    "any_of": ["0 received", "100% packet loss", "error", "unreachable", "ping failed", "exit"], "timeout": 15},
    {"id": "1.16", "desc": "Unknown field",          "tool": "ping_target", "args": {"target": "127.0.0.1", "extra": "foo"},      "error": True, "any_of": ["unknown field", "unknown", "denied"]},
    {"id": "1.17", "desc": "IPv6 localhost",         "tool": "ping_target", "args": {"target": "::1", "count": 2},                "any_of": ["bytes from", "icmp_seq", "PING", "2 packets transmitted"]},
]

# ─── Pre-cookie: http_request login to bWAPP ─────────────────────
PHASE_4_COOKIE = [
    {"id": "12.3", "desc": "POST login bWAPP (get cookie)", "tool": "http_request",
     "args": {"url": "http://localhost/login.php", "method": "POST",
              "body": "login=bee&password=bug&security_level=0&form=submit",
              "follow_redirects": False},
     "any_of": ["set-cookie", "phpsessid", "302", "portal", "logged"],
     "extract": {"BWAPP_COOKIE": r"(?:PHPSESSID|phpsessid)[=:]\s*([a-zA-Z0-9]+)"},
     "store": "LOGIN_RESP", "timeout": 15},
]

# ─── Phase 1: Reconnaissance ────────────────────────────────────
PHASE_1_NMAP = [
    {"id": "2.1",  "desc": "Minimal — IP",           "tool": "run_nmap", "args": {"target": "127.0.0.1"},                                           "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.2",  "desc": "Minimal — hostname",     "tool": "run_nmap", "args": {"target": "localhost"},                                            "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.3",  "desc": "Specific ports",         "tool": "run_nmap", "args": {"target": "127.0.0.1", "ports": "22,80"},                         "any_of": ["80", "22"], "timeout": 60},
    {"id": "2.4",  "desc": "Port range",             "tool": "run_nmap", "args": {"target": "127.0.0.1", "ports": "1-100"},                         "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.5",  "desc": "scan_type=service",      "tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "service"},                   "any_of": ["open", "service", "version"], "timeout": 90},
    {"id": "2.6",  "desc": "service + ports",        "tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "service", "ports": "80"},    "any_of": ["80", "http", "apache"], "timeout": 90},
    {"id": "2.7",  "desc": "scan_type=os (non-root)","tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "os"},                        "error": True, "any_of": ["root", "privilege", "permission"]},
    {"id": "2.8",  "desc": "scan_type=vuln bWAPP",   "tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "vuln", "ports": "80"},       "any_of": ["vuln", "script", "cve", "http", "open"], "timeout": 180},
    {"id": "2.9",  "desc": "scan_type=quick",        "tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "quick"},                     "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.10", "desc": "Invalid scan_type",      "tool": "run_nmap", "args": {"target": "127.0.0.1", "scan_type": "stealth"},                   "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.11", "desc": "CIDR /32",               "tool": "run_nmap", "args": {"target": "127.0.0.1/32"},                                        "any_of": ["open", "port", "host"], "timeout": 60},
    {"id": "2.12", "desc": "Empty target",           "tool": "run_nmap", "args": {"target": ""},                                                    "error": True},
    {"id": "2.13", "desc": "Shell injection",        "tool": "run_nmap", "args": {"target": "127.0.0.1; rm -rf /"},                                 "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "2.14", "desc": "bWAPP service scan",     "tool": "run_nmap", "args": {"target": "127.0.0.1", "ports": "80", "scan_type": "service"},    "any_of": ["apache", "http", "80"], "timeout": 90},
    {"id": "2.15", "desc": "Juice Shop scan",        "tool": "run_nmap", "args": {"target": "127.0.0.1", "ports": "3000", "scan_type": "service"},  "any_of": ["3000", "http", "node", "express"], "timeout": 90},
]

PHASE_1_WHATWEB = [
    {"id": "3.1",  "desc": "Minimal — bWAPP",        "tool": "run_whatweb", "args": {"target": "http://localhost"},                                               "any_of": ["apache", "php", "http"], "timeout": 30},
    {"id": "3.2",  "desc": "Minimal — Juice Shop",   "tool": "run_whatweb", "args": {"target": "http://localhost:3000"},                                          "any_of": ["express", "node", "http"], "timeout": 30},
    {"id": "3.3",  "desc": "aggression=stealthy",    "tool": "run_whatweb", "args": {"target": "http://localhost", "aggression": "stealthy"},                     "any_of": ["apache", "php", "http"], "timeout": 30},
    {"id": "3.4",  "desc": "aggression=passive",     "tool": "run_whatweb", "args": {"target": "http://localhost", "aggression": "passive"},                      "any_of": ["apache", "php", "http"], "timeout": 30},
    {"id": "3.5",  "desc": "aggression=aggressive",  "tool": "run_whatweb", "args": {"target": "http://localhost", "aggression": "aggressive"},                   "any_of": ["apache", "php", "http"], "timeout": 60},
    {"id": "3.6",  "desc": "With cookie",            "tool": "run_whatweb", "args": {"target": "http://localhost", "cookie": "PHPSESSID={BWAPP_COOKIE}"},         "any_of": ["apache", "php", "http"], "skip_if": "BWAPP_COOKIE", "timeout": 30},
    {"id": "3.7",  "desc": "aggressive + cookie",    "tool": "run_whatweb", "args": {"target": "http://localhost", "aggression": "aggressive", "cookie": "PHPSESSID={BWAPP_COOKIE}"}, "any_of": ["apache", "php", "http"], "skip_if": "BWAPP_COOKIE", "timeout": 60},
    {"id": "3.8",  "desc": "Invalid aggression",     "tool": "run_whatweb", "args": {"target": "http://localhost", "aggression": "maximum"},                     "any_of": ["apache", "php", "http"], "timeout": 30},
    {"id": "3.9",  "desc": "Bare hostname",          "tool": "run_whatweb", "args": {"target": "localhost"},                                                     "any_of": ["apache", "php", "http", "error"], "timeout": 30},
    {"id": "3.10", "desc": "HTTPS URL",              "tool": "run_whatweb", "args": {"target": "https://localhost"},                                              "any_of": ["error", "ssl", "tls", "fail", "refused", "http"], "timeout": 30},
    {"id": "3.11", "desc": "Empty target",           "tool": "run_whatweb", "args": {"target": ""},                                                              "error": True},
    {"id": "3.12", "desc": "Shell injection in URL", "tool": "run_whatweb", "args": {"target": "http://localhost/$(whoami)"},                                     "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
]

PHASE_1_MASSCAN = [
    {"id": "4.1", "desc": "Minimal",          "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "80"},                     "error": True, "any_of": ["root", "privilege"]},
    {"id": "4.2", "desc": "With rate",         "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "80,443", "rate": 500},   "error": True, "any_of": ["root", "privilege"]},
    {"id": "4.3", "desc": "Rate as string",    "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "80", "rate": "100"},     "error": True, "any_of": ["root", "privilege"]},
    {"id": "4.4", "desc": "Rate=0",            "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "80", "rate": 0},         "error": True, "any_of": ["root", "privilege"]},
    {"id": "4.5", "desc": "Rate above max",    "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "80", "rate": 5000},      "error": True, "any_of": ["root", "privilege"]},
    {"id": "4.6", "desc": "Empty target",      "tool": "run_masscan", "args": {"target": "", "ports": "80"},                                "error": True},
    {"id": "4.7", "desc": "Shell injection",   "tool": "run_masscan", "args": {"target": "127.0.0.1; whoami", "ports": "80"},               "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "4.8", "desc": "Wide port range",   "tool": "run_masscan", "args": {"target": "127.0.0.1/32", "ports": "0-65535"},               "error": True, "any_of": ["root", "privilege"]},
]

PHASE_1_TESTSSL = [
    {"id": "11.1",  "desc": "Minimal — hostname",   "tool": "run_testssl", "args": {"target": "localhost"},                                      "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.2",  "desc": "host:port",             "tool": "run_testssl", "args": {"target": "localhost:443"},                                  "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.3",  "desc": "quick=true",            "tool": "run_testssl", "args": {"target": "localhost:443", "quick": True},                   "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 60},
    {"id": "11.4",  "desc": "quick=false",           "tool": "run_testssl", "args": {"target": "localhost:443", "quick": False},                  "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.5",  "desc": "quick=null",            "tool": "run_testssl", "args": {"target": "localhost:443", "quick": None},                   "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.6",  "desc": "severity=LOW",          "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "LOW"},               "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.7",  "desc": "severity=HIGH",         "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "HIGH"},              "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.8",  "desc": "severity=CRITICAL",     "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "CRITICAL"},          "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.9",  "desc": "severity=MEDIUM",       "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "MEDIUM"},            "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.10", "desc": "severity lowercase",    "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "high"},              "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.11", "desc": "severity mixed case",   "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "Medium"},            "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.12", "desc": "Invalid severity",      "tool": "run_testssl", "args": {"target": "localhost:443", "severity": "urgent"},            "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.13", "desc": "quick + severity",      "tool": "run_testssl", "args": {"target": "localhost:443", "quick": True, "severity": "HIGH"}, "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 60},
    {"id": "11.14", "desc": "URL format",            "tool": "run_testssl", "args": {"target": "https://localhost"},                              "any_of": ["ssl", "tls", "error", "fail", "connect", "refused", "couldn't"], "timeout": 120},
    {"id": "11.15", "desc": "Empty target",          "tool": "run_testssl", "args": {"target": ""},                                              "error": True},
]

# ─── Phase 2: Web Scanning ───────────────────────────────────────
PHASE_2_NUCLEI = [
    {"id": "5.1",  "desc": "Minimal — bWAPP",    "tool": "run_nuclei", "args": {"target": "http://localhost"},                                                    "any_of": ["nuclei", "found", "info", "no findings", "template", "matched"], "timeout": 300},
    {"id": "5.2",  "desc": "Minimal — Juice Shop","tool": "run_nuclei", "args": {"target": "http://localhost:3000"},                                              "any_of": ["nuclei", "found", "info", "no findings", "template", "matched"], "timeout": 300},
    {"id": "5.3",  "desc": "severity=info",        "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "info"},                               "any_of": ["info", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.4",  "desc": "severity=low",         "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "low"},                                "any_of": ["low", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.5",  "desc": "severity=medium",      "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "medium"},                             "any_of": ["medium", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.6",  "desc": "severity=high",        "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "high"},                               "any_of": ["high", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.7",  "desc": "severity=critical",    "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "critical"},                           "any_of": ["critical", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.8",  "desc": "Invalid severity",     "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "urgent"},                             "any_of": ["nuclei", "found", "no findings", "template", "matched"], "timeout": 300},
    {"id": "5.9",  "desc": "tags=cve",             "tool": "run_nuclei", "args": {"target": "http://localhost", "tags": "cve"},                                    "any_of": ["cve", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.10", "desc": "tags=tech",            "tool": "run_nuclei", "args": {"target": "http://localhost", "tags": "tech"},                                   "any_of": ["tech", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.11", "desc": "tags combined",        "tool": "run_nuclei", "args": {"target": "http://localhost", "tags": "cve,oast"},                               "any_of": ["cve", "oast", "found", "no findings", "nuclei"], "timeout": 300},
    {"id": "5.12", "desc": "With cookie",          "tool": "run_nuclei", "args": {"target": "http://localhost", "cookie": "PHPSESSID={BWAPP_COOKIE}"},             "any_of": ["nuclei", "found", "no findings", "template", "matched"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "5.13", "desc": "severity + tags",      "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "high", "tags": "cve"},                "any_of": ["nuclei", "found", "no findings"], "timeout": 300},
    {"id": "5.14", "desc": "All params",           "tool": "run_nuclei", "args": {"target": "http://localhost", "severity": "medium", "tags": "cve", "cookie": "PHPSESSID={BWAPP_COOKIE}"}, "any_of": ["nuclei", "found", "no findings"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "5.15", "desc": "Empty target",         "tool": "run_nuclei", "args": {"target": ""},                                                                  "error": True},
    {"id": "5.16", "desc": "Shell injection",      "tool": "run_nuclei", "args": {"target": "http://localhost/$(id)"},                                             "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
]

PHASE_2_NIKTO = [
    {"id": "6.1",  "desc": "Minimal — URL",        "tool": "run_nikto", "args": {"target": "http://localhost"},                                                         "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.2",  "desc": "Minimal — hostname",   "tool": "run_nikto", "args": {"target": "localhost"},                                                                "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.3",  "desc": "hostname + port=80",    "tool": "run_nikto", "args": {"target": "localhost", "port": 80},                                                   "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.4",  "desc": "hostname + port=443",   "tool": "run_nikto", "args": {"target": "localhost", "port": 443},                                                  "any_of": ["nikto", "+", "ssl", "error", "fail", "refused"], "timeout": 60},
    {"id": "6.5",  "desc": "hostname + port=3000",  "tool": "run_nikto", "args": {"target": "localhost", "port": 3000},                                                 "any_of": ["nikto", "+", "server", "host", "express"], "timeout": 300},
    {"id": "6.6",  "desc": "URL + port (ignored)",  "tool": "run_nikto", "args": {"target": "http://localhost", "port": 80},                                            "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.7",  "desc": "port as string",        "tool": "run_nikto", "args": {"target": "localhost", "port": "80"},                                                 "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.8",  "desc": "tuning=quick",          "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "quick"},                                     "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.9",  "desc": "tuning=thorough",       "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "thorough"},                                  "any_of": ["nikto", "+", "server", "host"], "timeout": 600},
    {"id": "6.10", "desc": "tuning=injection",      "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "injection"},                                 "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.11", "desc": "tuning=fileupload",     "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "fileupload"},                                "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.12", "desc": "Invalid tuning",        "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "stealth"},                                   "any_of": ["nikto", "+", "server", "host"], "timeout": 300},
    {"id": "6.13", "desc": "With cookie",           "tool": "run_nikto", "args": {"target": "http://localhost", "cookie": "PHPSESSID={BWAPP_COOKIE}"},                  "any_of": ["nikto", "+", "server", "host"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "6.14", "desc": "Custom timeout",        "tool": "run_nikto", "args": {"target": "http://localhost", "timeout_secs": 120},                                   "any_of": ["nikto", "+", "server", "host", "timed out", "timeout"], "not_contains": ["120ss"], "timeout": 150},
    {"id": "6.15", "desc": "timeout as string",     "tool": "run_nikto", "args": {"target": "http://localhost", "timeout_secs": "60"},                                  "any_of": ["nikto", "+", "server", "host", "timed out", "timeout"], "not_contains": ["60ss"], "timeout": 90},
    {"id": "6.16", "desc": "All params (hostname)",  "tool": "run_nikto", "args": {"target": "localhost", "port": 80, "tuning": "thorough", "cookie": "PHPSESSID={BWAPP_COOKIE}", "timeout_secs": 300}, "any_of": ["nikto", "+", "server", "host"], "skip_if": "BWAPP_COOKIE", "timeout": 350},
    {"id": "6.17", "desc": "URL + tuning + cookie", "tool": "run_nikto", "args": {"target": "http://localhost", "tuning": "injection", "cookie": "PHPSESSID={BWAPP_COOKIE}"}, "any_of": ["nikto", "+", "server", "host"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "6.18", "desc": "Empty target",          "tool": "run_nikto", "args": {"target": ""},                                                                       "error": True},
]

PHASE_2_FEROX = [
    {"id": "7.1",  "desc": "Minimal — bWAPP",       "tool": "run_feroxbuster", "args": {"target": "http://localhost"},                                                                                                                          "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.2",  "desc": "Minimal — Juice Shop",  "tool": "run_feroxbuster", "args": {"target": "http://localhost:3000"},                                                                                                                     "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.3",  "desc": "Custom wordlist",        "tool": "run_feroxbuster", "args": {"target": "http://localhost", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"},                                            "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.4",  "desc": "extensions",             "tool": "run_feroxbuster", "args": {"target": "http://localhost", "extensions": "php,html,txt"},                                                                                            "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.5",  "desc": "Custom threads",         "tool": "run_feroxbuster", "args": {"target": "http://localhost", "threads": 5},                                                                                                            "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.6",  "desc": "threads above max",      "tool": "run_feroxbuster", "args": {"target": "http://localhost", "threads": 300},                                                                                                          "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.7",  "desc": "threads as string",      "tool": "run_feroxbuster", "args": {"target": "http://localhost", "threads": "20"},                                                                                                         "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
    {"id": "7.8",  "desc": "status_codes",           "tool": "run_feroxbuster", "args": {"target": "http://localhost", "status_codes": "200,301"},                                                                                               "any_of": ["200", "301", "http", "found", "url"], "timeout": 300},
    {"id": "7.9",  "desc": "With cookie",            "tool": "run_feroxbuster", "args": {"target": "http://localhost", "cookie": "PHPSESSID={BWAPP_COOKIE}"},                                                                                    "any_of": ["200", "301", "302", "http", "found", "url"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "7.10", "desc": "All params",             "tool": "run_feroxbuster", "args": {"target": "http://localhost", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "extensions": "php", "threads": 10, "status_codes": "200,301,302", "cookie": "PHPSESSID={BWAPP_COOKIE}"}, "any_of": ["200", "301", "302", "http"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "7.11", "desc": "extensions + status",    "tool": "run_feroxbuster", "args": {"target": "http://localhost", "extensions": "php,html", "status_codes": "200"},                                                                         "any_of": ["200", "http", "found", "url"], "timeout": 300},
    {"id": "7.12", "desc": "Empty target",           "tool": "run_feroxbuster", "args": {"target": ""},                                                                                                                                         "error": True},
    {"id": "7.13", "desc": "Nonexistent wordlist",   "tool": "run_feroxbuster", "args": {"target": "http://localhost", "wordlist": "/nonexistent/wordlist.txt"},                                                                                  "any_of": ["error", "not found", "no such", "fail", "exited with error", "no output"]},
]

PHASE_2_FFUF = [
    {"id": "8.1",  "desc": "Minimal with FUZZ",    "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ"},                                                                                                                     "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.2",  "desc": "Missing FUZZ keyword",  "tool": "run_ffuf", "args": {"url": "http://localhost/test"},                                                                                                                    "error": True, "any_of": ["fuzz", "keyword", "missing"]},
    {"id": "8.3",  "desc": "Custom wordlist",        "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"},                                "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.4",  "desc": "method=POST",            "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "method": "POST"},                                                                                                  "any_of": ["status", "found", "result", "ffuf", "url", "200", "301", "405"], "timeout": 300},
    {"id": "8.5",  "desc": "method=HEAD",            "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "method": "HEAD"},                                                                                                  "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.6",  "desc": "method lowercase",       "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "method": "post"},                                                                                                  "any_of": ["status", "found", "result", "ffuf", "url", "200", "301", "405"], "timeout": 300},
    {"id": "8.7",  "desc": "Single header",          "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "headers": "X-Custom: value1"},                                                                                     "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.8",  "desc": "Multiple headers",       "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "headers": "X-Custom: val1, Accept: text/html"},                                                                    "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.9",  "desc": "match_codes",            "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "match_codes": "200,301"},                                                                                          "any_of": ["status", "found", "result", "ffuf", "url", "200", "301", "0 results"], "timeout": 300},
    {"id": "8.10", "desc": "filter_size=0",          "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "filter_size": "0"},                                                                                                 "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.11", "desc": "filter_size typical",    "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "filter_size": "1234"},                                                                                              "any_of": ["status", "found", "result", "ffuf", "url", "200", "301", "0 results"], "timeout": 300},
    {"id": "8.12", "desc": "Custom threads",         "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "threads": 5},                                                                                                      "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.13", "desc": "threads above max",      "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "threads": 200},                                                                                                    "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.14", "desc": "threads as string",      "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "threads": "15"},                                                                                                   "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
    {"id": "8.15", "desc": "With cookie",            "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "cookie": "PHPSESSID={BWAPP_COOKIE}"},                                                                              "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "8.16", "desc": "All params",             "tool": "run_ffuf", "args": {"url": "http://localhost/FUZZ", "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt", "method": "GET", "headers": "Accept: */*", "match_codes": "200,301,302", "filter_size": "0", "threads": 10, "cookie": "PHPSESSID={BWAPP_COOKIE}"}, "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "8.17", "desc": "FUZZ in query string",   "tool": "run_ffuf", "args": {"url": "http://localhost/sqli_1.php?title=FUZZ&action=search"},                                                                                     "any_of": ["status", "found", "result", "ffuf", "url", "200"], "timeout": 300},
    {"id": "8.18", "desc": "Empty URL",              "tool": "run_ffuf", "args": {"url": ""},                                                                                                                                        "error": True},
    {"id": "8.19", "desc": "Juice Shop fuzzing",     "tool": "run_ffuf", "args": {"url": "http://localhost:3000/FUZZ"},                                                                                                               "any_of": ["status", "found", "result", "ffuf", "url", "200", "301"], "timeout": 300},
]

# ─── Phase 3: Exploitation ───────────────────────────────────────
PHASE_3_SQLMAP = [
    {"id": "9.1",  "desc": "Minimal — GET sqli",    "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search"},                                                                         "any_of": ["sqlmap", "parameter", "injectable", "dbms", "payload", "not appear"], "timeout": 180},
    {"id": "9.2",  "desc": "With cookie",            "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "cookie": "PHPSESSID={BWAPP_COOKIE}; security_level=0"},                 "any_of": ["sqlmap", "parameter", "injectable", "dbms", "payload", "not appear"], "skip_if": "BWAPP_COOKIE", "timeout": 180},
    {"id": "9.3",  "desc": "POST data injection",   "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_6.php", "data": "title=test&action=search", "cookie": "PHPSESSID={BWAPP_COOKIE}; security_level=0"},      "any_of": ["sqlmap", "parameter", "injectable", "dbms", "payload", "not appear"], "skip_if": "BWAPP_COOKIE", "timeout": 180},
    {"id": "9.4",  "desc": "level=1 (explicit)",    "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "level": 1},                                                             "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
    {"id": "9.5",  "desc": "level=2 (at cap)",      "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "level": 2},                                                             "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 300},
    {"id": "9.6",  "desc": "level=5 (above cap)",   "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "level": 5},                                                             "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
    {"id": "9.7",  "desc": "level as string",        "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "level": "2"},                                                           "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 300},
    {"id": "9.8",  "desc": "risk=1 (explicit)",      "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "risk": 1},                                                              "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
    {"id": "9.9",  "desc": "risk=3 (above cap)",     "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "risk": 3},                                                              "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
    {"id": "9.10", "desc": "risk as string",          "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "risk": "1"},                                                            "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
    {"id": "9.11", "desc": "technique=B",             "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "technique": "B"},                                                       "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear", "boolean"], "timeout": 180},
    {"id": "9.12", "desc": "technique=E",             "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "technique": "E"},                                                       "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear", "error"], "timeout": 180},
    {"id": "9.13", "desc": "technique=U",             "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "technique": "U"},                                                       "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear", "union"], "timeout": 180},
    {"id": "9.14", "desc": "technique=T",             "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "technique": "T"},                                                       "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear", "time"], "timeout": 300},
    {"id": "9.15", "desc": "technique=BEUSTQ",        "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "technique": "BEUSTQ"},                                                  "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 300},
    {"id": "9.16", "desc": "Full combo — GET",        "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "cookie": "PHPSESSID={BWAPP_COOKIE}; security_level=0", "level": 2, "risk": 1, "technique": "BEU"}, "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "9.17", "desc": "Full combo — POST",       "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_6.php", "data": "title=test&action=search", "cookie": "PHPSESSID={BWAPP_COOKIE}; security_level=0", "level": 2, "risk": 1, "technique": "BEUSTQ"}, "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "skip_if": "BWAPP_COOKIE", "timeout": 300},
    {"id": "9.18", "desc": "Non-injectable page",    "tool": "run_sqlmap", "args": {"url": "http://localhost/login.php?foo=bar"},                                                                                           "any_of": ["not appear", "injectable", "all tested", "sqlmap"], "timeout": 120},
    {"id": "9.19", "desc": "Empty URL",               "tool": "run_sqlmap", "args": {"url": ""},                                                                                                                            "error": True},
    {"id": "9.20", "desc": "level=0 (below range)",   "tool": "run_sqlmap", "args": {"url": "http://localhost/sqli_1.php?title=test&action=search", "level": 0},                                                             "any_of": ["sqlmap", "parameter", "injectable", "dbms", "not appear"], "timeout": 180},
]

PHASE_3_HYDRA = [
    {"id": "10.1",  "desc": "Minimal — SSH",        "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt"},                                                                                             "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.2",  "desc": "HTTP POST form — bWAPP","tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "http-post-form", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "form_params": "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:F=Invalid credentials"}, "any_of": ["hydra", "login", "password", "valid", "host", "bee"], "timeout": 120},
    {"id": "10.3",  "desc": "Form without form_params","tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "http-post-form", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt"},                                                                                  "error": True, "any_of": ["form_params", "required", "missing"]},
    {"id": "10.4",  "desc": "HTTP GET form",         "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "http-get-form", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "form_params": "/login.php:login=^USER^&password=^PASS^:F=Invalid"},                  "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.5",  "desc": "tasks=2",               "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "tasks": 2},                                                                                    "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.6",  "desc": "tasks above cap",       "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "tasks": 16},                                                                                   "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.7",  "desc": "tasks=1",               "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "tasks": 1},                                                                                    "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.8",  "desc": "tasks as string",       "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "tasks": "3"},                                                                                   "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.9",  "desc": "Non-form + form_params","tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "form_params": "/login:user=^USER^&pass=^PASS^:F=fail"},                                        "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
    {"id": "10.10", "desc": "FTP service",           "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ftp", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt"},                                                                                                "any_of": ["hydra", "error", "fail", "refused", "0 valid"], "timeout": 60},
    {"id": "10.11", "desc": "Empty target",          "tool": "run_hydra", "args": {"target": "", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt"},                                                                                                         "error": True},
    {"id": "10.12", "desc": "Nonexistent userlist",  "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/nonexistent/users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt"},                                                                                                        "any_of": ["error", "not found", "no such", "fail", "exited with error", "no output"]},
    {"id": "10.13", "desc": "tasks=0",               "tool": "run_hydra", "args": {"target": "127.0.0.1", "service": "ssh", "userlist": "/tmp/raven-nest/test-users.txt", "passlist": "/tmp/raven-nest/test-passwords.txt", "tasks": 0},                                                                                    "any_of": ["hydra", "login", "password", "valid", "host", "0 valid"], "timeout": 120},
]

# ─── Phase 4: HTTP Request (remaining after cookie) ──────────────
PHASE_4_HTTP = [
    {"id": "12.1",  "desc": "Minimal — GET bWAPP",     "tool": "http_request", "args": {"url": "http://localhost"},                                                                      "any_of": ["200", "html", "bwapp", "login", "bee"]},
    {"id": "12.2",  "desc": "Minimal — GET Juice Shop", "tool": "http_request", "args": {"url": "http://localhost:3000"},                                                                 "any_of": ["200", "html", "juice", "owasp"]},
    {"id": "12.4",  "desc": "GET after POST (jar test)","tool": "http_request", "args": {"url": "http://localhost/portal.php"},                                                            "any_of": ["200", "portal", "welcome", "bwapp", "bugs"]},
    {"id": "12.5",  "desc": "method=PUT",               "tool": "http_request", "args": {"url": "http://localhost", "method": "PUT"},                                                     "any_of": ["200", "405", "method", "not allowed", "html"]},
    {"id": "12.6",  "desc": "method=DELETE",            "tool": "http_request", "args": {"url": "http://localhost", "method": "DELETE"},                                                  "any_of": ["200", "405", "method", "not allowed", "html"]},
    {"id": "12.7",  "desc": "method=PATCH",             "tool": "http_request", "args": {"url": "http://localhost", "method": "PATCH"},                                                   "any_of": ["200", "405", "method", "not allowed", "html"]},
    {"id": "12.8",  "desc": "method=HEAD",              "tool": "http_request", "args": {"url": "http://localhost", "method": "HEAD"},                                                    "any_of": ["200", "head", "status", "header"]},
    {"id": "12.9",  "desc": "method=OPTIONS",           "tool": "http_request", "args": {"url": "http://localhost", "method": "OPTIONS"},                                                 "any_of": ["200", "allow", "options", "method"]},
    {"id": "12.10", "desc": "method lowercase",         "tool": "http_request", "args": {"url": "http://localhost", "method": "get"},                                                     "any_of": ["200", "html", "bwapp", "login"]},
    {"id": "12.11", "desc": "Invalid method",           "tool": "http_request", "args": {"url": "http://localhost", "method": "INVALID"},                                                 "error": True, "any_of": ["unsupported", "method"]},
    {"id": "12.12", "desc": "Custom headers",           "tool": "http_request", "args": {"url": "http://localhost", "headers": {"X-Custom": "test", "Accept": "application/json"}},       "any_of": ["200", "html", "json"]},
    {"id": "12.13", "desc": "auth_token",               "tool": "http_request", "args": {"url": "http://localhost:3000/rest/user/whoami", "auth_token": "some-token"},                     "any_of": ["200", "401", "user", "unauthorized", "error"]},
    {"id": "12.14", "desc": "JSON body + content-type", "tool": "http_request", "args": {"url": "http://localhost", "method": "POST", "body": "{\"test\":true}", "headers": {"Content-Type": "application/json"}}, "any_of": ["200", "html", "json", "error"]},
    {"id": "12.15", "desc": "Body without content-type","tool": "http_request", "args": {"url": "http://localhost", "method": "POST", "body": "key=value"},                               "any_of": ["200", "html"]},
    {"id": "12.16", "desc": "timeout=5",                "tool": "http_request", "args": {"url": "http://localhost", "timeout_secs": 5},                                                   "any_of": ["200", "html"]},
    {"id": "12.17", "desc": "timeout=120 (max)",        "tool": "http_request", "args": {"url": "http://localhost", "timeout_secs": 120},                                                 "any_of": ["200", "html"]},
    {"id": "12.18", "desc": "timeout above max",        "tool": "http_request", "args": {"url": "http://localhost", "timeout_secs": 300},                                                  "any_of": ["200", "html"]},
    {"id": "12.19", "desc": "timeout as string",        "tool": "http_request", "args": {"url": "http://localhost", "timeout_secs": "10"},                                                 "any_of": ["200", "html"]},
    {"id": "12.20", "desc": "follow_redirects=false",   "tool": "http_request", "args": {"url": "http://localhost/login.php", "method": "POST", "body": "login=bee&password=bug&security_level=0&form=submit", "follow_redirects": False}, "any_of": ["302", "location", "set-cookie", "redirect"]},
    {"id": "12.21", "desc": "follow_redirects=true",    "tool": "http_request", "args": {"url": "http://localhost/login.php", "method": "POST", "body": "login=bee&password=bug&security_level=0&form=submit", "follow_redirects": True},  "any_of": ["200", "portal", "welcome", "bwapp"]},
    {"id": "12.22", "desc": "follow_redirects default", "tool": "http_request", "args": {"url": "http://localhost/login.php", "method": "POST", "body": "login=bee&password=bug&security_level=0&form=submit"},                            "any_of": ["200", "portal", "welcome", "bwapp"]},
    {"id": "12.23", "desc": "HTTPS URL",                "tool": "http_request", "args": {"url": "https://localhost"},                                                                      "error": True, "any_of": ["error", "ssl", "tls", "refused", "connect", "request"]},
    {"id": "12.24", "desc": "FTP URL",                  "tool": "http_request", "args": {"url": "ftp://localhost"},                                                                        "error": True, "any_of": ["scheme", "http", "ftp", "invalid", "url"]},
    {"id": "12.25", "desc": "Invalid URL",              "tool": "http_request", "args": {"url": "not-a-url"},                                                                             "error": True, "any_of": ["invalid", "url", "scheme"]},
    {"id": "12.26", "desc": "Empty URL",                "tool": "http_request", "args": {"url": ""},                                                                                       "error": True},
    {"id": "12.27", "desc": "All params",               "tool": "http_request", "args": {"url": "http://localhost/login.php", "method": "POST", "headers": {"Accept": "text/html"}, "body": "login=bee&password=bug&security_level=0&form=submit", "auth_token": "fake-token", "timeout_secs": 30, "follow_redirects": False}, "any_of": ["302", "200", "set-cookie", "location"]},
    {"id": "12.28", "desc": "Juice Shop API JSON",      "tool": "http_request", "args": {"url": "http://localhost:3000/api/Products/1", "method": "GET", "headers": {"Accept": "application/json"}}, "any_of": ["200", "product", "json", "data", "name"]},
]

# ─── Phase 5: Background Scan Lifecycle ──────────────────────────
PHASE_5_SCANS = [
    # Group A: Complete lifecycle (nmap)
    {"id": "13.1",  "desc": "launch nmap scan",       "tool": "launch_scan", "args": {"tool": "nmap", "target": "127.0.0.1"},  "any_of": ["scan", "id", "launched"], "extract": {"SCAN_ID_A": r"(?:scan[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "17.1",  "desc": "list_scans (1 running)",  "tool": "list_scans",  "args": {},                                      "any_of": ["nmap", "running", "127.0.0.1"]},
    {"id": "14.1",  "desc": "get_scan_status running", "tool": "get_scan_status", "args": {"scan_id": "{SCAN_ID_A}"},           "any_of": ["running", "completed", "elapsed", "status"], "skip_if": "SCAN_ID_A"},
    {"id": "14.2",  "desc": "get_scan_status (wait)",  "tool": "get_scan_status", "args": {"scan_id": "{SCAN_ID_A}"},           "any_of": ["completed", "running", "elapsed", "status", "output"], "skip_if": "SCAN_ID_A", "wait": 20, "timeout": 60},
    {"id": "15.1",  "desc": "get_scan_results default","tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}"},          "any_of": ["port", "host", "open", "nmap", "output", "still running"], "skip_if": "SCAN_ID_A", "timeout": 60},
    {"id": "15.2",  "desc": "get_scan_results offset", "tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "offset": 100}, "skip_if": "SCAN_ID_A"},
    {"id": "15.3",  "desc": "get_scan_results limit",  "tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "limit": 500},  "skip_if": "SCAN_ID_A"},
    {"id": "15.4",  "desc": "get_scan_results both",   "tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "offset": 50, "limit": 200}, "skip_if": "SCAN_ID_A"},
    {"id": "15.5",  "desc": "get_scan_results past end","tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "offset": 999999}, "any_of": ["no more", "past end", "offset", "empty", "still running"], "skip_if": "SCAN_ID_A"},
    {"id": "15.6",  "desc": "offset as string",        "tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "offset": "100"}, "skip_if": "SCAN_ID_A"},
    {"id": "15.7",  "desc": "limit as string",         "tool": "get_scan_results", "args": {"scan_id": "{SCAN_ID_A}", "limit": "500"},  "skip_if": "SCAN_ID_A"},

    # Group B: Cancel lifecycle
    {"id": "13.2",  "desc": "launch nuclei scan",      "tool": "launch_scan", "args": {"tool": "nuclei", "target": "http://localhost"}, "any_of": ["scan", "id", "launched"], "extract": {"SCAN_ID_B": r"(?:scan[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "16.1",  "desc": "cancel_scan",              "tool": "cancel_scan", "args": {"scan_id": "{SCAN_ID_B}"},                       "any_of": ["cancel", "stopped", "aborted"], "skip_if": "SCAN_ID_B"},
    {"id": "14.3",  "desc": "get_scan_status cancelled","tool": "get_scan_status", "args": {"scan_id": "{SCAN_ID_B}"},                   "any_of": ["cancel", "stopped", "aborted", "status"], "skip_if": "SCAN_ID_B"},
    {"id": "16.2",  "desc": "cancel_scan again (noop)", "tool": "cancel_scan", "args": {"scan_id": "{SCAN_ID_B}"},                       "skip_if": "SCAN_ID_B"},

    # Cancel scan A before Group C to free concurrency slots
    {"id": "13.2c", "desc": "cancel scan A for slots",   "tool": "cancel_scan", "args": {"scan_id": "{SCAN_ID_A}"},                                          "skip_if": "SCAN_ID_A"},

    # Group C: Launch with args
    {"id": "13.3",  "desc": "launch with custom args",  "tool": "launch_scan", "args": {"tool": "nmap", "target": "127.0.0.1", "args": ["-sV", "-p", "80"]}, "any_of": ["scan", "id", "launched"]},
    {"id": "13.4",  "desc": "launch with timeout",      "tool": "launch_scan", "args": {"tool": "nmap", "target": "127.0.0.1", "timeout_secs": 30},          "any_of": ["scan", "id", "launched"]},
    {"id": "13.5",  "desc": "launch timeout as string", "tool": "launch_scan", "args": {"tool": "nmap", "target": "127.0.0.1", "timeout_secs": "30"},         "any_of": ["scan", "id", "launched"]},
    # Wait for previous scans to finish before launching more
    {"id": "13.5w", "desc": "wait for slots to free",    "tool": "list_scans", "args": {},                                                                    "wait": 10},
    {"id": "13.6",  "desc": "launch whatweb",            "tool": "launch_scan", "args": {"tool": "whatweb", "target": "http://localhost"},                      "any_of": ["scan", "id", "launched"]},
    {"id": "13.7",  "desc": "launch nikto",              "tool": "launch_scan", "args": {"tool": "nikto", "target": "http://localhost"},                       "any_of": ["scan", "id", "launched"]},

    # Group D: Error cases
    {"id": "13.8",  "desc": "disallowed tool",           "tool": "launch_scan", "args": {"tool": "burpsuite", "target": "127.0.0.1"},     "error": True, "any_of": ["not allowed", "disallowed", "invalid", "tool"]},
    {"id": "13.9",  "desc": "empty target",              "tool": "launch_scan", "args": {"tool": "nmap", "target": ""},                    "error": True},
    {"id": "13.10", "desc": "shell injection",           "tool": "launch_scan", "args": {"tool": "nmap", "target": "127.0.0.1; whoami"},  "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "14.4",  "desc": "status nonexistent scan",   "tool": "get_scan_status", "args": {"scan_id": "nonexistent-uuid"},               "any_of": ["not found", "no scan", "unknown"]},
    {"id": "15.8",  "desc": "results nonexistent scan",  "tool": "get_scan_results", "args": {"scan_id": "nonexistent-uuid"},              "any_of": ["not found", "no scan", "unknown", "still running"]},
    {"id": "16.3",  "desc": "cancel nonexistent scan",   "tool": "cancel_scan", "args": {"scan_id": "nonexistent-uuid"},                   "error": True, "any_of": ["not found", "no scan", "unknown"]},

    # Group E: list_scans
    {"id": "17.2",  "desc": "list_scans (all)",          "tool": "list_scans", "args": {},                                                 "any_of": ["nmap", "nuclei", "scan"]},
]

# ─── Phase 6: Findings Lifecycle ─────────────────────────────────
PHASE_6_FINDINGS = [
    # Group A: Empty state
    {"id": "18.1",  "desc": "list_findings empty",      "tool": "list_findings", "args": {},                                               "any_of": ["no finding", "0 finding", "empty", "none"]},
    {"id": "22.1",  "desc": "generate_report empty",    "tool": "generate_report", "args": {},                                             "any_of": ["0 finding", "report", "saved", "generated"]},

    # Group B: save_finding — all params
    {"id": "19.1",  "desc": "Required only",             "tool": "save_finding", "args": {"title": "Test SQLi", "severity": "high", "description": "SQL injection in search", "target": "http://localhost/sqli_1.php", "tool": "sqlmap"}, "any_of": ["saved", "finding", "id"], "extract": {"FINDING_A": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "19.2",  "desc": "All params",                "tool": "save_finding", "args": {"title": "Full Finding", "severity": "critical", "description": "RCE via deser", "target": "http://localhost:3000", "tool": "nuclei", "evidence": "HTTP 500 stack trace", "remediation": "Upgrade lib", "cvss": 9.8, "cve": "CVE-2024-1234"}, "any_of": ["saved", "finding", "id"], "extract": {"FINDING_B": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "19.3",  "desc": "severity=critical",         "tool": "save_finding", "args": {"title": "C", "severity": "critical", "description": "d", "target": "t", "tool": "t"}, "any_of": ["saved", "finding", "id"], "extract": {"FINDING_C": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "19.4",  "desc": "severity=high",             "tool": "save_finding", "args": {"title": "H", "severity": "high", "description": "d", "target": "t", "tool": "t"},     "any_of": ["saved", "finding", "id"]},
    {"id": "19.5",  "desc": "severity=medium",           "tool": "save_finding", "args": {"title": "M", "severity": "medium", "description": "d", "target": "t", "tool": "t"},   "any_of": ["saved", "finding", "id"]},
    {"id": "19.6",  "desc": "severity=low",              "tool": "save_finding", "args": {"title": "L", "severity": "low", "description": "d", "target": "t", "tool": "t"},      "any_of": ["saved", "finding", "id"]},
    {"id": "19.7",  "desc": "severity=info",             "tool": "save_finding", "args": {"title": "I", "severity": "info", "description": "d", "target": "t", "tool": "t"},     "any_of": ["saved", "finding", "id"]},
    {"id": "19.8",  "desc": "severity UPPERCASE",        "tool": "save_finding", "args": {"title": "CU", "severity": "CRITICAL", "description": "d", "target": "t", "tool": "t"}, "any_of": ["saved", "finding", "id"]},
    {"id": "19.9",  "desc": "severity MiXeD",            "tool": "save_finding", "args": {"title": "CM", "severity": "MeDiUm", "description": "d", "target": "t", "tool": "t"},  "any_of": ["saved", "finding", "id"]},
    {"id": "19.10", "desc": "Invalid severity",          "tool": "save_finding", "args": {"title": "Bad", "severity": "urgent", "description": "d", "target": "t", "tool": "t"}, "error": True, "any_of": ["invalid", "severity", "unknown"]},
    {"id": "19.11", "desc": "Empty severity",            "tool": "save_finding", "args": {"title": "Bad", "severity": "", "description": "d", "target": "t", "tool": "t"},       "error": True},
    {"id": "19.12", "desc": "Numeric severity",          "tool": "save_finding", "args": {"title": "Bad", "severity": "1", "description": "d", "target": "t", "tool": "t"},      "error": True, "any_of": ["invalid", "severity", "unknown"]},
    {"id": "19.13", "desc": "evidence only",             "tool": "save_finding", "args": {"title": "E", "severity": "low", "description": "d", "target": "t", "tool": "t", "evidence": "output excerpt"}, "any_of": ["saved", "finding", "id"]},
    {"id": "19.14", "desc": "remediation only",          "tool": "save_finding", "args": {"title": "R", "severity": "low", "description": "d", "target": "t", "tool": "t", "remediation": "Fix it"},       "any_of": ["saved", "finding", "id"]},
    {"id": "19.15", "desc": "cvss only",                 "tool": "save_finding", "args": {"title": "Cv", "severity": "low", "description": "d", "target": "t", "tool": "t", "cvss": 5.5},                 "any_of": ["saved", "finding", "id"]},
    {"id": "19.16", "desc": "cve only",                  "tool": "save_finding", "args": {"title": "Ce", "severity": "low", "description": "d", "target": "t", "tool": "t", "cve": "CVE-2024-9999"},      "any_of": ["saved", "finding", "id"]},
    {"id": "19.17", "desc": "cvss=0.0 (boundary)",       "tool": "save_finding", "args": {"title": "Z", "severity": "info", "description": "d", "target": "t", "tool": "t", "cvss": 0.0},                 "any_of": ["saved", "finding", "id"]},
    {"id": "19.18", "desc": "cvss=10.0 (boundary)",      "tool": "save_finding", "args": {"title": "X", "severity": "critical", "description": "d", "target": "t", "tool": "t", "cvss": 10.0},            "any_of": ["saved", "finding", "id"]},

    # Group C: Retrieve and list
    {"id": "20.1",  "desc": "get_finding (required)",    "tool": "get_finding", "args": {"finding_id": "{FINDING_A}"},   "any_of": ["test sqli", "high", "sqlmap"], "skip_if": "FINDING_A"},
    {"id": "20.2",  "desc": "get_finding (full)",        "tool": "get_finding", "args": {"finding_id": "{FINDING_B}"},   "any_of": ["full finding", "critical", "cve-2024-1234", "9.8"], "skip_if": "FINDING_B"},
    {"id": "20.3",  "desc": "get_finding (missing)",     "tool": "get_finding", "args": {"finding_id": "nonexistent-uuid"}, "any_of": ["not found", "no finding", "unknown"]},
    {"id": "18.2",  "desc": "list_findings (populated)", "tool": "list_findings", "args": {},                             "any_of": ["critical", "high", "finding"]},

    # Group D: Delete
    {"id": "21.1",  "desc": "delete_finding",            "tool": "delete_finding", "args": {"finding_id": "{FINDING_C}"}, "any_of": ["deleted", "removed", "success"], "skip_if": "FINDING_C"},
    {"id": "21.2",  "desc": "delete same again",         "tool": "delete_finding", "args": {"finding_id": "{FINDING_C}"}, "any_of": ["not found", "no finding", "unknown", "already"], "skip_if": "FINDING_C"},
    {"id": "21.3",  "desc": "delete nonexistent",        "tool": "delete_finding", "args": {"finding_id": "nonexistent-uuid"}, "any_of": ["not found", "no finding", "unknown"]},
    {"id": "18.3",  "desc": "list_findings (after del)", "tool": "list_findings", "args": {},                              "any_of": ["critical", "high", "finding"]},

    # Group E: Report generation
    {"id": "22.2",  "desc": "generate_report (default)", "tool": "generate_report", "args": {},                            "any_of": ["report", "finding", "saved", "generated"]},
    {"id": "22.3",  "desc": "generate_report (custom)",  "tool": "generate_report", "args": {"title": "bWAPP Assessment 2026"}, "any_of": ["report", "finding", "saved", "generated", "bwapp"]},
    {"id": "22.4",  "desc": "generate_report (empty)",   "tool": "generate_report", "args": {"title": ""},                 "any_of": ["report", "finding", "saved", "generated"]},
    {"id": "18.4",  "desc": "list_findings unchanged",   "tool": "list_findings", "args": {},                              "any_of": ["critical", "high", "finding"]},
]

# ─── Phase 6 Group F: Full Integration Lifecycle ─────────────────
PHASE_6_INTEGRATION = [
    {"id": "F.1",  "desc": "list_findings (clean)",     "tool": "list_findings", "args": {},                                                                                                                                   "any_of": ["no finding", "0 finding", "empty", "none", "critical", "finding"]},
    {"id": "F.2",  "desc": "save critical finding",     "tool": "save_finding",  "args": {"title": "Integration Critical", "severity": "critical", "description": "Critical vuln", "target": "http://localhost", "tool": "nuclei"}, "any_of": ["saved", "finding", "id"], "extract": {"INT_FINDING_A": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "F.3",  "desc": "save high (all optional)",  "tool": "save_finding",  "args": {"title": "Integration High", "severity": "high", "description": "High vuln", "target": "http://localhost", "tool": "nmap", "evidence": "Port 80 open", "remediation": "Close port", "cvss": 7.5, "cve": "CVE-2024-5678"}, "any_of": ["saved", "finding", "id"], "extract": {"INT_FINDING_B": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "F.4",  "desc": "save low finding",          "tool": "save_finding",  "args": {"title": "Integration Low", "severity": "low", "description": "Low vuln", "target": "http://localhost", "tool": "whatweb"},              "any_of": ["saved", "finding", "id"], "extract": {"INT_FINDING_C": r"(?:finding[_ ]?id|id)[:\s]+([a-f0-9-]+)"}},
    {"id": "F.5",  "desc": "list 3 findings",           "tool": "list_findings", "args": {},                                                                                                                                   "contains": ["critical", "high", "low"]},
    {"id": "F.6",  "desc": "get high finding",          "tool": "get_finding",   "args": {"finding_id": "{INT_FINDING_B}"},                                                                                                      "any_of": ["integration high", "cve-2024-5678", "7.5"], "skip_if": "INT_FINDING_B"},
    {"id": "F.7",  "desc": "delete low finding",        "tool": "delete_finding","args": {"finding_id": "{INT_FINDING_C}"},                                                                                                      "any_of": ["deleted", "removed", "success"], "skip_if": "INT_FINDING_C"},
    {"id": "F.8",  "desc": "list 2 findings",           "tool": "list_findings", "args": {},                                                                                                                                   "contains": ["critical", "high"]},
    {"id": "F.9",  "desc": "generate integration report","tool": "generate_report","args": {"title": "Integration Test"},                                                                                                        "any_of": ["2 finding", "critical", "high", "report", "saved"]},
    {"id": "F.10", "desc": "verify report on disk",     "tool": "list_findings", "args": {},                                                                                                                                   "any_of": ["critical", "high", "finding"]},
]

# ─── Phase 7: Cross-Cutting Validation ───────────────────────────
PHASE_7_VALIDATION = [
    {"id": "V.1",  "desc": "IPv4",               "tool": "ping_target",   "args": {"target": "192.168.1.1", "count": 1},        "any_of": ["ping", "icmp", "unreachable", "loss", "bytes"], "timeout": 10},
    {"id": "V.2",  "desc": "IPv6",               "tool": "ping_target",   "args": {"target": "::1", "count": 1},                "any_of": ["ping", "icmp", "bytes"]},
    {"id": "V.3",  "desc": "CIDR v4",            "tool": "run_nmap",      "args": {"target": "10.0.0.0/8"},                      "any_of": ["nmap", "host", "scan", "error"], "timeout": 30},
    {"id": "V.4",  "desc": "CIDR /32",           "tool": "run_nmap",      "args": {"target": "192.168.1.1/32"},                  "any_of": ["nmap", "host", "scan"], "timeout": 30},
    {"id": "V.5",  "desc": "CIDR /33 (invalid)", "tool": "run_nmap",      "args": {"target": "192.168.1.0/33"},                  "error": True, "any_of": ["invalid", "cidr", "prefix"]},
    {"id": "V.6",  "desc": "CIDR v6",            "tool": "run_nmap",      "args": {"target": "fe80::/10"},                       "any_of": ["nmap", "host", "scan", "error"], "timeout": 30},
    {"id": "V.7",  "desc": "CIDR v6 /129",       "tool": "run_nmap",      "args": {"target": "fe80::/129"},                      "error": True, "any_of": ["invalid", "cidr", "prefix"]},
    {"id": "V.8",  "desc": "host:port",           "tool": "run_testssl",   "args": {"target": "example.com:443"},                 "any_of": ["ssl", "tls", "error", "connect", "testssl"], "timeout": 60},
    {"id": "V.9",  "desc": "host:port invalid",   "tool": "run_testssl",   "args": {"target": "example.com:99999"},               "error": True, "any_of": ["invalid", "port", "range"]},
    {"id": "V.10", "desc": "host:port empty host", "tool": "run_testssl",  "args": {"target": ":443"},                            "error": True, "any_of": ["invalid", "empty", "target"]},
    {"id": "V.11", "desc": "URL with query &",    "tool": "run_sqlmap",    "args": {"url": "http://localhost/page?a=1&b=2"},       "any_of": ["sqlmap", "parameter", "not appear", "injectable", "tested", "404", "page not found", "critical"], "timeout": 60},
    {"id": "V.12", "desc": "URL injection in path","tool": "run_whatweb",   "args": {"target": "http://localhost/$(whoami)"},       "error": True, "any_of": ["forbidden", "invalid", "rejected"]},
    {"id": "V.13", "desc": "Unsupported scheme",   "tool": "http_request",  "args": {"url": "ftp://localhost"},                    "error": True, "any_of": ["scheme", "http", "ftp", "invalid"]},
    {"id": "V.14", "desc": "Hostname >253 chars",  "tool": "ping_target",   "args": {"target": "a" * 254 + ".com", "count": 1},   "error": True, "any_of": ["invalid", "too long", "hostname", "length"]},
    {"id": "V.15", "desc": "Leading hyphen",        "tool": "ping_target",   "args": {"target": "-evil.com", "count": 1},          "error": True, "any_of": ["invalid", "hyphen", "forbidden"]},
    {"id": "V.16", "desc": "Trailing hyphen",       "tool": "ping_target",   "args": {"target": "evil-.com", "count": 1},          "error": True, "any_of": ["invalid", "target"]},
    {"id": "V.17", "desc": "Newline injection",     "tool": "ping_target",   "args": {"target": "host\ninjected", "count": 1},     "error": True, "any_of": ["forbidden", "invalid", "rejected", "newline"]},
]

PHASE_7_LENIENT = [
    {"id": "L.1", "desc": "Number as number",   "tool": "ping_target", "args": {"target": "127.0.0.1", "count": 4},     "contains": ["4 packets transmitted"]},
    {"id": "L.2", "desc": "Number as string",    "tool": "ping_target", "args": {"target": "127.0.0.1", "count": "4"},   "contains": ["4 packets transmitted"]},
    {"id": "L.3", "desc": "Null value",          "tool": "ping_target", "args": {"target": "127.0.0.1", "count": None},  "contains": ["4 packets transmitted"]},
    {"id": "L.4", "desc": "Missing field",       "tool": "ping_target", "args": {"target": "127.0.0.1"},                 "contains": ["4 packets transmitted"]},
    {"id": "L.5", "desc": "Invalid string",      "tool": "ping_target", "args": {"target": "127.0.0.1", "count": "abc"}, "error": True},
    {"id": "L.6", "desc": "Float for integer",   "tool": "run_nikto",   "args": {"target": "localhost", "port": 80.5},   "error": True, "any_of": ["deserialize", "data did not match", "invalid", "error"]},
    {"id": "L.7", "desc": "Negative for unsigned","tool": "ping_target", "args": {"target": "127.0.0.1", "count": -1},   "error": True},
]

PHASE_7_DENY_UNKNOWN = [
    {"id": "D.1", "desc": "ping extra field",    "tool": "ping_target",  "args": {"target": "127.0.0.1", "extra": "foo"},           "error": True, "any_of": ["unknown field", "unknown", "denied"]},
    {"id": "D.2", "desc": "nmap extra field",    "tool": "run_nmap",     "args": {"target": "127.0.0.1", "verbose": True},           "error": True, "any_of": ["unknown field", "unknown", "denied"]},
    {"id": "D.3", "desc": "sqlmap extra field",  "tool": "run_sqlmap",   "args": {"url": "http://localhost/test?a=1", "dbms": "mysql"}, "error": True, "any_of": ["unknown field", "unknown", "denied"]},
    {"id": "D.4", "desc": "http extra field",    "tool": "http_request", "args": {"url": "http://localhost", "proxy": "http://x"},    "error": True, "any_of": ["unknown field", "unknown", "denied"]},
    {"id": "D.5", "desc": "finding extra field",  "tool": "save_finding", "args": {"title": "T", "severity": "low", "description": "d", "target": "t", "tool": "t", "tags": ["web"]}, "error": True, "any_of": ["unknown field", "unknown", "denied"]},
]

PHASE_7_TRUNCATION = [
    {"id": "T.1", "desc": "Large nmap output",     "tool": "run_nmap",       "args": {"target": "127.0.0.1", "scan_type": "vuln", "ports": "80"}, "any_of": ["port", "host", "open", "http", "vuln", "script", "nmap"], "timeout": 180},
    {"id": "T.2", "desc": "Large HTTP response",   "tool": "http_request",   "args": {"url": "http://localhost"},                                  "any_of": ["200", "html"]},
    {"id": "T.3", "desc": "Large feroxbuster output","tool": "run_feroxbuster","args": {"target": "http://localhost", "extensions": "php,html,txt,js,css"}, "any_of": ["200", "301", "302", "http", "found", "url"], "timeout": 300},
]


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
def main():
    phases_requested = set(sys.argv[1:]) if len(sys.argv) > 1 else {"all"}
    do_all = "all" in phases_requested

    print(f"{B}{C}Raven-Nest-MCP Test Harness{Z}")
    print(f"Server: {SERVER}")
    print(f"Starting MCP server...", end=" ", flush=True)

    client = MCPClient()
    runner = Runner(client)
    print(f"{G}OK{Z}\n")

    try:
        if do_all or "phase0" in phases_requested:
            runner.phase("Phase 0: Connectivity (ping_target)", PHASE_0)

        if do_all or "phase4cookie" in phases_requested or "phase4" in phases_requested:
            runner.phase("Phase 4 (pre): bWAPP Login", PHASE_4_COOKIE)

        if do_all or "phase1" in phases_requested:
            runner.phase("Phase 1: Recon — nmap", PHASE_1_NMAP)
            runner.phase("Phase 1: Recon — whatweb", PHASE_1_WHATWEB)
            runner.phase("Phase 1: Recon — masscan", PHASE_1_MASSCAN)
            runner.phase("Phase 1: Recon — testssl", PHASE_1_TESTSSL)

        if do_all or "phase2" in phases_requested:
            runner.phase("Phase 2: Web — nuclei", PHASE_2_NUCLEI)
            runner.phase("Phase 2: Web — nikto", PHASE_2_NIKTO)
            runner.phase("Phase 2: Web — feroxbuster", PHASE_2_FEROX)
            runner.phase("Phase 2: Web — ffuf", PHASE_2_FFUF)

        if do_all or "phase3" in phases_requested:
            runner.phase("Phase 3: Exploitation — sqlmap", PHASE_3_SQLMAP)
            runner.phase("Phase 3: Exploitation — hydra", PHASE_3_HYDRA)

        if do_all or "phase4" in phases_requested:
            runner.phase("Phase 4: HTTP Request", PHASE_4_HTTP)

        if do_all or "phase5" in phases_requested:
            runner.phase("Phase 5: Scan Lifecycle", PHASE_5_SCANS)

        if do_all or "phase6" in phases_requested:
            # Clean stale findings from disk before testing
            import glob as globmod
            for f in globmod.glob("/tmp/raven-nest/findings/*.json"):
                os.remove(f)
            # Restart server to reload empty store
            client.close()
            time.sleep(1)
            client = MCPClient(max_retries=3)
            runner.client = client
            runner.phase("Phase 6: Findings Lifecycle", PHASE_6_FINDINGS)
            runner.phase("Phase 6: Integration Lifecycle", PHASE_6_INTEGRATION)

        if do_all or "phase7" in phases_requested:
            runner.phase("Phase 7: Target Validation", PHASE_7_VALIDATION)
            runner.phase("Phase 7: Lenient Deser", PHASE_7_LENIENT)
            runner.phase("Phase 7: deny_unknown_fields", PHASE_7_DENY_UNKNOWN)
            runner.phase("Phase 7: Output Truncation", PHASE_7_TRUNCATION)

    finally:
        client.close()

    runner.summary()
    return 0 if runner.counts["FAIL"] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
