# Tool Validation Bugfixes Design

## Context

Comprehensive tool validation run (2026-03-05) revealed three issues:
1. `launch_scan` produces nmap help page instead of scan results
2. `run_hydra` cannot drive `http-post-form` attacks (missing format string param)
3. `feroxbuster`/`ffuf` crash localhost targets with excessive thread defaults

## Fix 1: launch_scan Default Args Builder

**Problem:** `launch_scan` passes user-provided `args` directly to `executor::run()`. When empty, nmap receives no arguments and prints help.

**Solution:** Add `fn default_args(tool: &str, target: &str) -> Vec<String>` in `scan_manager.rs`. When `args` is empty, build sensible defaults per tool. When args are provided, use them as-is (power user override).

**Default args per tool:**
- `nmap` → `["-T4", "-F", "-oX", "-", target]`
- `nuclei` → `["-u", target, "-silent"]`
- `nikto` → `["-h", target]`
- `whatweb` → `[target]`
- Unknown → `[target]`

**Files:** `crates/raven-core/src/scan_manager.rs` (lines ~65-98)

## Fix 2: Hydra form_params Field

**Problem:** `http-post-form` requires a format string like `"/login:user=^USER^&pass=^PASS^:F=incorrect"` as a positional arg after the service name. `HydraRequest` has no field for this.

**Solution:** Add `form_params: Option<String>` to `HydraRequest`. Validate that it's present when service is `http-post-form` or `http-get-form`. Append as positional arg after service name.

**Files:** `crates/raven-server/src/tools/hydra.rs` (lines 8-57)

## Fix 3: Localhost-Aware Thread Defaults

**Problem:** feroxbuster defaults to 50 threads, ffuf has no threads param (defaults to 40 internally). Both crash single-threaded localhost apps.

**Solution:**
- Add `fn is_localhost(target: &str) -> bool` utility (checks `localhost`, `127.0.0.1`, `::1`)
- **feroxbuster:** Change default from `unwrap_or(50)` to localhost-aware: 10 for localhost, 50 for remote
- **ffuf:** Add `threads: Option<u16>` to `FfufRequest`, pass `-t` flag. Same localhost-aware default (10 local, 40 remote)

**Files:**
- `crates/raven-server/src/tools/feroxbuster.rs` (line 50)
- `crates/raven-server/src/tools/ffuf.rs` (lines 9-74)

## Verification

1. Rebuild: `cargo build --release`
2. Run `launch_scan` with `tool: "nmap"`, `target: "ericjingryd.com"`, empty args → should produce scan results, not help
3. Run `run_hydra` with `service: "http-post-form"`, `form_params` set → should attempt login
4. Run `run_feroxbuster` against `http://localhost:3000` with no threads param → should use 10, not 50
5. Run `run_ffuf` against `http://localhost:3000/FUZZ` with no threads param → should use 10, not 40
