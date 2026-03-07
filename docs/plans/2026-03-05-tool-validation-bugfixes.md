# Tool Validation Bugfixes Implementation Plan

**Goal:** Fix three bugs found during tool validation: launch_scan nmap args, hydra form_params, and localhost-aware thread defaults.

**Architecture:** Each fix is isolated to 1-2 files. Fix 1 adds a default args builder in `scan_manager.rs`. Fix 2 adds a field to `HydraRequest`. Fix 3 adds localhost detection to feroxbuster/ffuf.

**Tech Stack:** Rust, rmcp, schemars, tokio

---

### Task 1: Fix launch_scan Default Args Builder

**Files:**
- Modify: `crates/raven-core/src/scan_manager.rs:65-98`

**Step 1: Add `default_args` function before the `launch` method**

In `scan_manager.rs`, add this function inside the `impl ScanManager` block, before `pub fn launch`:

```rust
/// Build sensible default arguments when the caller provides none.
/// Mirrors the defaults used by each dedicated tool handler.
fn default_args(tool: &str, target: &str) -> Vec<String> {
    match tool {
        "nmap" => vec![
            "-T4".into(), "-F".into(),
            "-oX".into(), "-".into(),
            target.into(),
        ],
        "nuclei" => vec!["-u".into(), target.into(), "-silent".into()],
        "nikto" => vec!["-h".into(), target.into()],
        _ => vec![target.into()],
    }
}
```

**Step 2: Update `launch` to use defaults when args are empty**

Change line 94 from:
```rust
let arg_strings = args;
```
to:
```rust
let arg_strings = if args.is_empty() {
    Self::default_args(tool, target)
} else {
    args
};
```

**Step 3: Add unit test**

Add to the existing `#[cfg(test)] mod tests` block at the bottom of `scan_manager.rs`:

```rust
#[test]
fn default_args_nmap_builds_quick_scan() {
    let args = ScanManager::default_args("nmap", "example.com");
    assert_eq!(args, vec!["-T4", "-F", "-oX", "-", "example.com"]);
}

#[test]
fn default_args_nuclei_builds_silent_scan() {
    let args = ScanManager::default_args("nuclei", "http://example.com");
    assert_eq!(args, vec!["-u", "http://example.com", "-silent"]);
}

#[test]
fn default_args_unknown_tool_appends_target() {
    let args = ScanManager::default_args("custom", "10.0.0.1");
    assert_eq!(args, vec!["10.0.0.1"]);
}
```

**Step 4: Run tests**

Run: `cargo test -p raven-core`
Expected: All pass including the 3 new tests.

**Step 5: Commit**

```
fix: build default args in launch_scan when none provided
```

---

### Task 2: Add form_params to HydraRequest

**Files:**
- Modify: `crates/raven-server/src/tools/hydra.rs:8-57`

**Step 1: Add `form_params` field to `HydraRequest`**

Add after the `tasks` field (line 19):

```rust
#[schemars(description = "Form attack string for http-post-form/http-get-form (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')")]
pub form_params: Option<String>,
```

**Step 2: Add validation and append to args**

In the `run` function, add validation after the `tasks` clamp (after line 36):

```rust
// http-*-form services require form_params
let is_form_service = req.service.starts_with("http-") && req.service.contains("form");
if is_form_service && req.form_params.is_none() {
    return Err(rmcp::ErrorData::invalid_params(
        "form_params is required for http-post-form/http-get-form \
         (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')",
        None,
    ));
}
```

Then change the args construction (lines 38-48) to append form_params after service:

```rust
let mut args = vec![
    "-L".to_string(),
    req.userlist,
    "-P".into(),
    req.passlist,
    "-t".into(),
    tasks.to_string(),
    "-f".into(),
    req.target,
    req.service,
];

if let Some(form_params) = req.form_params {
    args.push(form_params);
}
```

**Step 3: Run build**

Run: `cargo build -p raven-server`
Expected: Compiles with no errors.

**Step 4: Commit**

```
feat: add form_params to run_hydra for http-post-form attacks
```

---

### Task 3: Localhost-Aware Thread Defaults

**Files:**
- Modify: `crates/raven-server/src/tools/feroxbuster.rs:50`
- Modify: `crates/raven-server/src/tools/ffuf.rs:9-47`

**Step 1: Add `is_localhost` helper**

Create a small utility. Add to `crates/raven-server/src/tools/mod.rs` (or wherever the tools module is declared):

First check where `mod.rs` is:

```rust
/// Returns true if the target URL points to a localhost address.
pub(crate) fn is_localhost(target: &str) -> bool {
    let lower = target.to_lowercase();
    // Strip scheme if present
    let host_part = lower
        .strip_prefix("http://").or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(&lower);
    host_part.starts_with("localhost") || host_part.starts_with("127.0.0.1") || host_part.starts_with("[::1]")
}
```

**Step 2: Update feroxbuster thread default**

In `feroxbuster.rs`, change line 50 from:

```rust
let threads = req.threads.unwrap_or(50).min(200);
```

to:

```rust
let default_threads = if super::is_localhost(&req.target) { 10 } else { 50 };
let threads = req.threads.unwrap_or(default_threads).min(200);
```

Note: `req.target` is moved into args on line 39, so we need to read it before the move. Check if we need to clone or reorder. Looking at the code, `req.target` is moved on line 39 into the args vec. So we need to compute `default_threads` before that line.

Move the thread computation before the args construction:

```rust
let default_threads: u16 = if super::is_localhost(&req.target) { 10 } else { 50 };
let threads = req.threads.unwrap_or(default_threads).min(200);

let wordlist = req.wordlist.as_deref().unwrap_or(DEFAULT_WORDLIST);
let mut args = vec![
    "-u".to_string(),
    req.target,
    // ... rest unchanged
```

**Step 3: Add threads field to FfufRequest**

In `ffuf.rs`, add after `filter_size` field (line 22):

```rust
#[schemars(description = "Number of concurrent threads (default 40, reduced to 10 for localhost)")]
pub threads: Option<u16>,
```

**Step 4: Add thread arg to ffuf run function**

In `ffuf.rs`, after the `-noninteractive` arg is pushed (line 46), add:

```rust
let default_threads: u16 = if super::is_localhost(&req.url) { 10 } else { 40 };
let threads = req.threads.unwrap_or(default_threads).min(150);
args.extend(["-t".into(), threads.to_string()]);
```

**Step 5: Add tests for is_localhost**

In the tools `mod.rs` or a test module:

```rust
#[cfg(test)]
mod tests {
    use super::is_localhost;

    #[test]
    fn localhost_variants() {
        assert!(is_localhost("http://localhost:3000"));
        assert!(is_localhost("http://127.0.0.1:8080/path"));
        assert!(is_localhost("https://localhost/foo"));
        assert!(is_localhost("http://[::1]:3000"));
        assert!(is_localhost("localhost"));
    }

    #[test]
    fn remote_targets() {
        assert!(!is_localhost("http://example.com"));
        assert!(!is_localhost("https://10.0.0.1:443"));
        assert!(!is_localhost("hackthissite.org"));
    }
}
```

**Step 6: Run tests and build**

Run: `cargo test -p raven-server && cargo build --release`
Expected: All pass, clean build.

**Step 7: Commit**

```
feat: localhost-aware thread defaults for feroxbuster and ffuf
```

---

### Task 4: Final Verification

**Step 1: Full test suite**

Run: `cargo test --workspace`
Expected: All tests pass.

**Step 2: Build release**

Run: `cargo build --release`
Expected: Clean build.

**Step 3: Commit all if not yet committed**

Verify with `git status` that working tree is clean.
