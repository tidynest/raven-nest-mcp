# Contributing

Thanks for wanting to help. This project puts intrusive tools in the hands of
language models, so the bar for a change is a little unusual: a contribution
has to be correct, and it also has to keep the model from doing more than the
operator allowed. This page explains how to build and check your work, how to
add a tool wrapper without opening a hole, and what makes a pull request easy
to merge.

If you have found a way around a safety control, do not open an issue or a
pull request. Report it privately as described in [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a small fix, open a thread in
  [Discussions](https://github.com/tidynest/raven-nest-mcp/discussions) under
  Ideas first. It saves you from building something that does not fit.
- New tool wrappers always start as a proposal. See
  [Proposing a new tool wrapper](#proposing-a-new-tool-wrapper).
- [ROADMAP.md](ROADMAP.md) lists what is planned. Unchecked items are open.

## Build

You need Rust 1.93 or newer. `rust-toolchain.toml` selects stable with
rustfmt and clippy.

```bash
git clone https://github.com/tidynest/raven-nest-mcp.git
cd raven-nest-mcp
cargo build
```

The server binary is `target/debug/raven-server`. It speaks MCP on stdin and
stdout and logs to stderr, so starting it by hand shows only log lines. To
poke at it, point an MCP client at the binary, or use
[raven-nest-client](https://github.com/tidynest/raven-nest-client).

You do not need the scanners installed to build or to run the unit tests.
The tests work on recorded tool output.

## Layout

```
crates/
  raven-core/     config, target validation and scope, the executor that
                  starts every subprocess, background scans, the audit log,
                  the Metasploit RPC client
  raven-report/   finding and target stores, report generators for
                  Markdown, HTML, JSON and SARIF
  raven-server/   the MCP server, one module per tool under src/tools/,
                  the context budget, output parsers, progress notifications
config/
  default.toml          commented reference config
  sudoers-raven-nest    sudoers drop-in for masscan and nmap
docs/                   user documentation
packaging/aur/          Arch Linux PKGBUILD
tests/
  manual_test_harness.py   drives a built server over stdio
```

[docs/DATA_FLOW.md](docs/DATA_FLOW.md) follows one tool call through these
crates and says which module owns each piece of state.
[docs/SAFETY.md](docs/SAFETY.md) describes every control. Read both before
touching `safety.rs` or `executor.rs`.

## Checks

CI runs the commands below on every pull request, with warnings treated as
errors. Run them before you push. The maintainer runs the same set as a local
pre-push gate, so a branch that fails any of them will not be merged.

```bash
cargo fmt --all -- --check
```

```bash
cargo clippy --all-targets -- -D warnings
```

```bash
cargo test --all
```

```bash
cargo audit
```

```bash
cargo deny check
```

`cargo audit` and `cargo deny` are separate installs:

```bash
cargo install cargo-audit cargo-deny
```

What each one is for:

| Command | Catches |
|---------|---------|
| `cargo fmt` | formatting drift |
| `cargo clippy` | lints, with every warning an error |
| `cargo test` | unit and integration tests in all three crates |
| `cargo audit` | dependencies with a RustSec advisory |
| `cargo deny check` | advisories again, plus licences outside the allowlist in `deny.toml`, banned duplicates and unknown crate sources |

CI also runs `cargo check --workspace --locked` on Rust 1.93.0, the minimum
supported version. If you use a newer language or library feature, that job
fails.

Two tests are worth knowing about because they fail for reasons that are not
obvious:

- `crates/raven-server/tests/tool_manifest.rs` compares every `#[tool]`
  description in `server.rs` with [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md) and
  with the `TOOL_COUNT` constant. Change a description or add a tool, and you
  update all of them together.
- The same file rejects descriptions that look like hidden instructions or
  like data exfiltration, for example a verb such as "send" or "leak" close
  to a word such as "secret" or "token". Static scanners flag those patterns,
  so word the description around them.

### Testing against real tools

`tests/manual_test_harness.py` starts a built server and sends real MCP
requests:

```bash
cargo build --release
```

```bash
python3 -u tests/manual_test_harness.py phase0
```

Phases 0 and 4 to 7 finish in a few minutes. Phases 2 and 3 run real scans
and need a lab target such as bWAPP or Juice Shop on localhost. The phases
are listed in [docs/USAGE.md](docs/USAGE.md#testing). Run the harness only
against targets you own.

## Ground rules for code

- **Nothing reaches a shell.** Every process starts through
  `raven_core::executor::run`, which takes an argument list. Do not add
  `sh -c`, and do not build a command as one string.
- **The model never supplies a flag.** Expose a choice as a named preset or
  a typed field, and map it to arguments in the handler.
- **Every string the model sends is hostile until checked.** That includes
  strings that came out of a previous scan.
- **Reject, do not repair.** If input is wrong, return an error that names
  the field. Do not strip characters and carry on.
- **Defaults are the cautious setting.** Anything intrusive is off, or
  capped, until the operator changes the config.
- **No real targets in the repository.** Tests, docs and examples use
  `example.com`, `example.org`, `scanme.nmap.org` or private address ranges.
  Never commit output from a real engagement.
- **No personal paths or credentials** in code, tests or docs.

## Proposing a new tool wrapper

Open a thread in Discussions under Ideas, or use the tool proposal template
there. A proposal should answer these questions:

1. **What is the tool and what gap does it fill?** Say which existing wrapper
   comes closest and why it is not enough. A tool that mostly repeats one
   already here is unlikely to get in.
2. **What exactly would the model be allowed to ask for?** List the presets
   and fields. Leave out anything you would not want a model to choose at
   three in the morning.
3. **What is the worst thing the tool can do to a target?** Account lockouts,
   data changes, heavy load, files written to the target.
4. **Which parts need a cap or a gate?** A cap is a limit in `[safety]` that
   the model cannot exceed. A gate is an `enabled = false` switch in its own
   config section, as NetExec and Metasploit have.
5. **Does it contact anyone besides the target?** Public APIs, update
   servers, callback hosts, public DNS resolvers.
6. **Does it read local files or write them?** Say which paths.
7. **How is it installed,** and is it packaged for Kali? The container image
   is built from Kali packages where they exist.

Once the shape is agreed, the implementation follows the same steps as the
existing wrappers. `crates/raven-server/src/tools/whatweb.rs` is the smallest
complete example, and `netexec.rs` shows a gated tool.

### Handler checklist

- [ ] A request struct that derives `Deserialize` and `JsonSchema` and
      carries `#[serde(deny_unknown_fields)]`.
- [ ] Optional numeric fields use
      `deserialize_with = "super::lenient::option_number"`.
- [ ] The target goes through `safety::validate_target` before anything else.
      That call applies the syntax check and the engagement scope.
- [ ] Every other free-text field has its own check, either a fixed list of
      presets or a character check. A value that becomes a positional
      argument must not be able to start with `-`.
- [ ] File and directory arguments go through `validate_file_path`.
- [ ] Limits that matter are clamped against a `[safety]` setting, and the
      setting is range-checked in `SafetyConfig::validate`.
- [ ] The process starts through `executor::run` with the tool name and the
      target, so the allowlist, the cooldowns, the timeout and the audit log
      all apply. Pass `None` as the target only for tools with no network
      target.
- [ ] If any argument can carry a credential, its flag is in `SECRET_FLAGS`
      in `crates/raven-core/src/audit.rs`, and a test shows it redacted.
- [ ] A parser turns raw output into a short summary and returns `None` when
      it cannot, so the raw output is used.
- [ ] The MCP annotations are honest. Set `destructive_hint = true` if the
      tool can change the target or lock accounts.

### Wiring checklist

- [ ] `pub mod` line in `crates/raven-server/src/tools/mod.rs`.
- [ ] `#[tool]` method in `crates/raven-server/src/server.rs`, wrapped in
      `self.wrap_result(...)`.
- [ ] `TOOL_COUNT` in `server.rs`.
- [ ] The binary name in `allowed_tools` in `config/default.toml` and in
      `RavenConfig::default()` in `crates/raven-core/src/config.rs`. They are
      two separate lists.
- [ ] The description in [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md), copied
      exactly.
- [ ] The parameter table in [docs/USAGE.md](docs/USAGE.md) and the tool
      table in [README.md](README.md).
- [ ] Any new cap, gate or third-party contact in
      [docs/SAFETY.md](docs/SAFETY.md) and
      [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
- [ ] The package in the `Dockerfile` and in `optdepends` in
      `packaging/aur/PKGBUILD`.
- [ ] An entry under Unreleased in [CHANGELOG.md](CHANGELOG.md).

### Tests a wrapper needs

- Parser tests on real output from the tool, including an empty result and
  malformed input.
- A test for each validation rule that shows a hostile value being rejected,
  such as a flag-shaped value or a path with `..`.
- For a gated tool, a test that it refuses while disabled.
- For a capped tool, a test that a request above the cap is clamped.

## Changing a safety control

Changes to `safety.rs`, `executor.rs`, `audit.rs`, the scope check, the
Metasploit gates or any validation helper get a slower review. Help it along:

- Say in the pull request which control changes and what a caller can do
  afterwards that it could not do before, or the reverse.
- Add tests for the inputs that should now be rejected and for the ones that
  should still pass.
- Update [docs/SAFETY.md](docs/SAFETY.md) in the same pull request. That page
  is meant to be checkable against the code line by line.

A change that loosens a default needs a reason that holds for most users. A
config option that defaults to the old behaviour is usually the easier sell.

## What a good pull request looks like

- It does one thing. A fix and an unrelated refactor are two pull requests.
- The description says what changed and why, and how you tested it. If you
  ran it against a real tool, name the tool version.
- The checks above pass locally.
- New behaviour has tests, and a bug fix has a test that failed before it.
- Docs change in the same pull request as the behaviour they describe.
- `CHANGELOG.md` has a line under Unreleased for anything a user would
  notice.
- Commit subjects are short and say what the commit does. A type prefix such
  as `fix:` or `docs:` is common in this history and not required.
- No new dependency without a word on why. Every dependency has to pass the
  licence allowlist in `deny.toml`, and each one is more code that runs next
  to offensive tooling.

Small pull requests get reviewed quickly. I maintain this alone, so a large
one may wait.

## Docs-only changes

Documentation fixes are welcome and need no discussion first. Two things to
keep in mind:

- Statements about what the server blocks or logs have to match the code. If
  you are unsure, link the line you are describing.
- `docs/MCP_TOOLS.md` is checked by a test. Edit it only together with
  `server.rs`.

## Licence

The project is licensed under [Apache-2.0](LICENSE). By contributing you
agree that your contribution is licensed under the same terms.
