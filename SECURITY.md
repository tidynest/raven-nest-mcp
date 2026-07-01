# Security Policy

Raven Nest is an **offensive-security toolkit**. It wraps intrusive scanners and
exploitation frameworks behind an MCP interface and is intended **only** for
systems you own or are explicitly authorized to test. Running it against
third-party targets without written authorization may be illegal.

## Supported Versions

The project is pre-1.0 and under active development. Only the latest release on
the default branch (`main`) receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.2.x (latest `main`) | :white_check_mark: |
| older / forks | :x: |

## Reporting a Vulnerability

Please report security issues **privately** - do not open a public issue for a
vulnerability.

- Preferred: GitHub **private vulnerability reporting** -
  <https://github.com/tidynest/raven-nest-mcp/security/advisories/new>.
- Include: affected version/commit, a description, reproduction steps or a PoC,
  and the impact you observed.

You can expect an initial acknowledgement within a few days. If the report is
accepted, a fix will be tracked via a GitHub Security Advisory and credited to
the reporter unless anonymity is requested. If declined, you'll get a brief
explanation of why.

## Scope

In scope: bugs that let the server bypass its own safety controls - e.g. command
injection past `validate_target`, allowlist or scope bypass, path traversal in
finding/report/scan storage, or credential leakage in logs/output.

Out of scope: the tool performing the intrusive actions it is configured to
perform against a target you supplied. That is the intended function, not a
vulnerability.
