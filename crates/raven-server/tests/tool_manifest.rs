//! Guards the machine-readable tool manifest (`docs/MCP_TOOLS.md`) against the
//! `#[tool]` descriptions in `server.rs`.
//!
//! Why this exists: a static MCP security scanner (e.g. the Canopii Trust
//! Index) can only read the text formats it parses - it does not compile Rust,
//! so it never sees the `#[tool]` macros. `docs/MCP_TOOLS.md` re-declares the
//! tool surface in a form such a scanner extracts, which lets it evaluate the
//! tool-integrity controls instead of marking them "not checked". These tests
//! keep that mirror honest:
//!   1. every `#[tool]` description appears in the manifest verbatim (no drift);
//!   2. the manifest advertises strict schemas (`additionalProperties: false`);
//!   3. no description carries a hidden-instruction or exfiltration marker that
//!      would fail a scanner's tool-integrity guard and cap the score.

const SERVER_RS: &str = include_str!("../src/server.rs");
const MANIFEST: &str = include_str!("../../../docs/MCP_TOOLS.md");
// Single source of truth - kept in lockstep with the `#[tool]` methods by the
// count assertion below.
use raven_server::server::TOOL_COUNT;

/// Extract every `description = "..."` string literal from the `#[tool]` macros.
/// Tool descriptions carry no escaped quotes, so a scan to the next `"` is enough.
fn tool_descriptions() -> Vec<String> {
    const PREFIX: &str = "description = \"";
    let mut out = Vec::new();
    let mut rest = SERVER_RS;
    while let Some(i) = rest.find(PREFIX) {
        rest = &rest[i + PREFIX.len()..];
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].to_string());
            rest = &rest[end + 1..];
        }
    }
    out
}

#[test]
fn manifest_lists_every_tool_description() {
    let descs = tool_descriptions();
    assert_eq!(
        descs.len(),
        TOOL_COUNT,
        "expected {TOOL_COUNT} #[tool] descriptions in server.rs, found {}",
        descs.len()
    );
    for d in &descs {
        assert!(
            MANIFEST.contains(d.as_str()),
            "docs/MCP_TOOLS.md is out of sync: missing tool description {d:?}. \
             Regenerate the manifest block from server.rs."
        );
    }
}

#[test]
fn manifest_declares_strict_schemas() {
    assert!(
        MANIFEST.contains("additionalProperties: false"),
        "docs/MCP_TOOLS.md must state additionalProperties: false so a static \
         scanner records strict-schema enforcement."
    );
}

#[test]
fn descriptions_carry_no_injection_or_exfiltration_markers() {
    // Mirrors the high-precision markers a tool-integrity scanner flags; a hit
    // fails the guard and caps the published security score. See docs/MCP_TOOLS.md.
    const EXFIL_VERBS: [&str; 5] = ["send", "post", "upload", "exfiltrate", "leak"];
    const SECRET_NOUNS: [&str; 9] = [
        ".ssh",
        "id_rsa",
        ".env",
        "secret",
        "token",
        "credential",
        "api key",
        "api_key",
        "apikey",
    ];
    const HIDDEN_MARKERS: [&str; 5] = [
        "ignore previous",
        "disregard above",
        "you must always",
        "you must never",
        "<important>",
    ];

    for d in tool_descriptions() {
        let low = d.to_lowercase();
        for m in HIDDEN_MARKERS {
            assert!(
                !low.contains(m),
                "hidden-instruction marker {m:?} in tool description {d:?}"
            );
        }
        // Exfiltration: a leak/send verb followed within 40 chars by a secret noun.
        for v in EXFIL_VERBS {
            let mut from = 0;
            while let Some(i) = low[from..].find(v) {
                let start = from + i;
                let end = (start + 40).min(low.len());
                let window = low.get(start..end).unwrap_or(&low[start..]);
                for n in SECRET_NOUNS {
                    assert!(
                        !window.contains(n),
                        "exfiltration marker: {v:?} near {n:?} in tool description {d:?}"
                    );
                }
                from = start + v.len();
            }
        }
    }
}
