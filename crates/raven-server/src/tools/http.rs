//! Manual HTTP request handler for endpoint testing.
//!
//! Unlike the other tools (which shell out to external binaries), this handler
//! uses `reqwest` directly to send crafted HTTP requests. Supports:
//! - All standard HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
//! - Custom headers, request body, and Bearer token auth.
//! - Configurable redirect following (default: follow up to 10 hops).
//! - Timeout capping at 120s.
//! - Proxy support via [`NetworkConfig`](raven_core::config::NetworkConfig).
//! - Session cookie persistence via a shared [`Jar`](reqwest::cookie::Jar)
//!   that survives across requests within a session.
//!
//! Response body cap is derived from `context_budget` config (default 20KB).

use reqwest::cookie::CookieStore;
use rmcp::{
    model::{CallToolResult, Content},
    schemars,
};
use std::{collections::HashMap, time::Duration};

/// MCP request schema for `http_request`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    #[schemars(description = "Full URL (must start with http:// or https://)")]
    pub url: String,

    #[schemars(description = "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")]
    pub method: Option<String>,

    #[schemars(description = "Request headers as key-value pairs")]
    pub headers: Option<HashMap<String, String>>,

    #[schemars(description = "Request body (string)")]
    pub body: Option<String>,

    #[schemars(description = "Bearer token for Authorisation header")]
    pub auth_token: Option<String>,

    #[schemars(description = "Request timeout in seconds (default 30, max 120)")]
    #[serde(default, deserialize_with = "super::lenient::option_number")]
    pub timeout_secs: Option<u64>,

    #[schemars(description = "Follow redirects (default true)")]
    pub follow_redirects: Option<bool>,
}


/// Security-relevant response headers to keep in output.
/// All other headers are discarded to reduce context consumption.
const SECURITY_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "set-cookie",
    "content-type",
    "location",
    "www-authenticate",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "access-control-allow-origin",
    "x-xss-protection",
];

/// Execute an HTTP request using reqwest with proxy and cookie jar support.
pub async fn run(
    config: &raven_core::config::RavenConfig,
    cookie_jar: std::sync::Arc<reqwest::cookie::Jar>,
    req: HttpRequest,
) -> Result<CallToolResult, rmcp::ErrorData> {
    // Validate URL scheme (only http/https allowed)
    let parsed = reqwest::Url::parse(&req.url)
        .map_err(|_| rmcp::ErrorData::invalid_params("invalid url format", None))?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(rmcp::ErrorData::invalid_params(
                "URL scheme must be http or https",
                None,
            ));
        }
    }

    let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(30).min(120));

    let redirect_policy = if req.follow_redirects.unwrap_or(true) {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    // Build client with proxy support and shared cookie jar
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy)
        .cookie_provider(cookie_jar.clone());

    if let Some(ref proxy_url) = config.network.http_proxy {
        let proxy = reqwest::Proxy::http(proxy_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("invalid http_proxy: {e}"), None)
        })?;
        builder = builder.proxy(proxy);
    }
    if let Some(ref proxy_url) = config.network.https_proxy {
        let proxy = reqwest::Proxy::https(proxy_url).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("invalid https_proxy: {e}"), None)
        })?;
        builder = builder.proxy(proxy);
    }

    let client = builder
        .build()
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
    let method: reqwest::Method = method
        .parse()
        .map_err(|_| rmcp::ErrorData::invalid_params("invalid HTTP method", None))?;

    let mut request = client.request(method, &req.url);

    if let Some(headers) = &req.headers {
        for (k, v) in headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
    }

    if let Some(token) = &req.auth_token {
        request = request.bearer_auth(token);
    }

    if let Some(body) = req.body {
        let has_content_type = req
            .headers
            .as_ref()
            .is_some_and(|h| h.keys().any(|k| k.eq_ignore_ascii_case("content-type")));
        if !has_content_type {
            request = request.header("content-type", "application/x-www-form-urlencoded");
        }
        request = request.body(body);
    }

    let start = std::time::Instant::now();
    let response = request
        .send()
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
    let elapsed = start.elapsed();

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Filter to security-relevant headers only
    let resp_headers: Vec<String> = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            let name = k.as_str().to_lowercase();
            SECURITY_HEADERS.iter().any(|h| name == *h)
        })
        .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>")))
        .collect();

    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    // Convert body to text, stripping HTML if applicable
    let is_html = content_type.contains("text/html");
    let raw_body = String::from_utf8_lossy(&body_bytes);
    let body_text = if is_html {
        strip_html(&raw_body)
    } else {
        raw_body.into_owned()
    };

    // Truncate after processing
    let max_body = config.safety.effective_max_response_body();
    let body = if body_text.len() > max_body {
        format!(
            "{}\n\n--- truncated at {} chars ---",
            &body_text[..max_body],
            max_body
        )
    } else {
        body_text
    };

    // Surface session cookies from the jar so models can pass them to subprocess tools
    let cookies_line = cookie_jar
        .cookies(&parsed)
        .and_then(|v: reqwest::header::HeaderValue| v.to_str().ok().map(String::from))
        .unwrap_or_default();

    let mut output = format!(
        "HTTP {} {}\nElapsed: {:.1}ms\n\n--- Headers ---\n{}\n\n--- Body ---\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        elapsed.as_secs_f64() * 1000.0,
        resp_headers.join("\n"),
        body,
    );

    if !cookies_line.is_empty() {
        output.push_str(&format!("\n\n--- Session Cookies ---\n{cookies_line}"));
    }

    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Strip HTML to readable plain text.
///
/// Removes `<script>` and `<style>` blocks, strips remaining tags (inserting
/// newlines for block elements), decodes common HTML entities, and collapses
/// repeated whitespace. Not a full parser — optimised for reducing HTML
/// response size in context-constrained environments.
fn strip_html(html: &str) -> String {
    // Phase 1: Remove script/style blocks and HTML comments
    let mut cleaned = String::from(html);
    for tag in &["script", "style"] {
        loop {
            let lower = cleaned.to_lowercase();
            let open = format!("<{tag}");
            let close = format!("</{tag}>");
            let Some(start) = lower.find(&open) else {
                break;
            };
            let Some(end) = lower[start..].find(&close) else {
                break;
            };
            cleaned = format!(
                "{}{}",
                &cleaned[..start],
                &cleaned[start + end + close.len()..]
            );
        }
    }
    // Strip HTML comments (<!-- ... -->)
    loop {
        let Some(start) = cleaned.find("<!--") else {
            break;
        };
        let Some(end) = cleaned[start..].find("-->") else {
            break;
        };
        cleaned = format!("{}{}", &cleaned[..start], &cleaned[start + end + 3..]);
    }

    // Phase 2: Strip tags, inserting newlines for block elements
    let mut result = String::with_capacity(cleaned.len() / 3);
    let mut in_tag = false;
    let mut tag_buf = String::new();

    for ch in cleaned.chars() {
        if ch == '<' {
            in_tag = true;
            tag_buf.clear();
            continue;
        }
        if in_tag {
            if ch == '>' {
                in_tag = false;
                let lower_tag = tag_buf.to_lowercase();
                let name = lower_tag
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('/');
                if matches!(
                    name,
                    "p" | "div"
                        | "br"
                        | "li"
                        | "tr"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "h5"
                        | "h6"
                        | "hr"
                        | "table"
                        | "blockquote"
                        | "option"
                        | "select"
                        | "dt"
                        | "dd"
                ) {
                    result.push('\n');
                }
            } else {
                tag_buf.push(ch);
            }
            continue;
        }
        result.push(ch);
    }

    // Phase 3: Decode HTML entities (named + numeric decimal)
    let decoded = result
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&copy;", "\u{00A9}")
        .replace("&reg;", "\u{00AE}")
        .replace("&trade;", "\u{2122}")
        .replace("&hellip;", "\u{2026}")
        .replace("&ndash;", "\u{2013}")
        .replace("&mdash;", "\u{2014}");

    // Decode &#NNN; numeric entities in a single forward pass
    let decoded = {
        let mut out = String::with_capacity(decoded.len());
        let mut remaining = decoded.as_str();
        while let Some(pos) = remaining.find("&#") {
            out.push_str(&remaining[..pos]);
            let after = &remaining[pos + 2..];
            if let Some(semi) = after.find(';') {
                let digits = &after[..semi];
                if let Ok(cp) = digits.parse::<u32>()
                    && let Some(ch) = char::from_u32(cp)
                {
                    out.push(ch);
                    remaining = &after[semi + 1..];
                    continue;
                }
            }
            // Malformed — keep `&#` literal and advance past it
            out.push_str("&#");
            remaining = after;
        }
        out.push_str(remaining);
        out
    };

    // Phase 4: Collapse blank lines
    let mut final_out = String::with_capacity(decoded.len());
    let mut blank_count = 0;
    for line in decoded.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank_count += 1;
            if blank_count <= 1 {
                final_out.push('\n');
            }
        } else {
            blank_count = 0;
            final_out.push_str(trimmed);
            final_out.push('\n');
        }
    }

    final_out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_html_removes_scripts_and_styles() {
        let html = "<html><head><style>body{color:red}</style></head><body><script>alert(1)</script><p>Hello</p></body></html>";
        let text = strip_html(html);
        assert!(text.contains("Hello"));
        assert!(!text.contains("alert"));
        assert!(!text.contains("color:red"));
        assert!(!text.contains("<p>"));
    }

    #[test]
    fn strip_html_decodes_entities() {
        let html = "&amp; &lt;tag&gt; &quot;quoted&quot;";
        let text = strip_html(html);
        assert!(text.contains("& <tag> \"quoted\""));
    }

    #[test]
    fn strip_html_inserts_newlines_for_blocks() {
        let html = "<div>one</div><div>two</div>";
        let text = strip_html(html);
        assert!(text.contains("one\n"));
        assert!(text.contains("two"));
    }

    #[test]
    fn strip_html_collapses_whitespace() {
        let html = "<p>line1</p>\n\n\n\n<p>line2</p>";
        let text = strip_html(html);
        // Should not have more than one consecutive blank line
        assert!(!text.contains("\n\n\n"));
    }

    #[test]
    fn strip_html_removes_comments() {
        let html = "<!-- banner -->Hello<!-- end -->, world";
        let text = strip_html(html);
        assert_eq!(text, "Hello, world");
        assert!(!text.contains("-->"));
        assert!(!text.contains("<!--"));
    }

    #[test]
    fn strip_html_decodes_extended_entities() {
        let html = "&copy; 2024 &ndash; All rights reserved &hellip;";
        let text = strip_html(html);
        assert!(text.contains('\u{00A9}'));
        assert!(text.contains('\u{2013}'));
        assert!(text.contains('\u{2026}'));
        assert!(!text.contains("&copy;"));
    }

    #[test]
    fn strip_html_decodes_numeric_entities() {
        let html = "&#169; &#8212; &#65;";
        let text = strip_html(html);
        assert!(text.contains('\u{00A9}')); // &#169; = ©
        assert!(text.contains('\u{2014}')); // &#8212; = —
        assert!(text.contains('A')); // &#65; = A
        assert!(!text.contains("&#"));
    }
}
