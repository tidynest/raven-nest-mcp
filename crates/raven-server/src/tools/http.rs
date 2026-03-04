use rmcp::{model::{CallToolResult, Content}, schemars};
use std::{collections::HashMap, time::Duration};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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
    pub timeout_secs: Option<u64>,

    #[schemars(description = "Follow redirects (default true)")]
    pub follow_redirects: Option<bool>,
}

const MAX_RESPONSE_BODY: usize = 100_000;

pub async fn run(req: HttpRequest) -> Result<CallToolResult, rmcp::ErrorData> {
    // Scheme validation
    let parsed = reqwest::Url::parse(&req.url).map_err(|_| {
        rmcp::ErrorData::invalid_params("invalid url format", None)
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(rmcp::ErrorData::invalid_params(
            "URL scheme must be http or https", None,
        )),
    }

    let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(30).min(120));

    let redirect_policy = if req.follow_redirects.unwrap_or(true) {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy)
        .build()
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
    let method: reqwest::Method = method.parse()
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
        request = request.body(body);
    }

    let start = std::time::Instant::now();
    let response = request.send().await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
    let elapsed = start.elapsed();

    let status = response.status();
    let resp_headers: Vec<String> = response.headers().iter()
        .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>")))
        .collect();

    let body_bytes = response.bytes().await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    let body = if body_bytes.len() > MAX_RESPONSE_BODY {
        let truncated = String::from_utf8_lossy(&body_bytes[..MAX_RESPONSE_BODY]);
        format!("{truncated}\n\n--- truncated at {MAX_RESPONSE_BODY} bytes ---\n")
    } else {
        String::from_utf8_lossy(&body_bytes).into_owned()
    };

    let output = format!(
        "HTTP {} {}\nElapsed: {:.1}ms\n\n--Headers ---\n{}\n\n--- Body ---\n{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        elapsed.as_secs_f64() * 1000.0,
        resp_headers.join("\n"),
        body,
    );

    Ok(CallToolResult::success(vec![Content::text(output)]))
}
