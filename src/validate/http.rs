use crate::resource::http::HttpResource;
use crate::validate::matcher;
use curl::easy::{Easy, List};
use serde_json::Value;

const USER_AGENT: &str = concat!("vld/", env!("CARGO_PKG_VERSION"));

/// Result of a single resource check execution.
#[derive(Debug)]
pub struct ResourceTestResult {
    /// Map key / test identifier.
    pub name: String,
    /// Human-readable label from `title` field.
    pub title: Option<String>,
    /// Resource type (e.g. "http", "file").
    pub resource_type: String,
    /// `true` when all assertions passed (or the check was skipped).
    pub passed: bool,
    /// Whether this check was skipped.
    pub skipped: bool,
    /// Assertion failures (empty on success).
    pub failures: Vec<String>,
    /// Transport-level error, if any.
    pub error: Option<String>,
    /// Security warning when a check was deliberately not executed.
    pub warning: Option<String>,
    /// Bounded observed value reported by a non-asserting check.
    pub observation: Option<String>,
}

/// Execute one HTTP check and return a structured result.
pub fn validate(name: &str, resource: &HttpResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "http".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    // ---------- skip ----------------------------------------------------
    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let url = resource.effective_url(name).to_string();

    // ---------- build curl easy handle ----------------------------------
    let mut easy = Easy::new();

    macro_rules! curl_try {
        ($expr:expr, $msg:literal) => {
            if let Err(e) = $expr {
                result.error = Some(format!("{}: {}", $msg, e));
                return result;
            }
        };
    }

    const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024; // 4MB upper bound to prevent decompression/memory bombs
    const MAX_REDIRECTS: u32 = 10;

    curl_try!(easy.url(&url), "set URL");
    curl_try!(
        easy.ssl_verify_peer(!resource.allow_insecure),
        "ssl_verify_peer"
    );
    curl_try!(
        easy.ssl_verify_host(!resource.allow_insecure),
        "ssl_verify_host"
    );
    let follow = !resource.no_follow_redirects;
    curl_try!(easy.follow_location(follow), "follow_location");
    if follow {
        curl_try!(easy.max_redirections(MAX_REDIRECTS), "max_redirections");
    }
    curl_try!(
        easy.timeout(std::time::Duration::from_millis(resource.timeout_ms())),
        "set timeout"
    );
    curl_try!(easy.useragent(USER_AGENT), "user agent");

    // HTTP method
    let method = resource.effective_method().to_uppercase();
    match method.as_str() {
        "GET" => {
            curl_try!(easy.get(true), "set GET");
        }
        "POST" => {
            curl_try!(easy.post(true), "set POST");
        }
        "PUT" => {
            curl_try!(easy.put(true), "set PUT");
        }
        "HEAD" => {
            curl_try!(easy.nobody(true), "set HEAD");
        }
        other => {
            curl_try!(easy.custom_request(other), "custom method");
        }
    }

    // Basic auth
    if let (Some(user), Some(pass)) = (&resource.username, &resource.password) {
        curl_try!(easy.username(user), "username");
        curl_try!(easy.password(pass), "password");
    }

    // CA bundle
    if let Some(ca) = &resource.ca_file {
        curl_try!(easy.cainfo(ca), "ca-file");
    }

    // Client certificate + key
    if let (Some(cert), Some(key)) = (&resource.cert_file, &resource.key_file) {
        curl_try!(easy.ssl_cert(cert), "cert-file");
        curl_try!(easy.ssl_key(key), "key-file");
    }

    // Proxy
    if let Some(proxy) = &resource.proxy {
        curl_try!(easy.proxy(proxy), "proxy");
    }

    // Extra request headers (including the built-in user-agent override check)
    let mut headers = List::new();
    for h in &resource.request_headers {
        curl_try!(headers.append(h), "request header");
    }
    curl_try!(easy.http_headers(headers), "http headers");

    // ---------- perform -------------------------------------------------
    let mut status_code: u32 = 0;
    let mut response_headers: Vec<String> = Vec::new();
    let mut body_buf: Vec<u8> = Vec::new();

    {
        let mut transfer = easy.transfer();

        // Capture response body with strict upper bound (FINDING-05)
        curl_try!(
            transfer.write_function(|data| {
                if body_buf.len() < MAX_RESPONSE_BODY_BYTES {
                    let to_take = data.len().min(MAX_RESPONSE_BODY_BYTES - body_buf.len());
                    body_buf.extend_from_slice(&data[..to_take]);
                }
                Ok(data.len())
            }),
            "write_function"
        );

        // Capture response headers
        curl_try!(
            transfer.header_function(|line| {
                if let Ok(s) = std::str::from_utf8(line) {
                    response_headers.push(s.trim_end().to_string());
                }
                true
            }),
            "header_function"
        );

        if let Err(e) = transfer.perform() {
            result.error = Some(format!("HTTP request failed: {}", e));
            return result;
        }
    }

    // Read status after transfer is dropped
    if let Ok(code) = easy.response_code() {
        status_code = code;
    }

    // ---------- status --------------------------------------------------
    let res = matcher::validate(
        &Value::Number(serde_json::Number::from(status_code)),
        &resource.status,
    );
    if !res.passed {
        result.failures.push(format!(
            "status: {}",
            res.failure_message.unwrap_or_default()
        ));
    }

    // ---------- body ----------------------------------------------------
    let body_text = String::from_utf8_lossy(&body_buf).to_string();
    for expected in &resource.body {
        let res = matcher::validate(&Value::String(body_text.clone()), expected);
        if !res.passed {
            result
                .failures
                .push(format!("body: {}", res.failure_message.unwrap_or_default()));
        }
    }

    // Response header assertions
    if let Some(expected_headers) = &resource.headers {
        for (header_name, expected_values) in expected_headers {
            let name_lower = header_name.to_lowercase();
            for expected_value in expected_values {
                let found = response_headers.iter().any(|h| {
                    let h_lower = h.to_lowercase();
                    h_lower.starts_with(&format!("{}:", name_lower))
                        && h_lower.contains(&expected_value.to_lowercase())
                });
                if !found {
                    result.failures.push(format!(
                        "header: {:?}: {:?} not found in response headers",
                        header_name, expected_value
                    ));
                }
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}
