use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single HTTP check definition.
///
/// Field names support both the project's PascalCase fixture format and the
/// goss-compatible kebab-case YAML tags so that existing goss files can be
/// reused without modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResource {
    /// Optional human-readable label shown in output.
    #[serde(rename = "Title", alias = "title", default)]
    pub title: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<crate::resource::Meta>,

    /// Target URL.  When omitted the YAML map key is used as the URL.
    #[serde(rename = "url", alias = "URL", default)]
    pub url: Option<String>,

    /// HTTP method (default: GET).
    #[serde(rename = "method", alias = "Method", default)]
    pub method: Option<String>,

    /// Expected HTTP response status code (can be a literal integer or a matcher like { ge: 200 }).
    #[serde(rename = "status", alias = "Status", default = "default_status")]
    pub status: crate::resource::matcher::MatcherConfig,

    /// Skip TLS peer-certificate verification.
    #[serde(rename = "AllowInsecure", alias = "allow-insecure", default)]
    pub allow_insecure: bool,

    /// Do not follow 3xx redirects.
    #[serde(rename = "NoFollowRedirects", alias = "no-follow-redirects", default)]
    pub no_follow_redirects: bool,

    /// Request timeout in milliseconds (default: 5 000).
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Additional request headers in `"Header-Name: value"` format.
    #[serde(rename = "request-headers", alias = "RequestHeader", default)]
    pub request_headers: Vec<String>,

    /// List of matchers for the response body.
    #[serde(rename = "body", alias = "Body", default)]
    pub body: Vec<crate::resource::matcher::MatcherConfig>,

    /// Response headers that must be present, keyed by header name.
    #[serde(rename = "headers", alias = "Headers", default)]
    pub headers: Option<HashMap<String, Vec<String>>>,

    /// HTTP Basic-Auth username.
    #[serde(rename = "username", alias = "Username", default)]
    pub username: Option<String>,

    /// HTTP Basic-Auth password.
    #[serde(rename = "password", alias = "Password", default)]
    pub password: Option<String>,

    /// Path to a PEM CA-bundle file for server certificate verification.
    #[serde(rename = "ca-file", alias = "CAFile", default)]
    pub ca_file: Option<String>,

    /// Path to a client TLS certificate file.
    #[serde(rename = "cert-file", alias = "CertFile", default)]
    pub cert_file: Option<String>,

    /// Path to the client TLS private key file.
    #[serde(rename = "key-file", alias = "KeyFile", default)]
    pub key_file: Option<String>,

    /// Proxy URL (e.g. `http://proxy:3128`).
    #[serde(rename = "proxy", alias = "Proxy", default)]
    pub proxy: Option<String>,

    /// When `true` this check is skipped and reported as passed.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

fn default_status() -> crate::resource::matcher::MatcherConfig {
    crate::resource::matcher::MatcherConfig::Number(200.0)
}

impl HttpResource {
    /// Effective URL: uses the explicit `url` field or falls back to the map key.
    pub fn effective_url<'a>(&'a self, key: &'a str) -> &'a str {
        self.url.as_deref().unwrap_or(key)
    }

    /// Effective timeout in milliseconds (default: 5 000 ms).
    pub fn timeout_ms(&self) -> u64 {
        self.timeout.unwrap_or(5_000)
    }

    /// Effective HTTP method (default: `GET`).
    pub fn effective_method(&self) -> &str {
        self.method.as_deref().unwrap_or("GET")
    }
}
