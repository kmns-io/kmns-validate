use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a DNS resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The hostname to resolve. If omitted, the map key is used.
    #[serde(rename = "host", alias = "Host", default)]
    pub host: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the host is expected to be resolvable.
    #[serde(rename = "resolvable", alias = "Resolvable", default)]
    pub resolvable: Option<bool>,

    /// List of expected IP address matchers the host should resolve to.
    #[serde(rename = "addrs", alias = "Addrs", default)]
    pub addrs: Vec<crate::resource::matcher::MatcherConfig>,

    /// Optional DNS server to use for resolution.
    #[serde(rename = "server", alias = "Server", default)]
    pub server: Option<String>,

    /// Timeout in milliseconds for resolution.
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl DnsResource {
    pub fn effective_host(&self, id: &str) -> String {
        self.host.clone().unwrap_or_else(|| id.to_string())
    }
}
