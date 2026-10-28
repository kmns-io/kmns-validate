use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Port resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Port number as string (e.g. "22" or "tcp:22").
    #[serde(rename = "port", alias = "Port", default)]
    pub port: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the port should be listening.
    #[serde(rename = "listening", alias = "Listening")]
    pub listening: Option<bool>,

    /// Specific IP address it should be listening on (optional, can be a matcher).
    #[serde(rename = "ip", alias = "IP", default)]
    pub ip: Option<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl PortResource {
    /// Returns the port string (either the explicit `port` or the provided `id`).
    pub fn effective_port(&self, id: &str) -> String {
        self.port.clone().unwrap_or_else(|| id.to_string())
    }
}
