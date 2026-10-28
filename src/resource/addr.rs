use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for an Addr resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The network address to check (e.g., tcp://google.com:80). If omitted, the map key is used.
    #[serde(rename = "address", alias = "Address", default)]
    pub address: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the address is expected to be reachable.
    #[serde(rename = "reachable", alias = "Reachable", default)]
    pub reachable: Option<bool>,

    /// Timeout in milliseconds for connection attempts.
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl AddrResource {
    pub fn effective_address(&self, id: &str) -> String {
        self.address.clone().unwrap_or_else(|| id.to_string())
    }
}
