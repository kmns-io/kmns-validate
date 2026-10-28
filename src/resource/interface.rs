use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for an Interface resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The interface name (e.g., eth0, lo). If omitted, the map key is used.
    #[serde(rename = "interface", alias = "Interface", default)]
    pub interface: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the interface is expected to exist.
    #[serde(rename = "exists", alias = "Exists", default)]
    pub exists: Option<bool>,

    /// List of expected IP address matchers assigned to this interface.
    #[serde(rename = "addrs", alias = "Addrs", default)]
    pub addrs: Vec<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl InterfaceResource {
    pub fn effective_interface_name(&self, id: &str) -> String {
        self.interface.clone().unwrap_or_else(|| id.to_string())
    }
}
