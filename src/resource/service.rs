use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Service resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Name of the service. If omitted, the map key is used as the service name.
    #[serde(rename = "name", alias = "Name", default)]
    pub name: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the service should be enabled.
    #[serde(rename = "enabled", alias = "Enabled")]
    pub enabled: Option<bool>,

    /// Whether the service should be running.
    #[serde(rename = "running", alias = "Running")]
    pub running: Option<bool>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl ServiceResource {
    /// Returns the service name (either the explicit `name` or the provided `id`).
    pub fn effective_name(&self, id: &str) -> String {
        self.name.clone().unwrap_or_else(|| id.to_string())
    }
}
