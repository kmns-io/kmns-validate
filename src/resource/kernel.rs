use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Kernel (sysctl) resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The parameter name (e.g., net.ipv4.ip_forward). If omitted, the map key is used.
    #[serde(rename = "parameter", alias = "Parameter", default)]
    pub parameter: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Expected value of the kernel parameter (can be a matcher).
    #[serde(rename = "value", alias = "Value", default)]
    pub value: Option<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl KernelResource {
    pub fn effective_parameter_name(&self, id: &str) -> String {
        self.parameter.clone().unwrap_or_else(|| id.to_string())
    }
}
