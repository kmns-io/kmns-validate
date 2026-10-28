use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Process resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The process name. If omitted, the map key is used.
    #[serde(rename = "process", alias = "Process", default)]
    pub process: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the process is expected to be running.
    #[serde(rename = "running", alias = "Running", default)]
    pub running: Option<bool>,

    /// Expected owner UID (can be a matcher).
    #[serde(rename = "uid", alias = "UID", default)]
    pub uid: Option<crate::resource::matcher::MatcherConfig>,

    /// Expected group GID (can be a matcher).
    #[serde(rename = "gid", alias = "GID", default)]
    pub gid: Option<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl ProcessResource {
    pub fn effective_process_name(&self, id: &str) -> String {
        self.process.clone().unwrap_or_else(|| id.to_string())
    }
}
