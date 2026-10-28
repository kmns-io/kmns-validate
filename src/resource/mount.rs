use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Mount resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The mount point path (e.g., /). If omitted, the map key is used.
    #[serde(rename = "mount_point", alias = "MountPoint", default)]
    pub mount_point: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the mount point is expected to exist.
    #[serde(rename = "exists", alias = "Exists", default)]
    pub exists: Option<bool>,

    /// Expected mount option matchers (e.g., rw,relatime).
    #[serde(rename = "opts", alias = "Opts", default)]
    pub opts: Vec<crate::resource::matcher::MatcherConfig>,

    /// Expected source device (can be a matcher).
    #[serde(rename = "source", alias = "Source", default)]
    pub source: Option<crate::resource::matcher::MatcherConfig>,

    /// Expected filesystem type (can be a matcher).
    #[serde(rename = "vfs", alias = "Vfs", default)]
    pub vfs: Option<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl MountResource {
    pub fn effective_mount_point(&self, id: &str) -> String {
        self.mount_point.clone().unwrap_or_else(|| id.to_string())
    }
}
