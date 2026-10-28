use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Group resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Group name. If omitted, the map key is used.
    #[serde(rename = "groupname", alias = "GroupName", default)]
    pub groupname: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the group should exist.
    #[serde(rename = "exists", alias = "Exists")]
    pub exists: Option<bool>,

    /// Expected GID (can be a matcher).
    #[serde(rename = "gid", alias = "GID", default)]
    pub gid: Option<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl GroupResource {
    pub fn effective_groupname(&self, id: &str) -> String {
        self.groupname.clone().unwrap_or_else(|| id.to_string())
    }
}
