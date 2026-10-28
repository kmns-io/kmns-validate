use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a User resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Username. If omitted, the map key is used.
    #[serde(rename = "username", alias = "Username", default)]
    pub username: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the user should exist.
    #[serde(rename = "exists", alias = "Exists")]
    pub exists: Option<bool>,

    /// Expected UID (can be a matcher).
    #[serde(rename = "uid", alias = "UID", default)]
    pub uid: Option<crate::resource::matcher::MatcherConfig>,

    /// Expected primary GID (can be a matcher).
    #[serde(rename = "gid", alias = "GID", default)]
    pub gid: Option<crate::resource::matcher::MatcherConfig>,

    /// Expected list of secondary groups (matchers).
    #[serde(rename = "groups", alias = "Groups", default)]
    pub groups: Vec<crate::resource::matcher::MatcherConfig>,

    /// Expected home directory path.
    #[serde(rename = "home", alias = "Home", default)]
    pub home: Option<String>,

    /// Expected login shell.
    #[serde(rename = "shell", alias = "Shell", default)]
    pub shell: Option<String>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl UserResource {
    pub fn effective_username(&self, id: &str) -> String {
        self.username.clone().unwrap_or_else(|| id.to_string())
    }
}
