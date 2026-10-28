use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a File resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Path to the file. If omitted, the map key is used as the path.
    #[serde(rename = "path", alias = "Path", default)]
    pub path: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the file should exist. Defaults to true.
    #[serde(rename = "exists", alias = "Exists", default = "default_exists")]
    pub exists: bool,

    /// Expected file mode (e.g. "0644").
    #[serde(rename = "mode", alias = "Mode", default)]
    pub mode: Option<String>,

    /// Expected owner name.
    #[serde(rename = "owner", alias = "Owner", default)]
    pub owner: Option<String>,

    /// Expected group name.
    #[serde(rename = "group", alias = "Group", default)]
    pub group: Option<String>,

    /// Expected file type ("file", "directory", "symlink").
    #[serde(rename = "filetype", alias = "Filetype", default)]
    pub filetype: Option<String>,

    /// Expected link target if filetype is "symlink".
    #[serde(rename = "linked-to", alias = "LinkedTo", default)]
    pub linked_to: Option<String>,

    /// List of matchers for file content.
    #[serde(rename = "contents", alias = "Contents", default)]
    pub contents: Vec<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

fn default_exists() -> bool {
    true
}

impl FileResource {
    /// Returns the path to validate (either the explicit `path` or the provided `id`).
    pub fn effective_path(&self, id: &str) -> String {
        self.path.clone().unwrap_or_else(|| id.to_string())
    }
}
