use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Package resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The package name. If omitted, the map key is used.
    #[serde(rename = "package", alias = "Package", default)]
    pub package: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Whether the package is expected to be installed.
    #[serde(rename = "installed", alias = "Installed", default)]
    pub installed: Option<bool>,

    /// Expected version matchers.
    #[serde(rename = "version", alias = "Version", default)]
    pub version: Vec<crate::resource::matcher::MatcherConfig>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl PackageResource {
    pub fn effective_package_name(&self, id: &str) -> String {
        self.package.clone().unwrap_or_else(|| id.to_string())
    }
}
