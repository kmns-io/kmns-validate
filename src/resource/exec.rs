use crate::resource::matcher::MatcherConfig;
use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for an Exec resource validation (typed execution without shell).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Executable binary path. If omitted, the map key is used.
    #[serde(
        rename = "path",
        alias = "Path",
        alias = "bin",
        alias = "command",
        default
    )]
    pub path: Option<String>,

    /// Typed arguments list (argv, no shell interpretation).
    #[serde(rename = "args", alias = "Args", default)]
    pub args: Vec<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Expected exit status.
    #[serde(rename = "exit-status", alias = "ExitStatus", default)]
    pub exit_status: Option<i32>,

    /// Content that stdout must contain.
    #[serde(rename = "stdout", alias = "Stdout", default)]
    pub stdout: Vec<MatcherConfig>,

    /// Content that stderr must contain.
    #[serde(rename = "stderr", alias = "Stderr", default)]
    pub stderr: Vec<MatcherConfig>,

    /// Maximum time in seconds to wait for execution.
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl ExecResource {
    pub fn effective_path(&self, id: &str) -> String {
        self.path.clone().unwrap_or_else(|| id.to_string())
    }
}
