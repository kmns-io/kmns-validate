use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for a Command resource validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// The command line to execute. If omitted, the map key is used.
    #[serde(
        rename = "command",
        alias = "Command",
        alias = "exec",
        alias = "Exec",
        default
    )]
    pub command: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Expected exit status.
    #[serde(rename = "exit-status", alias = "ExitStatus", default)]
    pub exit_status: Option<i32>,

    /// Content that stdout must contain.
    #[serde(rename = "stdout", alias = "Stdout", default)]
    pub stdout: Vec<crate::resource::matcher::MatcherConfig>,

    /// Content that stderr must contain.
    #[serde(rename = "stderr", alias = "Stderr", default)]
    pub stderr: Vec<crate::resource::matcher::MatcherConfig>,

    /// Maximum time in seconds to wait for command completion.
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl CommandResource {
    pub fn effective_command(&self, id: &str) -> String {
        self.command.clone().unwrap_or_else(|| id.to_string())
    }
}
