use crate::resource::Meta;
use serde::{Deserialize, Serialize};

/// Configuration for Container resource validation (direct Docker/Podman REST API over Unix socket).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResource {
    /// Optional human-readable title.
    #[serde(rename = "title", alias = "Title", default)]
    pub title: Option<String>,

    /// Container name or ID. If omitted, the map key is used.
    #[serde(rename = "name", alias = "Name", alias = "id", default)]
    pub name: Option<String>,

    /// Expected lifecycle status: running, exited, paused, etc.
    #[serde(rename = "status", alias = "Status", default)]
    pub status: Option<String>,

    /// Expected image (exact match or substring).
    #[serde(rename = "image", alias = "Image", default)]
    pub image: Option<String>,

    /// Expected exposed or bound port specifications (e.g. ["25/tcp", "465/tcp", "993/tcp"]).
    #[serde(rename = "ports", alias = "Ports", default)]
    pub ports: Vec<String>,

    /// Path to Docker/Podman Unix domain socket.
    #[serde(rename = "socket", alias = "Socket", default)]
    pub socket: Option<String>,

    /// Target user for rootless containers (e.g. "mailserver").
    #[serde(rename = "user", alias = "User", default)]
    pub user: Option<String>,

    /// Optional metadata block.
    #[serde(default)]
    pub meta: Option<Meta>,

    /// Maximum time in seconds to wait for socket response.
    #[serde(rename = "timeout", alias = "Timeout", default)]
    pub timeout: Option<u64>,

    /// Whether to skip this check.
    #[serde(rename = "skip", alias = "Skip", default)]
    pub skip: bool,
}

impl ContainerResource {
    pub fn effective_name(&self, id: &str) -> String {
        self.name.clone().unwrap_or_else(|| id.to_string())
    }
}
