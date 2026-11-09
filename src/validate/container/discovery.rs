use crate::resource::container::ContainerResource;
use nix::unistd::User;
use std::path::{Path, PathBuf};

/// Discovery context parameterizing user identity and runtime paths for deterministic container socket selection.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveryContext {
    pub effective_uid: u32,
    pub xdg_runtime_dir: Option<PathBuf>,
    pub run_user_base: PathBuf,
    pub system_sockets: Vec<PathBuf>,
}

impl Default for DiscoveryContext {
    fn default() -> Self {
        let effective_uid = nix::unistd::geteuid().as_raw();
        let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok().map(PathBuf::from);
        let run_user_base = PathBuf::from("/run/user");
        let system_sockets = vec![
            PathBuf::from("/var/run/docker.sock"),
            PathBuf::from("/run/podman/podman.sock"),
            PathBuf::from("/run/docker.sock"),
        ];

        Self {
            effective_uid,
            xdg_runtime_dir,
            run_user_base,
            system_sockets,
        }
    }
}

/// Helper to resolve a user string (name or numeric UID) to a numeric UID.
pub(crate) fn resolve_user_uid(user_str: &str) -> Option<u32> {
    if let Ok(uid) = user_str.parse::<u32>() {
        return Some(uid);
    }
    User::from_name(user_str)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

/// Enforces the SPEC-045 reconciliation rule:
/// When `resource.user` is present, it must resolve to the authorized `run_as` identity
/// (if present) or the current effective user identity.
pub(crate) fn verify_user_scope(
    resource_user: Option<&str>,
    run_as: Option<&str>,
    effective_uid: u32,
) -> Result<Option<u32>, &'static str> {
    let authorized_uid = if let Some(run_as_str) = run_as {
        let uid = resolve_user_uid(run_as_str).ok_or("E_CONTAINER_USER_SCOPE_MISMATCH")?;
        Some(uid)
    } else {
        None
    };

    if let Some(res_user_str) = resource_user {
        let res_uid = resolve_user_uid(res_user_str).ok_or("E_CONTAINER_USER_SCOPE_MISMATCH")?;
        let expected_uid = authorized_uid.unwrap_or(effective_uid);
        if res_uid != expected_uid {
            return Err("E_CONTAINER_USER_SCOPE_MISMATCH");
        }
        Ok(Some(res_uid))
    } else {
        Ok(authorized_uid)
    }
}

/// Verifies that an $XDG_RUNTIME_DIR matches the effective UID path `/run/user/<effective_uid>`.
pub(crate) fn is_valid_xdg_runtime_dir(
    path: &Path,
    run_user_base: &Path,
    effective_uid: u32,
) -> bool {
    let expected = run_user_base.join(effective_uid.to_string());
    if path == expected {
        return true;
    }
    // Also check canonical equality if both paths exist
    if let (Ok(c1), Ok(c2)) = (path.canonicalize(), expected.canonicalize()) {
        if c1 == c2 {
            return true;
        }
    }
    false
}

/// Deterministically resolve candidate sockets under SPEC-045 security invariants.
///
/// Returns `Ok(candidates)` or `Err(error_code)`.
pub(crate) fn resolve_candidate_sockets_with_ctx(
    resource: &ContainerResource,
    run_as: Option<&str>,
    ctx: &DiscoveryContext,
) -> Result<Vec<PathBuf>, &'static str> {
    // 0. Verify resource.user scope match
    let designated_uid = verify_user_scope(resource.user.as_deref(), run_as, ctx.effective_uid)?;

    // 1. Explicit socket from resource definition (supports raw path or unix:// scheme)
    // INV-045-4: Explicit socket is exclusive and disables all automatic discovery.
    if let Some(sock) = &resource.socket {
        let clean_path = sock.strip_prefix("unix://").unwrap_or(sock);
        let p = PathBuf::from(clean_path);
        if p.exists() {
            return Ok(vec![p]);
        }
        return Err("E_CONTAINER_SOCKET_UNAVAILABLE");
    }

    // 2. Designated rootless identity (via run_as or validated resource.user)
    // INV-045-2 & INV-045-3: Eligible candidates are strictly UID's paths; no fallback to system/active.
    if let Some(uid) = designated_uid {
        let mut candidates = Vec::new();
        let user_dir = ctx.run_user_base.join(uid.to_string());
        let user_docker = user_dir.join("docker.sock");
        if user_docker.exists() {
            candidates.push(user_docker);
        }
        let user_podman = user_dir.join("podman/podman.sock");
        if user_podman.exists() {
            candidates.push(user_podman);
        }

        if candidates.is_empty() {
            return Err("E_CONTAINER_SOCKET_UNAVAILABLE");
        }
        return Ok(candidates);
    }

    // 3. Rootless discovery for current unprivileged user (effective_uid != 0)
    if ctx.effective_uid != 0 {
        // 3a. Active session via verified XDG_RUNTIME_DIR
        if let Some(ref xdg) = ctx.xdg_runtime_dir {
            if is_valid_xdg_runtime_dir(xdg, &ctx.run_user_base, ctx.effective_uid) {
                let mut candidates = Vec::new();
                let xdg_docker = xdg.join("docker.sock");
                if xdg_docker.exists() {
                    candidates.push(xdg_docker);
                }
                let xdg_podman = xdg.join("podman/podman.sock");
                if xdg_podman.exists() {
                    candidates.push(xdg_podman);
                }
                // Under SPEC-045 Table 3: valid XDG selects Docker/Podman paths below that runtime dir only.
                // Prohibited fallback: /run/user/<other_uid> and system sockets.
                if candidates.is_empty() {
                    return Err("E_CONTAINER_SOCKET_UNAVAILABLE");
                }
                return Ok(candidates);
            }
        }

        // 3b. No active runtime directory: check /run/user/<effective_uid>/ paths
        let user_dir = ctx.run_user_base.join(ctx.effective_uid.to_string());
        let mut user_candidates = Vec::new();
        let user_docker = user_dir.join("docker.sock");
        if user_docker.exists() {
            user_candidates.push(user_docker);
        }
        let user_podman = user_dir.join("podman/podman.sock");
        if user_podman.exists() {
            user_candidates.push(user_podman);
        }
        if !user_candidates.is_empty() {
            return Ok(user_candidates);
        }

        // 3c. If neither rootless path exists, fall back to standard system paths
        let mut sys_candidates = Vec::new();
        for sys in &ctx.system_sockets {
            if sys.exists() {
                sys_candidates.push(sys.clone());
            }
        }
        if sys_candidates.is_empty() {
            return Err("E_CONTAINER_SOCKET_UNAVAILABLE");
        }
        return Ok(sys_candidates);
    }

    // 4. Effective UID is root without a designated run_as identity
    // Standard system Docker/Podman socket paths only; no rootless discovery.
    let mut sys_candidates = Vec::new();
    for sys in &ctx.system_sockets {
        if sys.exists() {
            sys_candidates.push(sys.clone());
        }
    }
    if sys_candidates.is_empty() {
        return Err("E_CONTAINER_SOCKET_UNAVAILABLE");
    }
    Ok(sys_candidates)
}

pub(crate) fn resolve_candidate_sockets(
    resource: &ContainerResource,
    run_as: Option<&str>,
) -> Result<Vec<PathBuf>, &'static str> {
    resolve_candidate_sockets_with_ctx(resource, run_as, &DiscoveryContext::default())
}
