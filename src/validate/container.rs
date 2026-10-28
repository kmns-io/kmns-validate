use crate::resource::container::ContainerResource;
use crate::validate::http::ResourceTestResult;
use nix::unistd::User;
use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Discover all potential Docker/Podman Unix domain socket paths in priority order.
fn resolve_candidate_sockets(resource: &ContainerResource, run_as: Option<&str>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // 1. Explicit socket from resource definition (supports raw path or unix:// scheme)
    if let Some(sock) = &resource.socket {
        let clean_path = sock.strip_prefix("unix://").unwrap_or(sock);
        let p = PathBuf::from(clean_path);
        if p.exists() {
            candidates.push(p);
        }
    }

    // 2. Specific rootless user socket from resource.user or run_as
    let target_user = resource.user.as_deref().or(run_as);
    if let Some(user_str) = target_user {
        if let Ok(Some(u)) = User::from_name(user_str) {
            let user_docker = PathBuf::from(format!("/run/user/{}/docker.sock", u.uid));
            if user_docker.exists() && !candidates.contains(&user_docker) {
                candidates.push(user_docker);
            }
            let user_podman = PathBuf::from(format!("/run/user/{}/podman/podman.sock", u.uid));
            if user_podman.exists() && !candidates.contains(&user_podman) {
                candidates.push(user_podman);
            }
        }
    }

    // 3. Environment DOCKER_HOST (if pointing to unix domain socket)
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if let Some(sock_str) = host.strip_prefix("unix://") {
            let p = PathBuf::from(sock_str);
            if p.exists() && !candidates.contains(&p) {
                candidates.push(p);
            }
        }
    }

    // 4. Current user session rootless socket (XDG_RUNTIME_DIR or EUID)
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let xdg_docker = PathBuf::from(&xdg).join("docker.sock");
        if xdg_docker.exists() && !candidates.contains(&xdg_docker) {
            candidates.push(xdg_docker);
        }
        let xdg_podman = PathBuf::from(&xdg).join("podman/podman.sock");
        if xdg_podman.exists() && !candidates.contains(&xdg_podman) {
            candidates.push(xdg_podman);
        }
    }
    let my_uid = nix::unistd::geteuid().as_raw();
    let my_docker = PathBuf::from(format!("/run/user/{}/docker.sock", my_uid));
    if my_docker.exists() && !candidates.contains(&my_docker) {
        candidates.push(my_docker);
    }
    let my_podman = PathBuf::from(format!("/run/user/{}/podman/podman.sock", my_uid));
    if my_podman.exists() && !candidates.contains(&my_podman) {
        candidates.push(my_podman);
    }

    // 5. System-wide engine sockets
    let system_sockets = [
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/docker.sock",
    ];
    for sys in &system_sockets {
        let p = Path::new(sys);
        if p.exists() {
            let pb = p.to_path_buf();
            if !candidates.contains(&pb) {
                candidates.push(pb);
            }
        }
    }

    // 6. Discover any other rootless user sockets on system (/run/user/*/docker.sock)
    if let Ok(entries) = std::fs::read_dir("/run/user") {
        for entry in entries.flatten() {
            let u_docker = entry.path().join("docker.sock");
            if u_docker.exists() && !candidates.contains(&u_docker) {
                candidates.push(u_docker);
            }
            let u_podman = entry.path().join("podman/podman.sock");
            if u_podman.exists() && !candidates.contains(&u_podman) {
                candidates.push(u_podman);
            }
        }
    }

    candidates
}

enum QueryResult {
    Found(Value),
    NotFound,
    EngineError(String),
}

/// Enforce strict container identifier syntax: alphanumeric plus '.', '_', '-'
/// and reject control characters, CRLF, and path traversal sequences.
pub fn is_valid_container_name(name: &str) -> bool {
    let trimmed = name.trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn query_socket_for_container(
    socket_path: &Path,
    container_name: &str,
    timeout: Duration,
) -> Result<QueryResult, String> {
    if !is_valid_container_name(container_name) {
        return Err(format!(
            "Invalid container identifier for socket query: {container_name:?}"
        ));
    }

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!(
            "Failed to connect to socket {:?}: {}",
            socket_path.display(),
            e
        )
    })?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let sanitized_name = container_name.trim_start_matches('/');
    let http_request = format!(
        "GET /containers/{}/json HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        sanitized_name
    );

    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| format!("Failed to send request to socket {:?}: {}", socket_path, e))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).map_err(|e| {
        format!(
            "Failed to read response from socket {:?}: {}",
            socket_path, e
        )
    })?;

    let response_str = String::from_utf8_lossy(&response_bytes);
    let mut parts = response_str.splitn(2, "\r\n\r\n");
    let header_part = parts.next().unwrap_or("");
    let body_part = match parts.next() {
        Some(b) => b,
        None => {
            let mut alt_parts = response_str.splitn(2, "\n\n");
            alt_parts.next();
            alt_parts.next().unwrap_or("")
        }
    };

    let status_line = header_part.lines().next().unwrap_or("");
    if status_line.contains("404") {
        return Ok(QueryResult::NotFound);
    }

    if !status_line.contains("200") {
        return Ok(QueryResult::EngineError(format!(
            "HTTP error: {}",
            status_line
        )));
    }

    let json_data: Value = serde_json::from_str(body_part.trim()).map_err(|e| {
        format!(
            "Failed to parse container JSON response: {} (body: {:?})",
            e,
            &body_part[..body_part.len().min(200)]
        )
    })?;

    Ok(QueryResult::Found(json_data))
}

/// Validate a ContainerResource via direct Docker/Podman REST API over Unix domain socket.
/// Full support for rootless containers (via XDG_RUNTIME_DIR, /run/user/<uid>/docker.sock, or resource.user).
pub fn validate(
    name: &str,
    resource: &ContainerResource,
    run_as: Option<&str>,
) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "container".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let container_name = resource.effective_name(name);
    let candidate_sockets = resolve_candidate_sockets(resource, run_as);

    if candidate_sockets.is_empty() {
        result.error = Some(
            "No Docker or Podman Unix domain socket found (/var/run/docker.sock, /run/user/<uid>/docker.sock, /run/podman/podman.sock)".to_string(),
        );
        return result;
    }

    let timeout = Duration::from_secs(resource.timeout.unwrap_or(5));
    let mut container_data: Option<Value> = None;
    let mut saw_not_found = false;
    let mut last_error = None;

    for sock in &candidate_sockets {
        match query_socket_for_container(sock, &container_name, timeout) {
            Ok(QueryResult::Found(json)) => {
                container_data = Some(json);
                break;
            }
            Ok(QueryResult::NotFound) => {
                saw_not_found = true;
            }
            Ok(QueryResult::EngineError(err)) => {
                last_error = Some(format!("Socket {:?}: {}", sock, err));
            }
            Err(e) => {
                last_error = Some(e);
            }
        }
    }

    let json_data = match container_data {
        Some(d) => d,
        None => {
            if saw_not_found {
                result.failures.push(format!(
                    "container: container {:?} not found on any active container engine (checked {} sockets)",
                    container_name,
                    candidate_sockets.len()
                ));
            } else {
                result.error = Some(last_error.unwrap_or_else(|| {
                    format!(
                        "Failed to connect to any of {} candidate sockets",
                        candidate_sockets.len()
                    )
                }));
            }
            result.passed = false;
            return result;
        }
    };

    // 1. Verify Status (e.g. running)
    if let Some(expected_status) = &resource.status {
        let actual_status = json_data["State"]["Status"].as_str().unwrap_or("unknown");
        if !actual_status.eq_ignore_ascii_case(expected_status) {
            result.failures.push(format!(
                "status: expected {:?}, got {:?}",
                expected_status, actual_status
            ));
        }
    }

    // 2. Verify Image
    if let Some(expected_image) = &resource.image {
        let actual_image = json_data["Config"]["Image"].as_str().unwrap_or("");
        if !actual_image.contains(expected_image) {
            result.failures.push(format!(
                "image: expected {:?}, got {:?}",
                expected_image, actual_image
            ));
        }
    }

    // 3. Verify Exposed / Bound Ports
    if !resource.ports.is_empty() {
        let empty_map = serde_json::Map::new();
        let net_ports = json_data["NetworkSettings"]["Ports"]
            .as_object()
            .unwrap_or(&empty_map);
        let exp_ports = json_data["Config"]["ExposedPorts"]
            .as_object()
            .unwrap_or(&empty_map);

        for req_port in &resource.ports {
            let found = net_ports.contains_key(req_port) || exp_ports.contains_key(req_port);
            if !found {
                result.failures.push(format!(
                    "ports: container does not expose or bind required port {:?}",
                    req_port
                ));
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use tempfile::tempdir;

    #[test]
    fn test_container_validation_mock_socket_success() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("mock_docker.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 512];
            let _ = stream.read(&mut req);
            let body = r#"{"State":{"Status":"running"},"Config":{"Image":"ghcr.io/kmns/test:1.0","ExposedPorts":{"80/tcp":{}}},"NetworkSettings":{"Ports":{"80/tcp":[]}}}"#;
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let resource = ContainerResource {
            title: None,
            name: Some("test_app".to_string()),
            status: Some("running".to_string()),
            image: Some("test:1.0".to_string()),
            ports: vec!["80/tcp".to_string()],
            socket: Some(sock_path.to_string_lossy().to_string()),
            user: None,
            meta: None,
            timeout: Some(2),
            skip: false,
        };

        let res = validate("test_app", &resource, None);
        let _ = handle.join();

        assert!(res.passed, "Failures: {:?}", res.failures);
        assert_eq!(res.resource_type, "container");
    }

    #[test]
    fn test_container_validation_not_found() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("mock_docker_404.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 512];
            let _ = stream.read(&mut req);
            let resp = "HTTP/1.0 404 Not Found\r\n\r\n{\"message\":\"No such container: missing\"}";
            let _ = stream.write_all(resp.as_bytes());
        });

        let resource = ContainerResource {
            title: None,
            name: Some("missing_app".to_string()),
            status: Some("running".to_string()),
            image: None,
            ports: vec![],
            socket: Some(sock_path.to_string_lossy().to_string()),
            user: None,
            meta: None,
            timeout: Some(2),
            skip: false,
        };

        let res = validate("missing_app", &resource, None);
        let _ = handle.join();

        assert!(!res.passed);
        assert!(!res.failures.is_empty());
        assert!(res.failures[0].contains("not found"));
    }

    #[test]
    fn test_is_valid_container_name() {
        assert!(is_valid_container_name("kmns-web-prod"));
        assert!(is_valid_container_name("/sample-app"));
        assert!(is_valid_container_name("my_app.1"));

        // Reject injection / traversal / empty / CRLF
        assert!(!is_valid_container_name(""));
        assert!(!is_valid_container_name("/"));
        assert!(!is_valid_container_name("app/../secret"));
        assert!(!is_valid_container_name("app\r\nHost: evil.com"));
        assert!(!is_valid_container_name("app?param=val"));
    }
}
