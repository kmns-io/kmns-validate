use crate::resource::container::ContainerResource;
use crate::validate::http::ResourceTestResult;
use serde_json::Value;
use std::time::Duration;

pub(crate) mod assertions;
pub(crate) mod discovery;
pub(crate) mod docker_compat;

#[cfg(test)]
mod tests;

pub use docker_compat::is_valid_container_name;

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
    let candidate_sockets = match discovery::resolve_candidate_sockets(resource, run_as) {
        Ok(socks) => socks,
        Err(err_code) => {
            result.error = Some(err_code.to_string());
            return result;
        }
    };

    let timeout = Duration::from_secs(resource.timeout.unwrap_or(5));
    let mut container_data: Option<Value> = None;
    let mut saw_not_found = false;
    let mut last_error = None;

    for sock in &candidate_sockets {
        match docker_compat::query_socket_for_container(sock, &container_name, timeout) {
            Ok(docker_compat::QueryResult::Found(json)) => {
                container_data = Some(json);
                break;
            }
            Ok(docker_compat::QueryResult::NotFound) => {
                saw_not_found = true;
            }
            Ok(docker_compat::QueryResult::EngineError(err)) => {
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

    assertions::evaluate_assertions(resource, &json_data, &mut result.failures);

    result.passed = result.failures.is_empty();
    result
}
