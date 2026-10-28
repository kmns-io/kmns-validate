use crate::resource::service::ServiceResource;
use crate::validate::http::ResourceTestResult;
use std::process::Command;

/// Validate a ServiceResource and return a structured result.
pub fn validate(name: &str, resource: &ServiceResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "service".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    // ---------- skip ----------------------------------------------------
    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let service_name = resource.effective_name(name);

    // ---------- enabled -------------------------------------------------
    if let Some(expected_enabled) = resource.enabled {
        match is_enabled(&service_name) {
            Ok(actual_enabled) => {
                if actual_enabled != expected_enabled {
                    result.failures.push(format!(
                        "enabled: expected {} got {}",
                        expected_enabled, actual_enabled
                    ));
                }
            }
            Err(e) => {
                result.error = Some(format!("enabled: check failed: {}", e));
                return result;
            }
        }
    }

    // ---------- running -------------------------------------------------
    if let Some(expected_running) = resource.running {
        match is_active(&service_name) {
            Ok(actual_running) => {
                if actual_running != expected_running {
                    result.failures.push(format!(
                        "running: expected {} got {}",
                        expected_running, actual_running
                    ));
                }
            }
            Err(e) => {
                result.error = Some(format!("running: check failed: {}", e));
                return result;
            }
        }
    }

    result.passed = result.failures.is_empty() && result.error.is_none();
    result
}

/// Enforce strict service identifier syntax: alphanumeric plus '.', '_', '@', '-'
/// and strictly reject leading dashes to prevent systemctl CLI option injection.
pub fn is_valid_service_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '@' || c == '-')
}

/// Check if a service is enabled using 'systemctl is-enabled'.
fn is_enabled(service: &str) -> std::io::Result<bool> {
    if !is_valid_service_name(service) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid service name: {service}"),
        ));
    }
    // systemctl is-enabled -- <service>
    // 0: enabled
    // >0: disabled (or not found)
    let output = Command::new("systemctl")
        .arg("is-enabled")
        .arg("--")
        .arg(service)
        .output()?;

    Ok(output.status.success())
}

/// Check if a service is active using 'systemctl is-active'.
fn is_active(service: &str) -> std::io::Result<bool> {
    if !is_valid_service_name(service) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid service name: {service}"),
        ));
    }
    // systemctl is-active -- <service>
    // 0: active
    // >0: inactive (or not found)
    let output = Command::new("systemctl")
        .arg("is-active")
        .arg("--")
        .arg(service)
        .output()?;

    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_and_invalid_service_names() {
        assert!(is_valid_service_name("nginx"));
        assert!(is_valid_service_name("docker.service"));
        assert!(is_valid_service_name("user@1000.service"));
        assert!(is_valid_service_name("systemd-journald"));

        // Reject flags and injection attempts
        assert!(!is_valid_service_name("--user"));
        assert!(!is_valid_service_name("-H"));
        assert!(!is_valid_service_name(""));
        assert!(!is_valid_service_name("nginx; reboot"));
        assert!(!is_valid_service_name("svc\nname"));
    }
}
