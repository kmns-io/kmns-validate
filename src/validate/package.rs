use crate::resource::package::PackageResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::process::Command;

/// Validate a PackageResource and return a structured result.
pub fn validate(
    name: &str,
    resource: &PackageResource,
    package_manager: &str,
) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "package".to_string(),
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

    let pkg_name = resource.effective_package_name(name);
    let (is_installed, version) = check_package(package_manager, &pkg_name);

    // ---------- installed -----------------------------------------------
    if resource
        .installed
        .is_some_and(|expected| is_installed != expected)
    {
        result.failures.push(format!(
            "installed: expected {} got {}",
            resource.installed.unwrap(),
            is_installed
        ));
    }

    // ---------- version -------------------------------------------------
    if is_installed {
        if let Some(actual_version) = version {
            for expected in &resource.version {
                let res = matcher::validate(&Value::String(actual_version.clone()), expected);
                if !res.passed {
                    result.failures.push(format!(
                        "version: {}",
                        res.failure_message.unwrap_or_default()
                    ));
                }
            }
        } else if !resource.version.is_empty() {
            result
                .failures
                .push("version: could not determine package version".to_string());
        }
    }

    result.passed = result.failures.is_empty();
    result
}

/// Enforce strict package identifier syntax: alphanumeric plus '.', '_', '+', '@', '-'
/// and strictly reject leading dashes to prevent CLI option injection.
pub fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('-') {
        return false;
    }
    name.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '+' || c == '@' || c == '-'
    })
}

fn check_package(pm: &str, name: &str) -> (bool, Option<String>) {
    if !is_valid_package_name(name) {
        return (false, None);
    }
    match pm {
        "apt" => check_apt(name),
        "dnf" | "yum" => check_rpm(name),
        "pacman" => check_pacman(name),
        "apk" => check_apk(name),
        _ => (false, None), // Unsupported package manager
    }
}

fn check_apt(name: &str) -> (bool, Option<String>) {
    // dpkg-query -W -f='${Status} ${Version}' -- <name>
    let output = Command::new("dpkg-query")
        .arg("-W")
        .arg("-f=${Status} ${Version}")
        .arg("--")
        .arg(name)
        .output();

    match output {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("install ok installed") => {
            let res = String::from_utf8_lossy(&o.stdout);
            let version = res.split_whitespace().last().map(|v| v.to_string());
            (true, version)
        }
        _ => (false, None),
    }
}

fn check_rpm(name: &str) -> (bool, Option<String>) {
    // rpm -q --queryformat '%{VERSION}' -- <name>
    let output = Command::new("rpm")
        .arg("-q")
        .arg("--queryformat")
        .arg("%{VERSION}")
        .arg("--")
        .arg(name)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (true, Some(version))
        }
        _ => (false, None),
    }
}

fn check_pacman(name: &str) -> (bool, Option<String>) {
    // pacman -Q -- <name>
    let output = Command::new("pacman")
        .arg("-Q")
        .arg("--")
        .arg(name)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let res = String::from_utf8_lossy(&o.stdout);
            let version = res.split_whitespace().nth(1).map(|v| v.to_string());
            (true, version)
        }
        _ => (false, None),
    }
}

fn check_apk(name: &str) -> (bool, Option<String>) {
    // apk info -v -- <name>
    let output = Command::new("apk")
        .arg("info")
        .arg("-v")
        .arg("--")
        .arg(name)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let res = String::from_utf8_lossy(&o.stdout);
            // apk info -v usually returns "pkgname-version"
            let version = res
                .trim()
                .strip_prefix(name)
                .and_then(|v| v.strip_prefix('-'))
                .map(|v| v.to_string());
            (true, version)
        }
        _ => (false, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_and_invalid_package_names() {
        assert!(is_valid_package_name("nginx"));
        assert!(is_valid_package_name("libssl3"));
        assert!(is_valid_package_name("python3.10"));
        assert!(is_valid_package_name("systemd-sysv"));
        assert!(is_valid_package_name("libstdc++6"));

        // Reject flags and injection attempts
        assert!(!is_valid_package_name("-W"));
        assert!(!is_valid_package_name("--all"));
        assert!(!is_valid_package_name(""));
        assert!(!is_valid_package_name("nginx; rm -rf /"));
        assert!(!is_valid_package_name("pkg\nname"));
    }
}
