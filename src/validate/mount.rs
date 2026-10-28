use crate::resource::mount::MountResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::fs;

/// Validate a MountResource and return a structured result.
pub fn validate(name: &str, resource: &MountResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "mount".to_string(),
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

    let target_mount = resource.effective_mount_point(name);

    // Read and parse /proc/mounts
    let mounts_content = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("failed to read /proc/mounts: {}", e));
            return result;
        }
    };

    let mut current_exists = false;
    let mut current_source = String::new();
    let mut current_vfs = String::new();
    let mut current_opts = Vec::new();

    for line in mounts_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[1] == target_mount {
            current_exists = true;
            current_source = parts[0].to_string();
            current_vfs = parts[2].to_string();
            current_opts = parts[3].split(',').map(|s| s.to_string()).collect();
            break;
        }
    }

    // ---------- exists --------------------------------------------------
    if let Some(expected_exists) = resource.exists {
        if current_exists != expected_exists {
            result.failures.push(format!(
                "exists: expected {} got {}",
                expected_exists, current_exists
            ));
        }
    }

    if current_exists {
        // ---------- source ----------------------------------------------
        if let Some(expected) = &resource.source {
            let res = matcher::validate(&Value::String(current_source.clone()), expected);
            if !res.passed {
                result.failures.push(format!(
                    "source: {}",
                    res.failure_message.unwrap_or_default()
                ));
            }
        }

        // ---------- vfs -------------------------------------------------
        if let Some(expected) = &resource.vfs {
            let res = matcher::validate(&Value::String(current_vfs.clone()), expected);
            if !res.passed {
                result
                    .failures
                    .push(format!("vfs: {}", res.failure_message.unwrap_or_default()));
            }
        }

        // ---------- opts ------------------------------------------------
        for expected in &resource.opts {
            // Check if any mount option matches the matcher
            let mut found = false;
            let mut last_failure = String::from("no matching mount option found");
            for opt in &current_opts {
                let res = matcher::validate(&Value::String(opt.clone()), expected);
                if res.passed {
                    found = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }

            if !found {
                result.failures.push(format!("opts: {}", last_failure));
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}
