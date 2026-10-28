use crate::resource::process::ProcessResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Info collected from /proc/PID
struct ProcessInfo {
    uid: u32,
    gid: u32,
}

/// Validate a ProcessResource and return a structured result.
pub fn validate(name: &str, resource: &ProcessResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "process".to_string(),
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

    let process_name = resource.effective_process_name(name);
    let matching_processes = get_matching_processes(&process_name);
    let is_running = !matching_processes.is_empty();

    if let Some(expected_running) = resource.running {
        if is_running != expected_running {
            result.failures.push(format!(
                "running: expected {} got {}",
                expected_running, is_running
            ));
        }
    }

    // ---------- uid / gid -----------------------------------------------
    if is_running {
        // uid check
        if let Some(expected_uid) = &resource.uid {
            let mut found_matching_uid = false;
            let mut last_failure = String::new();
            for proc in &matching_processes {
                let res = matcher::validate(
                    &Value::Number(serde_json::Number::from(proc.uid)),
                    expected_uid,
                );
                if res.passed {
                    found_matching_uid = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }
            if !found_matching_uid {
                result.failures.push(format!("uid: {}", last_failure));
            }
        }

        // gid check
        if let Some(expected_gid) = &resource.gid {
            let mut found_matching_gid = false;
            let mut last_failure = String::new();
            for proc in &matching_processes {
                let res = matcher::validate(
                    &Value::Number(serde_json::Number::from(proc.gid)),
                    expected_gid,
                );
                if res.passed {
                    found_matching_gid = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }
            if !found_matching_gid {
                result.failures.push(format!("gid: {}", last_failure));
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}

/// Linux-specific check to see if a process with a given name is running.
/// Scans /proc and checks both 'comm' and 'cmdline'.
fn get_matching_processes(target_name: &str) -> Vec<ProcessInfo> {
    let mut matching = Vec::new();

    let proc_path = Path::new("/proc");
    if !proc_path.exists() {
        return matching;
    }

    let entries = match fs::read_dir(proc_path) {
        Ok(e) => e,
        Err(_) => return matching,
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        let name = match path.file_name() {
            Some(n) => n.to_string_lossy(),
            None => continue,
        };

        // We only care about numeric directories (PIDs)
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let mut matches = false;

        // 1. Check /proc/PID/comm (executable name without path)
        let comm_path = path.join("comm");
        if fs::read_to_string(comm_path).is_ok_and(|c| c.trim() == target_name) {
            matches = true;
        }

        if !matches {
            let cmdline_path = path.join("cmdline");
            if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
                if cmdline
                    .split('\0')
                    .next()
                    .and_then(|cmd| Path::new(cmd).file_name())
                    .is_some_and(|name| name.to_string_lossy() == target_name)
                {
                    matches = true;
                }
            }
        }

        if matches {
            // Get UID/GID from the PID directory's metadata (this is common on Linux /proc)
            if let Ok(meta) = fs::metadata(&path) {
                matching.push(ProcessInfo {
                    uid: meta.uid(),
                    gid: meta.gid(),
                });
            }
        }
    }

    matching
}
