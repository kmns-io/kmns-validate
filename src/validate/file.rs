use crate::resource::file::FileResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use nix::unistd::{Gid, Group, Uid, User};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Validate a FileResource and return a structured result.
pub fn validate(name: &str, resource: &FileResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "file".to_string(),
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

    let path_str = resource.effective_path(name);
    let path = std::path::Path::new(&path_str);

    // ---------- exists --------------------------------------------------
    let metadata_res = fs::symlink_metadata(path);
    let current_exists = metadata_res.is_ok();

    if current_exists != resource.exists {
        result.failures.push(format!(
            "exists: expected {} got {}",
            resource.exists, current_exists
        ));
        result.passed = false;
        return result;
    }

    // If it doesn't exist and was expected not to exist, we're done here.
    if !current_exists {
        result.passed = true;
        return result;
    }

    // ---------- metadata ------------------------------------------------
    let metadata = metadata_res.unwrap();
    let file_type = metadata.file_type();

    // ---------- filetype ------------------------------------------------
    if let Some(expected_type) = &resource.filetype {
        let actual_type = if file_type.is_dir() {
            "directory"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "file"
        };
        if actual_type != expected_type {
            result.failures.push(format!(
                "filetype: expected {} got {}",
                expected_type, actual_type
            ));
        }
    }

    // ---------- mode ----------------------------------------------------
    if let Some(expected_mode) = &resource.mode {
        // e.g. "0644" -> uint 0o644
        if let Ok(expected_val) = u32::from_str_radix(expected_mode.trim_start_matches('0'), 8) {
            let actual_mode = metadata.permissions().mode() & 0o7777;
            if actual_mode != expected_val {
                result.failures.push(format!(
                    "mode: expected {} got {:04o}",
                    expected_mode, actual_mode
                ));
            }
        } else {
            result
                .failures
                .push(format!("mode: invalid octal string: {}", expected_mode));
        }
    }

    // ---------- owner ---------------------------------------------------
    if let Some(expected_owner) = &resource.owner {
        let actual_uid = metadata.uid();
        if let Ok(Some(user)) = User::from_name(expected_owner) {
            if actual_uid != user.uid.as_raw() {
                // Try to get actual name
                let actual_name = User::from_uid(Uid::from_raw(actual_uid))
                    .ok()
                    .flatten()
                    .map(|u| u.name)
                    .unwrap_or_else(|| actual_uid.to_string());
                result.failures.push(format!(
                    "owner: expected {} got {}",
                    expected_owner, actual_name
                ));
            }
        } else {
            result
                .failures
                .push(format!("owner: system user not found: {}", expected_owner));
        }
    }

    // ---------- group ---------------------------------------------------
    if let Some(expected_group) = &resource.group {
        let actual_gid = metadata.gid();
        if let Ok(Some(group)) = Group::from_name(expected_group) {
            if actual_gid != group.gid.as_raw() {
                let actual_name = Group::from_gid(Gid::from_raw(actual_gid))
                    .ok()
                    .flatten()
                    .map(|g| g.name)
                    .unwrap_or_else(|| actual_gid.to_string());
                result.failures.push(format!(
                    "group: expected {} got {}",
                    expected_group, actual_name
                ));
            }
        } else {
            result
                .failures
                .push(format!("group: system group not found: {}", expected_group));
        }
    }

    // ---------- linked_to -----------------------------------------------
    if let Some(expected_link) = &resource.linked_to {
        if file_type.is_symlink() {
            match fs::read_link(path) {
                Ok(actual_link) => {
                    if actual_link.to_string_lossy() != *expected_link {
                        result.failures.push(format!(
                            "linked_to: expected {} got {}",
                            expected_link,
                            actual_link.to_string_lossy()
                        ));
                    }
                }
                Err(e) => {
                    result
                        .failures
                        .push(format!("linked_to: could not read link: {}", e));
                }
            }
        } else {
            result.failures.push("linked_to: not a symlink".into());
        }
    }

    // ---------- contents ------------------------------------------------
    if !resource.contents.is_empty() {
        if file_type.is_file() {
            match fs::read_to_string(&path_str) {
                Ok(content) => {
                    for expected in &resource.contents {
                        let res = matcher::validate(&Value::String(content.clone()), expected);
                        if !res.passed {
                            result.failures.push(format!(
                                "contents: {}",
                                res.failure_message.unwrap_or_default()
                            ));
                        }
                    }
                }
                Err(e) => {
                    result
                        .failures
                        .push(format!("contents: failed to read file: {}", e));
                }
            }
        } else {
            result.failures.push("contents: not a regular file".into());
        }
    }

    result.passed = result.failures.is_empty();
    result
}
