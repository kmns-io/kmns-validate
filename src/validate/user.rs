use crate::resource::user::UserResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use nix::unistd::{Group, User};
use serde_json::Value;

/// Validate a UserResource and return a structured result.
pub fn validate(name: &str, resource: &UserResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "user".to_string(),
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

    let username = resource.effective_username(name);

    // ---------- exists --------------------------------------------------
    let sys_user = match User::from_name(&username) {
        Ok(u) => u,
        Err(nix::errno::Errno::ENOENT) => None,
        Err(e) => {
            result.error = Some(format!("failed to lookup user {}: {}", username, e));
            return result;
        }
    };

    let current_exists = sys_user.is_some();

    if resource
        .exists
        .is_some_and(|expected| current_exists != expected)
    {
        result.failures.push(format!(
            "exists: expected {} got {}",
            resource.exists.unwrap(),
            current_exists
        ));
    }

    if !current_exists {
        result.passed = result.failures.is_empty();
        return result;
    }

    let user = sys_user.unwrap();

    // ---------- uid -----------------------------------------------------
    if let Some(expected) = &resource.uid {
        let res = matcher::validate(
            &Value::Number(serde_json::Number::from(user.uid.as_raw())),
            expected,
        );
        if !res.passed {
            result
                .failures
                .push(format!("uid: {}", res.failure_message.unwrap_or_default()));
        }
    }

    // ---------- gid -----------------------------------------------------
    if let Some(expected) = &resource.gid {
        let res = matcher::validate(
            &Value::Number(serde_json::Number::from(user.gid.as_raw())),
            expected,
        );
        if !res.passed {
            result
                .failures
                .push(format!("gid: {}", res.failure_message.unwrap_or_default()));
        }
    }

    // ---------- home ----------------------------------------------------
    if let Some(expected_home) = &resource.home {
        let actual_home = user.dir.to_string_lossy();
        if actual_home != *expected_home {
            result.failures.push(format!(
                "home: expected {} got {}",
                expected_home, actual_home
            ));
        }
    }

    // ---------- shell ---------------------------------------------------
    if let Some(expected_shell) = &resource.shell {
        let actual_shell = user.shell.to_string_lossy();
        if actual_shell != *expected_shell {
            result.failures.push(format!(
                "shell: expected {} got {}",
                expected_shell, actual_shell
            ));
        }
    }

    // ---------- groups --------------------------------------------------
    if !resource.groups.is_empty() {
        for expected in &resource.groups {
            // Check all groups user belongs to
            // This usually involves looking up group memberships
            // For now, let's just check against the set of all group names user belongs to.
            let user_groups = get_user_group_names(&username, user.gid);

            // Validate the matcher against EACH name, or as a set?
            // Goss "groups" usually checks if a specific group name is present.
            // So we'll try to find a match.
            let mut found = false;
            let mut last_failure = String::from("user not in matching group");
            for gname in &user_groups {
                let res = matcher::validate(&Value::String(gname.clone()), expected);
                if res.passed {
                    found = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }

            if !found {
                result.failures.push(format!("groups: {}", last_failure));
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}

fn get_user_group_names(username: &str, primary_gid: nix::unistd::Gid) -> Vec<String> {
    let mut names = Vec::new();
    // Primary group
    if let Ok(Some(g)) = Group::from_gid(primary_gid) {
        names.push(g.name);
    }

    // Secondary groups: parse /etc/group or use nix::unistd::getgrouplist if possible.
    // getgrouplist is better but requires Uid lookup and might be platform specific.
    // For now, let's just check /etc/group since we're on linux.
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let members: Vec<&str> = parts[3].split(',').collect();
                if members.contains(&username) {
                    names.push(parts[0].to_string());
                }
            }
        }
    }

    names
}
