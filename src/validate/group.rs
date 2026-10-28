use crate::resource::group::GroupResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use nix::unistd::Group;
use serde_json::Value;

/// Validate a GroupResource and return a structured result.
pub fn validate(name: &str, resource: &GroupResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "group".to_string(),
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

    let groupname = resource.effective_groupname(name);

    // ---------- exists --------------------------------------------------
    let sys_group = match Group::from_name(&groupname) {
        Ok(g) => g,
        Err(nix::errno::Errno::ENOENT) => None,
        Err(e) => {
            result.error = Some(format!("failed to lookup group {}: {}", groupname, e));
            return result;
        }
    };

    let current_exists = sys_group.is_some();

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

    let group = sys_group.unwrap();

    // ---------- gid -----------------------------------------------------
    if let Some(expected) = &resource.gid {
        let res = matcher::validate(
            &Value::Number(serde_json::Number::from(group.gid.as_raw())),
            expected,
        );
        if !res.passed {
            result
                .failures
                .push(format!("gid: {}", res.failure_message.unwrap_or_default()));
        }
    }

    result.passed = result.failures.is_empty();
    result
}
