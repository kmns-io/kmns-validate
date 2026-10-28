use crate::resource::kernel::KernelResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// Validate a KernelResource and return a structured result.
pub fn validate(name: &str, resource: &KernelResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "kernel".to_string(),
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

    let param_name = resource.effective_parameter_name(name);

    // Convert parameter name (e.g., net.ipv4.ip_forward) to path (e.g., /proc/sys/net/ipv4/ip_forward)
    let relative_path = param_name.replace('.', "/");
    let full_path = PathBuf::from("/proc/sys").join(relative_path);

    // Read parameter value
    let current_value = match fs::read_to_string(&full_path) {
        Ok(v) => v.trim().to_string(),
        Err(e) => {
            result.failures.push(format!(
                "kernel_param: failed to read parameter \"{}\" (at {:?}): {}",
                param_name, full_path, e
            ));
            result.passed = false;
            return result;
        }
    };

    // ---------- value ---------------------------------------------------
    if let Some(expected) = &resource.value {
        let res = matcher::validate(&Value::String(current_value), expected);
        if !res.passed {
            result.failures.push(format!(
                "value: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

    result.passed = result.failures.is_empty();
    result
}
