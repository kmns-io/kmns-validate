use crate::resource::interface::InterfaceResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use nix::ifaddrs::getifaddrs;
use serde_json::Value;

/// Validate an InterfaceResource and return a structured result.
pub fn validate(name: &str, resource: &InterfaceResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "interface".to_string(),
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

    let if_name = resource.effective_interface_name(name);

    // Get system interfaces
    let ifaddrs_iter = match getifaddrs() {
        Ok(iter) => iter,
        Err(e) => {
            result.error = Some(format!("failed to get system interfaces: {}", e));
            return result;
        }
    };

    let mut current_exists = false;
    let mut current_addrs = Vec::new();

    for iface in ifaddrs_iter {
        if iface.interface_name == if_name {
            current_exists = true;
            if let Some(address) = iface.address {
                // Formatting the address info
                if let Some(ip) = address.as_sockaddr_in() {
                    current_addrs.push(ip.ip().to_string());
                } else if let Some(ip6) = address.as_sockaddr_in6() {
                    current_addrs.push(ip6.ip().to_string());
                }
            }
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

    // ---------- addrs ---------------------------------------------------
    if current_exists && !resource.addrs.is_empty() {
        for expected in &resource.addrs {
            // Check if any interface address matches the matcher
            let mut found = false;
            let mut last_failure = String::from("no matching address assigned");
            for addr in &current_addrs {
                let res = matcher::validate(&Value::String(addr.clone()), expected);
                if res.passed {
                    found = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }

            if !found {
                result.failures.push(format!("addrs: {}", last_failure));
            }
        }
    }

    result.passed = result.failures.is_empty();
    result
}
