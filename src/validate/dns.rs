use crate::resource::dns::DnsResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::net::ToSocketAddrs;

/// Validate a DnsResource and return a structured result.
pub fn validate(name: &str, resource: &DnsResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "dns".to_string(),
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

    let host = resource.effective_host(name);

    // Resolve the host. Note: std doesn't support custom servers directly.
    // To support custom servers, we'd need a crate like trust-dns-resolver.
    // For now, we perform standard system resolution.
    let addr_result = format!("{}:0", host).to_socket_addrs();
    let (is_resolvable, resolved_addrs) = match addr_result {
        Ok(addrs) => {
            let list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            (true, list)
        }
        Err(_) => (false, Vec::new()),
    };

    // ---------- resolvable ----------------------------------------------
    if let Some(expected_resolvable) = resource.resolvable {
        if is_resolvable != expected_resolvable {
            result.failures.push(format!(
                "resolvable: expected {} got {}",
                expected_resolvable, is_resolvable
            ));
        }
    }

    // ---------- addrs ---------------------------------------------------
    if is_resolvable && !resource.addrs.is_empty() {
        for expected in &resource.addrs {
            // Check if any resolved address matches the matcher
            let mut found = false;
            let mut last_failure = String::from("no matching address found");
            for addr in &resolved_addrs {
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
