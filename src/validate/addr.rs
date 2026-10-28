use crate::resource::addr::AddrResource;
use crate::validate::http::ResourceTestResult;
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

/// Validate an AddrResource and return a structured result.
pub fn validate(name: &str, resource: &AddrResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "addr".to_string(),
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

    let full_addr = resource.effective_address(name);
    let timeout_ms = resource.timeout.unwrap_or(500); // Default 500ms
    let timeout = Duration::from_millis(timeout_ms);

    let is_reachable = check_reachability(&full_addr, timeout);

    // ---------- reachable -----------------------------------------------
    if resource
        .reachable
        .is_some_and(|expected| is_reachable != expected)
    {
        result.failures.push(format!(
            "reachable: expected {} got {}",
            resource.reachable.unwrap(),
            is_reachable
        ));
    }

    result.passed = result.failures.is_empty();
    result
}

fn check_reachability(addr: &str, timeout: Duration) -> bool {
    let (proto, target) = if let Some(idx) = addr.find("://") {
        (&addr[..idx], &addr[idx + 3..])
    } else {
        ("tcp", addr)
    };

    use std::net::ToSocketAddrs;
    let addrs = match target.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return false,
    };

    match proto {
        "tcp" => {
            for a in addrs {
                if TcpStream::connect_timeout(&a, timeout).is_ok() {
                    return true;
                }
            }
            false
        }
        "udp" => {
            for a in addrs {
                if UdpSocket::bind("0.0.0.0:0")
                    .and_then(|s| s.connect(a))
                    .is_ok()
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}
