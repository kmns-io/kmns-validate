use crate::resource::port::PortResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::fs;

/// Result of a single Port check execution.
#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub network: String, // "tcp", "tcp6", "udp", "udp6"
    pub ip: String,
    pub port: u16,
}

/// Validate a PortResource and return a structured result.
pub fn validate(name: &str, resource: &PortResource) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "port".to_string(),
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

    let full_port_str = resource.effective_port(name);
    let (target_network, target_port) = split_port(&full_port_str);

    // Get all listening ports on the system
    let listening_ports = match get_all_listening_ports() {
        Ok(ports) => ports,
        Err(e) => {
            result.error = Some(format!("failed to scan ports: {}", e));
            return result;
        }
    };

    // ---------- listening -----------------------------------------------
    let found_ports: Vec<&ListeningPort> = listening_ports
        .iter()
        .filter(|p| p.network == target_network && p.port == target_port)
        .collect();

    let is_listening = !found_ports.is_empty();

    if let Some(expected_listening) = resource.listening {
        if is_listening != expected_listening {
            result.failures.push(format!(
                "listening: expected {} got {}",
                expected_listening, is_listening
            ));
        }
    }

    // ---------- ip ------------------------------------------------------
    if is_listening {
        if let Some(expected) = &resource.ip {
            // Check if any interface address matches the matcher
            let mut found = false;
            let mut last_failure = String::from("no matching IP assigned");
            for p in &found_ports {
                let res = matcher::validate(&Value::String(p.ip.clone()), expected);
                if res.passed {
                    found = true;
                    break;
                } else {
                    last_failure = res.failure_message.unwrap_or_default();
                }
            }

            if !found {
                result.failures.push(format!("ip: {}", last_failure));
            }
        }
    }

    result.passed = result.failures.is_empty() && result.error.is_none();
    result
}

/// Split "network:port" or "port" string. Default network is "tcp".
fn split_port(s: &str) -> (String, u16) {
    if let Some(pos) = s.find(':') {
        let network = s[..pos].to_string();
        let port = s[pos + 1..].parse::<u16>().unwrap_or(0);
        (network, port)
    } else {
        let port = s.parse::<u16>().unwrap_or(0);
        ("tcp".to_string(), port)
    }
}

/// Scan /proc/net/ records to find all listening ports.
fn get_all_listening_ports() -> std::io::Result<Vec<ListeningPort>> {
    let mut ports = Vec::new();

    // TCP/UDP IPv4
    ports.extend(parse_proc_net("/proc/net/tcp", "tcp")?);
    ports.extend(parse_proc_net("/proc/net/udp", "udp")?);

    // TCP/UDP IPv6 (Ignore if file doesn't exist)
    if let Ok(p6) = parse_proc_net("/proc/net/tcp6", "tcp6") {
        ports.extend(p6);
    }
    if let Ok(p6) = parse_proc_net("/proc/net/udp6", "udp6") {
        ports.extend(p6);
    }

    Ok(ports)
}

fn parse_proc_net(path: &str, network: &str) -> std::io::Result<Vec<ListeningPort>> {
    let content = fs::read_to_string(path)?;
    let mut ports = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        // State "0A" (TCP_LISTEN) for TCP, UDP doesn't have "LISTEN" state in /proc/net/udp (it's "07")
        // but for UDP we essentially count all "open" sockets.
        let state = fields[3];
        if network.starts_with("tcp") && state != "0A" {
            continue;
        }

        // Local address is in field index 1
        let addr_parts: Vec<&str> = fields[1].split(':').collect();
        if let Some(p) = addr_parts
            .get(1)
            .and_then(|s| u16::from_str_radix(s, 16).ok())
        {
            let ip_hex = addr_parts[0];
            let ip = parse_hex_ip(ip_hex, network.ends_with('6'));
            ports.push(ListeningPort {
                network: network.to_string(),
                ip,
                port: p,
            });
        }
    }

    Ok(ports)
}

fn parse_hex_ip(hex: &str, is_v6: bool) -> String {
    if is_v6 {
        // IPv6 is 32 hex chars (16 bytes)
        // Grouped as 4 chunks of 8 hex chars (little-endian for each chunk)
        // Actually, it depends on the system, but usually:
        // "00000000000000000000000000000000" -> "::"
        // "0000000000000000FFFF00000100007F" -> "::ffff:127.0.0.1"
        // For simplicity, let's keep it basic.
        if hex == "00000000000000000000000000000000" {
            return "::".into();
        }
        // Fallback or more complex parser... but for now, just a placeholder or
        // specialized for "::" and "::1"
        if hex == "00000000000000000000000001000000" {
            return "::1".into();
        }
        hex.to_string() // return raw hex if complex
    } else {
        // IPv4 is 8 hex chars (4 bytes) "0100007F"
        // LITTLE ENDIAN order: 7F.0.0.1
        if let Ok(val) = u32::from_str_radix(hex, 16) {
            let b1 = (val & 0xFF) as u8;
            let b2 = ((val >> 8) & 0xFF) as u8;
            let b3 = ((val >> 16) & 0xFF) as u8;
            let b4 = ((val >> 24) & 0xFF) as u8;
            format!("{}.{}.{}.{}", b1, b2, b3, b4)
        } else {
            hex.to_string()
        }
    }
}
