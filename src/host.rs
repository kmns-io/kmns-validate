//! Bounded local host observations used by the default `host` contract.

use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;

pub const MAX_OBSERVATION_BYTES: usize = 256;

pub fn collect(field: &str) -> Result<String> {
    let value = match field {
        "hostname" => nix::unistd::gethostname()
            .map_err(|error| format!("cannot read hostname: {error}"))?
            .to_string_lossy()
            .into_owned(),
        "os" => {
            let info = os_info::get();
            format!("{} {}", info.os_type(), info.version())
        }
        "machine-id" => machine_id_digest(
            &std::fs::read_to_string("/etc/machine-id")
                .map_err(|error| format!("cannot read machine ID: {error}"))?,
        ),
        "uptime" => uptime_seconds()?.to_string(),
        _ => return Err("unsupported host observation field".to_owned()),
    };
    if value.is_empty()
        || value.len() > MAX_OBSERVATION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err("host observation is empty or exceeds its size limit".to_owned());
    }
    Ok(value)
}

pub fn machine_id_digest(machine_id: &str) -> String {
    let bytes = Sha256::digest(machine_id.trim().as_bytes());
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "linux")]
fn uptime_seconds() -> Result<u64> {
    let raw = std::fs::read_to_string("/proc/uptime")
        .map_err(|error| format!("cannot read uptime: {error}"))?;
    let value = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| "uptime is missing".to_owned())?;
    let seconds = value
        .split_once('.')
        .map_or(value, |(whole, _)| whole)
        .parse::<u64>()
        .map_err(|error| format!("uptime is invalid: {error}"))?;
    Ok(seconds)
}

#[cfg(not(target_os = "linux"))]
fn uptime_seconds() -> Result<u64> {
    Err("uptime observation is only supported on Linux".to_owned())
}

#[cfg(test)]
mod tests {
    use super::machine_id_digest;

    #[test]
    fn machine_id_is_never_returned_raw() {
        assert_eq!(machine_id_digest("example-machine-id\n").len(), 64);
        assert_ne!(
            machine_id_digest("example-machine-id"),
            "example-machine-id"
        );
    }
}
