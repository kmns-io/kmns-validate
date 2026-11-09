use serde_json::Value;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub(crate) enum QueryResult {
    Found(Value),
    NotFound,
    EngineError(String),
}

/// Enforce strict container identifier syntax: alphanumeric plus '.', '_', '-'
/// and reject control characters, CRLF, and path traversal sequences.
pub fn is_valid_container_name(name: &str) -> bool {
    let trimmed = name.trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

pub(crate) fn query_socket_for_container(
    socket_path: &Path,
    container_name: &str,
    timeout: Duration,
) -> Result<QueryResult, String> {
    if !is_valid_container_name(container_name) {
        return Err(format!(
            "Invalid container identifier for socket query: {container_name:?}"
        ));
    }

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!(
            "Failed to connect to socket {:?}: {}",
            socket_path.display(),
            e
        )
    })?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let sanitized_name = container_name.trim_start_matches('/');
    let http_request = format!(
        "GET /containers/{}/json HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        sanitized_name
    );

    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| format!("Failed to send request to socket {:?}: {}", socket_path, e))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let deadline = std::time::Instant::now() + timeout;
    let response_bytes = match crate::bounded_io::read_unix_stream_bounded(
        &mut stream,
        crate::bounded_io::MAX_CONTAINER_RESPONSE_BYTES,
        deadline,
        Some(timeout),
    ) {
        Ok(b) => b,
        Err(crate::bounded_io::BoundedReadError::LimitExceeded { .. }) => {
            return Err("E_CONTAINER_RESPONSE_LIMIT".to_string());
        }
        Err(crate::bounded_io::BoundedReadError::Timeout) => {
            return Err("E_CONTAINER_RESPONSE_TIMEOUT".to_string());
        }
        Err(e) => {
            return Err(format!(
                "Failed to read response from socket {:?}: {}",
                socket_path, e
            ));
        }
    };

    let response_str = String::from_utf8_lossy(&response_bytes);
    let mut parts = response_str.splitn(2, "\r\n\r\n");
    let header_part = parts.next().unwrap_or("");
    let body_part = match parts.next() {
        Some(b) => b,
        None => {
            let mut alt_parts = response_str.splitn(2, "\n\n");
            alt_parts.next();
            alt_parts.next().unwrap_or("")
        }
    };

    let status_line = header_part.lines().next().unwrap_or("");
    if status_line.contains("404") {
        return Ok(QueryResult::NotFound);
    }

    if !status_line.contains("200") {
        return Ok(QueryResult::EngineError(format!(
            "HTTP error: {}",
            status_line
        )));
    }

    let json_data: Value = serde_json::from_str(body_part.trim()).map_err(|e| {
        format!(
            "Failed to parse container JSON response: {} (body: {:?})",
            e,
            &body_part[..body_part.len().min(200)]
        )
    })?;

    Ok(QueryResult::Found(json_data))
}
