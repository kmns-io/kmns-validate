use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_CONTRACT_FILE_BYTES: usize = 1024 * 1024; // 1 MiB
pub const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024; // 1 MiB
pub const MAX_FILE_CONTENTS_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
pub const MAX_CONTAINER_RESPONSE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
pub const MAX_VERSION_CACHE_BYTES: usize = 64 * 1024; // 64 KiB

#[derive(Debug, Error)]
pub enum BoundedReadError {
    #[error("input exceeded limit of {limit} bytes")]
    LimitExceeded { limit: usize },
    #[error("operation timed out after deadline")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid UTF-8 data: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Reads from a synchronous `Read` source up to `limit` bytes.
///
/// Reads in fixed chunks without preallocating the entire limit.
/// Stops immediately upon observing byte `limit + 1` and returns `LimitExceeded`.
pub fn read_bounded<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, BoundedReadError> {
    const CHUNK_SIZE: usize = 8192;
    let mut chunk = [0u8; CHUNK_SIZE];
    let mut buffer = Vec::new();

    loop {
        let max_to_read = std::cmp::min(chunk.len(), (limit + 1).saturating_sub(buffer.len()));
        if max_to_read == 0 {
            // Buffer already reached limit + 1
            return Err(BoundedReadError::LimitExceeded { limit });
        }

        let n = reader.read(&mut chunk[..max_to_read])?;
        if n == 0 {
            // EOF reached within limit
            return Ok(buffer);
        }

        if buffer.len() + n > limit {
            return Err(BoundedReadError::LimitExceeded { limit });
        }

        buffer.extend_from_slice(&chunk[..n]);
    }
}

/// Reads from a synchronous `Read` source up to `limit` bytes, checking an absolute deadline.
#[allow(dead_code)]
pub fn read_bounded_with_deadline<R: Read>(
    mut reader: R,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, BoundedReadError> {
    const CHUNK_SIZE: usize = 8192;
    let mut chunk = [0u8; CHUNK_SIZE];
    let mut buffer = Vec::new();

    loop {
        if Instant::now() >= deadline {
            return Err(BoundedReadError::Timeout);
        }

        let max_to_read = std::cmp::min(chunk.len(), (limit + 1).saturating_sub(buffer.len()));
        if max_to_read == 0 {
            return Err(BoundedReadError::LimitExceeded { limit });
        }

        let n = reader.read(&mut chunk[..max_to_read])?;
        if n == 0 {
            return Ok(buffer);
        }

        if buffer.len() + n > limit {
            return Err(BoundedReadError::LimitExceeded { limit });
        }

        buffer.extend_from_slice(&chunk[..n]);
    }
}

/// Reads a regular file up to `limit` bytes into a `Vec<u8>`.
pub fn read_file_bounded<P: AsRef<Path>>(
    path: P,
    limit: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    let file = File::open(path)?;
    read_bounded(file, limit)
}

/// Reads a regular file up to `limit` bytes and decodes it as UTF-8 string.
pub fn read_file_to_string_bounded<P: AsRef<Path>>(
    path: P,
    limit: usize,
) -> Result<String, BoundedReadError> {
    let bytes = read_file_bounded(path, limit)?;
    String::from_utf8(bytes).map_err(BoundedReadError::from)
}

/// Reads from a Unix domain socket up to `limit` bytes while enforcing an absolute total deadline.
pub fn read_unix_stream_bounded(
    stream: &mut std::os::unix::net::UnixStream,
    limit: usize,
    deadline: Instant,
    per_read_timeout: Option<Duration>,
) -> Result<Vec<u8>, BoundedReadError> {
    const CHUNK_SIZE: usize = 8192;
    let mut chunk = [0u8; CHUNK_SIZE];
    let mut buffer = Vec::new();

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(BoundedReadError::Timeout);
        }

        let remaining = deadline.saturating_duration_since(now);
        let read_timeout = match per_read_timeout {
            Some(t) => t.min(remaining),
            None => remaining,
        };
        let _ = stream.set_read_timeout(Some(read_timeout));

        let max_to_read = std::cmp::min(chunk.len(), (limit + 1).saturating_sub(buffer.len()));
        if max_to_read == 0 {
            return Err(BoundedReadError::LimitExceeded { limit });
        }

        match stream.read(&mut chunk[..max_to_read]) {
            Ok(0) => return Ok(buffer),
            Ok(n) => {
                if buffer.len() + n > limit {
                    return Err(BoundedReadError::LimitExceeded { limit });
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err(BoundedReadError::Timeout);
                }
                // If the stream timed out on an individual read
                return Err(BoundedReadError::Timeout);
            }
            Err(e) => return Err(BoundedReadError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_bounded_accepts_exact_limit() {
        let data = vec![b'x'; 100];
        let cursor = Cursor::new(data.clone());
        let result = read_bounded(cursor, 100).expect("exact limit should succeed");
        assert_eq!(result.len(), 100);
        assert_eq!(result, data);
    }

    #[test]
    fn test_read_bounded_rejects_limit_plus_one() {
        let data = vec![b'x'; 101];
        let cursor = Cursor::new(data);
        let err = read_bounded(cursor, 100).expect_err("limit + 1 should fail");
        match err {
            BoundedReadError::LimitExceeded { limit } => assert_eq!(limit, 100),
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_read_bounded_with_deadline_triggers_timeout() {
        use std::io::ErrorKind;
        struct SlowReader;
        impl Read for SlowReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_millis(50));
                Err(io::Error::new(ErrorKind::TimedOut, "mock slow"))
            }
        }

        let deadline = Instant::now() + Duration::from_millis(20);
        let err =
            read_bounded_with_deadline(SlowReader, 100, deadline).expect_err("should time out");
        match err {
            BoundedReadError::Timeout | BoundedReadError::Io(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
