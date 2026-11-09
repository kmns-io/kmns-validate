use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum bounded bytes captured per stream (stdout/stderr).
pub const MAX_SUBPROCESS_OUTPUT_BYTES: usize = 16 * 1024; // 16 KiB

/// Default timeout for child processes when not specified.
pub const DEFAULT_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration parameters for executing a subprocess safely.
#[derive(Debug, Clone)]
pub struct SubprocessConfig<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub timeout: Duration,
    pub run_as: Option<&'a str>,
    pub max_output_bytes: usize,
}

impl<'a> SubprocessConfig<'a> {
    pub fn new(program: &'a str, args: &'a [String]) -> Self {
        Self {
            program,
            args,
            timeout: DEFAULT_SUBPROCESS_TIMEOUT,
            run_as: None,
            max_output_bytes: MAX_SUBPROCESS_OUTPUT_BYTES,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_run_as(mut self, run_as: Option<&'a str>) -> Self {
        self.run_as = run_as;
        self
    }

    pub fn with_max_output_bytes(mut self, max_bytes: usize) -> Self {
        self.max_output_bytes = max_bytes;
        self
    }
}

/// Output captured from a subprocess execution.
#[derive(Debug, Clone)]
pub struct SubprocessOutput {
    pub exit_status: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// Errors occurring during subprocess setup, spawning, waiting, or timeouts.
#[derive(Debug, thiserror::Error)]
pub enum SubprocessError {
    #[error("Security violation: invalid or prohibited run_as user '{0}' (root privilege escalation or invalid characters forbidden)")]
    SecurityViolation(String),

    #[error("failed to spawn command {program}: {source}")]
    SpawnError { program: String, source: io::Error },

    #[error("command execution timed out after {timeout:?}: {command}")]
    Timeout { timeout: Duration, command: String },

    #[error("error waiting for command {command}: {source}")]
    WaitError { command: String, source: io::Error },
}

/// Spawns a background thread that boundedly reads up to `max_bytes` into a buffer,
/// and then continuously copies any excess stream bytes into `std::io::sink()`.
///
/// This eliminates pipe buffer deadlocks (Linux 64 KiB default pipe capacity)
/// by ensuring standard output and standard error are drained concurrently while
/// the parent process monitors process status or timeout.
fn spawn_pipe_drainer<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut buffer = Vec::with_capacity(max_bytes.min(8192));
        let mut bounded_reader = (&mut reader).take((max_bytes + 1) as u64);
        let _ = bounded_reader.read_to_end(&mut buffer);

        let truncated = if buffer.len() > max_bytes {
            buffer.truncate(max_bytes);
            true
        } else {
            false
        };

        // Drain any remaining output to null sink until EOF to prevent child write block:
        let _ = io::copy(&mut reader, &mut io::sink());

        (buffer, truncated)
    })
}

/// Helper to format raw stream bytes and truncation state into final string.
pub fn format_stream_output(bytes: &[u8], truncated: bool) -> String {
    let mut s = String::from_utf8_lossy(bytes).trim().to_string();
    if truncated {
        s.push_str("\n[TRUNCATED: Output exceeded limit]");
    }
    s
}

/// Validates target username for privilege drop.
pub fn validate_run_as_user(target_user: &str) -> Result<&str, SubprocessError> {
    let trimmed = target_user.trim();
    let valid_user = !trimmed.is_empty()
        && trimmed != "root"
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if !valid_user {
        return Err(SubprocessError::SecurityViolation(target_user.to_string()));
    }
    Ok(trimmed)
}

/// Executes a child process using non-blocking output drainage and process tree cleanup.
pub fn execute(config: &SubprocessConfig) -> Result<SubprocessOutput, SubprocessError> {
    let current_uid = nix::unistd::geteuid();
    let is_root = current_uid.is_root();

    let mut cmd = if let Some(target_user) = config.run_as {
        let trimmed = validate_run_as_user(target_user)?;

        let need_switch = if let Ok(Some(u)) = nix::unistd::User::from_name(trimmed) {
            u.uid != current_uid
        } else {
            is_root
        };

        if need_switch {
            let mut c = Command::new("sudo");
            c.arg("-u")
                .arg(trimmed)
                .arg("--")
                .arg(config.program)
                .args(config.args);
            crate::validate::sanitize_cmd_env(&mut c, Some(trimmed));
            c
        } else {
            let mut c = Command::new(config.program);
            c.args(config.args);
            crate::validate::sanitize_cmd_env(&mut c, None);
            c
        }
    } else {
        let mut c = Command::new(config.program);
        c.args(config.args);
        crate::validate::sanitize_cmd_env(&mut c, None);
        c
    };

    // Isolate process in its own process group to allow complete tree cleanup
    cmd.process_group(0);

    // Set stdout and stderr to piped
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let command_repr = if config.args.is_empty() {
        config.program.to_string()
    } else {
        format!("{} {}", config.program, config.args.join(" "))
    };

    let mut child = cmd.spawn().map_err(|e| SubprocessError::SpawnError {
        program: command_repr.clone(),
        source: e,
    })?;

    let child_pid = child.id() as i32;

    // Concurrently drain stdout and stderr using bounded background drainers
    let stdout_handle = child
        .stdout
        .take()
        .map(|stdout| spawn_pipe_drainer(stdout, config.max_output_bytes));

    let stderr_handle = child
        .stderr
        .take()
        .map(|stderr| spawn_pipe_drainer(stderr, config.max_output_bytes));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > config.timeout {
                    // Send SIGKILL to entire process group (-child_pid) to prevent orphan forks
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(-child_pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    let _ = child.kill();
                    let _ = child.wait();

                    // Join drainers if spawned (they will terminate upon EOF from pipe close)
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }

                    return Err(SubprocessError::Timeout {
                        timeout: config.timeout,
                        command: command_repr,
                    });
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-child_pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.kill();
                let _ = child.wait();

                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }

                return Err(SubprocessError::WaitError {
                    command: command_repr,
                    source: e,
                });
            }
        }
    };

    let (stdout_bytes, stdout_truncated) = if let Some(h) = stdout_handle {
        h.join().unwrap_or_else(|_| (Vec::new(), false))
    } else {
        (Vec::new(), false)
    };

    let (stderr_bytes, stderr_truncated) = if let Some(h) = stderr_handle {
        h.join().unwrap_or_else(|_| (Vec::new(), false))
    } else {
        (Vec::new(), false)
    };

    let exit_status = status.code().unwrap_or(-1);

    Ok(SubprocessOutput {
        exit_status,
        stdout: format_stream_output(&stdout_bytes, stdout_truncated),
        stderr: format_stream_output(&stderr_bytes, stderr_truncated),
        stdout_truncated,
        stderr_truncated,
    })
}
