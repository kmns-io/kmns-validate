use crate::resource::exec::ExecResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use serde_json::Value;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

/// Validate an ExecResource (typed argv invocation without shell).
pub fn validate(name: &str, resource: &ExecResource, run_as: Option<&str>) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "exec".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let bin_path = resource.effective_path(name);

    // Reject shell control characters in binary path to ensure zero injection
    if bin_path.chars().any(|c| {
        c == ';'
            || c == '&'
            || c == '|'
            || c == '`'
            || c == '$'
            || c == '>'
            || c == '<'
            || c == '\n'
    }) {
        result.passed = false;
        result.error = Some(format!(
            "Security violation: binary path {:?} contains shell metacharacters",
            bin_path
        ));
        return result;
    }

    let current_uid = nix::unistd::geteuid();
    let is_root = current_uid.is_root();

    let mut cmd = if let Some(target_user) = run_as {
        let trimmed = target_user.trim();
        let valid_user = !trimmed.is_empty()
            && trimmed != "root"
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if !valid_user {
            result.passed = false;
            result.error = Some(format!(
                "Security violation: invalid or prohibited run_as user '{}' (root privilege escalation or invalid characters forbidden)",
                target_user
            ));
            return result;
        }

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
                .arg(&bin_path)
                .args(&resource.args);
            crate::validate::sanitize_cmd_env(&mut c, Some(trimmed));
            c
        } else {
            let mut c = Command::new(&bin_path);
            c.args(&resource.args);
            crate::validate::sanitize_cmd_env(&mut c, None);
            c
        }
    } else {
        let mut c = Command::new(&bin_path);
        c.args(&resource.args);
        crate::validate::sanitize_cmd_env(&mut c, None);
        c
    };

    // Isolate process in its own process group
    cmd.process_group(0);

    let timeout_duration = Duration::from_millis(
        resource
            .timeout
            .map(|t| if t > 1000 { t } else { t * 1000 })
            .unwrap_or(15000),
    );

    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("failed to spawn executable {:?}: {}", bin_path, e));
            return result;
        }
    };

    let child_pid = child.id() as i32;
    let start = Instant::now();

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout_duration {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(-child_pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    result.error = Some(format!(
                        "exec execution timed out after {:?}: {:?}",
                        timeout_duration, bin_path
                    ));
                    return result;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-child_pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.kill();
                result.error = Some(format!("error waiting for exec {:?}: {}", bin_path, e));
                return result;
            }
        }
    };

    const MAX_OUTPUT_BYTES: usize = 16 * 1024; // 16 KiB bounded output

    let mut stdout_bytes = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let mut reader = stdout.take((MAX_OUTPUT_BYTES + 1) as u64);
        let _ = reader.read_to_end(&mut stdout_bytes);
    }
    let mut stderr_bytes = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let mut reader = stderr.take((MAX_OUTPUT_BYTES + 1) as u64);
        let _ = reader.read_to_end(&mut stderr_bytes);
    }

    let exit_status = status.code().unwrap_or(-1);

    if resource
        .exit_status
        .is_some_and(|expected| exit_status != expected)
    {
        result.failures.push(format!(
            "exit-status: expected {} got {}",
            resource.exit_status.unwrap(),
            exit_status
        ));
    }

    let stdout_str = if stdout_bytes.len() > MAX_OUTPUT_BYTES {
        stdout_bytes.truncate(MAX_OUTPUT_BYTES);
        let mut s = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
        s.push_str("\n[TRUNCATED: Output exceeded limit]");
        s
    } else {
        String::from_utf8_lossy(&stdout_bytes).trim().to_string()
    };

    let stderr_str = if stderr_bytes.len() > MAX_OUTPUT_BYTES {
        stderr_bytes.truncate(MAX_OUTPUT_BYTES);
        let mut s = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        s.push_str("\n[TRUNCATED: Output exceeded limit]");
        s
    } else {
        String::from_utf8_lossy(&stderr_bytes).trim().to_string()
    };

    for expected in &resource.stdout {
        let res = matcher::validate(&Value::String(stdout_str.clone()), expected);
        if !res.passed {
            result.failures.push(format!(
                "stdout: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

    for expected in &resource.stderr {
        let res = matcher::validate(&Value::String(stderr_str.clone()), expected);
        if !res.passed {
            result.failures.push(format!(
                "stderr: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

    result.passed = result.failures.is_empty();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_successful_typed_invocation() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/echo".to_string()),
            args: vec!["kmns-typed-exec-test".to_string()],
            meta: None,
            exit_status: Some(0),
            stdout: vec![crate::resource::matcher::MatcherConfig::String(
                "kmns-typed-exec-test".to_string(),
            )],
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("/bin/echo", &resource, None);
        assert!(res.passed, "Failures: {:?}", res.failures);
        assert_eq!(res.resource_type, "exec");
    }

    #[test]
    fn test_exec_rejects_shell_metacharacters() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/echo; rm -rf /".to_string()),
            args: vec![],
            meta: None,
            exit_status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("bad_bin", &resource, None);
        assert!(!res.passed);
        assert!(res.error.is_some());
        assert!(res.error.unwrap().contains("shell metacharacters"));
    }

    #[test]
    fn test_exec_expected_exit_code() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/false".to_string()),
            args: vec![],
            meta: None,
            exit_status: Some(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("/bin/false", &resource, None);
        assert!(res.passed, "Failures: {:?}", res.failures);
    }
}
