use std::io::Write;
use std::process::{Command, Stdio};

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kmns-validate"))
}

#[test]
fn test_041_1_inline_json_contract_executes_cleanly() {
    let json = r#"{
        "schema_version": "kmns.io/validate/v1alpha1",
        "id": "inline-json-smoke",
        "metadata": {
            "name": "Inline JSON Smoke",
            "description": "Adhoc smoke test",
            "version": "0.1.0",
            "language": "en"
        },
        "checks": [
            {
                "id": "FILE_CHECK",
                "kind": "resource",
                "metadata": {
                    "name": "Check root directory exists",
                    "description": "Assert root directory exists",
                    "severity": "low"
                },
                "resource": {
                    "kind": "file",
                    "path": "/etc"
                },
                "expect": {
                    "exists": true
                }
            }
        ]
    }"#;

    let output = validate_command()
        .arg("--inline")
        .arg(json)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_041_2_inline_yaml_contract_executes_cleanly() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: inline-yaml-smoke
metadata:
  name: Inline YAML Smoke
  description: Adhoc smoke test
  version: "0.1.0"
  language: en
checks:
  - id: FILE_ETC
    kind: resource
    metadata:
      name: Check /etc
      description: Assert /etc directory exists
      severity: low
    resource:
      kind: file
      path: /etc
    expect:
      exists: true
"#;

    let output = validate_command()
        .arg("run")
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_041_3_stdin_stream_pipe_executes_cleanly() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: stdin-pipe-smoke
metadata:
  name: Stdin Pipe Smoke
  description: Adhoc pipe smoke test
  version: "0.1.0"
  language: en
checks:
  - id: FILE_DEV_NULL
    kind: resource
    metadata:
      name: Check /dev/null
      description: Assert /dev/null exists
      severity: low
    resource:
      kind: file
      path: /dev/null
    expect:
      exists: true
"#;

    let mut child = validate_command()
        .arg("run")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_041_4_inline_rejects_command_resource_with_security_violation() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: exploit-cmd
metadata:
  name: Exploit Command
  description: Command observer injection
  version: "0.1.0"
  language: en
checks:
  - id: CMD_01
    kind: resource
    metadata:
      name: Run shell
      description: Shell command
      severity: critical
    resource:
      kind: command
      command: cat /etc/shadow
    expect:
      exit-status: 0
"#;

    let output = validate_command()
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SecurityViolation"),
        "Expected SecurityViolation in stderr: {}",
        stderr
    );
}

#[test]
fn test_041_5_inline_rejects_exec_resource_with_security_violation() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: exploit-exec
metadata:
  name: Exploit Exec
  description: Exec observer injection
  version: "0.1.0"
  language: en
checks:
  - id: EXEC_01
    kind: resource
    metadata:
      name: Run argv
      description: Exec binary
      severity: critical
    resource:
      kind: exec
      path: /bin/echo
      args: ["hi"]
    expect:
      exit-status: 0
"#;

    let output = validate_command()
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SecurityViolation"),
        "Expected SecurityViolation in stderr: {}",
        stderr
    );
}

#[test]
fn test_041_6_quarantine_cannot_be_bypassed_by_allow_unsafe_flags() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: bypass-attempt
metadata:
  name: Bypass Attempt
  description: Attempting bypass via CLI flag
  version: "0.1.0"
  language: en
checks:
  - id: CMD_BYPASS
    kind: resource
    metadata:
      name: Command bypass
      description: Unsafe command
      severity: critical
    resource:
      kind: command
      command: uname -a
    expect:
      exit-status: 0
"#;

    let output = validate_command()
        .arg("--allow-unsafe-command")
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SecurityViolation"),
        "Quarantine must not be bypassed by --allow-unsafe-command"
    );
}

#[test]
fn test_041_7_no_false_positive_on_file_path_containing_exec() {
    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: safe-exec-path
metadata:
  name: Safe Exec Path
  description: Testing file path containing 'exec'
  version: "0.1.0"
  language: en
checks:
  - id: FILE_DEV
    kind: resource
    metadata:
      name: Check /dev
      description: Assert /dev exists
      severity: low
    resource:
      kind: file
      path: /etc/security/exec_shield.conf
    expect:
      exists: false
"#;

    let output = validate_command()
        .arg("check")
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_041_8_payload_too_large_rejection() {
    let oversized = "a".repeat(65537);

    let output = validate_command()
        .arg("--inline")
        .arg(&oversized)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PayloadTooLarge"),
        "Expected PayloadTooLarge in stderr: {}",
        stderr
    );
}

#[test]
fn test_041_9_mutual_exclusivity_rejects_inline_and_file_arguments() {
    let output = validate_command()
        .arg("--inline")
        .arg("{\"schema_version\":\"kmns.io/validate/v1alpha1\"}")
        .arg("some_file.yaml")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be combined"),
        "Expected mutual exclusivity error: {}",
        stderr
    );
}

#[test]
fn test_041_10_zero_file_fallback_runs_without_config_file() {
    let temp_empty_dir = tempfile::tempdir().unwrap();

    let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: zero-file-smoke
metadata:
  name: Zero File Fallback
  description: Runs in clean environment with no config file
  version: "0.1.0"
  language: en
checks:
  - id: DEV_NULL
    kind: resource
    metadata:
      name: Null device
      description: Null device check
      severity: low
    resource:
      kind: file
      path: /dev/null
    expect:
      exists: true
"#;

    let output = validate_command()
        .current_dir(temp_empty_dir.path())
        .env("HOME", temp_empty_dir.path())
        .arg("run")
        .arg("--inline")
        .arg(yaml)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
