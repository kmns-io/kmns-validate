use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kmns-validate"))
}

#[test]
fn test_042_1_stdout_pipe_deadlock_eliminated() {
    // Generates 1 MiB of data to stdout (far exceeding Linux 64 KiB pipe buffer).
    // Previously, this caused child.try_wait() loop to deadlock and hit 15s timeout.
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-1
metadata:
  name: Stdout Pipe Deadlock Test
  description: Verifies non-blocking output drainage on 1 MiB stdout
  version: "0.5.0"
  language: en
checks:
  - id: DRAIN_STDOUT
    kind: resource
    metadata:
      name: Drain large stdout
      description: Generate 1 MiB stdout
      severity: medium
    resource:
      kind: command
      command: "head -c 1048576 /dev/zero | tr '\\0' 'A'"
      timeout: 5000
    expect:
      exit-status: 0
      stdout:
        - "[TRUNCATED: Output exceeded limit]"
"#;
    fs::write(&contract_path, contract).unwrap();

    let start = std::time::Instant::now();
    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-command")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    let elapsed = start.elapsed();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed.as_millis() < 3000,
        "Execution must finish quickly without pipe buffer deadlock, took {:?}",
        elapsed
    );
}

#[test]
fn test_042_2_stderr_pipe_deadlock_eliminated() {
    // Generates 1 MiB of data to stderr (far exceeding Linux 64 KiB pipe buffer).
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-2
metadata:
  name: Stderr Pipe Deadlock Test
  description: Verifies non-blocking output drainage on 1 MiB stderr
  version: "0.5.0"
  language: en
checks:
  - id: DRAIN_STDERR
    kind: resource
    metadata:
      name: Drain large stderr
      description: Generate 1 MiB stderr
      severity: medium
    resource:
      kind: command
      command: "head -c 1048576 /dev/zero >&2"
      timeout: 5000
    expect:
      exit-status: 0
      stderr:
        - "[TRUNCATED: Output exceeded limit]"
"#;
    fs::write(&contract_path, contract).unwrap();

    let start = std::time::Instant::now();
    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-command")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    let elapsed = start.elapsed();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed.as_millis() < 3000,
        "Execution must finish quickly without pipe buffer deadlock, took {:?}",
        elapsed
    );
}

#[test]
fn test_042_3_simultaneous_stdout_and_stderr_drainage() {
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-3
metadata:
  name: Simultaneous Drainage Test
  description: Verifies concurrent drainage on both stdout and stderr
  version: "0.5.0"
  language: en
checks:
  - id: DRAIN_BOTH
    kind: resource
    metadata:
      name: Drain both streams
      description: Generate 1 MiB stdout and 1 MiB stderr
      severity: medium
    resource:
      kind: command
      command: "head -c 1048576 /dev/zero | tr '\\0' 'A'; head -c 1048576 /dev/zero >&2"
      timeout: 5000
    expect:
      exit-status: 0
      stdout:
        - "[TRUNCATED: Output exceeded limit]"
      stderr:
        - "[TRUNCATED: Output exceeded limit]"
"#;
    fs::write(&contract_path, contract).unwrap();

    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-command")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_042_4_subprocess_timeout_triggers_cleanly() {
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-4
metadata:
  name: Subprocess Timeout Test
  description: Verifies timeout termination
  version: "0.5.0"
  language: en
checks:
  - id: SLEEP_TIMEOUT
    kind: resource
    metadata:
      name: Sleep timeout
      description: Exceed timeout limit
      severity: medium
    resource:
      kind: command
      command: "sleep 10"
      timeout: 1
    expect:
      exit-status: 0
"#;
    fs::write(&contract_path, contract).unwrap();

    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-command")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("timed out after 1s") || stdout.contains("timed out after 1s"),
        "expected timeout error, got stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
}

#[test]
fn test_042_5_exec_observer_with_large_output() {
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-5
metadata:
  name: Exec Observer Large Output Test
  description: Verifies exec observer non-blocking drainage
  version: "0.5.0"
  language: en
checks:
  - id: EXEC_LARGE
    kind: resource
    metadata:
      name: Exec sh
      description: Large output via exec
      severity: medium
    resource:
      kind: exec
      path: "/bin/sh"
      args:
        - "-c"
        - "head -c 200000 /dev/zero | tr '\\0' 'B'"
      timeout: 5000
    expect:
      exit-status: 0
      stdout:
        - "[TRUNCATED: Output exceeded limit]"
"#;
    fs::write(&contract_path, contract).unwrap();

    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-exec")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "exec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_042_6_exec_security_violation_prohibits_metacharacters() {
    let dir = tempdir().unwrap();
    let contract_path = dir.path().join("contract.yaml");

    let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: test-042-6
metadata:
  name: Exec Metacharacters Test
  description: Verifies rejection of shell metacharacters
  version: "0.5.0"
  language: en
checks:
  - id: EXEC_META
    kind: resource
    metadata:
      name: Exec bad bin
      description: Should fail validation
      severity: medium
    resource:
      kind: exec
      path: "/bin/echo;rm -rf /"
      args: []
      timeout: 5000
    expect:
      exit-status: 0
"#;
    fs::write(&contract_path, contract).unwrap();

    let output = validate_command()
        .arg("run")
        .arg("--allow-unsafe-exec")
        .arg("--allow-root-execution")
        .arg(&contract_path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("Security violation") || stdout.contains("Security violation"),
        "expected Security violation, got stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
}
