use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kmns-validate"))
}

#[test]
fn check_accepts_a_typed_contract_without_executing_resources() {
    let temporary = tempfile::tempdir().unwrap();
    let absent_path = temporary.path().join("absent");
    let contract = temporary.path().join("syntax-only.yaml");
    std::fs::write(
        &contract,
        format!(
            r#"
schema_version: kmns.io/validate/v1alpha1
id: syntax-only
metadata:
  name: Syntax only
  description: Compile a contract without probing resources.
  version: "0.1.0"
  language: en
checks:
  - id: ABSENT_FILE
    kind: resource
    metadata:
      name: Absent file
      description: This path must remain absent during static validation.
      severity: high
    resource:
      kind: file
      path: {}
    expect:
      exists: true
"#,
            absent_path.display()
        ),
    )
    .unwrap();

    let output = validate_command()
        .arg("check")
        .arg(contract)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!absent_path.exists());
}

#[test]
fn check_and_run_reject_an_invalid_contract_with_nonzero_status() {
    for command in ["check", "run"] {
        let output = validate_command()
            .arg(command)
            .arg(fixture("invalid_contract.yaml"))
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "{command} accepted an invalid contract: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("contract YAML is invalid"),
            "{command} did not report the compiler diagnostic"
        );
    }
}

#[test]
fn check_and_run_reject_an_unreadable_contract_path() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("missing.yaml");

    for command in ["check", "run"] {
        let output = validate_command()
            .arg(command)
            .arg(&missing)
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "{command} accepted a missing path"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(missing.to_string_lossy().as_ref()),
            "{command} did not report the missing path"
        );
    }
}
