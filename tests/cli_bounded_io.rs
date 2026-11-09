use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kmns-validate"))
}

#[test]
fn test_044_1_contract_at_exact_one_mib_compiles() {
    // Contract padded with comments to exactly 1 MiB (1,048,576 bytes)
    let header = "schema_version: kmns.io/validate/v1alpha1\nid: exact-one-mib\nmetadata:\n  name: Exact One MiB\n  description: Exactly 1 MiB contract\n  version: 0.1.0\n  language: en\nchecks:\n  - id: DUMMY\n    kind: resource\n    metadata:\n      name: dummy\n      description: dummy check\n      severity: low\n    resource:\n      kind: port\n      port: tcp:80\n    expect:\n      listening: false\n# ";
    let target_size = 1024 * 1024;
    assert!(target_size > header.len());
    let padding_len = target_size - header.len();
    let mut payload = header.as_bytes().to_vec();
    payload.extend(vec![b'x'; padding_len]);
    assert_eq!(payload.len(), target_size);

    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(&payload).unwrap();

    let output = validate_command()
        .arg("check")
        .arg(temp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Expected success for exactly 1 MiB contract, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_044_2_contract_at_one_mib_plus_one_fails_with_limit_error() {
    // Contract padded to 1 MiB + 1 byte
    let header = "schema_version: kmns.io/validate/v1alpha1\nid: oversized-contract\n# ";
    let target_size = 1024 * 1024 + 1;
    let padding_len = target_size - header.len();
    let mut payload = header.as_bytes().to_vec();
    payload.extend(vec![b'x'; padding_len]);
    assert_eq!(payload.len(), target_size);

    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(&payload).unwrap();

    let output = validate_command()
        .arg("check")
        .arg(temp.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "Expected failure for oversized contract"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E_CONTRACT_INPUT_LIMIT"),
        "stderr should contain E_CONTRACT_INPUT_LIMIT, got: {stderr}"
    );
}

#[test]
fn test_044_3_config_at_one_mib_plus_one_fails_with_limit_error() {
    // Config padded to 1 MiB + 1 byte
    let header = "log:\n  level: info\n  format: text\n# ";
    let target_size = 1024 * 1024 + 1;
    let padding_len = target_size - header.len();
    let mut payload = header.as_bytes().to_vec();
    payload.extend(vec![b'x'; padding_len]);
    assert_eq!(payload.len(), target_size);

    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(&payload).unwrap();

    let output = validate_command()
        .arg("--config")
        .arg(temp.path())
        .arg("--inline")
        .arg("{\"schema_version\":\"kmns.io/validate/v1alpha1\",\"id\":\"t\"}")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "Expected failure for oversized config"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E_CONFIG_INPUT_LIMIT"),
        "stderr should contain E_CONFIG_INPUT_LIMIT, got: {stderr}"
    );
}

#[test]
fn test_044_8_version_cache_exceeding_sixty_four_kib_is_ignored() {
    let temp_cache_dir = tempfile::tempdir().unwrap();
    let app_cache_dir = temp_cache_dir.path().join("kmns-validate");
    std::fs::create_dir_all(&app_cache_dir).unwrap();
    let cache_file = app_cache_dir.join("version.json");

    // Write 64 KiB + 1 byte into cache file
    let oversized_data = vec![b' '; 64 * 1024 + 1];
    std::fs::write(&cache_file, oversized_data).unwrap();

    // With XDG_CACHE_HOME pointing to tempdir, upgrade_message() must remain fail-silent
    let result = std::panic::catch_unwind(|| {
        std::env::set_var("XDG_CACHE_HOME", temp_cache_dir.path());
        kmns_validate::version::upgrade_message()
    });

    assert!(result.is_ok(), "upgrade_message should not panic");
    assert_eq!(
        result.unwrap(),
        None,
        "Oversized version cache should yield None fail-silently"
    );
}
