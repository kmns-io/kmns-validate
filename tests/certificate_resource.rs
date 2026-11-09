use std::path::{Path, PathBuf};
use std::process::Command;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

const OVERSIZE_MARKER: &str = "oversize-material-marker";
const PARSE_MARKER: &str = "malformed-certificate-marker";

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kmns-validate"))
}

fn write_contract(directory: &Path, certificate_path: &Path, check_id: &str) -> PathBuf {
    let contract = directory.join("certificate-contract.yaml");
    std::fs::write(
        &contract,
        format!(
            r#"
schema_version: kmns.io/validate/v1alpha1
id: certificate-contract
metadata:
  name: Certificate contract
  description: Validate a local certificate bundle.
  version: "0.1.0"
  language: en
checks:
  - id: {check_id}
    kind: resource
    metadata:
      name: Certificate file
      description: Validate a local certificate before service startup.
      severity: critical
    resource:
      kind: certificate
      path: {}
    expect:
      valid_for: 30d
"#,
            certificate_path.display()
        ),
    )
    .unwrap();
    contract
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_trusted_contract(
    directory: &Path,
    certificate_path: &Path,
    anchor_path: &Path,
    hostname: &str,
    valid_for: &str,
    check_id: &str,
) -> PathBuf {
    let contract = directory.join(format!("{check_id}.yaml"));
    std::fs::write(
        &contract,
        format!(
            r#"
schema_version: kmns.io/validate/v1alpha1
id: trusted-certificate-contract
metadata:
  name: Trusted certificate contract
  description: Validate a local certificate against a local trust anchor.
  version: "0.1.0"
  language: en
checks:
  - id: {check_id}
    kind: resource
    metadata:
      name: Trusted certificate file
      description: Validate certificate trust and hostname before service startup.
      severity: critical
    resource:
      kind: certificate
      path: {}
      trust:
        public_roots: false
        anchor_paths:
          - {}
    expect:
      hostname: {hostname}
      chain_valid: true
      valid_for: {valid_for}
      not_after_gt: "2030-01-01T00:00:00Z"
      subject:
        common_name: certificate.example
      issuer:
        common_name: certificate-root.example
      san_contains:
        - certificate.example
      key_type: ECDSA
      min_key_bits: 256
      signature_algorithm: ECDSA-SHA256
      is_ca: false
"#,
            certificate_path.display(),
            anchor_path.display()
        ),
    )
    .unwrap();
    contract
}

fn write_certificate_chain(directory: &Path) -> (PathBuf, PathBuf, String) {
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "certificate-root.example");
    let issuer_key = KeyPair::generate().unwrap();
    let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec!["certificate.example".to_owned()]).unwrap();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "certificate.example");
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let certificate_path = directory.join("leaf.pem");
    let anchor_path = directory.join("anchor.pem");
    std::fs::write(&certificate_path, leaf.pem()).unwrap();
    std::fs::write(&anchor_path, issuer.pem()).unwrap();
    (certificate_path, anchor_path, leaf_key.serialize_pem())
}

fn write_unrelated_anchor(directory: &Path) -> PathBuf {
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    issuer_params
        .distinguished_name
        .push(DnType::CommonName, "unrelated-root.example");
    let issuer = CertifiedIssuer::self_signed(issuer_params, KeyPair::generate().unwrap()).unwrap();
    let anchor_path = directory.join("unrelated-anchor.pem");
    std::fs::write(&anchor_path, issuer.pem()).unwrap();
    anchor_path
}

#[test]
fn check_accepts_a_local_certificate_contract_without_reading_the_target() {
    let temporary = tempfile::tempdir().unwrap();
    let missing_certificate = temporary.path().join("not-present.pem");
    let contract = write_contract(temporary.path(), &missing_certificate, "LOCAL_CERTIFICATE");

    let output = validate_command()
        .arg("check")
        .arg(contract)
        .output()
        .unwrap();

    assert!(output.status.success());
}

#[test]
fn certificate_validation_redacts_private_key_material_and_path() {
    let temporary = tempfile::tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let private_key_pem = key.serialize_pem();
    let certificate_path = temporary.path().join("private-input.pem");
    std::fs::write(&certificate_path, &private_key_pem).unwrap();
    let contract = write_contract(temporary.path(), &certificate_path, "PRIVATE_KEY_CHECK");

    let output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(!output.status.success());
    assert!(report.contains("PRIVATE_KEY_CHECK"));
    assert!(report.contains("E_CERTIFICATE_PRIVATE_KEY"));
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
    assert!(!report.contains(&private_key_pem));
    assert!(!report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!report.contains("Certificate file"));
}

#[test]
fn certificate_validation_redacts_oversized_input_and_path() {
    let temporary = tempfile::tempdir().unwrap();
    let certificate_path = temporary.path().join("oversized-input.pem");
    let mut input = vec![b'X'; 1024 * 1024 + 1];
    input.extend_from_slice(OVERSIZE_MARKER.as_bytes());
    std::fs::write(&certificate_path, input).unwrap();
    let contract = write_contract(temporary.path(), &certificate_path, "OVERSIZED_CERTIFICATE");

    let output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(!output.status.success());
    assert!(report.contains("OVERSIZED_CERTIFICATE"));
    assert!(report.contains("E_CERTIFICATE_INPUT_LIMIT"));
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
    assert!(!report.contains(OVERSIZE_MARKER));
    assert!(!report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!report.contains("Certificate file"));
}

#[test]
fn certificate_validation_redacts_malformed_input_and_path() {
    let temporary = tempfile::tempdir().unwrap();
    let certificate_path = temporary.path().join("malformed-input.pem");
    std::fs::write(&certificate_path, PARSE_MARKER).unwrap();
    let contract = write_contract(temporary.path(), &certificate_path, "MALFORMED_CERTIFICATE");

    let output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(!output.status.success());
    assert!(report.contains("MALFORMED_CERTIFICATE"));
    assert!(report.contains("E_CERTIFICATE_PARSE"));
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
    assert!(!report.contains(PARSE_MARKER));
    assert!(!report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!report.contains("Certificate file"));
}

#[test]
fn certificate_validation_uses_explicit_local_anchors_and_hostname_verification() {
    let temporary = tempfile::tempdir().unwrap();
    let (certificate_path, anchor_path, _) = write_certificate_chain(temporary.path());
    let accepted = write_trusted_contract(
        temporary.path(),
        &certificate_path,
        &anchor_path,
        "certificate.example",
        "1h",
        "TRUSTED_CERTIFICATE",
    );
    let rejected = write_trusted_contract(
        temporary.path(),
        &certificate_path,
        &anchor_path,
        "other.example",
        "1h",
        "MISMATCHED_HOSTNAME",
    );

    let accepted_output = validate_command()
        .arg("run")
        .arg(accepted)
        .output()
        .unwrap();
    assert!(
        accepted_output.status.success(),
        "{}",
        combined_output(&accepted_output)
    );

    let rejected_output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(rejected)
        .output()
        .unwrap();
    let rejected_report = combined_output(&rejected_output);
    assert!(!rejected_output.status.success());
    assert!(rejected_report.contains("MISMATCHED_HOSTNAME"));
    assert!(rejected_report.contains("E_CERTIFICATE_HOSTNAME"));
    assert!(serde_json::from_str::<serde_json::Value>(&rejected_report).is_ok());
    assert!(!rejected_report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!rejected_report.contains(anchor_path.to_string_lossy().as_ref()));
    assert!(!rejected_report.contains("Trusted certificate file"));
}

#[test]
fn certificate_validation_redacts_untrusted_anchor_details() {
    let temporary = tempfile::tempdir().unwrap();
    let (certificate_path, _, _) = write_certificate_chain(temporary.path());
    let anchor_path = write_unrelated_anchor(temporary.path());
    let contract = write_trusted_contract(
        temporary.path(),
        &certificate_path,
        &anchor_path,
        "certificate.example",
        "1h",
        "UNTRUSTED_ANCHOR",
    );

    let output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(!output.status.success());
    assert!(report.contains("UNTRUSTED_ANCHOR"));
    assert!(report.contains("E_CERTIFICATE_TRUST"));
    assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
    assert!(!report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!report.contains(anchor_path.to_string_lossy().as_ref()));
    assert!(!report.contains("unrelated-root.example"));
    assert!(!report.contains("Trusted certificate file"));
}

#[test]
fn certificate_validation_enforces_the_remaining_validity_window() {
    let temporary = tempfile::tempdir().unwrap();
    let (certificate_path, anchor_path, _) = write_certificate_chain(temporary.path());
    let contract = write_trusted_contract(
        temporary.path(),
        &certificate_path,
        &anchor_path,
        "certificate.example",
        "999999d",
        "EXPIRING_CERTIFICATE",
    );

    let output = validate_command()
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(!output.status.success());
    assert!(report.contains("EXPIRING_CERTIFICATE"));
    assert!(report.contains("E_CERTIFICATE_VALIDITY"));
    assert!(!report.contains(certificate_path.to_string_lossy().as_ref()));
    assert!(!report.contains(anchor_path.to_string_lossy().as_ref()));
}

#[test]
fn certificate_validation_permits_combined_pem_with_warning() {
    let temporary = tempfile::tempdir().unwrap();
    let (certificate_path, anchor_path, private_key_pem) =
        write_certificate_chain(temporary.path());
    let mut content = std::fs::read_to_string(&certificate_path).unwrap();
    content.push('\n');
    content.push_str(&private_key_pem);
    let combined_path = temporary.path().join("combined.pem");
    std::fs::write(&combined_path, content).unwrap();

    let contract = write_trusted_contract(
        temporary.path(),
        &combined_path,
        &anchor_path,
        "certificate.example",
        "7d",
        "COMBINED_PEM_CHECK",
    );

    let output = validate_command()
        .args(["--format", "json"])
        .arg("run")
        .arg(contract)
        .output()
        .unwrap();
    let report = combined_output(&output);

    assert!(output.status.success(), "Validation failed: {report}");
    assert!(report.contains("COMBINED_PEM_CHECK"));
    assert!(report.contains("W_PRIVATE_KEY_IN_BUNDLE"));
    assert!(!report.contains("E_CERTIFICATE_PRIVATE_KEY"));
}
