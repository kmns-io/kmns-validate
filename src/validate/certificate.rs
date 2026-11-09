use crate::resource::matcher::MatcherConfig;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use kmns_contract::ResourceCheck;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use serde_json::Value as JsonValue;
use serde_yaml::Value;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::X509Name;

pub const MAX_CERTIFICATE_BUNDLE_BYTES: usize = 1024 * 1024;

pub fn validate(check: &ResourceCheck) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: check.id.clone(),
        title: None,
        resource_type: "certificate".to_owned(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    let Some(path) = check
        .resource
        .fields
        .get("path")
        .and_then(serde_yaml::Value::as_str)
    else {
        result.error = Some("E_CERTIFICATE_CONTRACT".to_owned());
        return result;
    };

    let input = match read_bounded_regular_file(Path::new(path)) {
        Ok(input) => input,
        Err(code) => {
            result.error = Some(code.to_owned());
            return result;
        }
    };

    let parsed = match parse_certificate_bundle(&input) {
        Ok(parsed) => parsed,
        Err(code) => {
            result.error = Some(code.to_owned());
            return result;
        }
    };

    let certificates = parsed.certificates;
    if parsed.has_private_key {
        result.warning = Some("W_PRIVATE_KEY_IN_BUNDLE".to_owned());
    }

    if let Err(code) = validate_structural_assertions(&certificates, &check.expect) {
        result.error = Some(code.to_owned());
        return result;
    }

    let chain_valid = match optional_bool(&check.expect, "chain_valid") {
        Ok(value) => value.unwrap_or(false),
        Err(code) => {
            result.error = Some(code.to_owned());
            return result;
        }
    };
    let hostname = match optional_string(&check.expect, "hostname") {
        Ok(value) => value,
        Err(code) => {
            result.error = Some(code.to_owned());
            return result;
        }
    };
    if chain_valid && hostname.is_none() {
        result.error = Some("E_CERTIFICATE_CONTRACT".to_owned());
        return result;
    }

    if let Some(hostname) = hostname {
        if verify_hostname(&certificates, &hostname).is_err() {
            result.error = Some("E_CERTIFICATE_HOSTNAME".to_owned());
            return result;
        }
    }

    if chain_valid {
        let trust = match trust_policy(check) {
            Ok(trust) => trust,
            Err(code) => {
                result.error = Some(code.to_owned());
                return result;
            }
        };
        if verify_chain(&certificates, &trust).is_err() {
            result.error = Some("E_CERTIFICATE_TRUST".to_owned());
            return result;
        }
    }

    result.passed = true;
    result
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, &'static str> {
    let canonical = fs::canonicalize(path).map_err(|_| "E_CERTIFICATE_READ")?;
    let metadata = fs::metadata(&canonical).map_err(|_| "E_CERTIFICATE_READ")?;
    if !metadata.is_file() {
        return Err("E_CERTIFICATE_READ");
    }
    if metadata.len() > MAX_CERTIFICATE_BUNDLE_BYTES as u64 {
        return Err("E_CERTIFICATE_INPUT_LIMIT");
    }

    let mut file = File::open(canonical).map_err(|_| "E_CERTIFICATE_READ")?;
    let mut input = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_CERTIFICATE_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "E_CERTIFICATE_READ")?;
    if input.len() > MAX_CERTIFICATE_BUNDLE_BYTES {
        return Err("E_CERTIFICATE_INPUT_LIMIT");
    }
    Ok(input)
}

struct ParsedCertificateBundle {
    certificates: Vec<Vec<u8>>,
    has_private_key: bool,
}

fn contains_private_key_marker(input: &[u8]) -> bool {
    input
        .windows(b"PRIVATE KEY".len())
        .any(|window| window == b"PRIVATE KEY")
}

fn parse_certificate_bundle(input: &[u8]) -> Result<ParsedCertificateBundle, &'static str> {
    let has_private_key = contains_private_key_marker(input);
    if input.starts_with(b"-----BEGIN") {
        let mut certificates = Vec::new();
        for pem in Pem::iter_from_buffer(input) {
            let Ok(pem) = pem else {
                continue;
            };
            if pem.label == "CERTIFICATE" {
                let Ok((remaining, _)) = parse_x509_certificate(&pem.contents) else {
                    return Err("E_CERTIFICATE_PARSE");
                };
                if !remaining.is_empty() {
                    return Err("E_CERTIFICATE_PARSE");
                }
                certificates.push(pem.contents);
            }
        }
        if certificates.is_empty() {
            if has_private_key {
                return Err("E_CERTIFICATE_PRIVATE_KEY");
            }
            return Err("E_CERTIFICATE_PARSE");
        }
        Ok(ParsedCertificateBundle {
            certificates,
            has_private_key,
        })
    } else {
        if has_private_key {
            return Err("E_CERTIFICATE_PRIVATE_KEY");
        }
        let (remaining, _) = parse_x509_certificate(input).map_err(|_| "E_CERTIFICATE_PARSE")?;
        if remaining.is_empty() {
            Ok(ParsedCertificateBundle {
                certificates: vec![input.to_vec()],
                has_private_key: false,
            })
        } else {
            Err("E_CERTIFICATE_PARSE")
        }
    }
}

#[derive(Default)]
struct TrustPolicy {
    public_roots: bool,
    anchor_paths: Vec<String>,
}

fn trust_policy(check: &ResourceCheck) -> Result<TrustPolicy, &'static str> {
    let Some(trust) = check.resource.fields.get("trust") else {
        return Ok(TrustPolicy::default());
    };
    let Value::Mapping(values) = trust else {
        return Err("E_CERTIFICATE_CONTRACT");
    };

    let mut policy = TrustPolicy::default();
    for (name, value) in values {
        let Some(name) = name.as_str() else {
            return Err("E_CERTIFICATE_CONTRACT");
        };
        match name {
            "public_roots" => {
                policy.public_roots = value.as_bool().ok_or("E_CERTIFICATE_CONTRACT")?;
            }
            "anchor_paths" => {
                let Value::Sequence(paths) = value else {
                    return Err("E_CERTIFICATE_CONTRACT");
                };
                for path in paths {
                    let path = path.as_str().ok_or("E_CERTIFICATE_CONTRACT")?;
                    policy.anchor_paths.push(path.to_owned());
                }
            }
            _ => return Err("E_CERTIFICATE_CONTRACT"),
        }
    }
    Ok(policy)
}

fn optional_bool(
    expectations: &std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<bool>, &'static str> {
    expectations
        .get(name)
        .map(|value| value.as_bool().ok_or("E_CERTIFICATE_CONTRACT"))
        .transpose()
}

fn optional_string(
    expectations: &std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<String>, &'static str> {
    expectations
        .get(name)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or("E_CERTIFICATE_CONTRACT")
        })
        .transpose()
}

fn validate_structural_assertions(
    certificates: &[Vec<u8>],
    expectations: &std::collections::BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    let (_, certificate) =
        parse_x509_certificate(&certificates[0]).map_err(|_| "E_CERTIFICATE_PARSE")?;
    validate_remaining_lifetime(&certificate, expectations)?;
    validate_absolute_expiry(&certificate, expectations)?;
    validate_name_expectations(
        certificate.subject(),
        expectations.get("subject"),
        "E_CERTIFICATE_SUBJECT",
    )?;
    validate_name_expectations(
        certificate.issuer(),
        expectations.get("issuer"),
        "E_CERTIFICATE_ISSUER",
    )?;
    validate_san_expectations(&certificate, expectations.get("san_contains"))?;
    validate_ca_expectation(&certificate, expectations.get("is_ca"))?;
    validate_key_expectations(&certificate, expectations)?;
    validate_signature_expectation(&certificate, expectations.get("signature_algorithm"))?;
    Ok(())
}

fn validate_remaining_lifetime(
    certificate: &X509Certificate<'_>,
    expectations: &std::collections::BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    let Some(value) = expectations.get("valid_for") else {
        return Ok(());
    };
    let duration = value
        .as_str()
        .and_then(parse_duration_seconds)
        .ok_or("E_CERTIFICATE_CONTRACT")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "E_CERTIFICATE_VALIDITY")?
        .as_secs() as i64;
    let remaining = certificate
        .validity()
        .not_after
        .timestamp()
        .saturating_sub(now);
    if remaining >= duration {
        Ok(())
    } else {
        Err("E_CERTIFICATE_VALIDITY")
    }
}

fn validate_absolute_expiry(
    certificate: &X509Certificate<'_>,
    expectations: &std::collections::BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    let Some(value) = expectations.get("not_after_gt") else {
        return Ok(());
    };
    let boundary = value
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or("E_CERTIFICATE_CONTRACT")?
        .timestamp();
    if certificate.validity().not_after.timestamp() > boundary {
        Ok(())
    } else {
        Err("E_CERTIFICATE_VALIDITY")
    }
}

fn validate_name_expectations(
    name: &X509Name<'_>,
    expected: Option<&Value>,
    code: &'static str,
) -> Result<(), &'static str> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let Value::Mapping(expected) = expected else {
        return Err("E_CERTIFICATE_CONTRACT");
    };
    for (field, expected) in expected {
        let field = field.as_str().ok_or("E_CERTIFICATE_CONTRACT")?;
        let actual = name_field(name, field).ok_or(code)?;
        if !matches_yaml(&actual, expected) {
            return Err(code);
        }
    }
    Ok(())
}

fn name_field(name: &X509Name<'_>, field: &str) -> Option<String> {
    let attribute = match field {
        "common_name" => name.iter_common_name().next(),
        "organization" => name.iter_organization().next(),
        "organizational_unit" => name.iter_organizational_unit().next(),
        "country" => name.iter_country().next(),
        _ => return None,
    };
    attribute
        .and_then(|attribute| attribute.as_str().ok())
        .map(ToOwned::to_owned)
}

fn validate_san_expectations(
    certificate: &X509Certificate<'_>,
    expected: Option<&Value>,
) -> Result<(), &'static str> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let Value::Sequence(expected) = expected else {
        return Err("E_CERTIFICATE_CONTRACT");
    };
    let sans = certificate
        .subject_alternative_name()
        .map_err(|_| "E_CERTIFICATE_SAN")?
        .ok_or("E_CERTIFICATE_SAN")?;
    let names: Vec<&str> = sans
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
        .collect();
    for matcher in expected {
        if !names.iter().any(|name| matches_yaml(name, matcher)) {
            return Err("E_CERTIFICATE_SAN");
        }
    }
    Ok(())
}

fn validate_ca_expectation(
    certificate: &X509Certificate<'_>,
    expected: Option<&Value>,
) -> Result<(), &'static str> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = expected.as_bool().ok_or("E_CERTIFICATE_CONTRACT")?;
    if certificate.is_ca() == expected {
        Ok(())
    } else {
        Err("E_CERTIFICATE_CA")
    }
}

fn validate_key_expectations(
    certificate: &X509Certificate<'_>,
    expectations: &std::collections::BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    let (key_type, key_bits) = certificate_key(certificate)?;
    if key_type == "RSA" && key_bits < 2048 {
        return Err("E_CERTIFICATE_KEY_POLICY");
    }
    if let Some(expected) = expectations.get("key_type") {
        let expected = expected.as_str().ok_or("E_CERTIFICATE_CONTRACT")?;
        if key_type != expected {
            return Err("E_CERTIFICATE_KEY_POLICY");
        }
    }
    if let Some(expected) = expectations.get("min_key_bits") {
        let expected = expected
            .as_i64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or("E_CERTIFICATE_CONTRACT")?;
        if key_bits < expected {
            return Err("E_CERTIFICATE_KEY_POLICY");
        }
    }
    Ok(())
}

fn certificate_key(
    certificate: &X509Certificate<'_>,
) -> Result<(&'static str, usize), &'static str> {
    let public_key = certificate
        .public_key()
        .parsed()
        .map_err(|_| "E_CERTIFICATE_KEY_POLICY")?;
    match public_key {
        PublicKey::RSA(key) => Ok(("RSA", key.key_size())),
        PublicKey::EC(key) => Ok(("ECDSA", key.key_size())),
        _ if certificate.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112" => {
            Ok(("Ed25519", 256))
        }
        _ => Err("E_CERTIFICATE_KEY_POLICY"),
    }
}

fn validate_signature_expectation(
    certificate: &X509Certificate<'_>,
    expected: Option<&Value>,
) -> Result<(), &'static str> {
    let signature = signature_algorithm(certificate);
    if is_disallowed_signature(&signature) {
        return Err("E_CERTIFICATE_SIGNATURE_POLICY");
    }
    if let Some(expected) = expected {
        if !matches_yaml(&signature, expected) {
            return Err("E_CERTIFICATE_SIGNATURE_POLICY");
        }
    }
    Ok(())
}

fn signature_algorithm(certificate: &X509Certificate<'_>) -> String {
    let oid = certificate
        .signature_algorithm
        .algorithm
        .to_id_string()
        .to_string();
    signature_algorithm_name(&oid).to_owned()
}

fn signature_algorithm_name(oid: &str) -> &str {
    match oid {
        "1.2.840.113549.1.1.4" => "MD5withRSA",
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
        "1.2.840.10045.4.1" => "ECDSA-SHA1",
        "1.3.101.112" => "Ed25519",
        _ => oid,
    }
}

fn is_disallowed_signature(signature: &str) -> bool {
    matches!(signature, "SHA1withRSA" | "MD5withRSA" | "ECDSA-SHA1")
}

fn matches_yaml(actual: &str, expected: &Value) -> bool {
    serde_yaml::from_value::<MatcherConfig>(expected.clone())
        .ok()
        .is_some_and(|expected| {
            matcher::validate(&JsonValue::String(actual.to_owned()), &expected).passed
        })
}

fn parse_duration_seconds(value: &str) -> Option<i64> {
    let (number, unit) = value.split_at(value.len().checked_sub(1)?);
    let number = number.parse::<i64>().ok()?;
    if number < 0 {
        return None;
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

fn verify_hostname(certificates: &[Vec<u8>], hostname: &str) -> Result<(), ()> {
    let certificate = CertificateDer::from(certificates[0].as_slice());
    let end_entity = EndEntityCert::try_from(&certificate).map_err(|_| ())?;
    let server_name = ServerName::try_from(hostname).map_err(|_| ())?;
    end_entity
        .verify_is_valid_for_subject_name(&server_name)
        .map_err(|_| ())
}

fn verify_chain(certificates: &[Vec<u8>], policy: &TrustPolicy) -> Result<(), ()> {
    let mut custom_anchor_data = Vec::new();
    for path in &policy.anchor_paths {
        let input = read_bounded_regular_file(Path::new(path)).map_err(|_| ())?;
        let parsed = parse_certificate_bundle(&input).map_err(|_| ())?;
        custom_anchor_data.extend(parsed.certificates);
    }

    let custom_anchor_certificates: Vec<CertificateDer<'_>> = custom_anchor_data
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let mut trust_anchors: Vec<TrustAnchor<'_>> = Vec::new();
    if policy.public_roots {
        trust_anchors.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for certificate in &custom_anchor_certificates {
        let (_, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(|_| ())?;
        if !parsed.is_ca() {
            return Err(());
        }
        trust_anchors.push(anchor_from_trusted_cert(certificate).map_err(|_| ())?);
    }
    if trust_anchors.is_empty() {
        return Err(());
    }

    let end_entity_der = CertificateDer::from(certificates[0].as_slice());
    let end_entity = EndEntityCert::try_from(&end_entity_der).map_err(|_| ())?;
    let intermediates: Vec<CertificateDer<'_>> = certificates[1..]
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_slice()))
        .collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediates,
            UnixTime::since_unix_epoch(now),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        contains_private_key_marker, is_disallowed_signature, parse_certificate_bundle,
        signature_algorithm_name,
    };

    #[test]
    fn private_key_markers_are_detected_without_exposing_input() {
        let key = rcgen::KeyPair::generate().unwrap();
        assert!(contains_private_key_marker(key.serialize_pem().as_bytes()));
    }

    #[test]
    fn non_certificate_pem_is_rejected() {
        assert!(parse_certificate_bundle(
            b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"
        )
        .is_err());
    }

    #[test]
    fn sha1_ecdsa_is_rejected_by_the_signature_policy() {
        let signature = signature_algorithm_name("1.2.840.10045.4.1");
        assert_eq!(signature, "ECDSA-SHA1");
        assert!(is_disallowed_signature(signature));
    }
}
