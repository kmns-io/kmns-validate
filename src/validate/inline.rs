use crate::validate::http::ResourceTestResult;
use crate::validate::runner::{self, FileSummary, RunOptions, TestCounts};
use crate::validate::template;
use kmns_contract::{Contract, ContractCheck, ContractLimits, NativeResourceKind};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Maximum allowable inline or streamed contract size (64 KB).
pub const MAX_INLINE_CONFIG_BYTES: usize = 65536;

/// Policy governing which resource observers are admitted for execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdmissionPolicy {
    /// Strictly rejects 'command' and 'exec' observers (fail-closed, zero-RCE sandbox).
    /// Used by CLI `--inline`, stdin pipes, and untrusted/remote caller paths.
    #[default]
    ExecQuarantine,

    /// Admits all schema-compliant observers.
    /// Execution of command/exec remains gated by RunOptions acknowledgements.
    Permissive,
}

/// Options for in-memory / streamed contract admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryAdmissionOptions {
    /// Maximum payload byte limit.
    pub max_bytes: usize,
    /// Admission policy applied to the contract AST and parsed resources.
    pub policy: AdmissionPolicy,
}

impl Default for InMemoryAdmissionOptions {
    fn default() -> Self {
        Self {
            max_bytes: MAX_INLINE_CONFIG_BYTES,
            policy: AdmissionPolicy::ExecQuarantine,
        }
    }
}

#[derive(Debug, Error)]
pub enum InlineError {
    #[error("PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes).")]
    PayloadTooLarge,

    #[error("SecurityViolation: 'command' and 'exec' observers are strictly prohibited when contract is provided via inline argument or stdin.")]
    SecurityViolation,

    #[error("cannot compile typed contract <{origin}>: {code}")]
    Template { origin: String, code: &'static str },

    #[error("cannot compile typed contract <{origin}>: {details}")]
    CompileError { origin: String, details: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Bounded reader for standard input (`stdin`), capped at `limit` bytes.
/// Reads at most `limit + 1` bytes to detect overflow without allocating unbounded memory.
pub fn read_stdin_bounded(limit: usize) -> Result<String, InlineError> {
    let mut buffer = Vec::new();
    let mut handle = std::io::stdin().take((limit + 1) as u64);
    handle.read_to_end(&mut buffer)?;

    if buffer.len() > limit {
        return Err(InlineError::PayloadTooLarge);
    }

    String::from_utf8(buffer).map_err(InlineError::Utf8)
}

/// Structural AST scanner for 'command' and 'exec' observers.
///
/// Operates on parsed key mappings and typed kind fields, ensuring that references
/// to files or descriptions containing substrings like "exec" or "command"
/// (e.g. `/etc/systemd/system/executor.service`) are never falsely flagged.
pub fn inspect_value_for_exec(value: &serde_yaml::Value) -> bool {
    // 1. Detect legacy top-level maps (e.g. {"command": {...}} or {"exec": {...}})
    if let Some(map) = value.as_mapping() {
        for (k, _) in map {
            if let Some(key_str) = k.as_str() {
                if key_str.eq_ignore_ascii_case("command") || key_str.eq_ignore_ascii_case("exec") {
                    return true;
                }
            }
        }
    }

    // 2. Detect v1alpha1 typed checks with kind: command or kind: exec
    if let Some(checks) = value.get("checks").and_then(|c| c.as_sequence()) {
        for item in checks {
            if let Some(kind) = item.get("kind").and_then(|k| k.as_str()) {
                if kind.eq_ignore_ascii_case("command") || kind.eq_ignore_ascii_case("exec") {
                    return true;
                }
            }
            if let Some(res) = item.get("resource") {
                if let Some(kind) = res.get("kind").and_then(|k| k.as_str()) {
                    if kind.eq_ignore_ascii_case("command") || kind.eq_ignore_ascii_case("exec") {
                        return true;
                    }
                }
                if let Some(res_map) = res.as_mapping() {
                    for (rk, _) in res_map {
                        if let Some(rk_str) = rk.as_str() {
                            if rk_str.eq_ignore_ascii_case("command")
                                || rk_str.eq_ignore_ascii_case("exec")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Compiles an in-memory or streamed contract string with configurable byte limit and admission policy.
///
/// Decoupled core engine reused by CLI `--inline`, stdin pipes, and programmatic orchestrators.
pub fn compile_in_memory_contract(
    raw_content: &str,
    source_name: &str,
    vars: &HashMap<String, String>,
    options: &InMemoryAdmissionOptions,
) -> Result<Contract, InlineError> {
    if raw_content.len() > options.max_bytes {
        return Err(InlineError::PayloadTooLarge);
    }

    let rendered = template::render(raw_content, vars).map_err(|err| InlineError::Template {
        origin: source_name.to_string(),
        code: err.code(),
    })?;

    // Defense-in-depth pre-scan if ExecQuarantine is enforced:
    if options.policy == AdmissionPolicy::ExecQuarantine {
        if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&rendered) {
            if inspect_value_for_exec(&value) {
                return Err(InlineError::SecurityViolation);
            }
        }
    }

    let contract =
        Contract::parse(rendered.as_bytes(), &ContractLimits::default()).map_err(|error| {
            InlineError::CompileError {
                origin: source_name.to_string(),
                details: error.to_string(),
            }
        })?;

    // Defense-in-depth post-parse scan if ExecQuarantine is enforced:
    if options.policy == AdmissionPolicy::ExecQuarantine {
        for check in &contract.checks {
            if let ContractCheck::Resource(resource) = check {
                if resource.resource.kind == NativeResourceKind::Command
                    || resource.resource.kind == NativeResourceKind::Exec
                {
                    return Err(InlineError::SecurityViolation);
                }
            }
        }
    }

    Ok(contract)
}

/// Compiles an ad-hoc inline or streamed contract string under default Exec Quarantine Gate.
pub fn compile_inline_contract(
    raw_content: &str,
    source_name: &str,
    vars: &HashMap<String, String>,
) -> Result<Contract, InlineError> {
    compile_in_memory_contract(
        raw_content,
        source_name,
        vars,
        &InMemoryAdmissionOptions::default(),
    )
}

/// Validates contract syntax and schema conformity of an in-memory contract under the specified admission options.
pub fn check_in_memory(
    raw_content: &str,
    source_name: &str,
    vars: &HashMap<String, String>,
    options: &InMemoryAdmissionOptions,
) -> Result<FileSummary, InlineError> {
    let _contract = compile_in_memory_contract(raw_content, source_name, vars, options)?;
    Ok(FileSummary {
        path: source_name.to_string(),
        valid: true,
        tests: TestCounts::default(),
    })
}

/// Validates contract syntax and schema conformity of an inline contract without executing live probes.
pub fn check_inline(
    raw_content: &str,
    source_name: &str,
    vars: &HashMap<String, String>,
) -> Result<FileSummary, InlineError> {
    check_in_memory(
        raw_content,
        source_name,
        vars,
        &InMemoryAdmissionOptions::default(),
    )
}

/// Executes an in-memory contract through the declarative observers under the specified admission options.
pub fn run_in_memory(
    raw_content: &str,
    source_name: &str,
    package_manager: &str,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
    options: &InMemoryAdmissionOptions,
) -> Result<(FileSummary, Vec<ResourceTestResult>), InlineError> {
    let contract = compile_in_memory_contract(raw_content, source_name, vars, options)?;
    let mut summary = FileSummary {
        path: source_name.to_string(),
        valid: true,
        tests: TestCounts::default(),
    };

    let (counts, results) =
        runner::run_typed_contract(&contract, package_manager, Path::new("."), vars, opts);
    summary.tests = counts;
    Ok((summary, results))
}

/// Executes an inline contract through the declarative observers under the default Exec Quarantine Gate.
pub fn run_inline(
    raw_content: &str,
    source_name: &str,
    package_manager: &str,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> Result<(FileSummary, Vec<ResourceTestResult>), InlineError> {
    run_in_memory(
        raw_content,
        source_name,
        package_manager,
        vars,
        opts,
        &InMemoryAdmissionOptions::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_json_contract_compiles_cleanly() {
        let json = r#"{
            "schema_version": "kmns.io/validate/v1alpha1",
            "id": "inline-json-test",
            "metadata": {
                "name": "Inline JSON",
                "description": "Tests inline JSON contract parsing",
                "version": "0.1.0",
                "language": "en"
            },
            "checks": [
                {
                    "id": "port-443",
                    "kind": "resource",
                    "metadata": {
                        "name": "Port 443 check",
                        "description": "Port 443 listening check",
                        "severity": "medium"
                    },
                    "resource": {
                        "kind": "port",
                        "port": "tcp:443"
                    },
                    "expect": {
                        "listening": true
                    }
                }
            ]
        }"#;

        let vars = HashMap::new();
        let res = compile_inline_contract(json, "<inline>", &vars);
        assert!(res.is_ok());
        let contract = res.unwrap();
        assert_eq!(contract.id, "inline-json-test");
        assert_eq!(contract.checks.len(), 1);
    }

    #[test]
    fn test_exec_quarantine_rejects_command_resource() {
        let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: inline-exploit-cmd
metadata:
  name: Exploit Command
  description: Command observer injection attempt
  version: "0.1.0"
  language: en
checks:
  - id: cmd-01
    kind: resource
    metadata:
      name: Malicious command
      description: Shell command
      severity: critical
    resource:
      kind: command
      command: cat /etc/shadow
    expect:
      exit-status: 0
"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(yaml, "<inline>", &vars).unwrap_err();
        match err {
            InlineError::SecurityViolation => {}
            other => panic!("Expected SecurityViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_exec_quarantine_rejects_exec_resource() {
        let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: inline-exploit-exec
metadata:
  name: Exploit Exec
  description: Exec observer injection attempt
  version: "0.1.0"
  language: en
checks:
  - id: exec-01
    kind: resource
    metadata:
      name: Malicious exec
      description: Argv execution
      severity: critical
    resource:
      kind: exec
      path: /bin/echo
      args:
        - hi
    expect:
      exit-status: 0
"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(yaml, "<inline>", &vars).unwrap_err();
        match err {
            InlineError::SecurityViolation => {}
            other => panic!("Expected SecurityViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_permissive_admission_policy_allows_command_compilation() {
        let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: permissive-cmd
metadata:
  name: Permissive Command
  description: Testing permissive admission for orchestrator
  version: "0.1.0"
  language: en
checks:
  - id: cmd-01
    kind: resource
    metadata:
      name: Uptime command
      description: Check system uptime
      severity: info
    resource:
      kind: command
      command: uptime
    expect:
      exit-status: 0
"#;
        let vars = HashMap::new();
        let options = InMemoryAdmissionOptions {
            max_bytes: MAX_INLINE_CONFIG_BYTES,
            policy: AdmissionPolicy::Permissive,
        };
        let res = compile_in_memory_contract(yaml, "<memory>", &vars, &options);
        assert!(
            res.is_ok(),
            "Permissive policy must allow compiling command resources"
        );
        assert_eq!(res.unwrap().checks.len(), 1);
    }

    #[test]
    fn test_exec_quarantine_rejects_legacy_top_level_command() {
        let json = r#"{"command": {"cat /etc/shadow": {"exit-status": 0}}}"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(json, "<inline>", &vars).unwrap_err();
        match err {
            InlineError::SecurityViolation => {}
            other => panic!("Expected SecurityViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_exec_quarantine_rejects_legacy_top_level_exec() {
        let json = r#"{"exec": {"echo hi": {"exit-status": 0}}}"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(json, "<inline>", &vars).unwrap_err();
        match err {
            InlineError::SecurityViolation => {}
            other => panic!("Expected SecurityViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_no_false_positive_on_file_path_containing_exec() {
        let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: inline-safe-file
metadata:
  name: Safe File Check
  description: Verifies executor service path
  version: "0.1.0"
  language: en
checks:
  - id: file-executor
    kind: resource
    metadata:
      name: Check executor unit file
      description: File existence check
      severity: low
    resource:
      kind: file
      path: /etc/systemd/system/executor.service
    expect:
      exists: true
"#;
        let vars = HashMap::new();
        let res = compile_inline_contract(yaml, "<inline>", &vars);
        assert!(
            res.is_ok(),
            "Must not trigger false positive on file path with 'exec'"
        );
    }

    #[test]
    fn test_inline_payload_too_large_rejection() {
        let oversized = "a".repeat(MAX_INLINE_CONFIG_BYTES + 1);
        let vars = HashMap::new();
        let err = compile_inline_contract(&oversized, "<inline>", &vars).unwrap_err();
        match err {
            InlineError::PayloadTooLarge => {}
            other => panic!("Expected PayloadTooLarge, got: {:?}", other),
        }
    }

    #[test]
    fn test_check_in_memory_and_check_inline_parity() {
        let yaml = r#"
schema_version: kmns.io/validate/v1alpha1
id: memory-test
metadata:
  name: Memory Check
  description: Verifies in-memory checking
  version: "0.1.0"
  language: en
checks:
  - id: port-check
    kind: resource
    metadata:
      name: Port Check
      description: Check port
      severity: medium
    resource:
      kind: port
      port: "tcp:443"
    expect:
      listening: true
"#;
        let vars = HashMap::new();
        let summary_inline = check_inline(yaml, "<inline>", &vars).unwrap();
        assert!(summary_inline.valid);

        let options = InMemoryAdmissionOptions {
            max_bytes: MAX_INLINE_CONFIG_BYTES,
            policy: AdmissionPolicy::Permissive,
        };
        let summary_mem = check_in_memory(yaml, "<memory>", &vars, &options).unwrap();
        assert!(summary_mem.valid);
    }

    #[test]
    fn test_inline_template_parse_error_sanitized() {
        let malformed = r#"
schema_version: kmns.io/validate/v1alpha1
id: template-error-test
metadata:
  name: Template Error
  description: Verifies template error propagation
  version: "0.1.0"
  language: en
checks:
  - id: file-check
    kind: resource
    metadata:
      name: File Check
      description: Check file
      severity: medium
    resource:
      kind: file
      path: {{ secret_leak_source
    expect:
      exists: true
"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(malformed, "inline", &vars).unwrap_err();
        let err_str = err.to_string();
        match err {
            InlineError::Template { origin, code } => {
                assert_eq!(origin, "inline");
                assert_eq!(code, "E_TEMPLATE_PARSE");
            }
            other => panic!("Expected InlineError::Template, got: {:?}", other),
        }
        assert!(!err_str.contains("secret_leak_source"));
        assert!(err_str.contains("E_TEMPLATE_PARSE"));
    }

    #[test]
    fn test_inline_template_error_precedes_quarantine() {
        // Even if the contract specifies kind: command (which quarantine rejects),
        // template error occurs before AST inspection or quarantine.
        let malformed_with_command = r#"
schema_version: kmns.io/validate/v1alpha1
id: template-quarantine-test
metadata:
  name: Template Quarantine
  description: Verifies template error precedence
  version: "0.1.0"
  language: en
checks:
  - id: cmd-check
    kind: resource
    metadata:
      name: Command Check
      description: Check command
      severity: high
    resource:
      kind: command
      command: echo evil {{ unclosed_syntax
    expect:
      exit-status: 0
"#;
        let vars = HashMap::new();
        let err = compile_inline_contract(malformed_with_command, "inline", &vars).unwrap_err();
        match err {
            InlineError::Template { origin, code } => {
                assert_eq!(origin, "inline");
                assert_eq!(code, "E_TEMPLATE_PARSE");
            }
            other => panic!(
                "Expected InlineError::Template before SecurityViolation, got: {:?}",
                other
            ),
        }
    }
}
