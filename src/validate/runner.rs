use crate::resource::ResourceConfig;
use crate::validate::http::ResourceTestResult;
use crate::validate::{
    addr, command, container, dns, exec, file, group, http, interface, kernel, mount, package,
    parallel, port, process, service, template, user,
};
use kmns_contract::{Contract, ContractCheck, ContractLimits, NativeResourceKind};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Failure while projecting a validated typed resource check into the existing native executor.
#[derive(Debug, Error)]
pub enum ContractResourceError {
    #[error("typed contract resource is invalid: {0}")]
    Contract(#[from] kmns_contract::ContractError),
    #[error("typed contract resource cannot be represented by the native executor: {0}")]
    NativeSchema(#[from] serde_yaml::Error),
}

/// Consistent test outcome counters used in both file and global summaries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestCounts {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub error: usize,
    pub warn: usize,
}

/// Options for controlling validation execution.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Enable parallel execution for network check resources.
    pub parallel: bool,
    /// Maximum concurrent requested for each validator type.
    pub max_threads: usize,
    /// System user for command execution (when the current process is root).
    pub run_as: Option<String>,
    /// Explicit acknowledgement for unsafe shell command execution.
    pub allow_unsafe_command: bool,
    /// Explicit acknowledgement for unsafe argv execution.
    pub allow_unsafe_exec: bool,
    /// Additional acknowledgement when this validator already runs as root.
    pub allow_root_execution: bool,
    /// Filter checks by stage/tag (e.g. 'pre-install', 'migration', 'production').
    pub tags: Vec<String>,
}

impl RunOptions {
    fn unsafe_execution_warning(&self, resource_type: &str) -> Option<String> {
        let permitted = match resource_type {
            "command" => self.allow_unsafe_command,
            "exec" => self.allow_unsafe_exec,
            _ => return None,
        };
        if !permitted {
            return Some(format!(
                "W_SECURITY_{resource_type_upper}_NOT_EXECUTED: {resource_type} is not executed by default; pass the matching --allow-unsafe-{resource_type} acknowledgement to permit unsafe local execution.",
                resource_type_upper = resource_type.to_uppercase(),
            ));
        }
        if nix::unistd::geteuid().is_root() && !self.allow_root_execution {
            return Some(format!(
                "W_SECURITY_{resource_type_upper}_ROOT_NOT_EXECUTED: {resource_type} is not executed by a root validator without --allow-root-execution; this contract can modify or disclose privileged target data.",
                resource_type_upper = resource_type.to_uppercase(),
            ));
        }
        None
    }
}

/// Detailed summary of a single resource file validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: String,
    pub valid: bool,
    pub tests: TestCounts,
}

/// Combined output of a validation run.
pub struct RunResult {
    /// All individual test outcomes.
    pub tests: Vec<ResourceTestResult>,
    /// Summary for each processed file.
    pub file_summaries: Vec<FileSummary>,
}

/// Executes one typed native check without parsing a legacy resource-contract file.
///
/// Callers retain ownership of contract parsing, authorization, scope resolution, and plugin
/// dispatch. Command and exec behavior remains governed by `opts`.
pub fn run_contract_resource(
    check: &kmns_contract::ResourceCheck,
    package_manager: &str,
    base_path: &Path,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> Result<(TestCounts, Vec<ResourceTestResult>), ContractResourceError> {
    let config = resource_config_from_contract(check)?;
    Ok(run_config(&config, package_manager, base_path, vars, opts))
}

fn resource_config_from_contract(
    check: &kmns_contract::ResourceCheck,
) -> Result<ResourceConfig, ContractResourceError> {
    let mut fields = Mapping::new();
    for (name, value) in check.to_legacy_fields()? {
        fields.insert(Value::String(name), value);
    }
    fields.insert(
        Value::String("title".to_string()),
        Value::String(check.metadata.name.clone()),
    );

    let mut resources = Mapping::new();
    let mut entries = Mapping::new();
    entries.insert(Value::String(check.id.clone()), Value::Mapping(fields));
    resources.insert(
        Value::String(native_resource_key(check.resource.kind).to_string()),
        Value::Mapping(entries),
    );
    Ok(serde_yaml::from_value(Value::Mapping(resources))?)
}

fn native_resource_key(kind: kmns_contract::NativeResourceKind) -> &'static str {
    use kmns_contract::NativeResourceKind;

    match kind {
        NativeResourceKind::Addr => "addr",
        NativeResourceKind::Command => "command",
        NativeResourceKind::Container => "container",
        NativeResourceKind::Dns => "dns",
        NativeResourceKind::Exec => "exec",
        NativeResourceKind::File => "file",
        NativeResourceKind::Group => "group",
        NativeResourceKind::Http => "http",
        NativeResourceKind::Interface => "interface",
        NativeResourceKind::Kernel => "kernel",
        NativeResourceKind::Mount => "mount",
        NativeResourceKind::Package => "package",
        NativeResourceKind::Port => "port",
        NativeResourceKind::Process => "process",
        NativeResourceKind::Service => "service",
        NativeResourceKind::User => "user",
        NativeResourceKind::Host => "host",
    }
}

/// Run validation against a list of paths.
pub fn run_list(
    list: &[String],
    package_manager: &str,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> RunResult {
    let mut result = RunResult {
        tests: Vec::new(),
        file_summaries: Vec::new(),
    };

    let mut file_paths: Vec<PathBuf> = Vec::new();

    for entry in list {
        let p = PathBuf::from(entry);
        if p.is_dir() {
            let mut dir_files = collect_yaml_files(&p);
            dir_files.sort();
            file_paths.extend(dir_files);
        } else if p.is_file() {
            file_paths.push(p);
        } else {
            eprintln!("validate: path not found or not accessible: {:?}", entry);
        }
    }

    for path in file_paths {
        let (summary, tests) = run_file(&path, package_manager, vars, opts);
        result.file_summaries.push(summary);
        result.tests.extend(tests);
    }

    result
}

/// Run validation for a single file.
pub fn run_file(
    path: &Path,
    package_manager: &str,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> (FileSummary, Vec<ResourceTestResult>) {
    let mut summary = FileSummary {
        path: path.to_string_lossy().to_string(),
        valid: false,
        tests: TestCounts::default(),
    };
    let tests = Vec::new();

    let raw_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("validate: cannot read {:?}: {}", path, e);
            return (summary, tests);
        }
    };

    // Apply template interpolation
    let content = template::render(&raw_content, vars);

    let contract = match Contract::parse(content.as_bytes(), &ContractLimits::default()) {
        Ok(contract) => contract,
        Err(error) => {
            eprintln!(
                "validate: cannot compile typed contract {:?}: {error}",
                path
            );
            return (summary, tests);
        }
    };
    summary.valid = true;

    let (counts, results) = run_typed_contract(&contract, package_manager, path, vars, opts);
    summary.tests = counts;
    (summary, results)
}

/// Execute a compiled, ordered contract through the local OSS native executors.
///
/// Callers retain ownership of contract parsing, authorization, scope resolution, and plugin
/// dispatch. Command and exec behavior remains governed by `opts`.
fn run_typed_contract(
    contract: &Contract,
    package_manager: &str,
    base_path: &Path,
    vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> (TestCounts, Vec<ResourceTestResult>) {
    let mut counts = TestCounts::default();
    let mut results = Vec::with_capacity(contract.checks.len());

    for check in &contract.checks {
        if !opts.tags.is_empty() {
            let (_, metadata) = check.identity_and_metadata();
            if !opts.tags.iter().any(|req_tag| {
                metadata
                    .tags
                    .iter()
                    .any(|check_tag| check_tag.eq_ignore_ascii_case(req_tag.trim()))
            }) {
                continue;
            }
        }
        match check {
            ContractCheck::Resource(resource)
                if resource.resource.kind == NativeResourceKind::Host =>
            {
                let result = run_host_observation(resource);
                record_result(&mut counts, &mut results, result);
            }
            ContractCheck::Resource(resource) => match run_contract_resource(
                resource,
                package_manager,
                base_path,
                vars,
                opts,
            ) {
                Ok((_, resource_results)) => {
                    for result in resource_results {
                        record_result(&mut counts, &mut results, result);
                    }
                }
                Err(error) => record_result(
                    &mut counts,
                    &mut results,
                    execution_error(&resource.id, &resource.metadata.name, "resource", error),
                ),
            },
            ContractCheck::Plugin(plugin) => record_result(
                &mut counts,
                &mut results,
                ResourceTestResult {
                    name: plugin.id.clone(),
                    title: Some(plugin.metadata.name.clone()),
                    resource_type: "plugin".to_owned(),
                    passed: false,
                    skipped: false,
                    failures: vec![
                        "W_LOCAL_PLUGIN_NOT_EXECUTED: plugin checks require remote caller execution path."
                            .to_owned(),
                    ],
                    error: None,
                    warning: Some("W_LOCAL_PLUGIN_NOT_EXECUTED".to_owned()),
                    observation: None,
                },
            ),
            ContractCheck::Contract(nested) => record_result(
                &mut counts,
                &mut results,
                ResourceTestResult {
                    name: nested.id.clone(),
                    title: Some(nested.metadata.name.clone()),
                    resource_type: "contract".to_owned(),
                    passed: false,
                    skipped: false,
                    failures: Vec::new(),
                    error: Some(
                        "E_LOCAL_NESTED_CONTRACT_UNSUPPORTED: nested contracts require trusted contract resolution."
                            .to_owned(),
                    ),
                    warning: None,
                    observation: None,
                },
            ),
        }
    }

    (counts, results)
}

fn run_host_observation(resource: &kmns_contract::ResourceCheck) -> ResourceTestResult {
    let field = resource
        .resource
        .fields
        .get("field")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match crate::host::collect(field) {
        Ok(observation) => ResourceTestResult {
            name: resource.id.clone(),
            title: Some(resource.metadata.name.clone()),
            resource_type: "host".to_owned(),
            passed: true,
            skipped: false,
            failures: Vec::new(),
            error: None,
            warning: None,
            observation: Some(observation),
        },
        Err(error) => execution_error(&resource.id, &resource.metadata.name, "host", error),
    }
}

fn execution_error(
    id: &str,
    title: &str,
    resource_type: &str,
    error: impl std::fmt::Display,
) -> ResourceTestResult {
    ResourceTestResult {
        name: id.to_owned(),
        title: Some(title.to_owned()),
        resource_type: resource_type.to_owned(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: Some(error.to_string()),
        warning: None,
        observation: None,
    }
}

fn record_result(
    counts: &mut TestCounts,
    results: &mut Vec<ResourceTestResult>,
    result: ResourceTestResult,
) {
    counts.total += 1;
    if result.warning.is_some() {
        counts.warn += 1;
    } else if result.skipped {
        counts.skip += 1;
    } else if result.error.is_some() {
        counts.error += 1;
    } else if result.passed {
        counts.pass += 1;
    } else {
        counts.fail += 1;
    }
    results.push(result);
}

/// Run validation for a loaded configuration.
/// `base_path` is the path to the file this config came from, used for relative inclusions.
pub fn run_config(
    config: &ResourceConfig,
    package_manager: &str,
    _base_path: &Path,
    _vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> (TestCounts, Vec<ResourceTestResult>) {
    let mut counts = TestCounts::default();
    let mut results = Vec::new();

    // Helper to add test results
    let mut add_res = |res: ResourceTestResult| {
        counts.total += 1;
        if res.warning.is_some() {
            counts.warn += 1;
        } else if res.skipped {
            counts.skip += 1;
        } else if res.error.is_some() {
            counts.error += 1;
        } else if !res.passed {
            counts.fail += 1;
        } else {
            counts.pass += 1;
        }
        results.push(res);
    };

    // ---------- HTTP ------------------------------------------------
    let mut http_names: Vec<String> = config.http.keys().cloned().collect();
    http_names.sort();
    let http_pairs: Vec<(String, &crate::resource::http::HttpResource)> = http_names
        .into_iter()
        .filter_map(|n| config.http.get(&n).map(|r| (n, r)))
        .collect();

    let http_results =
        parallel::dispatch_io(http_pairs, opts.parallel, opts.max_threads, |name, res| {
            http::validate(name, res)
        });
    for res in http_results {
        add_res(res);
    }

    // ---------- FILE ------------------------------------------------
    let mut file_names: Vec<String> = config.file.keys().cloned().collect();
    file_names.sort();
    for name in file_names {
        if let Some(resource) = config.file.get(&name) {
            add_res(file::validate(&name, resource));
        }
    }

    // ---------- SERVICE ---------------------------------------------
    let mut service_names: Vec<String> = config.service.keys().cloned().collect();
    service_names.sort();
    for name in service_names {
        if let Some(resource) = config.service.get(&name) {
            add_res(service::validate(&name, resource));
        }
    }

    // ---------- PORT ------------------------------------------------
    let mut port_names: Vec<String> = config.port.keys().cloned().collect();
    port_names.sort();
    for name in port_names {
        if let Some(resource) = config.port.get(&name) {
            add_res(port::validate(&name, resource));
        }
    }

    // ---------- USER ------------------------------------------------
    let mut user_names: Vec<String> = config.user.keys().cloned().collect();
    user_names.sort();
    for name in user_names {
        if let Some(resource) = config.user.get(&name) {
            add_res(user::validate(&name, resource));
        }
    }

    // ---------- GROUP -----------------------------------------------
    let mut group_names: Vec<String> = config.group.keys().cloned().collect();
    group_names.sort();
    for name in group_names {
        if let Some(resource) = config.group.get(&name) {
            add_res(group::validate(&name, resource));
        }
    }

    // ---------- COMMAND (explicit local acknowledgement required) ----
    let mut command_names: Vec<String> = config.command.keys().cloned().collect();
    command_names.sort();
    for name in command_names {
        if let Some(resource) = config.command.get(&name) {
            if let Some(message) = opts.unsafe_execution_warning("command") {
                add_res(ResourceTestResult {
                    name: name.clone(),
                    title: resource.title.clone(),
                    resource_type: "command".to_string(),
                    passed: false,
                    skipped: false,
                    failures: vec![message.clone()],
                    error: None,
                    warning: Some(message),
                    observation: None,
                });
            } else {
                add_res(command::validate(&name, resource, opts.run_as.as_deref()));
            }
        }
    }

    // ---------- EXEC (explicit local acknowledgement required) --------
    let mut exec_names: Vec<String> = config.exec.keys().cloned().collect();
    exec_names.sort();
    for name in exec_names {
        if let Some(resource) = config.exec.get(&name) {
            if let Some(message) = opts.unsafe_execution_warning("exec") {
                add_res(ResourceTestResult {
                    name: name.clone(),
                    title: resource.title.clone(),
                    resource_type: "exec".to_string(),
                    passed: false,
                    skipped: false,
                    failures: vec![message.clone()],
                    error: None,
                    warning: Some(message),
                    observation: None,
                });
            } else {
                add_res(exec::validate(&name, resource, opts.run_as.as_deref()));
            }
        }
    }

    // ---------- CONTAINER (Direct REST API, Zero-RCE) ----------------
    let mut container_names: Vec<String> = config.container.keys().cloned().collect();
    container_names.sort();
    for name in container_names {
        if let Some(resource) = config.container.get(&name) {
            add_res(container::validate(&name, resource, opts.run_as.as_deref()));
        }
    }

    // ---------- PROCESS ---------------------------------------------
    let mut process_names: Vec<String> = config.process.keys().cloned().collect();
    process_names.sort();
    for name in process_names {
        if let Some(resource) = config.process.get(&name) {
            add_res(process::validate(&name, resource));
        }
    }

    // ---------- PACKAGE ---------------------------------------------
    let mut package_names: Vec<String> = config.package.keys().cloned().collect();
    package_names.sort();
    for name in package_names {
        if let Some(resource) = config.package.get(&name) {
            add_res(package::validate(&name, resource, package_manager));
        }
    }

    // ---------- DNS -------------------------------------------------
    let mut dns_names: Vec<String> = config.dns.keys().cloned().collect();
    dns_names.sort();
    let dns_pairs: Vec<(String, &crate::resource::dns::DnsResource)> = dns_names
        .into_iter()
        .filter_map(|n| config.dns.get(&n).map(|r| (n, r)))
        .collect();

    let dns_results =
        parallel::dispatch_io(dns_pairs, opts.parallel, opts.max_threads, |name, res| {
            dns::validate(name, res)
        });
    for res in dns_results {
        add_res(res);
    }

    // ---------- ADDR ------------------------------------------------
    let mut addr_names: Vec<String> = config.addr.keys().cloned().collect();
    addr_names.sort();
    let addr_pairs: Vec<(String, &crate::resource::addr::AddrResource)> = addr_names
        .into_iter()
        .filter_map(|n| config.addr.get(&n).map(|r| (n, r)))
        .collect();

    let addr_results =
        parallel::dispatch_io(addr_pairs, opts.parallel, opts.max_threads, |name, res| {
            addr::validate(name, res)
        });
    for res in addr_results {
        add_res(res);
    }

    // ---------- INTERFACE -------------------------------------------
    let mut interface_names: Vec<String> = config.interface.keys().cloned().collect();
    interface_names.sort();
    for name in interface_names {
        if let Some(resource) = config.interface.get(&name) {
            add_res(interface::validate(&name, resource));
        }
    }

    // ---------- MOUNT -----------------------------------------------
    let mut mount_names: Vec<String> = config.mount.keys().cloned().collect();
    mount_names.sort();
    for name in mount_names {
        if let Some(resource) = config.mount.get(&name) {
            add_res(mount::validate(&name, resource));
        }
    }

    // ---------- KERNEL ----------------------------------------------
    let mut kernel_names: Vec<String> = config.kernel.keys().cloned().collect();
    kernel_names.sort();
    for name in kernel_names {
        if let Some(resource) = config.kernel.get(&name) {
            add_res(kernel::validate(&name, resource));
        }
    }

    (counts, results)
}

/// Collect all `*.yaml` / `*.yml` files inside `dir` (recursively, sorted).
fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_yaml_files_recursive(dir, &mut files);
    files.sort();
    files
}

fn collect_yaml_files_recursive(dir: &Path, acc: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("validate: cannot read directory {:?}: {}", dir, err);
            return;
        }
    };

    for entry in entries.flatten() {
        if let Ok(ft) = entry.file_type() {
            if ft.is_symlink() {
                eprintln!(
                    "validate: security warning: symlink {:?} skipped in contract discovery",
                    entry.path()
                );
                continue;
            }
        }
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files_recursive(&path, acc);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext == "yaml" || ext == "yml" {
                    acc.push(path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract_limits() -> kmns_contract::ContractLimits {
        kmns_contract::ContractLimits {
            max_artifact_bytes: 4096,
            max_graph_bytes: 16_384,
            max_checks: 4,
            max_graph_checks: 4,
            max_contract_depth: 1,
            max_yaml_depth: 16,
            metadata: kmns_contract::MetadataLimits {
                max_string_bytes: 256,
                max_list_items: 4,
                max_total_bytes: 1024,
            },
        }
    }

    #[test]
    fn typed_resource_projection_uses_the_native_executor_schema() {
        let contract = kmns_contract::Contract::parse(
            br#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Example
  description: Validate Example.
  version: "0.1.0"
  language: en
checks:
  - id: CONFIG_FILE
    kind: resource
    metadata:
      name: Configuration file
      description: Verify configuration.
      severity: high
    resource:
      kind: file
      path: /etc/kmns/example.yaml
    expect:
      exists: true
"#,
            &contract_limits(),
        )
        .unwrap();
        let check = match &contract.checks[0] {
            kmns_contract::ContractCheck::Resource(check) => check,
            _ => unreachable!(),
        };

        let config = resource_config_from_contract(check).unwrap();
        let resource = config.file.get("CONFIG_FILE").unwrap();
        assert_eq!(resource.title.as_deref(), Some("Configuration file"));
        assert_eq!(resource.path.as_deref(), Some("/etc/kmns/example.yaml"));
        assert!(resource.exists);
    }

    #[test]
    fn test_collect_yaml_files_recursive_and_pattern() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path();

        let sub1 = base.join("sub1");
        let sub2 = sub1.join("nested");
        std::fs::create_dir_all(&sub2).unwrap();

        let f1 = base.join("root.yaml");
        let f2 = sub1.join("mid.yml");
        let f3 = sub2.join("deep.yaml");
        let txt = sub1.join("readme.txt");
        let json = base.join("data.json");

        std::fs::write(&f1, "file: {}").unwrap();
        std::fs::write(&f2, "port: {}").unwrap();
        std::fs::write(&f3, "service: {}").unwrap();
        std::fs::write(&txt, "text").unwrap();
        std::fs::write(&json, "{}").unwrap();

        let collected = collect_yaml_files(base);
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0], f1.canonicalize().unwrap_or(f1));
        assert_eq!(collected[1], f2.canonicalize().unwrap_or(f2));
        assert_eq!(collected[2], f3.canonicalize().unwrap_or(f3));
    }

    #[test]
    fn run_list_reports_each_local_result_once() {
        let temp_dir = tempfile::tempdir().unwrap();
        let checked_file = temp_dir.path().join("present.txt");
        std::fs::write(&checked_file, "present").unwrap();
        let contract = temp_dir.path().join("contract.yaml");
        std::fs::write(
            &contract,
            format!(
                r#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Test contract
  description: Confirm results are not duplicated.
  version: "0.1.0"
  language: en
checks:
  - id: PRESENT_FILE
    kind: resource
    metadata:
      name: Present file
      description: Confirm the fixture exists.
      severity: high
    resource:
      kind: file
      path: {}
    expect:
      exists: true
"#,
                checked_file.display()
            ),
        )
        .unwrap();

        let run = run_list(
            &[contract.to_string_lossy().into_owned()],
            "apt",
            &HashMap::new(),
            &RunOptions::default(),
        );

        assert_eq!(run.file_summaries.len(), 1);
        assert_eq!(run.tests.len(), 1);
        assert!(run.tests[0].passed);
    }

    #[test]
    fn legacy_top_level_resource_maps_are_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let legacy = temp_dir.path().join("legacy.yaml");
        std::fs::write(&legacy, "file:\n  /tmp/example:\n    exists: true\n").unwrap();

        let (summary, tests) = run_file(&legacy, "apt", &HashMap::new(), &RunOptions::default());

        assert!(!summary.valid);
        assert!(tests.is_empty());
    }

    #[test]
    fn typed_contract_runs_checks_in_declared_order_and_reports_host_observations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let checked_file = temp_dir.path().join("present.txt");
        std::fs::write(&checked_file, "present").unwrap();
        let contract = temp_dir.path().join("contract.yaml");
        std::fs::write(
            &contract,
            format!(
                r#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Test contract
  description: Run ordered local checks.
  version: "0.1.0"
  language: en
checks:
  - id: HOSTNAME
    kind: resource
    metadata:
      name: Hostname
      description: Read the local hostname.
      severity: info
    resource:
      kind: host
      field: hostname
  - id: PRESENT_FILE
    kind: resource
    metadata:
      name: Present file
      description: Confirm the fixture exists.
      severity: high
    resource:
      kind: file
      path: {}
    expect:
      exists: true
"#,
                checked_file.display()
            ),
        )
        .unwrap();

        let (summary, tests) = run_file(&contract, "apt", &HashMap::new(), &RunOptions::default());

        assert!(summary.valid);
        assert_eq!(summary.tests.total, 2);
        assert_eq!(summary.tests.pass, 2);
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].name, "HOSTNAME");
        assert!(tests[0]
            .observation
            .as_deref()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(tests[1].name, "PRESENT_FILE");
        assert!(tests[1].passed);
    }

    #[test]
    fn typed_plugin_check_is_a_local_warning_without_provider_execution() {
        let temp_dir = tempfile::tempdir().unwrap();
        let contract = temp_dir.path().join("contract.yaml");
        std::fs::write(
            &contract,
            r#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Test contract
  description: Keep plugin dispatch remote.
  version: "0.1.0"
  language: en
checks:
  - id: PLUGIN_CHECK
    kind: plugin
    metadata:
      name: Plugin check
      description: A provider must run through remote caller.
      severity: medium
    provider: test:example
    capability: test:read
"#,
        )
        .unwrap();

        let (summary, tests) = run_file(&contract, "apt", &HashMap::new(), &RunOptions::default());

        assert!(summary.valid);
        assert_eq!(summary.tests.warn, 1);
        assert_eq!(
            tests[0].warning.as_deref(),
            Some("W_LOCAL_PLUGIN_NOT_EXECUTED")
        );
    }

    #[test]
    fn test_runner_warns_without_command_acknowledgement() {
        let yaml = r#"
command:
  evil_check:
    exec: "echo hacked"
    exit-status: 0
"#;
        let config: ResourceConfig = serde_yaml::from_str(yaml).unwrap();
        let vars = HashMap::new();
        let opts = RunOptions {
            parallel: false,
            max_threads: 1,
            run_as: Some("guest".to_string()),
            allow_unsafe_command: false,
            allow_unsafe_exec: false,
            allow_root_execution: false,
            ..Default::default()
        };

        let (counts, results) = run_config(
            &config,
            "apt",
            Path::new("/home/guest/.kmns/validate/spec.yaml"),
            &vars,
            &opts,
        );

        assert_eq!(counts.total, 1);
        assert_eq!(counts.warn, 1);
        assert!(!results.is_empty());
        assert!(results[0]
            .warning
            .as_ref()
            .unwrap()
            .contains("W_SECURITY_COMMAND_NOT_EXECUTED"));
    }

    #[test]
    fn test_runner_command_acknowledgement_permits_command_when_not_root() {
        let yaml = r#"
command:
  echo_test:
    exec: "echo legacy_ok"
    exit-status: 0
    stdout:
      - "legacy_ok"
"#;
        let config: ResourceConfig = serde_yaml::from_str(yaml).unwrap();
        let vars = HashMap::new();
        let opts = RunOptions {
            parallel: false,
            max_threads: 1,
            run_as: None,
            allow_unsafe_command: true,
            allow_unsafe_exec: false,
            allow_root_execution: true,
            ..Default::default()
        };

        let (counts, results) =
            run_config(&config, "apt", Path::new("/tmp/goss.yaml"), &vars, &opts);

        assert_eq!(counts.total, 1);
        assert_eq!(counts.pass, 1);
        assert_eq!(counts.fail, 0);
        assert!(results[0].passed);
    }

    #[test]
    fn test_runner_typed_exec_success() {
        let yaml = r#"
exec:
  /bin/echo:
    args: ["kmns_runner_exec_ok"]
    exit-status: 0
    stdout:
      - "kmns_runner_exec_ok"
"#;
        let config: ResourceConfig = serde_yaml::from_str(yaml).unwrap();
        let vars = HashMap::new();
        let opts = RunOptions {
            parallel: false,
            max_threads: 1,
            run_as: None,
            allow_unsafe_command: false,
            allow_unsafe_exec: true,
            allow_root_execution: true,
            ..Default::default()
        };

        let (counts, results) = run_config(
            &config,
            "apt",
            Path::new("/tmp/exec_spec.yaml"),
            &vars,
            &opts,
        );

        assert_eq!(counts.total, 1);
        assert_eq!(counts.pass, 1);
        assert!(results[0].passed);
    }

    #[test]
    fn test_runner_exec_warns_without_acknowledgement() {
        let yaml = r#"
exec:
  /bin/echo:
    args: ["must-not-run"]
"#;
        let config: ResourceConfig = serde_yaml::from_str(yaml).unwrap();
        let vars = HashMap::new();
        let opts = RunOptions::default();

        let (counts, results) = run_config(
            &config,
            "apt",
            Path::new("/tmp/exec_spec.yaml"),
            &vars,
            &opts,
        );

        assert_eq!(counts.total, 1);
        assert_eq!(counts.warn, 1);
        assert_eq!(results[0].warning.as_deref(), Some("W_SECURITY_EXEC_NOT_EXECUTED: exec is not executed by default; pass the matching --allow-unsafe-exec acknowledgement to permit unsafe local execution."));
    }

    #[test]
    fn test_root_execution_requires_second_acknowledgement() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let yaml = r#"
command:
  root-sensitive:
    exec: "true"
"#;
        let config: ResourceConfig = serde_yaml::from_str(yaml).unwrap();
        let vars = HashMap::new();
        let opts = RunOptions {
            allow_unsafe_command: true,
            ..RunOptions::default()
        };

        let (counts, results) = run_config(
            &config,
            "apt",
            Path::new("/tmp/root_command.yaml"),
            &vars,
            &opts,
        );

        assert_eq!(counts.warn, 1);
        assert!(results[0]
            .warning
            .as_deref()
            .is_some_and(|message| message.contains("--allow-root-execution")));
    }

    #[test]
    fn test_runner_filters_typed_contract_by_tags() {
        let yaml = r#"schema_version: kmns.io/validate/v1alpha1
id: test-tags-runner
metadata:
  name: Runner Tagging Test
  description: Tests stage tagging in local runner
  version: "1.0.0"
  language: en
checks:
  - kind: resource
    id: pre-check
    metadata:
      name: Pre-installation assertion
      description: Run before install
      severity: info
      tags: ["pre-install"]
    resource:
      kind: file
      path: /etc/hosts
    expect:
      exists: true
  - kind: resource
    id: prod-check
    metadata:
      name: Production assertion
      description: Run in production
      severity: high
      tags: ["production"]
    resource:
      kind: file
      path: /etc/hosts
    expect:
      exists: true
"#;
        let contract = kmns_contract::Contract::parse(
            yaml.as_bytes(),
            &kmns_contract::ContractLimits::default(),
        )
        .unwrap();
        let vars = HashMap::new();

        // Run with pre-install tag only
        let opts_pre = RunOptions {
            tags: vec!["pre-install".to_string()],
            ..Default::default()
        };
        let (counts_pre, results_pre) = run_typed_contract(
            &contract,
            "apt",
            Path::new("/tmp/contract.yaml"),
            &vars,
            &opts_pre,
        );
        assert_eq!(counts_pre.total, 1);
        assert_eq!(results_pre.len(), 1);
        assert_eq!(results_pre[0].name, "pre-check");

        // Run with production tag only
        let opts_prod = RunOptions {
            tags: vec!["production".to_string()],
            ..Default::default()
        };
        let (counts_prod, results_prod) = run_typed_contract(
            &contract,
            "apt",
            Path::new("/tmp/contract.yaml"),
            &vars,
            &opts_prod,
        );
        assert_eq!(counts_prod.total, 1);
        assert_eq!(results_prod.len(), 1);
        assert_eq!(results_prod[0].name, "prod-check");

        // Run with no tag filter (all checks)
        let opts_all = RunOptions::default();
        let (counts_all, results_all) = run_typed_contract(
            &contract,
            "apt",
            Path::new("/tmp/contract.yaml"),
            &vars,
            &opts_all,
        );
        assert_eq!(counts_all.total, 2);
        assert_eq!(results_all.len(), 2);
    }
}
