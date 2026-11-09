use crate::resource::ResourceConfig;
use crate::validate::http::ResourceTestResult;
use crate::validate::{
    addr, certificate, command, container, dns, exec, file, group, http, interface, kernel, mount,
    package, parallel, port, process, service, template, user,
};
use kmns_contract::{Contract, ContractCheck, ContractLimits, NativeResourceKind, ResourceCheck};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    /// Contract path or compiler diagnostics that prevent a valid run.
    pub errors: Vec<String>,
}

/// Executes one typed native check without parsing a legacy resource-contract file.
///
/// Callers retain ownership of contract parsing, authorization, scope resolution, and plugin
/// dispatch. Command and exec behavior remains governed by `opts`.
pub fn run_contract_resource(
    check: &ResourceCheck,
    package_manager: &str,
    _base_path: &Path,
    _vars: &HashMap<String, String>,
    opts: &RunOptions,
) -> (TestCounts, Vec<ResourceTestResult>) {
    let mut counts = TestCounts::default();
    let mut results = Vec::with_capacity(1);
    let result = dispatch_typed_resource(check, package_manager, opts);
    record_result(&mut counts, &mut results, result);
    (counts, results)
}

fn dispatch_typed_resource(
    check: &ResourceCheck,
    package_manager: &str,
    opts: &RunOptions,
) -> ResourceTestResult {
    let name = &check.id;
    let title = Some(check.metadata.name.clone());

    let mut merged = Mapping::new();
    for (k, v) in &check.resource.fields {
        merged.insert(Value::String(k.clone()), v.clone());
    }
    for (k, v) in &check.expect {
        merged.insert(Value::String(k.clone()), v.clone());
    }
    merged.insert(
        Value::String("title".to_string()),
        Value::String(check.metadata.name.clone()),
    );
    let merged_val = Value::Mapping(merged);

    match check.resource.kind {
        NativeResourceKind::Certificate => certificate::validate(check),
        NativeResourceKind::Host => run_host_observation(check),
        NativeResourceKind::File => {
            match serde_yaml::from_value::<crate::resource::file::FileResource>(merged_val) {
                Ok(res) => file::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "file", e),
            }
        }
        NativeResourceKind::Http => {
            match serde_yaml::from_value::<crate::resource::http::HttpResource>(merged_val) {
                Ok(res) => http::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "http", e),
            }
        }
        NativeResourceKind::Port => {
            match serde_yaml::from_value::<crate::resource::port::PortResource>(merged_val) {
                Ok(res) => port::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "port", e),
            }
        }
        NativeResourceKind::Service => {
            match serde_yaml::from_value::<crate::resource::service::ServiceResource>(merged_val) {
                Ok(res) => service::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "service", e),
            }
        }
        NativeResourceKind::User => {
            match serde_yaml::from_value::<crate::resource::user::UserResource>(merged_val) {
                Ok(res) => user::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "user", e),
            }
        }
        NativeResourceKind::Group => {
            match serde_yaml::from_value::<crate::resource::group::GroupResource>(merged_val) {
                Ok(res) => group::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "group", e),
            }
        }
        NativeResourceKind::Command => {
            if let Some(message) = opts.unsafe_execution_warning("command") {
                ResourceTestResult {
                    name: name.clone(),
                    title,
                    resource_type: "command".to_string(),
                    passed: false,
                    skipped: false,
                    failures: vec![message.clone()],
                    error: None,
                    warning: Some(message),
                    observation: None,
                }
            } else {
                match serde_yaml::from_value::<crate::resource::command::CommandResource>(
                    merged_val,
                ) {
                    Ok(res) => command::validate(name, &res, opts.run_as.as_deref()),
                    Err(e) => execution_error(name, &check.metadata.name, "command", e),
                }
            }
        }
        NativeResourceKind::Exec => {
            if let Some(message) = opts.unsafe_execution_warning("exec") {
                ResourceTestResult {
                    name: name.clone(),
                    title,
                    resource_type: "exec".to_string(),
                    passed: false,
                    skipped: false,
                    failures: vec![message.clone()],
                    error: None,
                    warning: Some(message),
                    observation: None,
                }
            } else {
                match serde_yaml::from_value::<crate::resource::exec::ExecResource>(merged_val) {
                    Ok(res) => exec::validate(name, &res, opts.run_as.as_deref()),
                    Err(e) => execution_error(name, &check.metadata.name, "exec", e),
                }
            }
        }
        NativeResourceKind::Container => {
            match serde_yaml::from_value::<crate::resource::container::ContainerResource>(
                merged_val,
            ) {
                Ok(res) => container::validate(name, &res, opts.run_as.as_deref()),
                Err(e) => execution_error(name, &check.metadata.name, "container", e),
            }
        }
        NativeResourceKind::Process => {
            match serde_yaml::from_value::<crate::resource::process::ProcessResource>(merged_val) {
                Ok(res) => process::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "process", e),
            }
        }
        NativeResourceKind::Package => {
            match serde_yaml::from_value::<crate::resource::package::PackageResource>(merged_val) {
                Ok(res) => package::validate(name, &res, package_manager),
                Err(e) => execution_error(name, &check.metadata.name, "package", e),
            }
        }
        NativeResourceKind::Dns => {
            match serde_yaml::from_value::<crate::resource::dns::DnsResource>(merged_val) {
                Ok(res) => dns::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "dns", e),
            }
        }
        NativeResourceKind::Addr => {
            match serde_yaml::from_value::<crate::resource::addr::AddrResource>(merged_val) {
                Ok(res) => addr::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "addr", e),
            }
        }
        NativeResourceKind::Interface => match serde_yaml::from_value::<
            crate::resource::interface::InterfaceResource,
        >(merged_val)
        {
            Ok(res) => interface::validate(name, &res),
            Err(e) => execution_error(name, &check.metadata.name, "interface", e),
        },
        NativeResourceKind::Mount => {
            match serde_yaml::from_value::<crate::resource::mount::MountResource>(merged_val) {
                Ok(res) => mount::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "mount", e),
            }
        }
        NativeResourceKind::Kernel => {
            match serde_yaml::from_value::<crate::resource::kernel::KernelResource>(merged_val) {
                Ok(res) => kernel::validate(name, &res),
                Err(e) => execution_error(name, &check.metadata.name, "kernel", e),
            }
        }
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
        errors: Vec::new(),
    };

    let (file_paths, path_errors) = collect_contract_paths(list);
    result.errors.extend(path_errors);

    for path in file_paths {
        let (summary, tests) = run_file(&path, package_manager, vars, opts);
        if !summary.valid {
            result
                .errors
                .push(format!("contract could not be compiled: {}", summary.path));
        }
        result.file_summaries.push(summary);
        result.tests.extend(tests);
    }

    result
}

/// Compile each selected contract without executing resource checks.
pub fn check_list(list: &[String], vars: &HashMap<String, String>) -> RunResult {
    let mut result = RunResult {
        tests: Vec::new(),
        file_summaries: Vec::new(),
        errors: Vec::new(),
    };

    let (file_paths, path_errors) = collect_contract_paths(list);
    result.errors.extend(path_errors);

    for path in file_paths {
        let summary = check_file(&path, vars);
        if !summary.valid {
            result
                .errors
                .push(format!("contract could not be compiled: {}", summary.path));
        }
        result.file_summaries.push(summary);
    }

    result
}

fn collect_contract_paths(list: &[String]) -> (Vec<PathBuf>, Vec<String>) {
    let mut file_paths = Vec::new();
    let mut errors = Vec::new();

    for entry in list {
        let path = PathBuf::from(entry);
        if path.is_dir() {
            let mut dir_files = collect_yaml_files(&path);
            dir_files.sort();
            file_paths.extend(dir_files);
        } else if path.is_file() {
            file_paths.push(path);
        } else {
            let error = format!("contract path not found or not accessible: {entry}");
            eprintln!("validate: {error}");
            errors.push(error);
        }
    }

    (file_paths, errors)
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

    let contract = match compile_contract(path, vars) {
        Ok(contract) => contract,
        Err(error) => {
            eprintln!("validate: {error}");
            return (summary, tests);
        }
    };
    summary.valid = true;

    let (counts, results) = run_typed_contract(&contract, package_manager, path, vars, opts);
    summary.tests = counts;
    (summary, results)
}

fn check_file(path: &Path, vars: &HashMap<String, String>) -> FileSummary {
    let mut summary = FileSummary {
        path: path.to_string_lossy().to_string(),
        valid: false,
        tests: TestCounts::default(),
    };

    match compile_contract(path, vars) {
        Ok(_) => summary.valid = true,
        Err(error) => eprintln!("validate: {error}"),
    }

    summary
}

fn compile_contract(path: &Path, vars: &HashMap<String, String>) -> Result<Contract, String> {
    let raw_content = match crate::bounded_io::read_file_to_string_bounded(
        path,
        crate::bounded_io::MAX_CONTRACT_FILE_BYTES,
    ) {
        Ok(content) => content,
        Err(crate::bounded_io::BoundedReadError::LimitExceeded { .. }) => {
            return Err(format!(
                "cannot compile typed contract {:?}: E_CONTRACT_INPUT_LIMIT",
                path
            ));
        }
        Err(error) => return Err(format!("cannot read {:?}: {error}", path)),
    };
    let content = template::render(&raw_content, vars)
        .map_err(|err| format!("cannot compile typed contract {:?}: {}", path, err.code()))?;
    Contract::parse(content.as_bytes(), &ContractLimits::default())
        .map_err(|error| format!("cannot compile typed contract {:?}: {error}", path))
}

/// Execute a compiled, ordered contract through the local OSS native executors.
///
/// Callers retain ownership of contract parsing, authorization, scope resolution, and plugin
/// dispatch. Command and exec behavior remains governed by `opts`.
pub fn run_typed_contract(
    contract: &Contract,
    package_manager: &str,
    _base_path: &Path,
    _vars: &HashMap<String, String>,
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
            ContractCheck::Resource(resource) => {
                let result = dispatch_typed_resource(resource, package_manager, opts);
                record_result(&mut counts, &mut results, result);
            }
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
    fn typed_resource_direct_dispatch_executes_native_observer() {
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
      path: /nonexistent-path-for-direct-dispatch-test
    expect:
      exists: false
"#,
            &contract_limits(),
        )
        .unwrap();
        let check = match &contract.checks[0] {
            kmns_contract::ContractCheck::Resource(check) => check,
            _ => unreachable!(),
        };

        let (counts, results) = run_contract_resource(
            check,
            "apt",
            Path::new("/tmp"),
            &HashMap::new(),
            &RunOptions::default(),
        );
        assert_eq!(counts.total, 1);
        assert_eq!(counts.pass, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "CONFIG_FILE");
        assert_eq!(results[0].resource_type, "file");
        assert!(results[0].passed);
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
    fn run_file_with_malformed_template_fails_before_execution() {
        let temp_dir = tempfile::tempdir().unwrap();
        let contract_path = temp_dir.path().join("malformed_template.yaml");
        std::fs::write(
            &contract_path,
            r#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Test template error
  description: Verifies fail-closed execution on template failure.
  version: "0.1.0"
  language: en
checks:
  - id: DUMMY_FILE
    kind: resource
    metadata:
      name: Dummy
      description: Must not run
      severity: high
    resource:
      kind: file
      path: /tmp/must-not-be-checked-{{ unclosed_tag
    expect:
      exists: true
"#,
        )
        .unwrap();

        let (summary, tests) = run_file(
            &contract_path,
            "apt",
            &HashMap::new(),
            &RunOptions::default(),
        );

        assert!(!summary.valid);
        assert!(tests.is_empty());
        assert_eq!(summary.tests.total, 0);
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
