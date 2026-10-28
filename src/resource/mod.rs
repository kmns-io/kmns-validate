use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod addr;
pub mod command;
pub mod container;
pub mod dns;
pub mod exec;
pub mod file;
pub mod group;
pub mod http;
pub mod interface;
pub mod kernel;
pub mod matcher;
pub mod mount;
pub mod package;
pub mod port;
pub mod process;
pub mod service;
pub mod user;

/// Per-test metadata block (mirrors goss `meta` type).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub description: Option<String>,
}

/// Unified configuration structure that can contain any supported resource type.
///
/// This allows a single YAML validation file to define multiple checks across
/// different modules (e.g. `http`, `file`, `dns`).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    #[serde(default)]
    pub http: HashMap<String, http::HttpResource>,

    #[serde(default)]
    pub file: HashMap<String, file::FileResource>,

    #[serde(default)]
    pub service: HashMap<String, service::ServiceResource>,

    #[serde(default)]
    pub port: HashMap<String, port::PortResource>,

    #[serde(default)]
    pub user: HashMap<String, user::UserResource>,

    #[serde(default)]
    pub group: HashMap<String, group::GroupResource>,

    #[serde(default)]
    pub command: HashMap<String, command::CommandResource>,

    #[serde(default)]
    pub exec: HashMap<String, exec::ExecResource>,

    #[serde(default)]
    pub container: HashMap<String, container::ContainerResource>,

    #[serde(default)]
    pub process: HashMap<String, process::ProcessResource>,

    #[serde(default)]
    pub package: HashMap<String, package::PackageResource>,

    #[serde(default)]
    pub dns: HashMap<String, dns::DnsResource>,

    #[serde(default)]
    pub addr: HashMap<String, addr::AddrResource>,

    #[serde(default)]
    pub interface: HashMap<String, interface::InterfaceResource>,

    #[serde(default)]
    pub mount: HashMap<String, mount::MountResource>,

    #[serde(default)]
    pub kernel: HashMap<String, kernel::KernelResource>,
}

#[cfg(test)]
mod contract_migration_tests {
    use super::ResourceConfig;

    #[test]
    fn ordered_contract_must_not_silently_become_an_empty_legacy_configuration() {
        // Invariant: no contract may report success after discarding its checks.
        let contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: migration-regression
metadata:
  name: Migration regression
  description: Ensure ordered checks are never silently discarded.
  version: "0.1.0"
  language: en
checks:
  - id: required-file
    kind: resource
    metadata:
      name: Required file
      description: Verify the required file exists.
      severity: high
    resource:
      kind: file
      path: /nonexistent/kmns-migration-regression
    expect:
      exists: true
"#;

        assert!(
            serde_yaml::from_str::<ResourceConfig>(contract).is_err(),
            "the legacy parser must reject the ordered grammar instead of silently discarding every check"
        );
    }
}
