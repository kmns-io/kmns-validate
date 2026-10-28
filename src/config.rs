use crate::runtime::Runtime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub const DEFAULT_CONFIG_DIR_PRIVILEGED: &str = "/etc/kmns";
pub const DEFAULT_CONFIG_DIR_NON_PRIVILEGED: &str = ".kmns";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub level: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Parallel {
    pub enabled: bool,
    #[serde(rename = "max-threads")]
    pub max_threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Environment {
    pub name: String,
    pub file: String,
    pub variables: Vec<HashMap<String, String>>,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            name: "dev".to_string(),
            file: "".to_string(),
            variables: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Validate {
    /// List of files and/or directories to scan for resource definitions.
    pub list: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    pub runtime: Runtime,
    pub path: PathBuf,
    pub log: Log,
    pub parallel: Parallel,
    pub environment: Environment,
    pub validate: Validate,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    pub log: Log,
    #[serde(default)]
    pub parallel: Parallel,
    #[serde(default)]
    pub environment: Option<Environment>,
    #[serde(default)]
    pub validate: Validate,
}

const DEFAULT_CONFIG: &str = include_str!("config.yaml");

impl Config {
    /// Loads the default configuration from the embedded YAML.
    pub fn load_default(runtime: Runtime) -> Self {
        let raw: RawConfig =
            serde_yaml::from_str(DEFAULT_CONFIG).expect("Critical: src/config.yaml is invalid");

        Config {
            runtime: runtime.clone(),
            path: PathBuf::new(), // To be determined by load()
            log: raw.log,
            parallel: raw.parallel,
            environment: raw.environment.unwrap_or_default(),
            validate: raw.validate,
        }
    }

    /// Primary entry point to load configuration.
    pub fn load(path: Option<PathBuf>) -> Self {
        let temp_runtime = Runtime::startup(0);
        let mut config = Self::load_default(temp_runtime);

        // Discovery order for config file:
        // 1. Explicit path from CLI
        // 2. ~/.config/kmns/vld.yaml
        // 3. ./.kmns/vld.yaml
        // 4. /etc/kmns/vld.yaml

        let config_path = if let Some(p) = path {
            Some(p)
        } else {
            Self::find_config_file()
        };

        if let Some(p) = config_path {
            config.path = p.clone();
            if let Err(e) = config.update_from_file(p.clone()) {
                eprintln!(
                    "FATAL: Configuration file {:?} could not be loaded: {}",
                    p, e
                );
                std::process::exit(exit_code::NO_INPUT);
            }
        }

        config.runtime = Runtime::startup(0);

        // Expand all paths in the validate list
        config.validate.list = config
            .validate
            .list
            .iter()
            .map(|p| Self::expand_path(p))
            .collect();

        config
    }

    fn find_config_file() -> Option<PathBuf> {
        // 1. ~/.config/kmns/vld.yaml
        if let Some(home) = dirs::home_dir() {
            let p: PathBuf = home.join(".config").join("kmns").join("vld.yaml");
            if p.exists() {
                return Some(p);
            }
        }

        // 2. ./.kmns/vld.yaml
        let local = PathBuf::from(DEFAULT_CONFIG_DIR_NON_PRIVILEGED).join("vld.yaml");
        if local.exists() {
            return Some(local);
        }

        // 3. /etc/kmns/vld.yaml
        let system = PathBuf::from(DEFAULT_CONFIG_DIR_PRIVILEGED).join("vld.yaml");
        if system.exists() {
            return Some(system);
        }

        None
    }

    fn expand_path(p: &str) -> String {
        shellexpand::tilde(p).to_string()
    }

    /// Updates the current configuration by parsing a YAML file from the given path.
    fn update_from_file(&mut self, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open(&path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let raw: RawConfig = serde_yaml::from_str(&content)?;

        self.path = path;
        self.log = raw.log;
        self.parallel = raw.parallel;
        if let Some(env) = raw.environment {
            self.environment = env;
        }
        self.validate = raw.validate;

        Ok(())
    }

    pub fn get_config_path(&self) -> &PathBuf {
        &self.path
    }

    /// Flattens the nested variable structure into a single map for easier usage.
    pub fn flatten_variables(&self) -> HashMap<String, String> {
        let mut flat = HashMap::new();
        for map in &self.environment.variables {
            for (k, v) in map {
                flat.insert(k.clone(), v.clone());
            }
        }
        flat
    }

    /// Performs semantic validation on configuration values.
    /// Returns a tuple containing: (List of Fatal Errors, List of Warnings)
    pub fn validate_values(&self) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Validate Log Level
        let valid_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
        if !valid_levels.contains(&self.log.level.to_uppercase().as_str()) {
            errors.push(format!(
                "log.level: Invalid value '{}'. Supported: {:?}",
                self.log.level, valid_levels
            ));
        }

        // Validate Log Format
        let valid_formats = ["text", "json"];
        if !valid_formats.contains(&self.log.format.to_lowercase().as_str()) {
            errors.push(format!(
                "log.format: Invalid value '{}'. Supported: {:?}",
                self.log.format, valid_formats
            ));
        }

        // Validate list entries
        if !self.validate.list.is_empty() {
            for entry in &self.validate.list {
                let p = PathBuf::from(entry);
                if !p.exists() {
                    errors.push(format!("validate.list: Path does not exist: '{}'", entry));
                } else if p.is_dir() {
                    match std::fs::read_dir(&p) {
                        Ok(mut entries) => {
                            if entries.next().is_none() {
                                warnings.push(format!(
                                    "validate.list: Directory is empty: '{}'",
                                    entry
                                ));
                            }
                        }
                        Err(e) => {
                            errors.push(format!(
                                "validate.list: Directory not readable: '{}' ({})",
                                entry, e
                            ));
                        }
                    }
                }
            }
        }

        (errors, warnings)
    }
}
