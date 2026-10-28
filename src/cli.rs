use crate::version::{BIN_NAME, DESC, LONG, NAME, VERSION};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser)]
#[command(name = NAME)]
#[command(bin_name = BIN_NAME)]
#[command(propagate_version = true, next_line_help = true)]
#[command(version = VERSION)]
#[command(about = DESC)]
#[command(long_about = LONG)]
#[command(disable_version_flag = true)]
pub struct Cli {
    // Version long option
    #[arg(long = "version", required = false, global = true)]
    pub version: bool,

    // Verbose mode
    #[arg(short = 'v', long = "verbose", required = false, global = true)]
    pub verbose: bool,

    // Define custom config path
    #[arg(
        short = 'c',
        long = "config",
        env = "VALIDATE_CONFIG_PATH",
        global = true
    )]
    pub config_path: Option<PathBuf>,

    // Output format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Text, global = true)]
    pub format: OutputFormat,

    /// Explicit contract path(s) to validate (alternative to positional arguments)
    #[arg(long = "contract", action = clap::ArgAction::Append, global = true)]
    pub contract: Option<Vec<String>>,

    /// Enable parallel execution for network check resources.
    #[arg(long, default_value_t = false, global = true)]
    pub parallel: bool,

    /// Maximum concurrent requests per validator type (0 = num_cpus).
    #[arg(long, default_value_t = 0, value_name = "N", global = true)]
    pub max_threads: usize,

    /// Acknowledge that contract command checks may execute unsafe shell code.
    #[arg(long = "allow-unsafe-command", global = true)]
    pub allow_unsafe_command: bool,

    /// Acknowledge that contract exec checks may execute unsafe local programs.
    #[arg(long = "allow-unsafe-exec", global = true)]
    pub allow_unsafe_exec: bool,

    /// Acknowledge unsafe command or exec execution by an already-root validator process.
    #[arg(long = "allow-root-execution", global = true)]
    pub allow_root_execution: bool,

    /// Filter checks by stage/tag (e.g. 'pre-install', 'migration', 'production'). Repeat or use comma-separated values.
    #[arg(short = 't', long = "tag", value_delimiter = ',', global = true)]
    pub tag: Vec<String>,

    /// Positional contracts when invoked without a subcommand (e.g. `kmns-validate contract.yaml`)
    #[arg(trailing_var_arg = true)]
    pub contracts: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display the installed version and any available release message
    Version,
    /// Execute declarative validation contracts against the system
    Run {
        /// Contract file(s) or directories to validate
        #[arg(trailing_var_arg = true)]
        contracts: Vec<String>,
    },
    /// Verify contract syntax and schema conformity without executing live network probes
    Check {
        /// Contract file(s) or directories to verify
        #[arg(trailing_var_arg = true)]
        contracts: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn unsafe_execution_flags_are_explicit_and_independent() {
        let cli = Cli::try_parse_from([
            "validate",
            "--allow-unsafe-command",
            "--allow-root-execution",
        ])
        .unwrap();
        assert!(cli.allow_unsafe_command);
        assert!(!cli.allow_unsafe_exec);
        assert!(cli.allow_root_execution);
    }

    #[test]
    fn legacy_goss_flags_are_pruned() {
        assert!(Cli::try_parse_from(["validate", "-g", "contract.yaml"]).is_err());
        assert!(Cli::try_parse_from(["validate", "--validate", "contract.yaml"]).is_err());
        assert!(Cli::try_parse_from(["validate", "--watchdog"]).is_err());
        assert!(Cli::try_parse_from(["validate", "--vldid-dc", "1"]).is_err());
    }

    #[test]
    fn run_subcommand_parses_positional_contracts() {
        let cli = Cli::try_parse_from(["validate", "run", "contract.yaml", "other.yaml"]).unwrap();
        match cli.command {
            Some(Commands::Run { contracts }) => {
                assert_eq!(contracts, vec!["contract.yaml", "other.yaml"]);
            }
            _ => panic!("Expected Commands::Run"),
        }
    }

    #[test]
    fn check_subcommand_parses_positional_contracts() {
        let cli = Cli::try_parse_from(["validate", "check", "contract.yaml"]).unwrap();
        match cli.command {
            Some(Commands::Check { contracts }) => {
                assert_eq!(contracts, vec!["contract.yaml"]);
            }
            _ => panic!("Expected Commands::Check"),
        }
    }

    #[test]
    fn default_positional_contracts_parse() {
        let cli = Cli::try_parse_from(["validate", "contract.yaml"]).unwrap();
        assert_eq!(cli.contracts, vec!["contract.yaml"]);
    }
}
