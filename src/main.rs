#![forbid(unsafe_code)]

use clap::Parser;
use kmns_validate::cli::{Cli, Commands, OutputFormat};
use kmns_validate::config::Config;
use kmns_validate::output::{
    json::format_json, resource_result_to_entry, text::format_text, OutputResult,
};
use kmns_validate::version;

fn main() {
    let args = Cli::parse();
    if args.version || matches!(args.command, Some(Commands::Version)) {
        println!("{}", version::get_version(args.verbose));
        if let Some(message) = version::upgrade_message() {
            eprintln!("{message}");
        }
        return;
    }

    let mut config = Config::load(args.config_path.clone());
    let mut output_result = OutputResult::new();
    output_result.verbose = args.verbose;
    output_result.vldid = config.runtime.vldid.clone();

    if args.allow_unsafe_command {
        output_result.add_success(
            "Acknowledgement accepted: unsafe local command execution is enabled for this run."
                .to_string(),
        );
    }
    if args.allow_unsafe_exec {
        output_result.add_success(
            "Acknowledgement accepted: unsafe local exec execution is enabled for this run."
                .to_string(),
        );
    }
    if args.allow_root_execution {
        if args.allow_unsafe_command || args.allow_unsafe_exec {
            output_result.add_success(
                "Acknowledgement accepted: unsafe execution by an already-root validator is enabled for this run."
                    .to_string(),
            );
        } else {
            output_result.add_warning(
                "unsafe_execution".to_string(),
                "--allow-root-execution has no effect without --allow-unsafe-command or --allow-unsafe-exec."
                    .to_string(),
            );
        }
    }

    // Determine target contract list:
    // 1. --contract flag(s)
    // 2. Subcommand contracts: `run [contracts...]` or `check [contracts...]`
    // 3. Positional default contracts: `kmns-validate [contracts...]`
    let mut explicit_contracts = Vec::new();
    if let Some(contracts) = args.contract {
        explicit_contracts.extend(contracts);
    }

    let is_check_mode = match &args.command {
        Some(Commands::Check { contracts }) => {
            explicit_contracts.extend(contracts.clone());
            true
        }
        Some(Commands::Run { contracts }) => {
            explicit_contracts.extend(contracts.clone());
            false
        }
        _ => {
            explicit_contracts.extend(args.contracts.clone());
            false
        }
    };

    // Check for inline mode or stdin streaming
    let is_stdin_positional = explicit_contracts.len() == 1 && explicit_contracts[0] == "-";
    let is_inline = args.inline.is_some() || is_stdin_positional;

    if args.inline.is_some() && !explicit_contracts.is_empty() && !is_stdin_positional {
        eprintln!("error: --inline cannot be combined with contract path arguments or flags.");
        std::process::exit(2);
    }

    if is_inline {
        config.validate.list.clear();
    } else if !explicit_contracts.is_empty() {
        config.validate.list = explicit_contracts;
    }

    let (errors, warnings) = config.validate_values();

    for warn in warnings {
        output_result.add_warning("config".to_string(), warn);
    }

    if !errors.is_empty() {
        output_result.add_error(
            "config_fatal".to_string(),
            format!(
                "Configuration validation failed for {:?}",
                config.get_config_path()
            ),
        );
        for err in errors {
            output_result.add_error("config".to_string(), err);
        }
    }

    if is_inline {
        use kmns_validate::validate::inline::{
            check_inline, read_stdin_bounded, run_inline, InlineError, MAX_INLINE_CONFIG_BYTES,
        };

        let (raw_content, source_name) = match &args.inline {
            Some(spec) if spec == "-" => match read_stdin_bounded(MAX_INLINE_CONFIG_BYTES) {
                Ok(content) => (content, "<stdin>".to_string()),
                Err(InlineError::PayloadTooLarge) => {
                    eprintln!(
                        "PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes)."
                    );
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("Error reading stdin: {}", e);
                    std::process::exit(2);
                }
            },
            Some(spec) => {
                if spec.len() > MAX_INLINE_CONFIG_BYTES {
                    eprintln!(
                        "PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes)."
                    );
                    std::process::exit(2);
                }
                (spec.clone(), "<inline>".to_string())
            }
            None if is_stdin_positional => match read_stdin_bounded(MAX_INLINE_CONFIG_BYTES) {
                Ok(content) => (content, "<stdin>".to_string()),
                Err(InlineError::PayloadTooLarge) => {
                    eprintln!(
                        "PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes)."
                    );
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("Error reading stdin: {}", e);
                    std::process::exit(2);
                }
            },
            _ => unreachable!(),
        };

        if args.verbose {
            output_result.add_verbose(format!("Inline source: {}", source_name));
            output_result.add_verbose(format!("Payload bytes: {}", raw_content.len()));
        }

        let vars = config.flatten_variables();
        if is_check_mode {
            match check_inline(&raw_content, &source_name, &vars) {
                Ok(summary) => {
                    output_result.file_summaries.push(summary);
                    output_result.add_success(format!(
                        "Validation contract {:?} is syntactically valid.",
                        source_name
                    ));
                }
                Err(InlineError::SecurityViolation) => {
                    eprintln!(
                        "SecurityViolation: 'command' and 'exec' observers are strictly prohibited when contract is provided via inline argument or stdin."
                    );
                    std::process::exit(2);
                }
                Err(InlineError::PayloadTooLarge) => {
                    eprintln!(
                        "PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes)."
                    );
                    std::process::exit(2);
                }
                Err(e) => {
                    output_result.add_error("contract".to_string(), e.to_string());
                }
            }
        } else {
            let parallel_enabled = args.parallel || config.parallel.enabled;
            let max_threads = if args.max_threads > 0 {
                args.max_threads
            } else {
                config.parallel.max_threads
            };
            let opts = kmns_validate::validate::runner::RunOptions {
                parallel: parallel_enabled,
                max_threads,
                run_as: None,
                allow_unsafe_command: false,
                allow_unsafe_exec: false,
                allow_root_execution: false,
                tags: args.tag.clone(),
            };

            match run_inline(
                &raw_content,
                &source_name,
                &config.runtime.package_manager,
                &vars,
                &opts,
            ) {
                Ok((summary, results)) => {
                    output_result.file_summaries.push(summary);
                    for r in results {
                        output_result.add_test(resource_result_to_entry(r));
                    }
                }
                Err(InlineError::SecurityViolation) => {
                    eprintln!(
                        "SecurityViolation: 'command' and 'exec' observers are strictly prohibited when contract is provided via inline argument or stdin."
                    );
                    std::process::exit(2);
                }
                Err(InlineError::PayloadTooLarge) => {
                    eprintln!(
                        "PayloadTooLarge: inline validation contract exceeds maximum allowed size of 64KB (65536 bytes)."
                    );
                    std::process::exit(2);
                }
                Err(e) => {
                    output_result.add_error("contract".to_string(), e.to_string());
                }
            }
        }
    } else if is_check_mode {
        let vars = config.flatten_variables();
        let check = kmns_validate::validate::runner::check_list(&config.validate.list, &vars);
        output_result.file_summaries = check.file_summaries;
        for error in check.errors {
            output_result.add_error("contract".to_string(), error);
        }
        if !output_result.has_errors() {
            output_result.add_success(format!(
                "Validation contracts and configuration {:?} are syntactically valid.",
                config.validate.list
            ));
        }
    } else {
        // Verbose runtime info
        if args.verbose {
            output_result.add_verbose(format!(
                "Time: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            ));
            output_result.add_verbose(format!(
                "OS: type={:?}, version={:?}, arch={:?}, cpus={}, load={:.2}/{:.2}/{:.2}, mem={}/{} MB",
                config.runtime.os.name,
                config.runtime.os.version,
                config.runtime.os.arch,
                config.runtime.os.cpus,
                config.runtime.os.load_average.0,
                config.runtime.os.load_average.1,
                config.runtime.os.load_average.2,
                config.runtime.os.mem_free / (1024 * 1024),
                config.runtime.os.mem_total / (1024 * 1024),
            ));
            output_result.add_verbose(format!(
                "Package manager: {:?}",
                config.runtime.package_manager
            ));
            output_result.add_verbose(format!(
                "Running as: uid={}, gid={}, privileged={}",
                config.runtime.uid, config.runtime.gid, config.runtime.privileged
            ));
            output_result.add_verbose(format!("Working directory: {:?}", config.runtime.workdir));
            output_result.add_verbose(format!(
                "Log level: {:?}, format: {:?}",
                config.log.level, config.log.format
            ));
            output_result.add_verbose(format!(
                "Environment: name={}, file={}",
                config.environment.name, config.environment.file
            ));
            // Merge CLI flags and config settings early for logging and execution
            let parallel_enabled = args.parallel || config.parallel.enabled;
            let max_threads = if args.max_threads > 0 {
                args.max_threads
            } else {
                config.parallel.max_threads
            };

            output_result.add_verbose(format!(
                "Parallel: enabled={}, max-threads={}",
                parallel_enabled, max_threads
            ));
            output_result.add_verbose(format!("Validate list: {:?}", config.validate.list));
            output_result.add_verbose(format!("Config path: {:?}", config.get_config_path()));
        }

        // Run validation against all resource files in the configured list
        if !output_result.has_errors() || args.verbose {
            let vars = config.flatten_variables();

            let parallel_enabled = args.parallel || config.parallel.enabled;
            let max_threads = if args.max_threads > 0 {
                args.max_threads
            } else {
                config.parallel.max_threads
            };

            let opts = kmns_validate::validate::runner::RunOptions {
                parallel: parallel_enabled,
                max_threads,
                run_as: None,
                allow_unsafe_command: args.allow_unsafe_command,
                allow_unsafe_exec: args.allow_unsafe_exec,
                allow_root_execution: args.allow_root_execution,
                tags: args.tag.clone(),
            };
            let run = kmns_validate::validate::runner::run_list(
                &config.validate.list,
                &config.runtime.package_manager,
                &vars,
                &opts,
            );
            output_result.file_summaries = run.file_summaries;
            for error in run.errors {
                output_result.add_error("contract".to_string(), error);
            }
            for r in run.tests {
                output_result.add_test(resource_result_to_entry(r));
            }
        }
    }

    let final_output = match args.format {
        OutputFormat::Text => format_text(&output_result),
        OutputFormat::Json => format_json(&output_result),
    };

    if output_result.has_errors() {
        eprintln!("{}", final_output);
        std::process::exit(exit_code::CONFIG_ERROR);
    } else {
        println!("{}", final_output);
        std::process::exit(exit_code::SUCCESS);
    }
}
