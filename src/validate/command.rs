use crate::resource::command::CommandResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use crate::validate::subprocess::{self, SubprocessConfig};
use serde_json::Value;
use std::time::Duration;

/// Validate a CommandResource and return a structured result.
pub fn validate(
    name: &str,
    resource: &CommandResource,
    run_as: Option<&str>,
) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "command".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    // ---------- skip ----------------------------------------------------
    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let command_str = resource.effective_command(name);

    let timeout_duration = Duration::from_millis(
        resource
            .timeout
            .map(|t| if t > 1000 { t } else { t * 1000 })
            .unwrap_or(15000),
    );

    let sh_args = vec!["-c".to_string(), command_str.clone()];
    let config = SubprocessConfig::new("sh", &sh_args)
        .with_timeout(timeout_duration)
        .with_run_as(run_as);

    let output = match subprocess::execute(&config) {
        Ok(out) => out,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };

    // ---------- exit-status ---------------------------------------------
    if resource
        .exit_status
        .is_some_and(|expected| output.exit_status != expected)
    {
        result.failures.push(format!(
            "exit-status: expected {} got {}",
            resource.exit_status.unwrap(),
            output.exit_status
        ));
    }

    // Check stdout matchers
    for expected in &resource.stdout {
        let res = matcher::validate(&Value::String(output.stdout.clone()), expected);
        if !res.passed {
            result.failures.push(format!(
                "stdout: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

    // Check stderr matchers
    for expected in &resource.stderr {
        let res = matcher::validate(&Value::String(output.stderr.clone()), expected);
        if !res.passed {
            result.failures.push(format!(
                "stderr: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

    result.passed = result.failures.is_empty();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_timeout_kills_process_group() {
        let resource = CommandResource {
            title: None,
            command: Some("(sleep 20 &) ; sleep 10".to_string()),
            meta: None,
            exit_status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(1), // 1 second timeout
            skip: false,
        };

        let start = std::time::Instant::now();
        let res = validate("timeout_test", &resource, None);
        let elapsed = start.elapsed();

        assert!(!res.passed);
        assert!(res.error.is_some());
        let err = res.error.unwrap();
        assert!(err.contains("timed out"));
        assert!(elapsed.as_secs() < 5); // Guarantee process group did not hang for 20s
    }

    #[test]
    fn test_command_output_bounded_truncation() {
        let resource = CommandResource {
            title: None,
            command: Some("python3 -c 'print(\"X\" * 30000)'".to_string()),
            meta: None,
            exit_status: Some(0),
            stdout: vec![crate::resource::matcher::MatcherConfig::String(
                "[TRUNCATED: Output exceeded limit]".to_string(),
            )],
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("truncation_test", &resource, None);
        assert!(res.passed, "Failures: {:?}", res.failures);
    }

    #[test]
    fn test_command_prohibits_root_run_as() {
        let resource = CommandResource {
            title: None,
            command: Some("whoami".to_string()),
            meta: None,
            exit_status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("root_test", &resource, Some("root"));
        assert!(!res.passed);
        assert!(res.error.is_some());
        assert!(res.error.unwrap().contains("Security violation"));
    }
}
