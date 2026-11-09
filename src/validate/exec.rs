use crate::resource::exec::ExecResource;
use crate::validate::http::ResourceTestResult;
use crate::validate::matcher;
use crate::validate::subprocess::{self, SubprocessConfig};
use serde_json::Value;
use std::time::Duration;

/// Validate an ExecResource (typed argv invocation without shell).
pub fn validate(name: &str, resource: &ExecResource, run_as: Option<&str>) -> ResourceTestResult {
    let mut result = ResourceTestResult {
        name: name.to_string(),
        title: resource.title.clone(),
        resource_type: "exec".to_string(),
        passed: false,
        skipped: false,
        failures: Vec::new(),
        error: None,
        warning: None,
        observation: None,
    };

    if resource.skip {
        result.passed = true;
        result.skipped = true;
        return result;
    }

    let bin_path = resource.effective_path(name);

    // Reject shell control characters in binary path to ensure zero injection
    if bin_path.chars().any(|c| {
        c == ';'
            || c == '&'
            || c == '|'
            || c == '`'
            || c == '$'
            || c == '>'
            || c == '<'
            || c == '\n'
    }) {
        result.passed = false;
        result.error = Some(format!(
            "Security violation: binary path {:?} contains shell metacharacters",
            bin_path
        ));
        return result;
    }

    let timeout_duration = Duration::from_millis(
        resource
            .timeout
            .map(|t| if t > 1000 { t } else { t * 1000 })
            .unwrap_or(15000),
    );

    let config = SubprocessConfig::new(&bin_path, &resource.args)
        .with_timeout(timeout_duration)
        .with_run_as(run_as);

    let output = match subprocess::execute(&config) {
        Ok(out) => out,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };

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

    for expected in &resource.stdout {
        let res = matcher::validate(&Value::String(output.stdout.clone()), expected);
        if !res.passed {
            result.failures.push(format!(
                "stdout: {}",
                res.failure_message.unwrap_or_default()
            ));
        }
    }

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
    fn test_exec_successful_typed_invocation() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/echo".to_string()),
            args: vec!["kmns-typed-exec-test".to_string()],
            meta: None,
            exit_status: Some(0),
            stdout: vec![crate::resource::matcher::MatcherConfig::String(
                "kmns-typed-exec-test".to_string(),
            )],
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("/bin/echo", &resource, None);
        assert!(res.passed, "Failures: {:?}", res.failures);
        assert_eq!(res.resource_type, "exec");
    }

    #[test]
    fn test_exec_rejects_shell_metacharacters() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/echo; rm -rf /".to_string()),
            args: vec![],
            meta: None,
            exit_status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("bad_bin", &resource, None);
        assert!(!res.passed);
        assert!(res.error.is_some());
        assert!(res.error.unwrap().contains("shell metacharacters"));
    }

    #[test]
    fn test_exec_expected_exit_code() {
        let resource = ExecResource {
            title: None,
            path: Some("/bin/false".to_string()),
            args: vec![],
            meta: None,
            exit_status: Some(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
            timeout: Some(5),
            skip: false,
        };

        let res = validate("/bin/false", &resource, None);
        assert!(res.passed, "Failures: {:?}", res.failures);
    }
}
