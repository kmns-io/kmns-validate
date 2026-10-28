use crate::output::{OutputResult, TestStatus};

pub fn format_text(result: &OutputResult) -> String {
    let mut output = String::new();

    for verbose in &result.verboses {
        output.push_str(&format!("[INFO] {}\n", verbose));
    }

    for success in &result.successes {
        output.push_str(&format!("[OK] {}\n", success));
    }

    for warning in &result.warnings {
        output.push_str(&format!(
            "[WARN] {}: {}\n",
            warning.warning_type, warning.message
        ));
    }

    for error in &result.errors {
        output.push_str(&format!("[FAIL] {}: {}\n", error.error_type, error.message));
    }

    // Test results
    for test in &result.tests {
        let label = test
            .title
            .as_deref()
            .map(|t| format!(" [{}]", t))
            .unwrap_or_default();

        match &test.status {
            TestStatus::Pass => {
                output.push_str(&format!(
                    "[PASS] {}/{}{}\n",
                    test.resource_type, test.name, label
                ));
                if let Some(observation) = &test.observation {
                    output.push_str(&format!("       = {observation}\n"));
                }
            }
            TestStatus::Skip => {
                output.push_str(&format!(
                    "[SKIP] {}/{}{}\n",
                    test.resource_type, test.name, label
                ));
            }
            TestStatus::Fail => {
                output.push_str(&format!(
                    "[FAIL] {}/{}{}\n",
                    test.resource_type, test.name, label
                ));
                for f in &test.failures {
                    output.push_str(&format!("       - {}\n", f));
                }
            }
            TestStatus::Warning => {
                output.push_str(&format!(
                    "[WARN] {}/{}{}\n",
                    test.resource_type, test.name, label
                ));
                for f in &test.failures {
                    output.push_str(&format!("       - {}\n", f));
                }
            }
            TestStatus::Error => {
                output.push_str(&format!(
                    "[ERROR] {}/{}{}: {}\n",
                    test.resource_type,
                    test.name,
                    label,
                    test.error.as_deref().unwrap_or("unknown error")
                ));
            }
        }
    }

    let counts = result.test_summary();

    output.push_str("\n--- Summary ---\n");
    if result.verbose && !result.file_summaries.is_empty() {
        for f in &result.file_summaries {
            output.push_str(&format!(
                "File: {} [valid={}, pass={}, fail={}, skip={}, error={}, warn={}]\n",
                f.path,
                f.valid,
                f.tests.pass,
                f.tests.fail,
                f.tests.skip,
                f.tests.error,
                f.tests.warn
            ));
        }
    }

    if counts.total > 0 {
        output.push_str(&format!(
            "Tests: {} total, {} passed, {} failed, {} skipped, {} errors, {} warnings\n",
            counts.total, counts.pass, counts.fail, counts.skip, counts.error, counts.warn
        ));
    }
    output.push_str(&format!("VldId: {}\n", result.vldid));
    output.push_str(&format!(
        "Total time: {:.3}s\n",
        result.start_time.elapsed().as_secs_f64()
    ));

    output
}
