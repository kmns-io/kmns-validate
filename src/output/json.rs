use crate::output::{ErrorEntry, OutputResult, TestEntry, TestStatus, WarningEntry};
use crate::version::VERSION;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonCountSummary {
    pub tests: crate::validate::runner::TestCounts,
    pub file_summaries: Vec<crate::validate::runner::FileSummary>,
}

#[derive(Serialize)]
pub struct JsonTimeSummary {
    pub total: String,
}

#[derive(Serialize)]
pub struct JsonVersionSummary {
    pub vld: String,
}

#[derive(Serialize)]
pub struct JsonSummary<'a> {
    pub count: JsonCountSummary,
    pub time: JsonTimeSummary,
    pub version: JsonVersionSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verbose: &'a Vec<String>,
}

#[derive(Serialize)]
pub struct JsonReport<'a> {
    #[serde(rename = "VldId")]
    pub vldid: &'a String,
    pub status: &'a str,
    pub summary: JsonSummary<'a>,
    pub success: &'a Vec<String>,
    pub warnings: &'a Vec<WarningEntry>,
    pub errors: &'a Vec<ErrorEntry>,
    pub tests: &'a Vec<TestEntry>,
}

pub fn format_json(result: &OutputResult) -> String {
    let status = if result.has_errors() {
        "error"
    } else if !result.warnings.is_empty()
        || result
            .tests
            .iter()
            .any(|test| test.status == TestStatus::Warning)
    {
        "warning"
    } else {
        "success"
    };

    let counts = result.test_summary();

    // Map test results into the summary success/warning/error lists for easy lookup
    let mut successes: Vec<String> = result.successes.clone();
    successes.extend(
        result
            .tests
            .iter()
            .filter(|t| t.status == TestStatus::Pass)
            .map(|t| format!("{}/{}", t.resource_type, t.name)),
    );

    let mut warnings: Vec<WarningEntry> = result.warnings.clone();
    warnings.extend(
        result
            .tests
            .iter()
            .filter(|t| t.status == TestStatus::Warning)
            .map(|t| WarningEntry {
                warning_type: "test_warning".to_string(),
                message: format!("{}/{}", t.resource_type, t.name),
            }),
    );

    let mut errors: Vec<ErrorEntry> = result.errors.clone();
    errors.extend(
        result
            .tests
            .iter()
            .filter(|t| matches!(t.status, TestStatus::Fail | TestStatus::Error))
            .map(|t| ErrorEntry {
                error_type: "test_failure".to_string(),
                message: format!("{}/{}", t.resource_type, t.name),
            }),
    );

    let report = JsonReport {
        status,
        summary: JsonSummary {
            count: JsonCountSummary {
                tests: counts,
                file_summaries: result.file_summaries.clone(),
            },
            time: JsonTimeSummary {
                total: format!("{:.3}s", result.start_time.elapsed().as_secs_f64()),
            },
            version: JsonVersionSummary {
                vld: VERSION.to_string(),
            },
            verbose: &result.verboses,
        },
        vldid: &result.vldid,
        success: &successes,
        warnings: &warnings,
        errors: &errors,
        tests: &result.tests,
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
