use serde::{Deserialize, Serialize};
use std::time::Instant;

pub mod json;
pub mod text;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningEntry {
    #[serde(rename = "type")]
    pub warning_type: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEntry {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

/// Outcome of a single validation check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Pass,
    Fail,
    Skip,
    Error,
    Warning,
}

/// Structured result for one validation test (e.g. an HTTP check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEntry {
    /// Unique test name / map key.
    pub name: String,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Resource type identifier (e.g. `"http"`).
    pub resource_type: String,
    pub status: TestStatus,
    /// Non-empty only when status is `Fail`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
    /// Non-empty only when status is `Error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A bounded value observed by a non-asserting check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<String>,
}

pub struct OutputResult {
    pub start_time: Instant,
    pub verboses: Vec<String>,
    pub successes: Vec<String>,
    pub warnings: Vec<WarningEntry>,
    pub errors: Vec<ErrorEntry>,
    pub tests: Vec<TestEntry>,
    /// Summary for each processed resource file.
    pub file_summaries: Vec<crate::validate::runner::FileSummary>,
    /// Whether verbose mode was enabled.
    pub verbose: bool,
    /// Unique identifier for this validation run.
    pub vldid: String,
}

impl Default for OutputResult {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputResult {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            verboses: Vec::new(),
            successes: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            tests: Vec::new(),
            file_summaries: Vec::new(),
            verbose: false,
            vldid: String::new(),
        }
    }

    pub fn add_verbose(&mut self, item: String) {
        self.verboses.push(item);
    }

    pub fn add_success(&mut self, item: String) {
        self.successes.push(item);
    }

    pub fn add_warning(&mut self, warning_type: String, message: String) {
        self.warnings.push(WarningEntry {
            warning_type,
            message,
        });
    }

    pub fn add_error(&mut self, error_type: String, message: String) {
        self.errors.push(ErrorEntry {
            error_type,
            message,
        });
    }

    /// Add a structured test result from any resource type.
    pub fn add_test(&mut self, entry: TestEntry) {
        self.tests.push(entry);
    }

    /// Returns `true` when there are config-level errors OR any test failures / errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
            || self
                .tests
                .iter()
                .any(|t| matches!(t.status, TestStatus::Fail | TestStatus::Error))
    }

    /// Counts of all test outcomes across all resource files.
    pub fn test_summary(&self) -> crate::validate::runner::TestCounts {
        let counts = crate::validate::runner::TestCounts {
            total: self.tests.len(),
            pass: self
                .tests
                .iter()
                .filter(|t| t.status == TestStatus::Pass)
                .count(),
            fail: self
                .tests
                .iter()
                .filter(|t| t.status == TestStatus::Fail)
                .count(),
            skip: self
                .tests
                .iter()
                .filter(|t| t.status == TestStatus::Skip)
                .count(),
            error: self
                .tests
                .iter()
                .filter(|t| t.status == TestStatus::Error)
                .count(),
            warn: self
                .tests
                .iter()
                .filter(|t| t.status == TestStatus::Warning)
                .count(),
        };

        counts
    }
}

pub fn resource_result_to_entry(r: crate::validate::http::ResourceTestResult) -> TestEntry {
    let status = if r.skipped {
        TestStatus::Skip
    } else if r.error.is_some() {
        TestStatus::Error
    } else if r.warning.is_some() {
        TestStatus::Warning
    } else if r.passed {
        TestStatus::Pass
    } else {
        TestStatus::Fail
    };

    TestEntry {
        name: r.name,
        title: r.title,
        resource_type: r.resource_type,
        status,
        failures: r.failures,
        error: r.error,
        observation: r.observation,
    }
}

#[cfg(test)]
mod tests {
    use super::{resource_result_to_entry, OutputResult, TestEntry, TestStatus};
    use crate::validate::http::ResourceTestResult;
    use crate::validate::runner::{FileSummary, TestCounts};

    #[test]
    fn host_observation_is_preserved_in_structured_output() {
        let entry = resource_result_to_entry(ResourceTestResult {
            name: "HOSTNAME".to_owned(),
            title: Some("Hostname".to_owned()),
            resource_type: "host".to_owned(),
            passed: true,
            skipped: false,
            failures: Vec::new(),
            error: None,
            warning: None,
            observation: Some("node.example".to_owned()),
        });

        assert_eq!(entry.status, TestStatus::Pass);
        assert_eq!(entry.observation.as_deref(), Some("node.example"));
    }

    #[test]
    fn summary_does_not_double_count_test_warnings_from_file_summaries() {
        let mut output = OutputResult::new();
        output.add_test(TestEntry {
            name: "STATUS_PROVIDER".to_owned(),
            title: None,
            resource_type: "plugin".to_owned(),
            status: TestStatus::Warning,
            failures: Vec::new(),
            error: None,
            observation: None,
        });
        output.file_summaries.push(FileSummary {
            path: "contract.yaml".to_owned(),
            valid: true,
            tests: TestCounts {
                total: 1,
                warn: 1,
                ..TestCounts::default()
            },
        });

        assert_eq!(output.test_summary().warn, 1);
    }
}
