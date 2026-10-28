use crate::resource::matcher::MatcherConfig;
use regex::Regex;
use semver::{Version, VersionReq};
use serde_json::Value;

/// Result of a matcher validation.
pub struct MatchResult {
    pub passed: bool,
    pub failure_message: Option<String>,
}

impl MatchResult {
    pub fn pass() -> Self {
        MatchResult {
            passed: true,
            failure_message: None,
        }
    }

    pub fn fail(msg: String) -> Self {
        MatchResult {
            passed: false,
            failure_message: Some(msg),
        }
    }
}

/// Validates an actual JSON value against a matcher configuration.
pub fn validate(actual: &Value, config: &MatcherConfig) -> MatchResult {
    match config {
        // --- Literal primitive values ---
        MatcherConfig::String(expected_str) => {
            let actual_str = value_to_string(actual);
            if actual_str == *expected_str
                || (!expected_str.is_empty() && actual_str.contains(expected_str))
            {
                MatchResult::pass()
            } else {
                MatchResult::fail(format!(
                    "expected \"{}\" got \"{}\"",
                    expected_str, actual_str
                ))
            }
        }
        MatcherConfig::Number(expected_num) => {
            let actual_num = value_to_f64(actual);
            if (actual_num - *expected_num).abs() < f64::EPSILON {
                MatchResult::pass()
            } else {
                MatchResult::fail(format!("expected {} got {}", expected_num, actual_num))
            }
        }
        MatcherConfig::Boolean(expected_bool) => {
            if actual.as_bool() == Some(*expected_bool) {
                MatchResult::pass()
            } else {
                MatchResult::fail(format!("expected {} got {:?}", expected_bool, actual))
            }
        }

        // --- List of matchers (maps to 'contain-elements') ---
        MatcherConfig::List(sub_matchers) => validate_contain_elements(actual, sub_matchers),

        // --- Complex Matchers ---
        MatcherConfig::Matcher(map) => {
            if map.is_empty() {
                return MatchResult::fail("Syntax Error: Missing required matcher".to_string());
            }
            if map.len() > 1 {
                return MatchResult::fail(format!(
                    "Syntax Error: Only one matcher is allowed per level. Found: {:?}",
                    map.keys().collect::<Vec<_>>()
                ));
            }

            let (match_type, value_config) = map.iter().next().unwrap();
            match match_type.as_str() {
                "equal" => validate(actual, value_config),
                "have-prefix" => {
                    let prefix = get_string(value_config);
                    let actual_str = value_to_string(actual);
                    if actual_str.starts_with(&prefix) {
                        MatchResult::pass()
                    } else {
                        MatchResult::fail(format!(
                            "expected prefix \"{}\" got \"{}\"",
                            prefix, actual_str
                        ))
                    }
                }
                "have-suffix" => {
                    let suffix = get_string(value_config);
                    let actual_str = value_to_string(actual);
                    if actual_str.ends_with(&suffix) {
                        MatchResult::pass()
                    } else {
                        MatchResult::fail(format!(
                            "expected suffix \"{}\" got \"{}\"",
                            suffix, actual_str
                        ))
                    }
                }
                "contain-substring" | "contains" => {
                    let sub = get_string(value_config);
                    let actual_str = value_to_string(actual);
                    if actual_str.contains(&sub) {
                        MatchResult::pass()
                    } else {
                        MatchResult::fail(format!(
                            "expected to contain \"{}\" got \"{}\"",
                            sub, actual_str
                        ))
                    }
                }
                "match-regexp" | "matches" => {
                    let pattern = get_string(value_config);
                    match Regex::new(&pattern) {
                        Ok(re) => {
                            let actual_str = value_to_string(actual);
                            if re.is_match(&actual_str) {
                                MatchResult::pass()
                            } else {
                                MatchResult::fail(format!(
                                    "expected to match regex \"{}\" got \"{}\"",
                                    pattern, actual_str
                                ))
                            }
                        }
                        Err(e) => {
                            MatchResult::fail(format!("invalid regex \"{}\": {}", pattern, e))
                        }
                    }
                }
                "have-len" => {
                    let actual_len = match actual {
                        Value::Array(a) => a.len(),
                        Value::Object(m) => m.len(),
                        Value::String(s) => s.len(),
                        _ => 0,
                    };
                    let res = validate(
                        &Value::Number(serde_json::Number::from(actual_len)),
                        value_config,
                    );
                    if res.passed {
                        MatchResult::pass()
                    } else {
                        MatchResult::fail(format!(
                            "length: {}",
                            res.failure_message.unwrap_or_default()
                        ))
                    }
                }
                "gt" => validate_numeric(actual, value_config, |a, e| a > e, ">"),
                "ge" => validate_numeric(actual, value_config, |a, e| a >= e, ">="),
                "lt" => validate_numeric(actual, value_config, |a, e| a < e, "<"),
                "le" => validate_numeric(actual, value_config, |a, e| a <= e, "<="),

                "not" => {
                    let res = validate(actual, value_config);
                    if res.passed {
                        MatchResult::fail("expected NOT to match".to_string())
                    } else {
                        MatchResult::pass()
                    }
                }
                "and" => {
                    if let MatcherConfig::List(list) = value_config {
                        for sub in list {
                            let res = validate(actual, sub);
                            if !res.passed {
                                return res;
                            }
                        }
                        MatchResult::pass()
                    } else {
                        MatchResult::fail("and matcher expects a list".to_string())
                    }
                }
                "or" => {
                    if let MatcherConfig::List(list) = value_config {
                        for sub in list {
                            let res = validate(actual, sub);
                            if res.passed {
                                return MatchResult::pass();
                            }
                        }
                        MatchResult::fail("no sub-matchers in 'or' passed".to_string())
                    } else {
                        MatchResult::fail("or matcher expects a list".to_string())
                    }
                }
                "semver-constraint" => {
                    let req_str = get_string(value_config);
                    match VersionReq::parse(&req_str) {
                        Ok(req) => {
                            let actual_str = value_to_string(actual).trim().to_string();
                            // Goss strips certain prefixes sometimes, but we try standard parse
                            // Many system tools version -v might output "v1.2.3"
                            let clean_actual = actual_str.strip_prefix('v').unwrap_or(&actual_str);
                            match Version::parse(clean_actual) {
                                Ok(ver) => {
                                    if req.matches(&ver) {
                                        MatchResult::pass()
                                    } else {
                                        MatchResult::fail(format!(
                                            "version \"{}\" does not satisfy \"{}\"",
                                            actual_str, req_str
                                        ))
                                    }
                                }
                                Err(e) => MatchResult::fail(format!(
                                    "cannot parse version \"{}\": {}",
                                    actual_str, e
                                )),
                            }
                        }
                        Err(e) => MatchResult::fail(format!(
                            "invalid semver constraint \"{}\": {}",
                            req_str, e
                        )),
                    }
                }
                "gjson" => {
                    if let MatcherConfig::Matcher(sub_map) = value_config {
                        // If actual is a string, try to parse it as JSON first
                        let parsed_json: Value = if let Value::String(s) = actual {
                            match serde_json::from_str(s) {
                                Ok(json) => json,
                                Err(e) => {
                                    return MatchResult::fail(format!(
                                        "gjson: failed to parse as JSON: {}",
                                        e
                                    ))
                                }
                            }
                        } else {
                            actual.clone()
                        };

                        for (path, sub_config) in sub_map {
                            // Simple GJSON support (dot path)
                            let parts: Vec<&str> = path.split('.').collect();
                            let mut current = &parsed_json;
                            for part in parts {
                                if let Some(next) = current.get(part) {
                                    current = next;
                                } else {
                                    return MatchResult::fail(format!(
                                        "gjson: path \"{}\" not found",
                                        path
                                    ));
                                }
                            }
                            let res = validate(current, sub_config);
                            if !res.passed {
                                return MatchResult::fail(format!(
                                    "gjson path \"{}\" failed: {}",
                                    path,
                                    res.failure_message.unwrap_or_default()
                                ));
                            }
                        }
                        MatchResult::pass()
                    } else {
                        MatchResult::fail(
                            "gjson matcher expects a map of path: matcher".to_string(),
                        )
                    }
                }

                _ => MatchResult::fail(format!("Syntax Error: Unknown matcher \"{}\"", match_type)),
            }
        }
    }
}

// --- Helpers ---

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => v.to_string(),
    }
}

fn value_to_f64(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn get_string(config: &MatcherConfig) -> String {
    match config {
        MatcherConfig::String(s) => s.clone(),
        _ => "".to_string(),
    }
}

fn get_number(config: &MatcherConfig) -> f64 {
    match config {
        MatcherConfig::Number(n) => *n,
        _ => 0.0,
    }
}

fn validate_numeric<F>(actual: &Value, expected: &MatcherConfig, op: F, op_str: &str) -> MatchResult
where
    F: Fn(f64, f64) -> bool,
{
    let e = get_number(expected);
    let a = value_to_f64(actual);
    if op(a, e) {
        MatchResult::pass()
    } else {
        MatchResult::fail(format!("expected {} {} got {}", a, op_str, e))
    }
}

fn validate_contain_elements(actual: &Value, sub_matchers: &[MatcherConfig]) -> MatchResult {
    let actual_list = match actual {
        Value::Array(a) => a.clone(),
        _ => vec![actual.clone()],
    };

    for sub in sub_matchers {
        let mut found = false;
        for item in &actual_list {
            let res = validate(item, sub);
            if res.passed {
                found = true;
                break;
            }
        }
        if !found {
            return MatchResult::fail(format!("did not find element matching {:?}", sub));
        }
    }
    MatchResult::pass()
}
