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
                "json" => validate_json(actual, value_config),
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

fn validate_json(actual: &Value, json_config: &MatcherConfig) -> MatchResult {
    let parsed_val: Value = match actual {
        Value::String(raw) => match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(json_error) => match serde_yaml::from_str(raw) {
                Ok(value) => value,
                Err(yaml_error) => {
                    return MatchResult::fail(format!(
                        "JSON parse error: {}; YAML parse error: {}",
                        json_error, yaml_error
                    ))
                }
            },
        },
        value => value.clone(),
    };

    match json_config {
        MatcherConfig::Matcher(map) => {
            let pointer_str = match map.get("pointer") {
                Some(MatcherConfig::String(p)) => p.as_str(),
                _ => {
                    return MatchResult::fail(
                        "Syntax Error: 'json' matcher requires 'pointer' string".to_string(),
                    )
                }
            };

            let predicates: Vec<(&String, &MatcherConfig)> = map
                .iter()
                .filter(|(key, _)| key.as_str() != "pointer")
                .collect();
            if predicates.len() != 1 {
                return MatchResult::fail(format!(
                    "Syntax Error: 'json' matcher requires exactly one predicate, found {}",
                    predicates.len()
                ));
            }

            let target_val = match parsed_val.pointer(pointer_str) {
                Some(v) => v,
                None => {
                    return MatchResult::fail(format!(
                        "pointer '{}' not found in JSON payload",
                        pointer_str
                    ))
                }
            };

            let (predicate_name, predicate_config) = predicates[0];
            let predicate = MatcherConfig::Matcher(std::collections::HashMap::from([(
                predicate_name.clone(),
                predicate_config.clone(),
            )]));
            validate(target_val, &predicate)
        }
        _ => MatchResult::fail(
            "Syntax Error: 'json' matcher must be a map with 'pointer'".to_string(),
        ),
    }
}

/// Returns whether a matcher requires structured JSON/YAML payload parsing.
pub fn contains_json_matcher(config: &MatcherConfig) -> bool {
    match config {
        MatcherConfig::List(matchers) => matchers.iter().any(contains_json_matcher),
        MatcherConfig::Matcher(map) => {
            map.contains_key("json") || map.values().any(contains_json_matcher)
        }
        MatcherConfig::String(_) | MatcherConfig::Number(_) | MatcherConfig::Boolean(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_json_sub_matcher_string_equality() {
        let json_text = r#"{"name": "kmns-validate", "version": "0.4.0"}"#;
        let mut inner = HashMap::new();
        inner.insert(
            "pointer".to_string(),
            MatcherConfig::String("/version".to_string()),
        );
        inner.insert(
            "equal".to_string(),
            MatcherConfig::String("0.4.0".to_string()),
        );

        let mut outer = HashMap::new();
        outer.insert("json".to_string(), MatcherConfig::Matcher(inner));
        let matcher = MatcherConfig::Matcher(outer);

        let res = validate(&Value::String(json_text.to_string()), &matcher);
        assert!(
            res.passed,
            "Expected match to pass, got: {:?}",
            res.failure_message
        );
    }

    #[test]
    fn test_json_sub_matcher_have_prefix() {
        let json_text =
            r#"{"channels": {"production": {"apps": {"kompass": {"version": "2026.10.4"}}}}}"#;
        let mut inner = HashMap::new();
        inner.insert(
            "pointer".to_string(),
            MatcherConfig::String("/channels/production/apps/kompass/version".to_string()),
        );
        inner.insert(
            "have-prefix".to_string(),
            MatcherConfig::String("2026.".to_string()),
        );

        let mut outer = HashMap::new();
        outer.insert("json".to_string(), MatcherConfig::Matcher(inner));
        let matcher = MatcherConfig::Matcher(outer);

        let res = validate(&Value::String(json_text.to_string()), &matcher);
        assert!(
            res.passed,
            "Expected prefix match to pass, got: {:?}",
            res.failure_message
        );
    }

    #[test]
    fn test_json_sub_matcher_number_and_boolean() {
        let json_text = r#"{"active": true, "port": 443}"#;
        let mut inner_bool = HashMap::new();
        inner_bool.insert(
            "pointer".to_string(),
            MatcherConfig::String("/active".to_string()),
        );
        inner_bool.insert("equal".to_string(), MatcherConfig::Boolean(true));

        let mut outer_bool = HashMap::new();
        outer_bool.insert("json".to_string(), MatcherConfig::Matcher(inner_bool));
        let res_bool = validate(
            &Value::String(json_text.to_string()),
            &MatcherConfig::Matcher(outer_bool),
        );
        assert!(res_bool.passed);

        let mut inner_num = HashMap::new();
        inner_num.insert(
            "pointer".to_string(),
            MatcherConfig::String("/port".to_string()),
        );
        inner_num.insert("equal".to_string(), MatcherConfig::Number(443.0));

        let mut outer_num = HashMap::new();
        outer_num.insert("json".to_string(), MatcherConfig::Matcher(inner_num));
        let res_num = validate(
            &Value::String(json_text.to_string()),
            &MatcherConfig::Matcher(outer_num),
        );
        assert!(res_num.passed);
    }

    #[test]
    fn test_json_sub_matcher_missing_pointer() {
        let json_text = r#"{"name": "test"}"#;
        let mut inner = HashMap::new();
        inner.insert(
            "pointer".to_string(),
            MatcherConfig::String("/missing".to_string()),
        );
        inner.insert(
            "equal".to_string(),
            MatcherConfig::String("foo".to_string()),
        );

        let mut outer = HashMap::new();
        outer.insert("json".to_string(), MatcherConfig::Matcher(inner));
        let res = validate(
            &Value::String(json_text.to_string()),
            &MatcherConfig::Matcher(outer),
        );
        assert!(!res.passed);
        assert!(res
            .failure_message
            .unwrap()
            .contains("pointer '/missing' not found"));
    }

    #[test]
    fn test_json_sub_matcher_yaml_auto_detection() {
        let yaml_text = "channels:\n  production:\n    version: '0.4.0'\n";
        let mut inner = HashMap::new();
        inner.insert(
            "pointer".to_string(),
            MatcherConfig::String("/channels/production/version".to_string()),
        );
        inner.insert(
            "equal".to_string(),
            MatcherConfig::String("0.4.0".to_string()),
        );

        let mut outer = HashMap::new();
        outer.insert("json".to_string(), MatcherConfig::Matcher(inner));
        let res = validate(
            &Value::String(yaml_text.to_string()),
            &MatcherConfig::Matcher(outer),
        );
        assert!(
            res.passed,
            "Expected YAML auto-detection to pass: {:?}",
            res.failure_message
        );
    }

    #[test]
    fn test_json_sub_matcher_requires_exactly_one_predicate() {
        let mut pointer_only = HashMap::new();
        pointer_only.insert(
            "pointer".to_string(),
            MatcherConfig::String("/version".to_string()),
        );
        let mut outer = HashMap::new();
        outer.insert("json".to_string(), MatcherConfig::Matcher(pointer_only));

        let res = validate(
            &Value::String(r#"{"version":"0.4.0"}"#.to_string()),
            &MatcherConfig::Matcher(outer),
        );
        assert!(!res.passed);
        assert!(res
            .failure_message
            .unwrap()
            .contains("exactly one predicate"));

        let mut multiple_predicates = HashMap::new();
        multiple_predicates.insert(
            "pointer".to_string(),
            MatcherConfig::String("/version".to_string()),
        );
        multiple_predicates.insert(
            "equal".to_string(),
            MatcherConfig::String("0.4.0".to_string()),
        );
        multiple_predicates.insert(
            "have-prefix".to_string(),
            MatcherConfig::String("0.".to_string()),
        );
        let mut outer = HashMap::new();
        outer.insert(
            "json".to_string(),
            MatcherConfig::Matcher(multiple_predicates),
        );

        let res = validate(
            &Value::String(r#"{"version":"0.4.0"}"#.to_string()),
            &MatcherConfig::Matcher(outer),
        );
        assert!(!res.passed);
        assert!(res
            .failure_message
            .unwrap()
            .contains("exactly one predicate"));
    }

    #[test]
    fn test_gjson_matcher_is_rejected() {
        let mut paths = HashMap::new();
        paths.insert(
            "status".to_string(),
            MatcherConfig::String("ok".to_string()),
        );
        let mut outer = HashMap::new();
        outer.insert("gjson".to_string(), MatcherConfig::Matcher(paths));

        let res = validate(
            &Value::String(r#"{"status":"ok"}"#.to_string()),
            &MatcherConfig::Matcher(outer),
        );
        assert!(!res.passed);
        assert!(res
            .failure_message
            .unwrap()
            .contains("Unknown matcher \"gjson\""));
    }
}
