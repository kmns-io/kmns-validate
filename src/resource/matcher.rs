use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a value that can be validated against a matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MatcherConfig {
    /// Literal string (maps to 'equal' or 'toString' + 'equal').
    String(String),
    /// Literal number (maps to 'be-numerically eq').
    Number(f64),
    /// Literal boolean (maps to 'equal').
    Boolean(bool),
    /// A list of matchers (maps to 'contain-elements').
    List(Vec<MatcherConfig>),
    /// A complex matcher (e.g. { "have-prefix": "foo" }).
    Matcher(HashMap<String, MatcherConfig>),
}

impl Default for MatcherConfig {
    fn default() -> Self {
        MatcherConfig::String(String::new())
    }
}
