use minijinja::{context, Environment, ErrorKind};
use std::collections::HashMap;
use thiserror::Error;

/// Structured template processing error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TemplateError {
    #[error("E_TEMPLATE_PARSE")]
    Parse,

    #[error("E_TEMPLATE_RENDER")]
    Render,
}

impl TemplateError {
    pub fn code(&self) -> &'static str {
        match self {
            TemplateError::Parse => "E_TEMPLATE_PARSE",
            TemplateError::Render => "E_TEMPLATE_RENDER",
        }
    }
}

/// Renders a template content using the provided environment and configuration variables.
/// Supports Goss-compatible '{{ .Env.VAR }}' and '{{ .Vars.VAR }}' syntax by pre-processing
/// the content to match standard Jinja patterns.
///
/// In case of syntax or evaluation failure, returns a sanitized `TemplateError` without
/// logging to stderr or returning unrendered fallback content.
pub fn render(content: &str, vars: &HashMap<String, String>) -> Result<String, TemplateError> {
    let env = Environment::new();

    // Pre-process goss-style '{{ .Env.' and '{{ .Vars.' to '{{ Env.' and '{{ Vars.'
    // This allows standard Jinja engines to process the templates while maintaining compatibility.
    let pre_processed = content
        .replace("{{ .Env.", "{{ Env.")
        .replace("{{.Env.", "{{Env.")
        .replace("{{ .Vars.", "{{ Vars.")
        .replace("{{.Vars.", "{{Vars.");

    // Only expose explicit validator and test prefixes from ambient process environment
    // to prevent leaking ambient secrets, cloud tokens, or private keys (FINDING-04).
    let sys_env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            k.starts_with("KMNS_")
                || k.starts_with("VLD_")
                || k.starts_with("TEST_")
                || k == "PATH"
                || k == "USER"
                || k == "HOME"
        })
        .collect();

    let ctx = context! {
        Env => sys_env,
        Vars => vars,
    };

    env.render_str(&pre_processed, ctx)
        .map_err(|e| match e.kind() {
            ErrorKind::SyntaxError => TemplateError::Parse,
            _ => TemplateError::Render,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_filters_ambient_secrets() {
        std::env::set_var("SECRET_API_KEY", "super-secret-token");
        std::env::set_var("KMNS_ALLOWED_VAR", "visible-value");

        let template = "secret={{ Env.SECRET_API_KEY }} allowed={{ Env.KMNS_ALLOWED_VAR }}";
        let rendered = render(template, &HashMap::new()).unwrap();

        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("visible-value"));
    }

    #[test]
    fn test_render_parse_error_sanitized() {
        let malformed = "value={{ unclosed_tag";
        let err = render(malformed, &HashMap::new()).unwrap_err();
        assert_eq!(err, TemplateError::Parse);
        assert_eq!(err.code(), "E_TEMPLATE_PARSE");
        assert_eq!(err.to_string(), "E_TEMPLATE_PARSE");
    }

    #[test]
    fn test_render_evaluation_error_sanitized() {
        // Calling an undefined or invalid function triggers a render error
        let invalid_eval = "value={{ non_existent_function() }}";
        let err = render(invalid_eval, &HashMap::new()).unwrap_err();
        assert_eq!(err, TemplateError::Render);
        assert_eq!(err.code(), "E_TEMPLATE_RENDER");
        assert_eq!(err.to_string(), "E_TEMPLATE_RENDER");
    }
}
