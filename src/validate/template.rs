use minijinja::{context, Environment};
use std::collections::HashMap;

/// Renders a template content using the provided environment and configuration variables.
/// Supports Goss-compatible '{{ .Env.VAR }}' and '{{ .Vars.VAR }}' syntax by pre-processing
/// the content to match standard Jinja patterns.
pub fn render(content: &str, vars: &HashMap<String, String>) -> String {
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

    match env.render_str(&pre_processed, ctx) {
        Ok(rendered) => rendered,
        Err(e) => {
            eprintln!("validate: template rendering error: {}", e);
            // Return original content if rendering fails to avoid data loss on partial parsing
            content.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_filters_ambient_secrets() {
        std::env::set_var("SECRET_API_KEY", "super-secret-token");
        std::env::set_var("KMNS_ALLOWED_VAR", "visible-value");

        let template = "secret={{ Env.SECRET_API_KEY }} allowed={{ Env.KMNS_ALLOWED_VAR }}";
        let rendered = render(template, &HashMap::new());

        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("visible-value"));
    }
}
