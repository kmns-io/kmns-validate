use curl::easy::{Easy, WriteError};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "kmns-validate";
pub const BIN_NAME: &str = "kmns-validate";
pub const DESC: &str = "Lightning-fast, zero-dependency infrastructure contract validation tool";
pub const LONG: &str = "kmns-validate is an ultra-fast, zero-dependency infrastructure testing and validation tool designed for local dev, CI/CD, and production nodes, services, and containers.";
pub const DEFAULT_VERSION_MANIFEST_URL: &str = "https://kmns.io/api/v1/version.json";

/// The version manifest URL compiled into the binary.
pub const VERSION_MANIFEST_URL: &str = match option_env!("KMNS_VERSION_MANIFEST_URL") {
    Some(url) => url,
    None => DEFAULT_VERSION_MANIFEST_URL,
};

pub const VERSION_MANIFEST_MAX_BYTES: usize = 64 * 1024;
const VERSION_MESSAGE_MAX_BYTES: usize = 1024;
const VERSION_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const VERSION_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const VERSION_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct VersionManifest {
    schema_version: String,
    applications: std::collections::BTreeMap<String, VersionApplication>,
}

#[derive(Debug, Deserialize)]
struct VersionApplication {
    latest: String,
    message: Option<String>,
}

// Returns the short or verbose kmns-validate version.
pub fn get_version(verbose: bool) -> String {
    if verbose {
        format!("{} version {}", NAME, VERSION)
    } else {
        VERSION.to_string()
    }
}

/// Returns the optional, informational release message. All network and cache
/// failures are deliberately silent so explicit version output always succeeds.
pub fn upgrade_message() -> Option<String> {
    let cache_path = version_cache_path()?;

    if cache_is_fresh(&cache_path) {
        if let Ok(cached) = fs::read(&cache_path) {
            if let Some(manifest) = parse_manifest(&cached) {
                return manifest_message_from(&manifest);
            }
        }
    }

    let response = fetch_manifest().ok()?;
    let manifest = parse_manifest(&response)?;
    let _ = write_cache(&cache_path, &response);
    manifest_message_from(&manifest)
}

pub fn version_user_agent(os: &str, arch: &str) -> String {
    format!("KMNS-Validate/{VERSION} ({os}; {arch}; stable)")
}

#[cfg(test)]
fn manifest_message(bytes: &[u8]) -> Option<String> {
    parse_manifest(bytes).and_then(|manifest| manifest_message_from(&manifest))
}

fn manifest_message_from(manifest: &VersionManifest) -> Option<String> {
    let application = manifest.applications.get(NAME)?;
    let published_version = semver::Version::parse(&application.latest).ok()?;
    let installed_version = semver::Version::parse(VERSION).ok()?;
    if published_version <= installed_version {
        return None;
    }
    let message = application.message.as_deref()?;

    if message.is_empty() || message.len() > VERSION_MESSAGE_MAX_BYTES {
        return None;
    }

    Some(
        message
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect(),
    )
}

fn parse_manifest(bytes: &[u8]) -> Option<VersionManifest> {
    if bytes.len() > VERSION_MANIFEST_MAX_BYTES {
        return None;
    }

    let manifest: VersionManifest = serde_json::from_slice(bytes).ok()?;
    (manifest.schema_version == "kmns.io/version/v1alpha1").then_some(manifest)
}

fn fetch_manifest() -> Result<Vec<u8>, String> {
    let mut easy = Easy::new();
    easy.url(VERSION_MANIFEST_URL)
        .map_err(|error| error.to_string())?;
    easy.get(true).map_err(|error| error.to_string())?;
    easy.useragent(&version_user_agent(
        std::env::consts::OS,
        std::env::consts::ARCH,
    ))
    .map_err(|error| error.to_string())?;
    easy.connect_timeout(VERSION_CONNECT_TIMEOUT)
        .map_err(|error| error.to_string())?;
    easy.timeout(VERSION_REQUEST_TIMEOUT)
        .map_err(|error| error.to_string())?;
    easy.follow_location(false)
        .map_err(|error| error.to_string())?;
    easy.ssl_verify_peer(true)
        .map_err(|error| error.to_string())?;
    easy.ssl_verify_host(true)
        .map_err(|error| error.to_string())?;

    let mut body = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer
            .write_function(|chunk| {
                if body.len().saturating_add(chunk.len()) > VERSION_MANIFEST_MAX_BYTES {
                    return Err(WriteError::Pause);
                }
                body.extend_from_slice(chunk);
                Ok(chunk.len())
            })
            .map_err(|error| error.to_string())?;
        transfer.perform().map_err(|error| error.to_string())?;
    }

    let status = easy.response_code().map_err(|error| error.to_string())?;
    if status == 200 {
        Ok(body)
    } else {
        Err(format!("version endpoint returned HTTP {status}"))
    }
}

fn version_cache_path() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join(NAME).join("version.json"))
}

fn cache_is_fresh(path: &std::path::Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age <= VERSION_CACHE_TTL)
}

fn write_cache(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().expect("cache path has a parent");
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!("version-{}.json", std::process::id()));
    fs::write(&temporary, body)?;
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::{manifest_message, version_user_agent, VERSION, VERSION_MANIFEST_MAX_BYTES};

    #[test]
    fn extracts_and_sanitizes_the_application_message() {
        let manifest = br#"{
          "schema_version": "kmns.io/version/v1alpha1",
          "applications": {
            "kmns-validate": {
              "latest": "0.4.1",
              "message": "Upgrade now\nplease\u001b[2J"
            }
          }
        }"#;

        assert_eq!(
            manifest_message(manifest),
            Some("Upgrade now please [2J".to_string())
        );
    }

    #[test]
    fn rejects_empty_oversized_and_invalid_manifests() {
        assert_eq!(manifest_message(br#"{"applications": {}}"#), None);
        assert_eq!(
            manifest_message(
                format!(
                    r#"{{"schema_version":"kmns.io/version/v1alpha1","applications":{{"kmns-validate":{{"latest":"0.4.1","message":"{}"}}}}}}"#,
                    "x".repeat(1025)
                )
                .as_bytes()
            ),
            None
        );
        assert_eq!(
            manifest_message(&vec![b'x'; VERSION_MANIFEST_MAX_BYTES + 1]),
            None
        );
    }

    #[test]
    fn does_not_show_a_message_when_the_installed_version_is_current() {
        let manifest = format!(
            r#"{{"schema_version":"kmns.io/version/v1alpha1","applications":{{"kmns-validate":{{"latest":"{VERSION}","message":"Do not show"}}}}}}"#
        );

        assert_eq!(manifest_message(manifest.as_bytes()), None);
    }

    #[test]
    fn user_agent_is_limited_to_release_fingerprint_fields() {
        assert_eq!(
            version_user_agent("linux", "x86_64"),
            format!("KMNS-Validate/{VERSION} (linux; x86_64; stable)")
        );
    }

    #[test]
    fn version_manifest_url_is_immutable_and_matches_canonical_default() {
        assert_eq!(
            super::VERSION_MANIFEST_URL,
            super::DEFAULT_VERSION_MANIFEST_URL
        );
        assert!(super::VERSION_MANIFEST_URL.starts_with("https://"));
    }
}
