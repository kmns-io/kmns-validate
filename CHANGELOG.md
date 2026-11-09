# Changelog

All notable changes to `kmns-validate` are documented in this file.

## [0.5.1] - 2026-11-09

### Added

- **Combined PEM Certificate Validation**: Support reading certificates from combined PEM bundles containing public X.509 certificates and PKCS#8/SEC1 private keys without failing validation.
- **Private Key Warning Gate**: Emit non-fatal `W_PRIVATE_KEY_IN_BUNDLE` warning when private key material is present in certificate bundles while safely ignoring private key bytes in memory.
- **Resource Warning Propagation**: Propagate non-fatal resource-level warnings across both JSON and human-readable text output formatters.

## [0.5.0] - Internal (Superseded by 0.5.1)

### Added

- **Native X.509 Certificate Validation**: Inspect local TLS bundles, validity windows (`valid_for`), hostname SANs, and WebPKI trust anchors with automatic private-key protection.
- **Deadlock-Free Subprocess Engine**: High-throughput non-blocking output drainage prevents pipe buffer freezes during high-volume command and argv execution.
- **Zero-Disk Ephemeral Contracts**: Execute inline JSON/YAML validations via `--inline` without persisting temporary files to disk.
- **Process-Safe Stdin Streaming**: Stream contracts directly over standard input (`run -`) for clean container and CI/CD pipeline integration.
- **Rootless Container Inspection**: Validate Docker and Podman container state over local Unix sockets with automatic session discovery.
- **RFC 6901 JSON Sub-Matcher**: Assert structured JSON and YAML payload values using standard JSON pointers.

### Security

- **Container User & Session Isolation**: Enforce deterministic engine discovery scoping rootless Docker/Podman sockets strictly to authorized identities (`run_as`, verified `$XDG_RUNTIME_DIR`, `/run/user/<effective_uid>`, or system engines) while completely eliminating cross-user runtime directory scans.
- **Bounded I/O Hardening**: Enforce strict chunked input caps and deterministic non-secret error limits across contracts (1 MiB), configuration files (1 MiB), file contents (4 MiB), Docker/Podman container engine socket responses (4 MiB with absolute response timeout), and local version manifest caches (64 KiB).
- **Fail-Closed Execution Quarantine**: Automatically disallow child-process execution in agentic, inline and streamed contracts to neutralize remote code execution risks in CI/CD.
- **Process Group Isolation & Guaranteed Tree Cleanup**: Isolate subprocesses in dedicated process groups and clean up orphaned background children on timeout via group signal dispatch.
- **Memory-Safe Input Caps**: Strict payload size bounds on inline contracts (64 KiB), structured files (4 MiB), and captured process streams (16 KiB) to prevent memory exhaustion.
- **Credential Protection**: Redact private keys from certificate validation reports to prevent secret exposure.

### Changed

- **Unified Subprocess Architecture**: Consolidated shell `command` and typed `exec` runners under a hardened, concurrent drainage layer with deterministic truncation.
- Streamlined `json` matcher syntax requiring one pointer and a single predicate.
- Enforced mutual exclusivity between inline contracts and filesystem contract paths.

### Removed

- Legacy `gjson` syntax in favor of standard RFC 6901 JSON pointers.

## 0.4.0

- Initial release.
