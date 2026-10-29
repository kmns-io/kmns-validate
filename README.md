# KMNS Validate (`kmns-validate`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Documentation](https://img.shields.io/badge/docs-validate.kmns.io-cyan.svg)](https://validate.kmns.io)

**`kmns-validate`** is an ultra-fast (<20ms), zero-dependency infrastructure testing and validation tool designed for local development, CI/CD pipelines, autonomous AI coding agents (Antigravity, Cursor, Claude Code), and production systems.

It replaces complex and heavy testing frameworks (like Goss, InSpec, or custom shell verification scripts) with clean, declarative, typed YAML/JSON contracts.

---

## Key Features

- ⚡ **Blazingly Fast**: Native compiled Rust binary; executes complex multi-resource checks in <20 milliseconds.
- 📦 **Zero Runtime Dependencies**: Completely standalone statically compiled binary (static curl + OpenSSL). No Python, JVM, or ruby runtime needed.
- 🤖 **Agentic ASDLC Enabler**: Replaces speculative agentic trial-and-error shell probing with a single deterministic evaluation pass. Saves 80–90% of AI agent context window tokens.
- 🛡️ **Defensive Security & Isolation**: `#![forbid(unsafe_code)]`, strict input validation against option injection, isolated container socket queries, and ambient environment variable secret shielding.
- 📐 **Declarative Typed Contracts**: Powered by the [`kmns-contract`](https://github.com/kmns-io/kmns-validate) schema with rich check metadata, severities, tags, and automated remediation hints.
- 🔄 **Safe Version Discovery**: Non-blocking, cached version checks (`kmns-validate --version`) against `https://kmns.io/api/v1/version.json` with zero network egress during normal validation runs.

---

## Installation

### Pre-built Binary (Recommended)

```bash
# Quick install script (verified checksum & signature)
curl -fsSL https://validate.kmns.io/install.sh | bash
```

### From Source

```bash
cargo build --release -p kmns-validate
sudo cp target/release/kmns-validate /usr/local/bin/
```

### Via Docker / OCI Container

Run validation without installing host binaries:

```bash
# Docker Hub (shorthand alias)
docker run --rm -v $(pwd):/contracts:ro kmnsio/validate:latest run /contracts/validate.yaml

# GitHub Packages (GHCR)
docker run --rm -v $(pwd):/contracts:ro ghcr.io/kmns-io/kmns-validate:latest run /contracts/validate.yaml
```

Verify installation:
```bash
kmns-validate --version
```

---

## Quick Start: Writing Your First Contract

Create a contract file `validate.yaml`:

```yaml
schema_version: kmns.io/validate/v1alpha1
id: web-server-health
metadata:
  name: Web Server Health Check
  description: Validates Nginx web server port, process, and HTTP endpoint.
  version: "0.1.0"
  language: en
checks:
  - id: NGINX_PORT
    kind: resource
    metadata:
      name: HTTP port listener
      description: Verify TCP port 80 is listening
      severity: high
    resource:
      kind: port
      port: tcp:80
    expect:
      listening: true

  - id: NGINX_PROCESS
    kind: resource
    metadata:
      name: Nginx master process
      description: Verify nginx process is running
      severity: high
    resource:
      kind: process
      process: nginx
    expect:
      running: true

  - id: NGINX_HTTP
    kind: resource
    metadata:
      name: Local HTTP endpoint check
      description: Ensure endpoint returns HTTP 200
      severity: medium
    resource:
      kind: http
      url: http://127.0.0.1/
    expect:
      status: 200
```

### Run Validation

```bash
# Run validation (Human-friendly terminal presentation)
kmns-validate validate.yaml

# Machine-readable JSON output for CI/CD or AI agents
kmns-validate --format json validate.yaml

# Filter checks by tag or stage
kmns-validate --tag pre-install validate.yaml
```

---

## Supported Resource Checks

| Resource Kind | Check Scope |
| :--- | :--- |
| **`port`** | TCP/UDP port listener verification (`tcp:80`, `udp:53`). |
| **`process`** | Process status and execution check. |
| **`file`** | File/directory existence, permissions, ownership, and content matching. |
| **`http`** | HTTP/HTTPS status, headers, response body match, SSL certificate validation. |
| **`container`** | Docker & Podman container status, image, port bindings via Unix domain socket. |
| **`service`** | Systemd service `is-active` and `is-enabled` states. |
| **`package`** | System packages (`apt`, `dnf`, `pacman`, `apk`) status and version. |
| **`dns`** | DNS resolution and record verification (`A`, `AAAA`, `TXT`, `MX`). |
| **`addr`** | L4 network address reachability. |
| **`interface`** | Network interface MTU, state, and IP allocation. |
| **`mount`** | Filesystem mount point and mount option validation. |
| **`kernel`** | Sysctl parameter values and kernel module checks. |

---

## Security Model

`kmns-validate` follows a strict default-deny defensive posture:
- **No Unsafe Execution By Default**: Arbitrary shell commands (`command:`) or process executions (`exec:`) are rejected unless explicit CLI acknowledgement flags are provided (`--allow-unsafe-command`, `--allow-unsafe-exec`).
- **Root Acknowledgement Gate**: When executed as `root`, unsafe commands require a mandatory second flag (`--allow-root-execution`).
- **Secret Filtering**: MiniJinja template variables filter ambient environment variables to prevent accidental token or credential exposure in validation reports.

---

## Architecture & Licensing

`kmns-validate` is part of the KMNS ecosystem:

- **`kmns-validate`**: Licensed under the **[Apache License 2.0](LICENSE)**. Free for unlimited use, CI/CD, and personal/commercial deployments.

---

## Community & Support

- **Documentation**: [validate.kmns.io](https://validate.kmns.io)
- **Issues & Contributions**: [github.com/kmns-io/kmns-validate/issues](https://github.com/kmns-io/kmns-validate/issues)
- **Security Disclosures**: Please report security vulnerabilities to `security@kmns.io`.
