+++
title = "KMNS Validate: Sub-15ms Declarative Infrastructure Verification"
description = "Stop guessing infrastructure state. Sub-15ms zero-dependency declarative verification in pure Rust."
sort_by = "weight"
+++

<div class="hero-banner">
  <span class="hero-tag">
    Engineered for SREs &amp; Autonomous AI Agents
  </span>
  <h1 class="hero-title">
    Stop Guessing Infrastructure State.
  </h1>
  <p class="hero-subtitle">
    The sub-15ms, zero-dependency declarative verification engine in pure Rust. Cut agent context window burn by 85% with 100% static musl binaries and deterministic validation contracts.
  </p>

  <div class="feature-grid">
    <div class="feature-card">
      <div class="feature-val" style="color: #38bdf8;">⚡ &lt; 15ms</div>
      <div class="feature-desc">Native kernel &amp; socket syscalls</div>
    </div>
    <div class="feature-card">
      <div class="feature-val" style="color: #4ade80;">🔒 Static musl</div>
      <div class="feature-desc">Zero libc or dlopen dependencies</div>
    </div>
    <div class="feature-card">
      <div class="feature-val" style="color: #f472b6;">📉 85% Less Tokens</div>
      <div class="feature-desc">Stops noisy agent bash scraping</div>
    </div>
    <div class="feature-card">
      <div class="feature-val" style="color: #fbbf24;">🎯 Deterministic</div>
      <div class="feature-desc">Exact exit codes &amp; structured JSON</div>
    </div>
  </div>

  <div class="hero-actions">
    <a href="/quickstart/" class="btn-primary-doc">
      ⚡ Quickstart (60s)
    </a>
    <a href="/contracts/" class="btn-secondary-doc">
      Explore Contracts &amp; Schema
    </a>
  </div>
  <div class="hero-install-code">
    <code>
      {{ install_cmd() }}
    </code>
  </div>
</div>

---

## The Problem: Brittle Infrastructure Probes

Traditional infrastructure testing relies on brittle shell scripts, heavyweight Python runtimes (`Testinfra`), or unmaintained Go binaries (`Goss`):

- **Missing Host Dependencies**: Your probe script fails because `curl`, `netstat`, `python3`, or `openssl` are missing on minimalist server images.
- **RCE Attack Surface**: Ad-hoc bash verification scripts invite arbitrary command execution and lack sandbox containment.
- **Slow Pipeline Gates**: Waiting 30–90 seconds for heavy Ruby/Python runners to assert 5 listening ports kills developer feedback loops.
- **Flaky Exit Codes & Parsing**: Scraping text stdout in CI pipelines leads to silent false-positives and missed outages.

---

## The Solution: `kmns-validate`

`kmns-validate` delivers high-assurance, mathematical certainty of OS and container state:

| Feature | Legacy Shell / Goss | `kmns-validate` (Rust) |
| :--- | :--- | :--- |
| **Execution Time** | 200ms – 4,000ms | **< 15ms** (Sub-millisecond kernel socket inspection) |
| **Dependencies** | Requires `curl`, `python`, `netstat` | **Zero dynamic dependencies** (Static `musl` binary) |
| **Container Checks** | Spawns `docker ps` shell commands | **Direct UNIX socket protocol** (`/var/run/docker.sock`) |
| **Security Posture** | Raw shell execution (`command:`) | **Zero-CMD hardened** with AST capability bounding |
| **AI Agent Context Footprint** | 15,000–30,000 tokens (noisy stdout, blind loops) | **< 200 tokens** (clean, deterministic structured JSON) |
| **Output Formats** | Proprietary stdout text | **Structured JSON (`-f json`), Colorized CLI text** |
| **Memory Footprint** | 40MB – 120MB RSS | **< 6MB RSS** |

---

## Real-Time Terminal Demo

```bash
$ kmns-validate run /etc/kmns/validate.yaml
# Or validate an entire directory of contracts:
# $ kmns-validate run /etc/kmns/validate/

[PASS] port/tcp:22 (sshd listening on 0.0.0.0)
[PASS] port/tcp:443 (haproxy listening on 0.0.0.0, TLS 1.3 enabled)
[PASS] service/haproxy (systemd: active, running, enabled)
[PASS] container/docker-mailserver (Docker: healthy, uptime > 600s)
[PASS] file/etc/kmns/ssl/cert.pem (exists, mode: 0600, owner: root)
[PASS] http/https://127.0.0.1:443/healthz (status: 200 OK, latency: 1.2ms)

--- Summary ---
Tests: 6 total, 6 passed, 0 failed, 0 errors, 0 warnings
Validation ID: 233898850736254976
Execution Time: 0.009s (9.2ms)
```

---

## 3 Core Pillars of KMNS Validate

### 1. Declarative Contract As Code
Write simple, clean YAML contracts defining your expected system state. No procedural logic, no bash syntax errors:

```yaml
port:
  tcp:443:
    listening: true
    ip: ["0.0.0.0"]

service:
  haproxy:
    enabled: true
    running: true

container:
  ingress:
    state: "running"

file:
  /var/log/audit/audit.log:
    exists: true
    mode: "0600"
```

### 2. High-Assurance CI/CD Integration
Drop `kmns-validate` directly into GitLab CI, GitHub Actions, or pre-flight deployment stages:

```yaml
# .gitlab-ci.yml or GitHub Actions step
verify_deployment:
  stage: test
  script:
    - {{ install_cmd() }}
    - kmns-validate run ./contracts/web.yaml --format json > report.json
```

### 3. Edge-Native & Air-Gapped Ready
Single static binary (<12MB) compiles with all TLS root certs and syscall wrappers embedded. Perfect for air-gapped environments, hardened CoreOS instances, edge nodes, and scratch containers.

---

## Documentation Quick Links

Ready to explore? Dive into the full documentation:

- 🚀 **[Quickstart in 60 Seconds](/quickstart/)**: Install and run your first contract in under a minute.
- 📦 **[Installation Guide](/installation/)**: Multi-arch Linux binaries, macOS, and custom directories.
- 🐳 **[Docker & Containers](/docker/)**: Run via lightweight container without installing host binaries.
- ⚙️ **[CLI Reference](/cli/)**: Full flag documentation, formatters, and watchdog modes.
- 📜 **[Contract Schema](/contracts/)**: Syntax guide for ports, files, systemd, containers, HTTP, and kernel sysctls.
