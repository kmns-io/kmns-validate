+++
title = "CLI Reference"
description = "Command-line flags, tagging, output formats, and exit codes for kmns-validate."
weight = 4
+++

# CLI Reference

`kmns-validate` (and its canonical alias `validate`) provides an ultra-fast, zero-dependency command-line interface engineered for both interactive operator use and autonomous AI agents.

---

## Command Syntax

```bash
kmns-validate [COMMAND] [OPTIONS] [CONTRACTS]...
```

### Primary Subcommands

| Command | Description |
| :--- | :--- |
| `run [CONTRACT...]` | Execute declarative validation contracts against the system (default). |
| `check [CONTRACT...]` | Verify contract syntax and schema conformity without executing live network probes. |
| `version` | Display installed version, build metadata, and upgrade notices. |
| `help` | Print help information for the binary or subcommands. |

---

## Global Options & Flags

```txt
Options:
  -v, --verbose
          Enable verbose execution output. Displays runtime working directory,
          loaded config paths, and detailed per-file test breakdown summaries.

  -f, --format <FORMAT>
          Output format: text, json [default: text].
          - text: Human-readable terminal output with test labels and observations.
          - json: Machine-readable JSON object for CI/CD and AI agent ingestion.

  -t, --tag <TAG>
          Filter checks by lifecycle stage/tag (e.g. 'pre-install', 'production').
          Can be specified multiple times or as comma-separated values.

  -c, --config <CONFIG_PATH>
          Explicit path to configuration file [env: VALIDATE_CONFIG_PATH].

      --contract <PATH>
          Explicit contract path or directory to validate (repeatable; alternative to positional args).

      --parallel
          Enable concurrent asynchronous execution for network check resources.

      --max-threads <N>
          Maximum concurrent probe threads per validator type (0 = num_cpus).

      --allow-unsafe-command
          Acknowledge that contract command checks may execute shell code.

      --allow-unsafe-exec
          Acknowledge that contract exec checks may execute local binaries.

      --allow-root-execution
          Acknowledge unsafe command or exec execution by an already-root process.

  -h, --help
          Print help documentation.
```

---

## Lifecycle Stage Tagging (`-t, --tag`)

`kmns-validate` features first-class tag filtering, allowing you to maintain a single unified contract while executing targeted checks based on deployment phase.

### Declaring Tags in Contracts

Tags are declared inside each check's `metadata.tags` list:

```yaml
schema_version: kmns.io/validate/v1alpha1
id: web-gateway-contract
metadata:
  name: Web Gateway Deployment Gate
  description: Validates ingress ports, systemd units, and synthetic HTTP probes

checks:
  # Pre-installation check: runs before software deployment
  - kind: resource
    id: pre-check-port-clean
    metadata:
      name: Ingress port unallocated
      tags: ["pre-install"]
    resource:
      kind: port
      protocol: tcp
      address: "0.0.0.0:443"
    expect:
      listening: false

  # Post-installation check: runs in production
  - kind: resource
    id: prod-haproxy-running
    metadata:
      name: HAProxy Ingress Service Active
      tags: ["production", "edge"]
    resource:
      kind: service
      name: haproxy
    expect:
      running: true
      state: active
```

### Running Targeted Tags

```bash
# Run only pre-installation checks before touching the node
kmns-validate run /etc/kmns/validate/ -t pre-install

# Run production and edge checks post-deployment
kmns-validate run /etc/kmns/validate/ -t production,edge
```

---

## Output Formats & Verbosity

### 1. Human-Readable Text (`--format text`)

Default terminal format. Outputs colorized status badges, optional human labels (`metadata.name`), empirical observations (`= ...`), and failures:

```txt
[PASS] port/tcp:22 [SSH Daemon Socket]
       = sshd listening on 0.0.0.0:22
[PASS] port/tcp:443 [HTTPS Ingress Socket]
       = haproxy listening on 0.0.0.0:443
[PASS] service/haproxy [HAProxy Service]
       = haproxy active running enabled
[PASS] file//etc/hosts [Local Resolution]
       = /etc/hosts exists (mode: 0644, user: root)

--- Summary ---
Tests: 4 total, 4 passed, 0 failed, 0 skipped, 0 errors, 0 warnings
VldId: 233898850736254976
Total time: 0.009s
```

### 2. Verbose Terminal Mode (`-v, --verbose`)

Adding `-v` or `--verbose` prints internal configuration diagnostics and per-file test breakdown summaries:

```bash
kmns-validate validate /etc/kmns/validate/ -v
```

```txt
[INFO] Config path: "/etc/kmns/validate.conf"
[INFO] Working directory: "/etc/kmns"
[PASS] port/tcp:443 [HTTPS Ingress]
[PASS] service/haproxy [HAProxy Service]

--- Summary ---
File: /etc/kmns/validate/web.yaml [valid=true, pass=2, fail=0, skip=0, error=0, warn=0]
Tests: 2 total, 2 passed, 0 failed, 0 skipped, 0 errors, 0 warnings
VldId: 233898850736254976
Total time: 0.008s
```

### 3. Machine-Readable JSON (`--format json`)

Engineered for GitLab CI, Ansible automation, and LLM AI agent context windows:

```bash
kmns-validate validate /etc/kmns/validate.yaml --format json
```

```json
{
  "summary": {
    "total": 2,
    "pass": 2,
    "fail": 0,
    "skip": 0,
    "error": 0,
    "warn": 0
  },
  "tests": [
    {
      "name": "tcp:443",
      "resource_type": "port",
      "title": "HTTPS Ingress",
      "status": "Pass",
      "observation": "haproxy listening on 0.0.0.0:443",
      "failures": []
    },
    {
      "name": "haproxy",
      "resource_type": "service",
      "title": "HAProxy Service",
      "status": "Pass",
      "observation": "haproxy active running enabled",
      "failures": []
    }
  ],
  "vldid": 233898850736254976,
  "duration_secs": 0.008
}
```

---

## Exit Codes

`kmns-validate` provides deterministic exit codes for CI/CD gates:

| Exit Code | Meaning | Action in CI/CD |
| :--- | :--- | :--- |
| `0` | **Success**: All contract assertions passed. | Proceed to next deployment stage. |
| `1` | **Assertion Failure**: One or more expectations failed. | Halt pipeline; trigger automated rollback. |
| `2` | **Syntax or I/O Error**: Invalid contract YAML or file unreadable. | Check YAML schema and file paths. |
