+++
title = "Contract Specifications"
description = "Declarative YAML contract schema and directives for kmns-validate."
sort_by = "weight"
+++

# Contract Specifications

`kmns-validate` parses deterministic declarative YAML contracts describing desired system state.

---

## Canonical Schema Format (`kmns.io/validate/v1alpha1`)

All contracts declare the typed schema version and unique identifier:

```yaml
# yaml-language-server: $schema={{ schema_url() }}
schema_version: kmns.io/validate/v1alpha1
id: infrastructure-core
metadata:
  name: "Core Infrastructure State"
  description: "Ensures critical sockets, services, and files are valid"
  version: "0.1.0"
  language: en
checks:
  - id: check-unique-identifier
    kind: resource
    metadata:
      name: "Check Descriptive Title"
      severity: high
      tags: ["production", "pre-install"]
    resource:
      kind: port | service | file | container | http | addr | dns | process
      # Resource-specific parameters
    expect:
      # Desired state assertions
```

---

## IDE & Tooling Schema Integration

Add the schema header to the first line of any contract to enable real-time autocompletion, field validation, and hover tooltips in VS Code, Cursor, JetBrains, or Neovim:

```yaml
# yaml-language-server: $schema={{ schema_url() }}
```

- **Canonical Schema ID**: `https://kmns.io/validate/v1alpha1`
- **Active Schema Reference**: `{{ schema_url() }}`

---

## Resource Reference Guides

- **[Services (systemd)](/contracts/services/)**: `kind: service` — Running, enabled states via native systemd D-Bus.
- **[Ports & Sockets](/contracts/ports/)**: `kind: port` and `kind: addr` — Local socket listeners and remote network reachability.
- **[Files & Permissions](/contracts/files/)**: `kind: file` — File existence, mode octal permissions, ownership.
- **[Containers (Docker/OCI)](/contracts/containers/)**: `kind: container` — Running state, image tags via UNIX socket.
- **[HTTP Probes](/contracts/http/)**: `kind: http` — Liveness, health endpoints, response body and headers.
