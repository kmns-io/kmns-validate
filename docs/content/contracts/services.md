+++
title = "Services (systemd)"
description = "Assert state and health of Linux systemd units via native D-Bus/sysfs inspection."
weight = 2
+++

# Services (systemd)

Asserts state and health of Linux `systemd` units via native D-Bus and systemd state inspection without spawning subprocess subshells.

---

## Canonical Syntax (`kmns.io/validate/v1alpha1`)

```yaml
# yaml-language-server: $schema=https://kmns.io/validate/v1alpha1
schema_version: kmns.io/validate/v1alpha1
id: systemd-services-contract
metadata:
  name: "Core System Services"
  description: "Verify essential systemd services are enabled and running"
  severity: high
checks:
  - id: SERVICE_HAPROXY
    kind: resource
    metadata:
      name: "HAProxy Ingress Service"
      severity: high
    resource:
      kind: service
      name: haproxy
    expect:
      enabled: true
      running: true

  - id: SERVICE_DOCKER
    kind: resource
    metadata:
      name: "Docker Engine Daemon"
      severity: high
    resource:
      kind: service
      name: docker
    expect:
      enabled: true
      running: true
```

---

## Supported Attributes

### Resource Parameters (`resource:`)

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `kind` | string | **Yes** | Must be `service` |
| `name` | string | **Yes** | The systemd unit name (e.g. `haproxy` or `docker.service`) |

### Expectations (`expect:`)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | boolean | `null` | Unit is enabled in systemd boot targets |
| `running` | boolean | `null` | Unit is currently active and running |
