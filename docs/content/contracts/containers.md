+++
title = "Containers (Docker / Podman)"
description = "Assert container runtime state directly via UNIX socket without spawning subprocess shells."
weight = 3
+++

# Containers (Docker / Podman)

Asserts container runtime state directly via the `/var/run/docker.sock` UNIX socket protocol or Podman REST API without spawning external subprocess shells.

---

## Canonical Specification (`v1alpha1`)

```yaml
schema_version: kmns.io/validate/v1alpha1
id: container-runtime-gate
metadata:
  name: Container Runtime Verification
  description: Validates active containers and health states

checks:
  - kind: resource
    id: web-container-active
    metadata:
      name: KMNS Web Nginx Gateway
      tags: ["production", "edge"]
    resource:
      kind: container
      name: kmns-web
    expect:
      running: true

  - kind: resource
    id: mail-container-active
    metadata:
      name: Docker Mailserver Stack
      tags: ["production", "mail"]
    resource:
      kind: container
      name: docker-mailserver
    expect:
      running: true
```

---

## Supported Attributes

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `name` | string | Target container name or ID |
| `running` | boolean | Expected running status (`true` / `false`) |
| `tags` | list of strings | Lifecycle filter tags (e.g. `["production"]`) |
