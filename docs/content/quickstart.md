+++
title = "Quickstart (60 Seconds)"
description = "Get up and running with kmns-validate in under a minute."
weight = 1
+++

# Quickstart (60 Seconds)

Get up and running with `kmns-validate` in under a minute.

## 1. Install

```bash
# Official one-line installer
{{ install_cmd() }}
```

Alternatively, download the prebuilt binary from GitHub Releases or run via Docker.

---

## 2. Define a Contract (`validate.yaml`)

Create a declarative verification file:

```yaml
schema_version: kmns.io/validate/v1alpha1
id: quickstart-host-gate
metadata:
  name: Base Host Health
  description: Validates SSH, Ingress, and host resolution

checks:
  - kind: resource
    id: ssh-port
    metadata:
      name: SSH daemon listening
      tags: ["production", "pre-install"]
    resource:
      kind: port
      protocol: tcp
      address: "0.0.0.0:22"
    expect:
      listening: true

  - kind: resource
    id: haproxy-service
    metadata:
      name: HAProxy Ingress Service
      tags: ["production"]
    resource:
      kind: service
      name: haproxy
    expect:
      running: true
      state: active

  - kind: resource
    id: hosts-file
    metadata:
      name: Local DNS Hosts
    resource:
      kind: file
      path: /etc/hosts
    expect:
      exists: true
```

---

## 3. Run Verification

```bash
# Validate a single contract
kmns-validate run /etc/kmns/validate.yaml

# Filter by lifecycle tags (e.g. pre-install or production)
kmns-validate run /etc/kmns/validate.yaml -t production

# Or validate an entire directory with verbose diagnostics
kmns-validate run /etc/kmns/validate/ -v
```

Output:
```txt
[PASS] port/tcp:22 [SSH daemon listening]
       = sshd listening on 0.0.0.0:22
[PASS] service/haproxy [HAProxy Ingress Service]
       = haproxy active running enabled
[PASS] file//etc/hosts [Local DNS Hosts]
       = /etc/hosts exists (mode: 0644, user: root)

--- Summary ---
Tests: 3 total, 3 passed, 0 failed, 0 skipped, 0 errors, 0 warnings
VldId: 233898850736254976
Total time: 0.007s
```
