+++
title = "Ports & Sockets"
description = "Assert TCP and UDP listening ports and IP interface bindings with kmns-validate."
weight = 1
+++

# Ports & Sockets

Asserts TCP and UDP listening ports and IP interface bindings via direct kernel socket syscalls.

---

## Canonical Syntax (`kmns.io/validate/v1alpha1`)

### Local Port Listener (`kind: port`)

Inspects local host socket tables without executing external CLI tools like `netstat` or `ss`:

```yaml
# yaml-language-server: $schema=https://kmns.io/validate/v1alpha1
schema_version: kmns.io/validate/v1alpha1
id: network-ports-contract
metadata:
  name: "Network Listener Sockets"
  description: "Verify TCP/UDP ports are listening locally"
  severity: high
checks:
  - id: PORT_SSH
    kind: resource
    metadata:
      name: "SSH Daemon Listener"
      severity: high
    resource:
      kind: port
      port: tcp:22
    expect:
      listening: true

  - id: PORT_HTTPS
    kind: resource
    metadata:
      name: "HTTPS Public Listener"
      severity: high
    resource:
      kind: port
      port: tcp:443
    expect:
      listening: true
```

### Remote Address Reachability (`kind: addr`)

Tests remote network connectivity across hosts or edge proxies:

```yaml
  - id: ADDR_API_GATEWAY
    kind: resource
    metadata:
      name: "API Gateway HTTPS Reachability"
      severity: high
    resource:
      kind: addr
      address: tcp://192.0.2.1:443
      timeout: 3000
    expect:
      reachable: true
```

---

## Supported Attributes

### Local Port (`resource.kind: port`)

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `port` | string | **Yes** | Socket descriptor in `protocol:port` format (e.g. `tcp:80`, `udp:53`) |
| `listening` *(expect)* | boolean | No | Socket must be in LISTEN state (`true`) |
| `ip` *(expect)* | string / list | No | Specific bound IP address (e.g. `"127.0.0.1"`, `"0.0.0.0"`) |

### Remote Addr (`resource.kind: addr`)

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `address` | string | **Yes** | Target URI formatted as `protocol://host:port` (e.g. `tcp://192.0.2.1:80`) |
| `timeout` | integer | No | Connection timeout in milliseconds (default: 5000) |
| `reachable` *(expect)* | boolean | **Yes** | Target socket must complete TCP handshake (`true`) |
