+++
title = "Files & Permissions"
description = "Assert presence, permissions, mode, and ownership of files and directories with kmns-validate."
weight = 4
+++

# Files & Permissions

Asserts presence, permissions, mode, ownership, and contents of files and directories using direct stat syscalls.

---

## Canonical Syntax (`kmns.io/validate/v1alpha1`)

```yaml
# yaml-language-server: $schema=https://kmns.io/validate/v1alpha1
schema_version: kmns.io/validate/v1alpha1
id: filesystem-integrity-contract
metadata:
  name: "Critical Configuration Files"
  description: "Assert ownership and permissions on security files"
  severity: high
checks:
  - id: FILE_HOSTS
    kind: resource
    metadata:
      name: "Hosts Resolution File"
      severity: medium
    resource:
      kind: file
      path: /etc/hosts
    expect:
      exists: true
      mode: "0644"
      owner: "root"

  - id: FILE_SECRET_ENV
    kind: resource
    metadata:
      name: "Encrypted SOPS Secrets"
      severity: critical
    resource:
      kind: file
      path: /etc/kmns/secrets.sops.env
    expect:
      exists: true
      mode: "0600"
      filetype: file
```

---

## Supported Attributes

### Resource Parameters (`resource:`)

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `kind` | string | **Yes** | Must be `file` |
| `path` | string | **Yes** | Absolute filesystem path |

### Expectations (`expect:`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `exists` | boolean | Path exists in filesystem (`true` or `false`) |
| `mode` | string | Expected octal permissions mode (e.g. `"0644"`, `"0600"`) |
| `owner` | string | Expected owner username or UID |
| `group` | string | Expected group name or GID |
| `filetype` | string | Expected file type (`file`, `directory`, `symlink`) |
| `contents` | list of string | Substrings that must be present in file contents |
