+++
title = "Installation"
description = "Install kmns-validate on Linux, macOS, or in CI/CD pipelines."
weight = 2
+++

# Installation

`kmns-validate` is distributed as a statically linked binary without external dependencies.

---

## Method 1: Canonical Installer (Recommended)

Run the universal installer via `curl`:

```bash
# Default: installs system-wide to /usr/local/bin if root/sudo, else ~/.local/bin
{{ install_cmd() }}

# Force global system-wide installation (available for all users)
{{ install_cmd() }} -s -- --global

# Force user-local installation without sudo (~/.local/bin)
{{ install_cmd() }} -s -- --local
```

The script automatically detects privileges:
1. **Root / Passwordless Sudo**: Installs system-wide to `/usr/local/bin` (immediately available in `$PATH` for all users).
2. **Unprivileged User**: Gracefully falls back to `~/.local/bin` (or `~/bin`) without requiring root access.

---

## Method 2: Manual Download & Architecture Matrix

Prebuilt release tarballs are distributed for the following target architectures:

| Target Platform | Architecture Triple | Binary Type |
| :--- | :--- | :--- |
| **Linux x86_64** | `x86_64-unknown-linux-musl` | Static musl (Zero dependency) |
| **Linux x86_64** | `x86_64-unknown-linux-gnu` | Dynamic glibc |
| **Linux ARM64** | `aarch64-unknown-linux-musl` | Static musl (Zero dependency) |
| **Linux ARM64** | `aarch64-unknown-linux-gnu` | Dynamic glibc (Raspberry Pi, AWS Graviton, etc.) |
| **macOS Apple Silicon** | `aarch64-apple-darwin` | Native Mach-O universal binary |
