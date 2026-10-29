+++
title = "Container Usage (Docker)"
description = "Running kmns-validate via OCI container images in local development and CI pipelines."
weight = 3
+++

# Container Usage (Docker & OCI)

Official multi-architecture OCI container images are published on every release to both **Docker Hub** and **GitHub Container Registry (GHCR)**:

| Registry | Canonical Image Reference | Shorthand Alias |
| :--- | :--- | :--- |
| **Docker Hub** | `docker.io/kmnsio/kmns-validate:latest` | `docker.io/kmnsio/validate:latest` |
| **GitHub Packages (GHCR)** | `ghcr.io/kmns-io/kmns-validate:latest` | — |

---

## Quickstart

Validate contracts in the current working directory without installing host binaries:

```bash
# Via Docker Hub (short alias)
docker run --rm -v $(pwd):/contracts:ro kmnsio/validate:latest run /contracts/validate.yaml

# Via GitHub Packages (GHCR)
docker run --rm -v $(pwd):/contracts:ro ghcr.io/kmns-io/kmns-validate:latest run /contracts/validate.yaml
```

---

## Comprehensive Host Infrastructure Validation

Validate host UNIX sockets, Docker/Podman engines, and systemd services from within a container by mounting runtime sockets:

```bash
docker run --rm \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /run/systemd/system:/run/systemd/system:ro \
  -v $(pwd)/validate.yaml:/etc/kmns/validate.yaml:ro \
  kmnsio/validate:latest run /etc/kmns/validate.yaml
```

---

## Image Tags & Architectures

| Tag | Target Architecture | Base |
| :--- | :--- | :--- |
| `latest` | Multi-arch (`linux/amd64`, `linux/arm64`) | `scratch` static musl (< 15 MB) |
| `0.4.0` | Multi-arch (`linux/amd64`, `linux/arm64`) | `scratch` static musl (< 15 MB) |
