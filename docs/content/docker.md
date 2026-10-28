+++
title = "Container Usage (Docker)"
description = "Running kmns-validate via OCI container images in local development and CI pipelines."
weight = 3
+++

# Container Usage (Docker)

OCI container images are published on release to GitHub Container Registry (`ghcr.io/kmns-io/kmns-validate`) and mirrored to Docker Hub.

---

## Running in Container

Validate host sockets and services from within a container by mounting runtime sockets:

```bash
docker run --rm \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /run/systemd/system:/run/systemd/system:ro \
  -v $(pwd)/validate.yaml:/etc/kmns/validate.yaml:ro \
  ghcr.io/kmns-io/kmns-validate:latest run /etc/kmns/validate.yaml
```

---

## Image Tags

| Tag | Target Architecture | Base |
| :--- | :--- | :--- |
| `latest` | Multi-arch (`amd64`, `arm64`) | `scratch` static musl (< 15 MB) |
| `v0.4.0` | Multi-arch (`amd64`, `arm64`) | `scratch` static musl (< 15 MB) |
| `alpine` | Multi-arch (`amd64`, `arm64`) | Alpine minimal runtime |
