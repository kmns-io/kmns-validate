+++
title = "HTTP Probes"
description = "Assert HTTP/HTTPS status, latency, response body, and headers with native TLS 1.3."
weight = 5
+++

# HTTP Probes

Validates live HTTP and HTTPS endpoints directly using native kernel sockets and embedded TLS 1.3 without relying on `curl` or external binaries.

---

## Canonical Specification (`v1alpha1`)

```yaml
schema_version: kmns.io/validate/v1alpha1
id: ingress-http-gate
metadata:
  name: Web Ingress HTTP Health
  description: Asserts health endpoint status, TLS headers, and body

checks:
  - kind: resource
    id: web-health-check
    metadata:
      name: Web Healthz Endpoint
      tags: ["production", "edge"]
    resource:
      kind: http
      url: "https://127.0.0.1:443/healthz"
      timeout_ms: 3000
    expect:
      status: 200
      body_contains: "ok"

  - kind: resource
    id: api-version-check
    metadata:
      name: API Version Manifest
      tags: ["production"]
    resource:
      kind: http
      url: "https://127.0.0.1:443/api/v1/version.json"
      request_headers:
        - "Accept: application/json"
    expect:
      status: 200
      headers:
        Content-Type: "application/json"
```

---

## Supported Attributes

| Attribute | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | string | **Required** | Target HTTP or HTTPS URL to probe |
| `method` | string | `GET` | HTTP request method (`GET`, `POST`, `HEAD`) |
| `timeout_ms` | integer | `5000` | Request timeout in milliseconds |
| `allow_insecure` | boolean | `false` | Skip TLS certificate validation (dev testing only) |
| `no_follow_redirects` | boolean | `false` | Do not follow HTTP 3xx redirects |
| `request_headers` | list of strings | `[]` | Additional request headers (`Header-Name: value`) |
| `status` | integer | `200` | Expected HTTP response status code |
| `body_contains` | string | - | Substring required in response body |
| `headers` | map of strings | `{}` | Required response headers |
