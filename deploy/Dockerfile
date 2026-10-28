# SPDX-License-Identifier: Apache-2.0
# kmns-validate — Declarative Infrastructure Testing Engine
# Multi-stage zero-dependency distroless build

# Stage 1: Static certificate extraction
FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

# Stage 2: Minimalist, scratch-based runtime
FROM scratch AS runtime

# Import CA certificates for HTTPS/TLS probe execution
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy pre-compiled static musl release binary
# Defaults to target/x86_64-unknown-linux-musl/release/kmns-validate (or local release binary)
COPY target/x86_64-unknown-linux-musl/release/kmns-validate /usr/local/bin/kmns-validate

# Default runtime configuration and contract mount directory
WORKDIR /contracts

# Run unprivileged by default (overridable when host socket inspection requires root)
USER 65534:65534

ENTRYPOINT ["/usr/local/bin/kmns-validate"]
CMD ["--help"]

# Build arguments for dynamic metadata injection (zero hardcoded version drift)
ARG VERSION=0.4.0
ARG REVISION=""
ARG CREATED=""

# OCI Spec & Marketing-Aligned Metadata Labels
LABEL org.opencontainers.image.title="kmns-validate" \
      org.opencontainers.image.description="Sub-15ms declarative infrastructure testing engine for SecDD, TDD, and autonomous AI agents." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="kmns.io" \
      org.opencontainers.image.url="https://validate.kmns.io" \
      org.opencontainers.image.documentation="https://validate.kmns.io/cli/" \
      org.opencontainers.image.source="https://github.com/kmns-io/kmns-validate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.kmns.category="Infrastructure Verification & SecDD" \
      io.kmns.agentic.token-reduction="80-95%" \
      io.kmns.security.runtime-hijacking="zero-env-lookup"
