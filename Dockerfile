# Multi-stage build for optimized production image

# ─────────────────────────────────────────────────────────────────────────────────────────────
# THE AUTHZ-UI PIN — this ARG is the ONLY place the hosted-login bundle's version is written
# down in this repository. `.github/actions/stage-authz-ui` greps this exact line out of this
# exact file so that the Dockerfile.dist/CI path and this Dockerfile can never disagree about
# which bundle ships. If you move or rename this ARG, fix that action in the same commit.
#
# ADR-0021 Decisions 1 + 10, as amended by ADR-0028: the hosted login page's source home is
# `converse-frontends`' `apps/authz-ui` (ADORSYS-GIS/converse-frontends#408), NOT this repo. This
# repo builds no JavaScript. The bundle arrives as an assets-only `FROM scratch` OCI image whose
# entire contents are the Vite build output at `/dist`.
#
# PINNED BY DIGEST, NEVER BY TAG. A tag is mutable; a digest is the artifact. The tag below is a
# comment for humans reading the diff — it is NOT what gets resolved.
#
# HOW TO BUMP (this is the deploy — see ADR-0028's version-skew rule):
#   1. Merge the UI change in converse-frontends; let `authz-ui-image.yml` publish.
#   2. Read the run's job summary for the `pinned reference` row, or:
#        skopeo inspect docker://ghcr.io/adorsys-gis/converse-frontends/authz-ui:sha-<gitsha> \
#          --format '{{.Digest}}'
#   3. Update BOTH lines below (the comment tag and the digest) in one commit.
#   4. `just all-checks` + let CI's `it-idp` suite prove `/ui/` still serves the SPA.
# Nothing else in this repo changes. There is no second place to edit.
#
# DEPENDENCY AUTOMATION MUST NOT TOUCH THIS. `.github/dependabot.yml`'s `docker` ecosystem is
# explicitly configured to ignore this image (see the `ignore:` block there). An automated digest
# bump would be an unreviewed UI deploy to the authentication boundary, arriving as a "chore".
#
#   tag: ghcr.io/adorsys-gis/converse-frontends/authz-ui:sha-f5376de
ARG AUTHZ_UI_REF=ghcr.io/adorsys-gis/converse-frontends/authz-ui@sha256:08a77826dfd6999d06e7dc18f1f6e10573db22fdda75b9aa7039d5a97c7315a2

# `--platform=linux/amd64` because the published image is single-arch amd64 and this stage holds
# nothing executable — it is a tarball of HTML/JS/CSS. Forcing the platform here keeps an arm64
# host (a developer's Mac running `just up`) from failing to resolve a manifest for its own arch
# while the `builder` stage below still cross-builds correctly via TARGETARCH.
FROM --platform=linux/amd64 ${AUTHZ_UI_REF} AS frontend

FROM rust:1-alpine as builder

ARG TARGETARCH

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
    musl-dev \
    build-base \
    pkgconfig \
    perl \
    openssl-dev \
    openssl-libs-static \
    postgresql-dev \
    git \
    protobuf-dev \
    zlib-static \
    clang-dev \
    llvm-dev \
    ca-certificates \
    cmake

# Create app directory
WORKDIR /app


RUN \
  # Mount workspace files and only the necessary crates
  --mount=type=bind,source=./Cargo.toml,target=/app/Cargo.toml \
  --mount=type=bind,source=./Cargo.lock,target=/app/Cargo.lock \
  --mount=type=bind,source=./app/,target=/app/app \
  --mount=type=bind,source=./crates/,target=/app/crates \
  --mount=type=bind,source=./migrations/,target=/app/migrations \
  --mount=type=bind,source=./migrations-usage/,target=/app/migrations-usage \
  --mount=type=cache,target=/app/target \
  --mount=type=cache,target=/usr/local/cargo/registry/cache \
  --mount=type=cache,target=/usr/local/cargo/registry/index \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  case "$TARGETARCH" in \
    "amd64") \
      export RUST_TARGET=x86_64-unknown-linux-musl; \
      ;; \
    "arm64") \
      export RUST_TARGET=aarch64-unknown-linux-musl; \
      ;; \
    *) \
      echo "Unsupported TARGETARCH: $TARGETARCH"; \
      exit 1; \
      ;; \
  esac; \
  cargo build --profile prod --locked --target "${RUST_TARGET}" \
  && ls -lash ./target/"${RUST_TARGET}"/prod \
  && cp ./target/"${RUST_TARGET}"/prod/lightbridge-authz-healthcheck lightbridge-authz-healthcheck \
  && cp ./target/"${RUST_TARGET}"/prod/lightbridge-authz lightbridge-authz \
  && cp ./target/"${RUST_TARGET}"/prod/lightbridge-mcp lightbridge-mcp \
  && cp ./target/"${RUST_TARGET}"/prod/lightbridge-authz-usage lightbridge-authz-usage

# Runtime stage
FROM gcr.io/distroless/base-debian12:nonroot as runtime

LABEL maintainer="stephane-segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="Backend for LightBridge Authz"

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/lightbridge-authz /usr/local/bin/lightbridge-authz
COPY --from=builder /app/lightbridge-authz-healthcheck /usr/local/bin/lightbridge-authz-healthcheck

# Hosted login page static build (ADR-0021 Decisions 1 + 10, amended by ADR-0028) -- authz-idp
# serves this from `server.idp.static_dir` (.docker/authz/container.yaml defaults to this path).
# Harmless on api/opa/budget, which never mount the static fallback at all.
#
# `/dist` is converse-frontends' published contract for this image, not a path this repo chose;
# see the AUTHZ_UI_REF block at the top of this file and apps/authz-ui/Containerfile there.
COPY --from=frontend /dist /app/static

# Expose port
EXPOSE 3000

# Health check (API server)
HEALTHCHECK --interval=30s --timeout=3s --start-period=1s --retries=3 \
    CMD ["/usr/local/bin/lightbridge-authz-healthcheck", "-r", "3000"]

# Set environment variables
ENV RUST_LOG=info

USER 65532:65532

# Run the binary
ENTRYPOINT ["lightbridge-authz"]

FROM gcr.io/distroless/base-debian12:nonroot as usage-runtime

LABEL maintainer="stephane-segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="Backend for LightBridge Authz Usage"

WORKDIR /app

COPY --from=builder /app/lightbridge-authz-usage /usr/local/bin/lightbridge-authz-usage
COPY --from=builder /app/lightbridge-authz-healthcheck /usr/local/bin/lightbridge-authz-healthcheck

EXPOSE 3002

ENV RUST_LOG=info

USER 65532:65532

ENTRYPOINT ["lightbridge-authz-usage"]
CMD ["serve"]

FROM gcr.io/distroless/base-debian12:nonroot as mcp-runtime

LABEL maintainer="stephane-segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="Backend for LightBridge Authz MCP"

WORKDIR /app

COPY --from=builder /app/lightbridge-mcp /usr/local/bin/lightbridge-mcp
COPY --from=builder /app/lightbridge-authz-healthcheck /usr/local/bin/lightbridge-authz-healthcheck

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=1s --retries=3 \
    CMD ["/usr/local/bin/lightbridge-authz-healthcheck", "-r", "3000"]

ENV RUST_LOG=info

USER 65532:65532

ENTRYPOINT ["lightbridge-mcp"]
CMD ["serve"]
