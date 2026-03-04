# Multi-stage build for optimized production image
FROM rust:1-alpine as builder

ARG TARGETARCH

RUN --mount=type=cache,target=/var/cache/apk \
    apk add \
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

# Expose port
EXPOSE 3000

# Health check (API server)
HEALTHCHECK --interval=30s --timeout=3s --start-period=1s --retries=3 \
    CMD ["/usr/local/bin/lightbridge-authz-healthcheck", "-r", "3000"]

# Set environment variables
ENV RUST_LOG=info

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

ENTRYPOINT ["lightbridge-mcp"]
CMD ["serve"]
