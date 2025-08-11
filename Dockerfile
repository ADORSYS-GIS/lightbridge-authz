# Multi-stage build for optimized production image
FROM rust:1 as builder

# Install system dependencies
RUN apt update && apt install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY diesel.toml diesel.toml ./
COPY crates/ ./crates/
COPY migrations/ ./migrations/

# Build dependencies (this is cached if dependencies don't change)
RUN cargo build --profile prod --locked

FROM debian:12 as dep

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt update \
  && apt install -y libpq5 ca-certificates libssl3 --no-install-recommends

# Dependencies for libpq (used by diesel)
RUN \
  --mount=type=cache,target=/usr/lib/*-linux-gnu \
  mkdir /deps && \
  cp /usr/lib/*-linux-gnu/*.so* /deps

# Runtime stage
FROM gcr.io/distroless/base-debian12:nonroot

LABEL maintainer="stephane-segning <selastlambou@gmail.com>"
LABEL org.opencontainers.image.description="Backend for Adorsys's LightBridge Authz"

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/prod/lightbridge-authz /usr/local/bin/lightbridge-authz
COPY --from=builder /app/target/prod/lightbridge-authz-healthcheck /usr/local/bin/lightbridge-authz-healthcheck
COPY --from=dep /deps /usr/lib/

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD (/usr/local/bin/lightbridge-authz-healthcheck -p 3000 && /usr/local/bin/lightbridge-authz-healthcheck -p 3001) || exit 1

# Set environment variables
ENV RUST_LOG=info

# Run the binary
ENTRYPOINT ["lightbridge-authz"]
