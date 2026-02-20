# Platform-specific helm workflow

This document collects the concrete commands that worked when we tested the Helm chart locally. Each section is dedicated to a different platform so you can follow the exact steps that succeeded on a similar environment.

## macOS + Docker Desktop (install)

- Prerequisites: `docker Desktop` running the `docker-desktop` kubectl context, Helm v3 CLI, and `kubectl` configured to talk to that cluster.
- Install dependencies and build the runtime image before deploying:
  ```bash
  helm repo add bitnami https://charts.bitnami.com/bitnami
  helm repo update
  helm install lb-postgres bitnami/postgresql \
    --set auth.postgresPassword=postgres \
    --set auth.username=postgres \
    --set auth.database=lightbridge_authz \
    --set primary.persistence.enabled=false \
    --wait --timeout 5m
  docker build -t lightbridge-authz:0.5.0 .
  ```
- Generate the TLS secrets that the umbrella chart consumes (create the certs once and store them in Kubernetes):
  ```bash
  TMPDIR=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$TMPDIR/api.key" -out "$TMPDIR/api.crt" -subj "/CN=lightbridge-authz-api"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$TMPDIR/opa.key" -out "$TMPDIR/opa.crt" -subj "/CN=lightbridge-authz-opa"
  kubectl create secret generic lightbridge-lightbridge-api-tls ...
  kubectl create secret generic lightbridge-lightbridge-opa-tls ...
  ```

## Linux (configure)

- The chart expects a YAML config at `/etc/lightbridge/config.yaml` and a few secrets.
- Write the file so it matches `config/default.yaml`, including the `otel` block, environment interpolation, and the TLS/basic-auth paths:
  ```bash
  cat <<'EOF' >/tmp/lightbridge-config.yaml
  logging:
    level: info
  database:
    url: "${DATABASE_URL}"
    pool_size: 10
  oauth2:
    jwks_url: http://keycloak:9100/realms/dev/protocol/openid-connect/certs
  otel:
    enabled: true
    otlp_endpoint: http://localhost:4317
    service_name: lightbridge-authz
  server:
    api:
      address: 0.0.0.0
      port: 3000
      tls:
        cert_path: /etc/lightbridge/tls/api.crt
        key_path: /etc/lightbridge/tls/api.key
    opa:
      address: 0.0.0.0
      port: 3001
      tls:
        cert_path: /etc/lightbridge/tls/opa.crt
        key_path: /etc/lightbridge/tls/opa.key
      basic_auth:
        username: authorino
        password: "${OPA_PASSWORD}"
  EOF
  kubectl create configmap lightbridge-lightbridge-api-config --from-file=config.yaml=/tmp/lightbridge-config.yaml --dry-run=client -o yaml | kubectl apply -f -
  kubectl create configmap lightbridge-lightbridge-opa-config ...
  ```
- Create the secrets the chart references, keeping the same connection string as the Postgres service names:
  ```bash
  kubectl create secret generic lightbridge-lightbridge-api-secrets \
    --from-literal=DATABASE_URL=postgres://postgres:postgres@lb-postgres-postgresql.default.svc.cluster.local:5432/lightbridge_authz \
    --from-literal=OPA_PASSWORD=change-me --dry-run=client -o yaml | kubectl apply -f -
  kubectl create secret generic lightbridge-lightbridge-opa-secrets ...
  ```

## Windows/WSL (deploy)

- Run Helm with overrides for the shared config, ingresses, and the injected `CONFIG_PATH` env var so the CLI knows where to read `/etc/lightbridge/config.yaml`:
  ```bash
  helm install lightbridge charts/lightbridge \
    --set global.tls.job.enabled=false \
    --set sharedConfig.database.url=postgres://postgres:postgres@lb-postgres-postgresql.default.svc.cluster.local:5432/lightbridge_authz \
    --set global.config.database.url=postgres://postgres:postgres@lb-postgres-postgresql.default.svc.cluster.local:5432/lightbridge_authz \
    --set secrets.secrets.stringData.DATABASE_URL=postgres://postgres:postgres@lb-postgres-postgresql.default.svc.cluster.local:5432/lightbridge_authz \
    --set lightbridge-api.ingress.main.enabled=true \
    --set 'lightbridge-api.ingress.main.hosts[0].host'=api.local \
    --set 'lightbridge-api.ingress.main.hosts[0].paths[0].path'=/ \
    --set 'lightbridge-api.ingress.main.hosts[0].paths[0].service.name'=lightbridge-lightbridge-api \
    --set 'lightbridge-api.ingress.main.hosts[0].paths[0].service.port'=3000 \
    --set lightbridge-opa.ingress.main.enabled=true \
    --set 'lightbridge-opa.ingress.main.hosts[0].host'=opa.local \
    --set 'lightbridge-opa.ingress.main.hosts[0].paths[0].path'=/ \
    --set 'lightbridge-opa.ingress.main.hosts[0].paths[0].service.name'=lightbridge-lightbridge-opa \
    --set 'lightbridge-opa.ingress.main.hosts[0].paths[0].service.port'=3000 \
    --set lightbridge-api.ingress.annotations.enabled=false \
    --set lightbridge-opa.ingress.annotations.enabled=false \
    --set lightbridge-api.controllers.main.containers.main.env[0].name=CONFIG_PATH \
    --set lightbridge-api.controllers.main.containers.main.env[0].value=/etc/lightbridge/config.yaml \
    --set lightbridge-opa.controllers.main.containers.main.env[0].name=CONFIG_PATH \
    --set lightbridge-opa.controllers.main.containers.main.env[0].value=/etc/lightbridge/config.yaml \
    --wait --timeout 600s
  ```
- Monitor the workloads with `kubectl get pods` and `kubectl logs` to ensure both `lightbridge-lightbridge-api` and `lightbridge-lightbridge-opa` transition to `Running`. If TLS certs, secrets, or the config map change, delete the pods so new ones mount the updated assets.

With this file you have a repeatable recipe per platform: macOS for installing chart prerequisites, Linux for configuring the shared YAML/secrets, and Windows/WSL for deploying the Helm release that wires everything into `/etc/lightbridge` volumes.
