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
  docker build -t lightbridge-authz:0.6.5 .
  ```
- Generate the TLS secrets manually (optional unless you prefer full control or the built-in job/tag fails):
  ```bash
  TMPDIR=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$TMPDIR/api.key" -out "$TMPDIR/api.crt" -subj "/CN=lightbridge-authz-api"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$TMPDIR/opa.key" -out "$TMPDIR/opa.crt" -subj "/CN=lightbridge-authz-opa"
  kubectl create secret generic lightbridge-lightbridge-api-tls ...
  kubectl create secret generic lightbridge-lightbridge-opa-tls ...
  ```

  The chart already bundles a pre-install hook job (`global.tls.job`) that can generate a secret containing these certs in-cluster. Manual TLS generation is only needed when you want a different certificate authority, need to target hosts outside the default service FQDNs, or if the job hook cannot run (e.g., permissions or webhook issues).

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
      port: 3000
      tls:
        cert_path: /etc/lightbridge/tls/opa.crt
        key_path: /etc/lightbridge/tls/opa.key
      basic_auth:
        username: authorino
        password: "${OPA_PASSWORD}"
  EOF
  kubectl create configmap lightbridge-lightbridge-api-config --from-file=config.yaml=/tmp/lightbridge-config.yaml --dry-run=client -o yaml | kubectl apply -f -
  kubectl create configmap lightbridge-lightbridge-opa-config --from-file=config.yaml=/tmp/lightbridge-config.yaml --dry-run=client -o yaml | kubectl apply -f -

Tips:
  - Keep `lightbridge-api.ingress.main.enabled=true` so external consumers can reach the CRUD API and the chart renders the matching rules for you.
  - Leave `lightbridge-opa.ingress.main.enabled=false`, because the OPA validation API is intended to be called internally (Authorino or other gateways) and should stay internal only.

Since the API and OPA workloads are never deployed together in this guide, we keep `server.api.port` and `server.opa.port` synced (3000) and mirror that value on the `lightbridge-opa.service.port` override. This keeps the TLS job, shared config, and the resulting `Service` objects consistent without worrying about different ports for each pod.

- Create the secrets the chart references, keeping the same connection string as the Postgres service names:
  ```bash
  kubectl create secret generic lightbridge-lightbridge-api-secrets \
    --from-literal=DATABASE_URL=postgres://postgres:postgres@lb-postgres-postgresql.default.svc.cluster.local:5432/lightbridge_authz \
    --from-literal=OPA_PASSWORD=change-me --dry-run=client -o yaml | kubectl apply -f -
  kubectl create secret generic lightbridge-lightbridge-opa-secrets ...
  ```

Each controller alias (`api` and `opa`) ends up with three supporting resources so secrets/config can be rotated independently:

1. `<release>-lightbridge-<alias>-config` is the ConfigMap rendered from `sharedConfig`/`global.config` and mounted as `/etc/lightbridge/config.yaml`.
2. `<release>-lightbridge-<alias>-secrets` keeps `DATABASE_URL` plus `OPA_PASSWORD` (mounted with `secretKeyRef` to avoid baking credentials into the ConfigMap).
3. `<release>-lightbridge-<alias>-tls` holds the TLS cert/key pair written by the umbrella hook job or supplied by cert-manager so each pod can mount `/etc/lightbridge/tls`.

Because those names are derived from the same `bjw-s/common` fullname helper, the Linux instructions above intentionally create the config map and the `-secrets` secret with matching release aliases (`lightbridge-lightbridge-api-*` and `lightbridge-lightbridge-opa-*`), while the TLS job produces `lightbridge-lightbridge-api-tls` and `lightbridge-lightbridge-opa-tls`.

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
    --set lightbridge-opa.ingress.main.enabled=false \
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

## Migration job

The umbrella also wires a `migration` dependency (`charts/lightbridge-migrate`, aliased as `migration`) that renders a pre-install/pre-upgrade job running `lightbridge-authz migrate --config-path /tmp/lightbridge-config/config.yaml`. That job reuses the same config map and handshake secrets that the API/OPA subcharts consume, so schema migrations always run before new controllers spin up. `migration.enabled`, `migration.backoffLimit`, `migration.ttlSecondsAfterFinished`, and the image knobs under `migration.image` let you tune retries or run a different build, while the `bjw-s/common v4` loader takes care of creating the supporting config map/secret/job resources with the familiar naming helpers.

Check `kubectl get jobs` or `kubectl logs` on the job whose name follows the migration subchart's fullname to confirm completion; if you ever disable the job (e.g., for manual migrations), rerun the migration binary yourself and re-enable the hook before the next upgrade so the database and API/OPA workloads stay in sync.

## TLS certificate generation paths

LightBridge Authz only exposes TLS-secured ports, so you need a certificate in Kubernetes for the service FQDNs (`lightbridge-lightbridge-api.default.svc.cluster.local` and `lightbridge-lightbridge-opa.default.svc.cluster.local`). Two production-style workflows have been exercised:

- **Manual job within the umbrella chart** – the chart already includes a pre-install hook job (`global.tls.job`) that runs in-cluster, generates OpenSSL certs, and writes a `lightbridge-authz-tls` secret with `api.*` and `opa.*` files. To target the service FQDNs, override the common names and keep the job enabled:
  ```yaml
  global:
    tls:
      enabled: true
      tlsSecretName: lightbridge-authz-tls
      apiCommonName: lightbridge-lightbridge-api.default.svc.cluster.local
      opaCommonName: lightbridge-lightbridge-opa.default.svc.cluster.local
      job:
        enabled: true
  ```
  Run `helm upgrade --install lightbridge charts/lightbridge ...` with that snippet merged into your values; the job will create the secret in the same namespace before the API/OPA pods start.

- **Cert-manager certificate** – install cert-manager (`kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml`), then provision a `Certificate` that writes to the same secret name and covers the service FQDNs. The chart can skip its job once cert-manager owns the secret:
  ```yaml
  global:
    tls:
      enabled: true
      tlsSecretName: lightbridge-authz-tls
      job:
        enabled: false
  ```
  Then apply an Issuer and Certificate such as:
  ```yaml
  apiVersion: cert-manager.io/v1
  kind: Issuer
  metadata:
    name: lightbridge-selfsigned
  spec:
    selfSigned: {}

  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: lightbridge-authz-tls
  spec:
    secretName: lightbridge-authz-tls
    issuerRef:
      name: lightbridge-selfsigned
      kind: Issuer
    commonName: lightbridge-lightbridge-api.default.svc.cluster.local
    dnsNames:
      - lightbridge-lightbridge-api.default.svc.cluster.local
      - lightbridge-lightbridge-opa.default.svc.cluster.local
    usages:
      - server auth
      - client auth
  ```
Once the cert-manager resource emits a TLS secret, the chart mounts it and pods get valid certificates for the internal FQDNs.

### Live cert-manager example
1. Install cert-manager from the official release, then create the `lightbridge-selfsigned` `Issuer` and the `lightbridge-authz-tls` `Certificate` that covers both `lightbridge-lightbridge-api` and `lightbridge-lightbridge-opa` service names (the `Secret` name must match what `global.tls.tlsSecretName` expects).
2. Run `helm upgrade lightbridge charts/lightbridge --reuse-values --set global.tls.job.enabled=false --wait` so the release relies on the cert-manager secret instead of the built-in job.
3. Launch an Ubuntu pod, install `curl`, and call the API health endpoint over the service FQDN:
   ```bash
   kubectl run curl-ubuntu --image=ubuntu:22.04 --restart=Never -- bash -lc 'apt-get update >/tmp/apt.log && apt-get install -y curl >/tmp/curl.log && curl -k -s -o /tmp/health.out -w "HTTP %{http_code}\n" https://lightbridge-lightbridge-api.default.svc.cluster.local:3000/health && cat /tmp/health.out'
   ```
   The pod prints `HTTP 200`, proving the cluster-internal TLS cert is trusted by clients that skip verification (`-k`) and the API endpoint is reachable. Delete the test pod after reading the logs.
