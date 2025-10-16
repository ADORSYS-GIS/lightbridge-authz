# AI Gateway with External Authorization - Integration Guide

# Overview

This document outlines the complete process of deploying an [AI gateway stack](https://gateway.envoyproxy.io/docs/) with external authorization using a Rust-based [self-service authentication system](https://github.com/ADORSYS-GIS/lightbridge-authz).
Prerequisites

    Ubuntu 20.04+ or similar Linux distribution

    Minimum 2 CPU cores, 4GB RAM, 20GB disk space

    sudo privileges

# Step 1: Install [k3s](https://k3s.io/) Kubernetes Cluster

[Quick k3s Installation](https://k3s.io/)
```bash
# Download and install k3s
curl -sfL https://get.k3s.io | sh -
``
## Verify installation: this may fail with connect: connection refused
```bash
sudo kubectl get nodes
sudo kubectl get pods --all-namespaces
```
This should fail with 
`text
# sudo kubectl get nodes
E1016 10:58:29.705017  605007 memcache.go:265] "Unhandled Error" err="couldn't get current server API group list: Get \"http://localhost:8080/api?timeout=32s\": dial tcp 127.0.0.1:8080: connect: connection refused"

#sudo kubectl get pods --all-namespaces
E1016 10:57:06.955436  602883 memcache.go:265] "Unhandled Error" err="couldn't get current server API group list: Get \"http://localhost:8080/api?timeout=32s\": dial tcp 127.0.0.1:8080: connect: connection refused"
`
## Configure kubectl access
```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
export KUBECONFIG=~/.kube/config
```
## Test access
```bash
kubectl get nodes
```
You should get something similar to this
`text
NAME        STATUS   ROLES                  AGE     VERSION
derick-ws   Ready    control-plane,master   3m29s   v1.33.5+k3s1
`
# Step 2: Deploy the Self-Service Application

## Create Namespace
```bash
kubectl create namespace envoy-gateway-system
```
Deploy the Database from [postgres.yaml](../deployment/postgres.yaml)
```bash
# Apply the deployment
kubectl apply -f deployment/postgres.yaml
```
Deploy [Keycloak](https://k3s.io/) from [keycloak.yaml](../deployment/keycloak.yaml) for JWT Token Management
```bash
# Deploy Keycloak for JWT token generation and validation
kubectl apply -f deployment/keycloak.yaml

# Wait for Keycloak to be ready
kubectl wait --for=condition=ready pod -l app=keycloak -n envoy-gateway-system --timeout=180s

# Port forward to access Keycloak (optional, for administration)
kubectl port-forward -n envoy-gateway-system service/keycloak 8080:8080 &
```
Deploy Rust [Self-Service Application](https://github.com/ADORSYS-GIS/lightbridge-authz) from [self-service-deployment.yaml](../deployment/self-service-deployment.yaml)
```bash

# Apply the deployment
kubectl apply -f deployment/self-service-deployment.yaml

# Verify deployment
kubectl get pods -n envoy-gateway-system
kubectl get svc -n envoy-gateway-system
```
# Step 3: [Install Envoy AI Stack](https://aigateway.envoyproxy.io/docs/getting-started/)

## Install Envoy Gateway from [gateway.yaml](../deployment/gateway.yaml)
```bash

# Install Envoy Gateway CRDs and components
kubectl apply --server-side -f https://github.com/envoyproxy/gateway/releases/download/v1.5.3/install.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=gateway-helm -n envoy-gateway-system --timeout=300s
```
Alternatively, you can install the Envoy gateway CRDs from this [terraform module](https://github.com/ADORSYS-GIS/ai-ops-terraform/tree/main/modules/tf-aigateway)

## Verify Envoy Gateway Installation
```bash
kubectl get pods -n envoy-gateway-system
```
# Step 4: Configure Gateway and HTTPRoute
## Create [Gateway](https://kubernetes.io/docs/concepts/services-networking/gateway/) Resource

[gateway.yaml](../deployment/gateway.yaml)
```bash
kubectl apply -f deployment/gateway.yaml

# Verify gateway installation
kubectl get gateways -n envoy-gateway-system
```
## Create Sample Backend Application
[ai-backend](../deployment/ai-backend.yaml)
```bash
kubectl apply -f deployment/ai-backend.yaml
```
## Create [HTTPRoute](https://gateway-api.sigs.k8s.io/guides/http-routing/) from [http-route.yaml](../deployment/http-route.yaml)
```bash
kubectl apply -f deployment/http-route.yaml
```
# Step 5: Configure External Authorization

## Create [ReferenceGrant](https://gateway-api.sigs.k8s.io/api-types/referencegrant/) for Cross-Namespace Access from [reference-grant.yaml](../deployment/reference-grant.yaml)
```bash
# Apply ReferenceGrant to allow SecurityPolicy to reference services across namespaces
kubectl apply -f deployment/reference-grant.yaml
```
## create an authorisation adapter from [auth-adapter.yaml](../deployment/auth-adapter.yaml)
```bash
kubectl apply -f deployment/auth-adapter.yaml
```
## Create [SecurityPolicy](https://www.varonis.com/blog/what-is-a-security-policy) for External Auth

[ext-authz-policy.yaml](../deployment/ext-authz-policy.yaml)
```bash
kubectl apply -f deployment/ext-authz-policy.yaml

# Verify SecurityPolicy is accepted
kubectl get securitypolicy -A
```
# Step 6: Testing and Validation
## Get Gateway External IP
```bash
# Check the data plane gateway service for NodePort
kubectl get svc -n envoy-gateway-system -l app.kubernetes.io/component=proxy

# Get the NodePort and Node IP
export GATEWAY_PORT=$(kubectl get svc -n envoy-gateway-system envoy-envoy-gateway-system-ai-gateway-78adb12c -o jsonpath='{.spec.ports[?(@.port==80)].nodePort}')
export K3S_NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "Gateway URL: http://$K3S_NODE_IP:$GATEWAY_PORT"
```
## Generate Test JWT Token
```bash

# Create test user and get JWT token from Keycloak
ADMIN_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" | jq -r '.access_token')

# Create test user
curl -s -X POST \
  http://localhost:8080/admin/realms/master/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "enabled": true,
    "credentials": [
      {
        "type": "password",
        "value": "testpass123",
        "temporary": false
      }
    ]
  }'

# Get user token
USER_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass123&grant_type=password&client_id=admin-cli" | jq -r '.access_token')

echo "Test JWT Token: $USER_TOKEN"
```
# Test Authorization Flow

# Test 1: Request without auth header (Should be denied)
```bash

curl -v -H "Host: ai.local.dev" http://$K3S_NODE_IP:$GATEWAY_PORT/
```
Expected Result: 403 Forbidden from your Rust auth service
`text
...
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< server: nginx/1.29.2
< date: Thu, 16 Oct 2025 10:41:37 GMT
< content-type: application/octet-stream
< content-length: 9
< www-authenticate: Bearer
< x-envoy-upstream-service-time: 0
< 
* Connection #0 to host 192.168.4.35 left intact
Forbidden%                                       
`
Test 2: Request with valid JWT auth header
```bash
curl -v -H "Host: ai.local.dev" -H "authorization: Bearer $USER_TOKEN" http://$K3S_NODE_IP:$GATEWAY_PORT/
```
Expected Result: 200 OK from the AI backend service
`text
...
Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< server: nginx/1.29.2
< date: Thu, 16 Oct 2025 10:41:49 GMT
< content-type: text/html
< content-length: 615
< last-modified: Tue, 07 Oct 2025 18:13:31 GMT
< etag: "68e5584b-267"
< accept-ranges: bytes
...
`
# Monitor Logs for Verification
Check Rust Self-Service Logs
```bash
kubectl logs -f -n envoy-gateway-system deployment/self-service-app
```
Expected Log Output:
`text
INFO: Received auth request from 10.42.X.X
INFO: Validating JWT token against JWKS endpoint
INFO: Authorization decision: ALLOWED for user: testuser
`
Check Envoy Gateway Logs
```bash
kubectl logs -f -n envoy-gateway-system -l app.kubernetes.io/component=proxy -c envoy
```
Expected Log Output:
`text
[info] External auth check completed, status: OK
[info] Routing authorized request to backend
`
Check AI Backend Logs
```bash
kubectl logs -f -n model deployment/ai-backend
```
Expected Log Output:
`text
10.42.X.X - - [timestamp] "GET / HTTP/1.1" 200 -
`
# Step 7: Troubleshooting
Verify All Components
```bash
# Check all pods are running
kubectl get pods --all-namespaces

# Check services
kubectl get svc --all-namespaces

# Check SecurityPolicy
kubectl get securitypolicy -A

# Check HTTPRoute status
kubectl get httproute -o yaml

# Check ReferenceGrant
kubectl get referencegrant -A
```
# Common Issues and Solutions

## Issue: SecurityPolicy not working
```bash
# Check SecurityPolicy events
kubectl describe securitypolicy self-service-authz

# Check if targetRef matches HTTPRoute
kubectl get httproute ai-http-route -o yaml
```
## Issue: Rust service not reachable
```bash
# Test service connectivity directly
kubectl run -it --rm debug-pod --image=curlimages/curl --restart=Never -- \
  curl -v http://self-service-svc.envoy-gateway-system.svc.cluster.local:3000/health

# Check service endpoints
kubectl get endpoints -n envoy-gateway-system self-service-svc
```
## Issue: JWT Token Validation Failing
```bash
# Check Keycloak JWKS endpoint
curl -s http://keycloak.envoy-gateway-system.svc.cluster.local:8080/realms/master/protocol/openid-connect/certs | jq

# Check Rust service JWT validation logs
kubectl logs -n envoy-gateway-system deployment/self-service-app | grep -i jwt
```
# Step 8: Performance Testing

## Load Test with Authentication
```bash

# Install hey load testing tool
go install github.com/rakyll/hey@latest

# Run load test with JWT headers
hey -n 100 -c 10 -H "Host: ai.local.dev" -H "authorization: Bearer $USER_TOKEN" http://$K3S_NODE_IP:$GATEWAY_PORT/
```
Expected Architecture Diagram
`text

┌─────────────────┐    ┌─────────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Client        │ ──▶│ Envoy AI Gateway    │ ──▶│ Rust Auth Service│ ──▶│   Keycloak       │
│                 │    │                     │    │ (Self-Service)   │    │   JWKS Validation│
└─────────────────┘    └─────────────────────┘    └──────────────────┘    └──────────────────┘
                              │                           │                         │
                              │                           │                         │
                              ▼                           │                         │
                    ┌──────────────────┐                 │                         │
                    │   AI Backend     │ ◀────────────────┘                         │
                    │   Services       │                                            │
                    └──────────────────┘                                            │
                                                                                    │
                              JWT Token Validation ◀────────────────────────────────┘
`
Success Criteria

    ✅ k3s cluster running

    ✅ Keycloak deployed for JWT token management

    ✅ Self-service Rust application deployed and responsive with JWKS validation

    ✅ Envoy AI Stack installed and gateway operational

    ✅ SecurityPolicy configured and targeting HTTPRoute

    ✅ ReferenceGrant configured for cross-namespace access

    ✅ Requests without auth headers are denied (403)

    ✅ Requests with valid JWT tokens reach AI backend (200)

    ✅ All components logging appropriately

    ✅ End-to-end request flow working as expected

# Conclusion

This documentation provides a complete workflow for integrating external authorization with Envoy AI Gateway using JWT tokens and Keycloak. The setup ensures that all incoming requests are first validated by your Rust self-service application against a JWKS endpoint before reaching the AI backend services, providing a secure and scalable authorization layer for your AI platform.