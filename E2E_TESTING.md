# End-to-End Testing Guide for Lightbridge Authz

This document provides a step-by-step guide to deploy and test the `lightbridge-authz` service in a local Kubernetes environment using `k3s`. The setup includes deploying the application, a PostgreSQL database, and a configured Envoy proxy to act as a gateway that uses `lightbridge-authz` for external authorization.

## Prerequisites

Before you begin, ensure you have the following tools installed:

*   **Docker**: To build the container image.
*   **kubectl**: The Kubernetes command-line tool.
*   **Helm**: The package manager for Kubernetes.
*   **curl**: A command-line tool for transferring data with URLs.

## Step 1: Install k3s and Configure Environment

`k3s` is a lightweight, certified Kubernetes distribution.

1.  **Install k3s:**
    ```bash
    curl -sfL https://get.k3s.io | sh - 
    ```
    *This command downloads and runs the official `k3s` installation script.*

2.  **Configure `kubectl`:**
    The installer automatically configures a `kubectl` config file at `/etc/rancher/k3s/k3s.yaml`. To use it, either set the `KUBECONFIG` environment variable or merge it with your existing configuration.
    ```bash
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    kubectl get nodes
    ```
    *You should see the master node in the `Ready` state.*

## Step 2: Build and Load the Container Image

Build the `lightbridge-authz` container image and load it into the `k3s` container runtime so the cluster can access it without a remote registry.

1.  **Build the image using Docker:**
    The `Dockerfile` in the root of the project is a multi-stage build. We will tag the resulting image as `lightbridge-authz:latest`.
    ```bash
    docker build -t lightbridge-authz:latest .
    ```

2.  **Load the image into k3s:**
    `k3s` uses containerd as its runtime. Use the `k3s ctr` command to import the image.
    ```bash
    docker save lightbridge-authz:latest | sudo k3s ctr images import -
    ```
    *This command pipes the Docker image into the `k3s` containerd image store.*

## Step 3: Deploy PostgreSQL

The application requires a PostgreSQL database. A sample manifest is provided in the repository.

1.  **Deploy PostgreSQL:**
    ```bash
    kubectl apply -f k8s-postgresql.yaml
    ```
    *This creates a `StatefulSet` for PostgreSQL and a `Service` named `postgres` in the `default` namespace.*

2.  **Verify the deployment:**
    ```bash
    kubectl get pods -l app=postgres
    ```
    *Wait until the `postgres-0` pod is in the `Running` state.*

## Step 4: Deploy Lightbridge Authz

Deploy the application using the provided Helm chart.

1.  **Update Helm dependencies:**
    ```bash
    helm dependency update charts/lightbridge-authz
    ```

2.  **Install the Helm chart:**
    We need to override some default values in the chart, specifically the image repository and tag, and ensure the application connects to the correct database.
    ```bash
    helm install authz charts/lightbridge-authz \
      --set image.repository=lightbridge-authz \
      --set image.tag=latest \
      --set image.pullPolicy=Never \
      --set config.database.url="postgres://postgres:postgres@postgres:5432/postgres"
    ```
    *This command deploys `lightbridge-authz` with the name `authz`. It uses the local image `lightbridge-authz:latest` and configures the database connection string to point to the `postgres` service.*

3.  **Verify the deployment:**
    ```bash
    kubectl get pods -l app.kubernetes.io/name=lightbridge-authz
    ```
    *Wait until the pod is `Running`.*

## Step 5: Deploy and Configure Envoy

Deploy Envoy and configure it to use `lightbridge-authz` for external authorization using the `lightbridge-config` Helm chart.

1.  **Install the Envoy Gateway chart:**
    This is a prerequisite for the `lightbridge-config` chart.
    ```bash
    helm install gateway envoy-gateway/gateway -n envoy-gateway-system --create-namespace
    ```

2.  **Install the `lightbridge-config` chart:**
    This chart configures Envoy to route traffic and use our `authz` service as an external authorizer. The `security.extAuth.http.backendRefs` value must point to the gRPC service of our deployment (`authz-lightbridge-authz` on port `3001`).
    ```bash
    helm install config charts/lightbridge-config \
      --set security.extAuth.http.backendRefs[0].name=authz-lightbridge-authz \
      --set security.extAuth.http.backendRefs[0].port=3001
    ```

3.  **Verify the deployment:**
    ```bash
    kubectl get gateway,httproute,securitypolicy
    ```
    *This shows the created Envoy resources.*

## Step 6: Verify the Integration

Test the full flow by sending a request through the Envoy proxy.

1.  **Get the Envoy Gateway IP:**
    ```bash
    export GATEWAY_IP=$(kubectl get service -n envoy-gateway-system -l "gateway.envoyproxy.io/gateway-name=public-gw" -o jsonpath='{.items[0].spec.clusterIP}')
    echo "Envoy Gateway IP: $GATEWAY_IP"
    ```

2.  **Create an API Key (Example):**
    For a real test, you would need to generate a valid API key and store it in the database. For this example, we will assume a key `test-key` exists. You can connect to the PostgreSQL pod to insert one manually if needed.

3.  **Send a request WITHOUT an API key:**
    The request should be denied by the authorizer.
    ```bash
    curl -v http://$GATEWAY_IP/
    ```
    *You should receive an HTTP `403 Forbidden` response.*

4.  **Send a request WITH an API key:**
    The request should be allowed.
    ```bash
    curl -v -H "Authorization: Bearer test-key" http://$GATEWAY_IP/
    ```
    *Assuming `test-key` is a valid key, you should receive an HTTP `200 OK` response from the upstream service.*

5.  **Check Logs:**
    You can inspect the logs of the `lightbridge-authz` pod to see the incoming authorization requests.
    ```bash
    kubectl logs -l app.kubernetes.io/name=lightbridge-authz -f
    ```

## Step 7: Cleanup

To remove all the resources created during this guide:

1.  **Uninstall Helm releases:**
    ```bash
    helm uninstall config
    helm uninstall authz
    helm uninstall gateway -n envoy-gateway-system
    ```

2.  **Delete the database:**
    ```bash
    kubectl delete -f k8s-postgresql.yaml
    ```

3.  **Uninstall k3s:**
    ```bash
    /usr/local/bin/k3s-uninstall.sh
    ```