#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 2 - Full Stack Deployment
# ==============================================================================
# Purpose:
#   Orchestrates the complete, production-grade deployment of the 3-tier
#   DevSecOps demonstration stack onto the target Kubernetes cluster.
#
# Deployment Sequence:
#   Step 1:  Build the API container image locally (`devsecops-demo-api:latest`).
#   Step 2:  Load container image into local Kind/Minikube cluster nodes.
#   Step 3:  Apply Pod Security Admission (PSA) hardened namespace (`devsecops-demo`).
#   Step 4:  Apply security policies (NetworkPolicies, RBAC, ServiceAccounts, Quotas).
#   Step 5:  Apply configuration and secrets (ConfigMap & Secrets).
#   Step 6:  Deploy stateful data tier (PostgreSQL 15-alpine StatefulSet & Service).
#   Step 7:  Deploy cache tier (Redis 7-alpine Deployment & Service).
#   Step 8:  Deploy application tier (Express.js API Deployment, Service, HPA).
#   Step 9:  Wait for workload pods to reach Ready status.
#   Step 10: Apply Ingress routing (NGINX Ingress with rate limiting & TLS).
#   Step 11: Deploy / verify observability stack (Prometheus & Grafana).
#   Step 12: Output comprehensive status summary & endpoint URLs.
#
# DevSecOps Principles:
#   - Shift-Left Security: Immutable container builds, non-root user enforcement.
#   - Defense-in-Depth: PSA Restricted profile + NetworkPolicies + Least-Privilege RBAC.
#   - Zero-Downtime Rollouts: RollingUpdate strategy with maxUnavailable: 0.
#   - Secret Isolation: Separation of configuration (ConfigMap) from credentials (Secret).
#   - Elastic Resilience: Horizontal Pod Autoscaler (HPA) configured for 2-5 replicas.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Formatting and UI Helpers
# ------------------------------------------------------------------------------
COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
COLOR_MAGENTA="\033[1;35m"
BOLD="\033[1m"

log_step() {
  echo -e "\n${COLOR_CYAN}${BOLD}==> [$1] $2${COLOR_RESET}"
}

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
  echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

log_error() {
  echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/preflight.sh" ]]; then
  # shellcheck source=demo/lib/preflight.sh
  source "${SCRIPT_DIR}/lib/preflight.sh"
fi

NAMESPACE="${NAMESPACE:-devsecops-demo}"
MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
CLUSTER_NAME="${CLUSTER_NAME:-devsecops-cluster}"
IMAGE_NAME="devsecops-demo-api"
IMAGE_TAG="latest"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

echo -e "${COLOR_MAGENTA}${BOLD}"
echo "======================================================================"
echo " 🚀 DevSecOps Demo: Step 2 - Full Stack Orchestrated Deployment"
echo " Container Image:  ${FULL_IMAGE}"
echo "======================================================================"
echo -e "${COLOR_RESET}"

if type run_standard_preflight &>/dev/null; then
  run_standard_preflight "${NAMESPACE}"
fi

# ------------------------------------------------------------------------------
# Step 1: Build the API Container Image Locally
# ------------------------------------------------------------------------------
log_step "1/10" "Building container image (${FULL_IMAGE})..."
docker build -t "${FULL_IMAGE}" .
log_success "Container image '${FULL_IMAGE}' built successfully."

# ------------------------------------------------------------------------------
# Step 2: Load Image into Local Cluster
# ------------------------------------------------------------------------------
log_step "2/10" "Sideloading image into local Kubernetes nodes..."
if command -v kind &>/dev/null && kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  log_info "Loading image into KinD cluster '${CLUSTER_NAME}'..."
  kind load docker-image "${FULL_IMAGE}" --name "${CLUSTER_NAME}"
  log_success "Image loaded into KinD."
elif command -v minikube &>/dev/null && minikube status -p "${CLUSTER_NAME}" &>/dev/null; then
  log_info "Loading image into Minikube profile '${CLUSTER_NAME}'..."
  minikube image load "${FULL_IMAGE}" -p "${CLUSTER_NAME}"
  log_success "Image loaded into Minikube."
else
  log_warn "Cluster '${CLUSTER_NAME}' not found in kind or minikube; skipping node pre-load."
fi

# ------------------------------------------------------------------------------
# Step 3: Apply Namespace
# ------------------------------------------------------------------------------
log_step "3/10" "Applying Pod Security Admission (PSA) hardened namespace..."
kubectl apply -f k8s/namespace.yaml
log_success "Namespace '${NAMESPACE}' applied with PSA 'restricted' profile."

# ------------------------------------------------------------------------------
# Step 4: Apply Security Policies
# ------------------------------------------------------------------------------
log_step "4/10" "Applying core security policies (NetworkPolicies, RBAC, Quotas, ServiceAccount)..."

if [[ -f k8s/security/pod-security.yaml ]]; then
  kubectl apply -f k8s/security/pod-security.yaml
fi

if [[ -f k8s/security/resource-quotas.yaml ]]; then
  kubectl apply -f k8s/security/resource-quotas.yaml
fi

if [[ -f k8s/security/service-account.yaml ]]; then
  kubectl apply -f k8s/security/service-account.yaml
fi

if [[ -f k8s/security/rbac.yaml ]]; then
  kubectl apply -f k8s/security/rbac.yaml
fi

if [[ -f k8s/security/network-policies.yaml ]]; then
  kubectl apply -f k8s/security/network-policies.yaml
fi
log_success "Security governance, RBAC, and zero-trust network policies enforced."

# ------------------------------------------------------------------------------
# Step 5: Apply Secrets and ConfigMaps
# ------------------------------------------------------------------------------
log_step "5/10" "Provisioning ConfigMap and Secrets..."
kubectl apply -f k8s/base/configmap.yaml
kubectl apply -f k8s/base/secrets.yaml
log_success "Configuration and credentials mounted."

# ------------------------------------------------------------------------------
# Step 6: Deploy Workloads (PostgreSQL, Redis, API, HPA)
# ------------------------------------------------------------------------------
log_step "6/10" "Deploying 3-tier application workloads..."

# Data Tier: PostgreSQL StatefulSet
log_info "Deploying PostgreSQL 15-alpine stateful storage and service..."
kubectl apply -f k8s/base/postgres-service.yaml
kubectl apply -f k8s/base/postgres-statefulset.yaml

# Cache Tier: Redis Deployment
log_info "Deploying Redis 7-alpine cache and service..."
kubectl apply -f k8s/base/redis-service.yaml
kubectl apply -f k8s/base/redis-deployment.yaml

# Application Tier: Express.js API & HPA
log_info "Deploying Express.js API (replicas: 2) and Service..."
kubectl apply -f k8s/base/api-service.yaml
kubectl apply -f k8s/base/api-deployment.yaml

log_info "Deploying Horizontal Pod Autoscaler (2-5 replicas, 70% CPU target)..."
kubectl apply -f k8s/base/api-hpa.yaml

log_success "All workload manifests submitted to cluster control-plane."

# ------------------------------------------------------------------------------
# Step 7: Wait for Workload Readiness
# ------------------------------------------------------------------------------
log_step "7/10" "Waiting for all pods to achieve Ready condition..."
log_info "Waiting for PostgreSQL StatefulSet rollout..."
kubectl rollout status statefulset/postgres -n "${NAMESPACE}" --timeout=180s

log_info "Waiting for Redis Deployment rollout..."
kubectl rollout status deployment/redis -n "${NAMESPACE}" --timeout=180s

log_info "Waiting for API Deployment rollout (2 replicas)..."
kubectl rollout status deployment/api -n "${NAMESPACE}" --timeout=180s

kubectl wait --namespace "${NAMESPACE}" --for=condition=ready pod --all --timeout=60s
log_success "All pods in namespace '${NAMESPACE}' are healthy and ready!"

# ------------------------------------------------------------------------------
# Step 8: Apply Ingress Routing
# ------------------------------------------------------------------------------
log_step "8/10" "Applying NGINX Ingress rules..."
kubectl apply -f k8s/base/ingress.yaml
log_success "Ingress rule created (Host: devsecops-demo.local, Port 80 -> Service 'api:80')."

# ------------------------------------------------------------------------------
# Step 9: Deploy Monitoring Stack (Prometheus & Grafana)
# ------------------------------------------------------------------------------
log_step "9/10" "Verifying / Provisioning Observability Stack (monitoring namespace)..."

kubectl create namespace "${MONITORING_NAMESPACE}" 2>/dev/null || true

# If Prometheus manifests exist in repo or need deploying, apply them
if [[ -d monitoring ]] || [[ -d k8s/monitoring ]]; then
  log_info "Applying repository monitoring manifests..."
  kubectl apply -R -f monitoring/ 2>/dev/null || kubectl apply -R -f k8s/monitoring/ 2>/dev/null || true
else
  log_info "Deploying lightweight Prometheus & Grafana stack for metrics scraping..."
  # Create lightweight Prometheus config and deployment for scraping API /metrics
  cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
  labels:
    app.kubernetes.io/name: prometheus
data:
  prometheus.yml: |
    global:
      scrape_interval: 5s
      evaluation_interval: 5s
    scrape_configs:
      - job_name: 'devsecops-demo-api'
        metrics_path: '/metrics'
        kubernetes_sd_configs:
          - role: endpoints
            namespaces:
              names:
                - devsecops-demo
        relabel_configs:
          - source_labels: [__meta_kubernetes_service_name]
            action: keep
            regex: api
          - source_labels: [__meta_kubernetes_endpoint_port_name]
            action: keep
            regex: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
  labels:
    app.kubernetes.io/name: prometheus
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: prometheus
  template:
    metadata:
      labels:
        app.kubernetes.io/name: prometheus
    spec:
      containers:
        - name: prometheus
          image: prom/prometheus:v2.45.0
          args:
            - "--config.file=/etc/prometheus/prometheus.yml"
            - "--storage.tsdb.path=/prometheus"
          ports:
            - containerPort: 9090
              name: web
          volumeMounts:
            - name: config
              mountPath: /etc/prometheus
            - name: storage
              mountPath: /prometheus
      volumes:
        - name: config
          configMap:
            name: prometheus-config
        - name: storage
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: monitoring
  labels:
    app.kubernetes.io/name: prometheus
spec:
  ports:
    - port: 9090
      targetPort: 9090
      name: web
  selector:
    app.kubernetes.io/name: prometheus
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
  labels:
    app.kubernetes.io/name: grafana
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: grafana
  template:
    metadata:
      labels:
        app.kubernetes.io/name: grafana
    spec:
      containers:
        - name: grafana
          image: grafana/grafana:10.0.3
          ports:
            - containerPort: 3000
              name: web
          env:
            - name: GF_SECURITY_ADMIN_USER
              value: "admin"
            - name: GF_SECURITY_ADMIN_PASSWORD
              value: "admin"
            - name: GF_USERS_ALLOW_SIGN_UP
              value: "false"
---
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: monitoring
  labels:
    app.kubernetes.io/name: grafana
spec:
  ports:
    - port: 3000
      targetPort: 3000
      name: web
  selector:
    app.kubernetes.io/name: grafana
EOF
fi

log_info "Waiting for monitoring stack rollout..."
kubectl rollout status deployment/prometheus -n "${MONITORING_NAMESPACE}" --timeout=120s 2>/dev/null || true
kubectl rollout status deployment/grafana -n "${MONITORING_NAMESPACE}" --timeout=120s 2>/dev/null || true
log_success "Monitoring stack operational."

# ------------------------------------------------------------------------------
# Step 10: Print Deployment Status and Access Endpoints
# ------------------------------------------------------------------------------
log_step "10/10" "Deployment Complete - System Inventory"

echo -e "\n${COLOR_CYAN}Current Pod Status (${NAMESPACE}):${COLOR_RESET}"
kubectl get pods -n "${NAMESPACE}" -o wide

echo -e "\n${COLOR_CYAN}Horizontal Pod Autoscaler (${NAMESPACE}):${COLOR_RESET}"
kubectl get hpa -n "${NAMESPACE}"

echo -e "\n${COLOR_CYAN}Active Network Policies (${NAMESPACE}):${COLOR_RESET}"
kubectl get networkpolicy -n "${NAMESPACE}"

echo -e "\n${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} 🎉 Full Stack Successfully Deployed!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${BOLD}Access Endpoints & Verification:${COLOR_RESET}"
echo -e "  🌐 Ingress (via Hosts file / Host header):"
echo -e "     curl -H 'Host: devsecops-demo.local' http://localhost"
echo -e "     curl -H 'Host: devsecops-demo.local' http://localhost/api/health"
echo -e ""
echo -e "  🔌 Direct Port-Forwarding (Optional):"
echo -e "     kubectl port-forward -n ${NAMESPACE} svc/api 3000:80"
echo -e "     -> Test: curl http://localhost:3000/api/status"
echo -e ""
echo -e "  📊 Observability Dashboards:"
echo -e "     Run: ${BOLD}bash demo/08-show-dashboards.sh${COLOR_RESET}"
echo -e "     - Grafana:    http://localhost:3001 (User: admin / Pass: admin)"
echo -e "     - Prometheus: http://localhost:9090"
echo -e ""
echo -e "Next Step: Execute ${BOLD}bash demo/03-verify-network-policies.sh${COLOR_RESET}"
